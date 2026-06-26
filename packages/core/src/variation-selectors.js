/**
 * Variation Selectors detection.
 *
 * Detects Unicode Variation Selectors (VS) which can be abused for
 * "Emoji Smuggling" / GlassWorm-style steganographic payloads:
 *
 * - VS1-16  : U+FE00 .. U+FE0F  (standard Variation Selectors)
 * - VS17-256: U+E0100 .. U+E01EF (Variation Selectors Supplement)
 *
 * Severity is context-aware to avoid false-positive explosion (Risk #2):
 *
 *   info    : U+FE0F immediately after an Emoji_Base codepoint
 *             (legitimate "make this emoji render in color" usage)
 *   info    : VS17-256 immediately after a CJK ideograph base
 *             (legitimate Japanese / Han IVS, e.g. 葛 + U+E0100)
 *   warning : Two consecutive VS characters
 *   danger  : Three or more consecutive VS characters
 *             (GlassWorm / Emoji Smuggling signal)
 *   danger  : VS17-256 attached to a non-CJK / non-Emoji_Base codepoint
 *   danger  : A VS appearing standalone with no base character
 *
 * NOTE: This module ONLY detects. It does not decode VS payloads back
 * into bytes/ASCII (Risk #12: decoded output would become a secondary
 * injection vector if echoed back through the scan response).
 */

import { getContext } from "./utils.js";

// --- Range helpers ----------------------------------------------------------

/** Standard Variation Selectors VS1..VS16 */
function isVS1to16(cp) {
  return cp >= 0xfe00 && cp <= 0xfe0f;
}

/** Variation Selectors Supplement VS17..VS256 */
function isVS17to256(cp) {
  return cp >= 0xe0100 && cp <= 0xe01ef;
}

/** Any Variation Selector */
function isVariationSelector(cp) {
  return isVS1to16(cp) || isVS17to256(cp);
}

/**
 * CJK Unified Ideographs ranges that legitimately use IVS (VS17-256).
 *  - CJK Unified Ideographs                : U+3400 .. U+9FFF
 *    (covers Extension A U+3400..U+4DBF and the main block U+4E00..U+9FFF)
 *  - CJK Unified Ideographs Extension B    : U+20000 .. U+2A6DF
 *
 * This intentionally matches the spec given in the task. We keep it
 * conservative (a small set of well-known blocks) rather than every CJK
 * extension, because broader allowlists would weaken Risk #2 protection.
 */
function isCjkBase(cp) {
  if (cp >= 0x3400 && cp <= 0x9fff) return true;
  if (cp >= 0x20000 && cp <= 0x2a6df) return true;
  return false;
}

/**
 * Emoji_Base heuristic: codepoints that legitimately take U+FE0F as a
 * "use emoji presentation" selector.
 *
 *  - Misc Symbols & Pictographs / Emoticons / Transport / etc:
 *      U+1F300 .. U+1F9FF
 *  - Misc Symbols and Dingbats:
 *      U+2600  .. U+27BF
 *
 * This is a deliberate heuristic, not an exhaustive emoji table — the goal
 * is just to suppress the FE0F-after-emoji false-positive flood. Anything
 * outside this range that carries FE0F still gets flagged.
 */
function isEmojiBase(cp) {
  if (cp >= 0x1f300 && cp <= 0x1f9ff) return true;
  if (cp >= 0x2600 && cp <= 0x27bf) return true;
  return false;
}

// --- Formatting -------------------------------------------------------------

function formatCodePoint(cp) {
  const hex = cp.toString(16).toUpperCase();
  return `U+${hex.padStart(cp > 0xffff ? 5 : 4, "0")}`;
}

/** Character length in UTF-16 code units (1 for BMP, 2 for supplementary). */
function charLen(cp) {
  return cp > 0xffff ? 2 : 1;
}

/**
 * Look up the codepoint immediately *before* `pos` in `text`, handling
 * surrogate pairs. Returns null if there is no preceding character.
 */
function prevCodePoint(text, pos) {
  if (pos <= 0) return null;
  const prevUnit = text.charCodeAt(pos - 1);
  // Low surrogate -> combine with the high surrogate before it
  if (prevUnit >= 0xdc00 && prevUnit <= 0xdfff && pos >= 2) {
    const high = text.charCodeAt(pos - 2);
    if (high >= 0xd800 && high <= 0xdbff) {
      return text.codePointAt(pos - 2);
    }
  }
  return prevUnit;
}

// --- Main detector ----------------------------------------------------------

/**
 * Scan text for Variation Selectors and return findings.
 *
 * @param {string} text - Text to scan.
 * @returns {Array<{
 *   type: string,
 *   severity: "info"|"warning"|"danger",
 *   char: string,
 *   codePoint: number,
 *   position: number,
 *   context: string,
 *   message: string,
 *   count?: number,
 * }>}
 */
export function detectVariationSelectors(text) {
  const findings = [];
  if (typeof text !== "string" || text.length === 0) return findings;

  let i = 0;
  while (i < text.length) {
    const cp = text.codePointAt(i);
    if (cp === undefined) {
      i++;
      continue;
    }

    if (!isVariationSelector(cp)) {
      i += charLen(cp);
      continue;
    }

    // --- Found a VS at position i. Collect the full run. -------------------
    const runStart = i;
    const run = []; // array of { cp, position }
    let j = i;
    while (j < text.length) {
      const c = text.codePointAt(j);
      if (c === undefined || !isVariationSelector(c)) break;
      run.push({ cp: c, position: j });
      j += charLen(c);
    }

    const runLen = run.length;
    const baseCp = prevCodePoint(text, runStart); // null = standalone
    const firstVs = run[0];
    const firstVsLen = charLen(firstVs.cp);

    // --- Classify ----------------------------------------------------------

    if (runLen >= 3) {
      // 3+ consecutive VS — strong steganography signal.
      findings.push({
        type: "variationSelector",
        severity: "danger",
        char: formatCodePoint(firstVs.cp),
        codePoint: firstVs.cp,
        position: runStart,
        context: getContext(text, runStart, firstVsLen),
        message: `Variation Selector run of ${runLen} consecutive selectors (possible Emoji Smuggling / steganographic payload).`,
        count: runLen,
      });
    } else if (runLen === 2) {
      // Two in a row — uncommon enough to warn on.
      findings.push({
        type: "variationSelector",
        severity: "warning",
        char: formatCodePoint(firstVs.cp),
        codePoint: firstVs.cp,
        position: runStart,
        context: getContext(text, runStart, firstVsLen),
        message: `Two consecutive Variation Selectors (unusual; may indicate hidden payload).`,
        count: runLen,
      });
    } else {
      // runLen === 1 — single VS. Classification depends on the base char.
      const vs = firstVs.cp;

      if (baseCp === null) {
        // Standalone VS with no base — never legitimate.
        findings.push({
          type: "variationSelector",
          severity: "danger",
          char: formatCodePoint(vs),
          codePoint: vs,
          position: runStart,
          context: getContext(text, runStart, firstVsLen),
          message: `Standalone Variation Selector with no base character.`,
          count: 1,
        });
      } else if (isVS1to16(vs)) {
        // VS1-16. U+FE0F after an Emoji_Base is the common legitimate case.
        if (vs === 0xfe0f && isEmojiBase(baseCp)) {
          findings.push({
            type: "variationSelector",
            severity: "info",
            char: formatCodePoint(vs),
            codePoint: vs,
            position: runStart,
            context: getContext(text, runStart, firstVsLen),
            message: `U+FE0F emoji presentation selector after Emoji_Base ${formatCodePoint(baseCp)} (likely legitimate).`,
            count: 1,
          });
        } else {
          // Other VS1-15, or FE0F on a non-emoji base — warn.
          findings.push({
            type: "variationSelector",
            severity: "warning",
            char: formatCodePoint(vs),
            codePoint: vs,
            position: runStart,
            context: getContext(text, runStart, firstVsLen),
            message: `Variation Selector ${formatCodePoint(vs)} after non-emoji base ${formatCodePoint(baseCp)}.`,
            count: 1,
          });
        }
      } else {
        // VS17-256. Legitimate after a CJK base (Japanese / Han IVS);
        // suspicious elsewhere.
        if (isCjkBase(baseCp)) {
          findings.push({
            type: "variationSelector",
            severity: "info",
            char: formatCodePoint(vs),
            codePoint: vs,
            position: runStart,
            context: getContext(text, runStart, firstVsLen),
            message: `IVS selector ${formatCodePoint(vs)} after CJK base ${formatCodePoint(baseCp)} (likely legitimate Han/Japanese IVS).`,
            count: 1,
          });
        } else {
          findings.push({
            type: "variationSelector",
            severity: "danger",
            char: formatCodePoint(vs),
            codePoint: vs,
            position: runStart,
            context: getContext(text, runStart, firstVsLen),
            message: `IVS selector ${formatCodePoint(vs)} attached to non-CJK / non-Emoji base ${formatCodePoint(baseCp)} (possible hidden payload).`,
            count: 1,
          });
        }
      }
    }

    // Skip past the entire run.
    i = j;
  }

  return findings;
}

export default detectVariationSelectors;
