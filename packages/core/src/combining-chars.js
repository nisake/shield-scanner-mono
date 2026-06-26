/**
 * Combining-character density detection (Zalgo / stacked-diacritic abuse).
 *
 * Combining marks attach to a preceding base character to form a single
 * grapheme cluster. Legitimate scripts use them sparingly (1-3 marks per
 * base for accents, vowel signs, tone marks, etc.). Attackers stack them
 * dozens-deep to produce "Zalgo text" — visually disruptive payloads that
 * can hide instructions, blow past length limits, smuggle visual noise
 * past LLM tokenizers, or otherwise trick downstream consumers.
 *
 * Ranges scanned (per spec):
 *   U+0300..U+036F : Combining Diacritical Marks
 *   U+1AB0..U+1AFF : Combining Diacritical Marks Extended
 *   U+1DC0..U+1DFF : Combining Diacritical Marks Supplement
 *   U+20D0..U+20FF : Combining Diacritical Marks for Symbols
 *   U+FE20..U+FE2F : Combining Half Marks
 *
 * Severity (per spec):
 *   stackDepth >= 8  -> warning  (visually noisy, rarely legitimate)
 *   stackDepth >= 15 -> danger   (Zalgo typical)
 *   stackDepth <  8  -> not reported (suppresses real-world FPs)
 *
 * Language-aware threshold relaxation (per spec, +4 each):
 *   Arabic base        (U+0600..U+06FF / U+0750..U+077F / U+08A0..U+08FF)
 *   Thai base          (U+0E00..U+0E7F)
 *   Devanagari base    (U+0900..U+097F)
 *   Vietnamese base    (Latin Extended Additional U+1EA0..U+1EFF — Vietnamese
 *                       precomposed block, the prose script most commonly
 *                       written with extra stacked tone+diacritic marks)
 *
 * Each contiguous run of combiners on a single base produces at most ONE
 * finding (the run is reported as one event, not one finding per mark) —
 * keeps output proportional to the attack, not to the stack depth.
 *
 * Risk guardrails honored:
 *   - This module ONLY detects. It does not strip / normalize / decode.
 *     The caller's text is never mutated. (Risk #1, #12)
 *   - Pure ESM `export` — MCP edition. (no CommonJS)
 *   - Does not get wired into detector.js / sanitizer pipeline here, so the
 *     existing 62 PASS / 0 FAIL test baseline is preserved. (Risk #13)
 */

import { getContext } from "./utils.js";

// --- Combining-range helpers -----------------------------------------------

function isCombiningMark(cp) {
  if (cp >= 0x0300 && cp <= 0x036f) return true; // Combining Diacritical Marks
  if (cp >= 0x1ab0 && cp <= 0x1aff) return true; // Combining Diacritical Marks Extended
  if (cp >= 0x1dc0 && cp <= 0x1dff) return true; // Combining Diacritical Marks Supplement
  if (cp >= 0x20d0 && cp <= 0x20ff) return true; // Combining Diacritical Marks for Symbols
  if (cp >= 0xfe20 && cp <= 0xfe2f) return true; // Combining Half Marks
  return false;
}

// --- Language-aware base classifiers (for +4 threshold relaxation) ---------

function isArabicBase(cp) {
  if (cp >= 0x0600 && cp <= 0x06ff) return true;
  if (cp >= 0x0750 && cp <= 0x077f) return true;
  if (cp >= 0x08a0 && cp <= 0x08ff) return true;
  return false;
}

function isThaiBase(cp) {
  return cp >= 0x0e00 && cp <= 0x0e7f;
}

function isDevanagariBase(cp) {
  return cp >= 0x0900 && cp <= 0x097f;
}

/**
 * Vietnamese precomposed Latin block (U+1EA0..U+1EFF). The spec asks for
 * "Vietnamese base (subset of Latin Extended A)" — the script is actually
 * concentrated in Latin Extended *Additional* (U+1EA0..U+1EFF). This is the
 * block where Vietnamese characters live, and it's the only Latin range where
 * a stacked tone+diacritic combiner is a realistic legitimate pattern.
 */
function isVietnameseBase(cp) {
  return cp >= 0x1ea0 && cp <= 0x1eff;
}

/**
 * Return the +N depth bonus the spec grants to scripts whose typography
 * legitimately stacks multiple combining marks per base.
 */
function depthRelaxationFor(baseCp) {
  if (baseCp === null) return 0;
  if (
    isArabicBase(baseCp) ||
    isThaiBase(baseCp) ||
    isDevanagariBase(baseCp) ||
    isVietnameseBase(baseCp)
  ) {
    return 4;
  }
  return 0;
}

// --- Formatting + cursor helpers ------------------------------------------

function formatCodePoint(cp) {
  const hex = cp.toString(16).toUpperCase();
  return `U+${hex.padStart(cp > 0xffff ? 5 : 4, "0")}`;
}

/** Character length in UTF-16 code units (1 for BMP, 2 for supplementary). */
function charLen(cp) {
  return cp > 0xffff ? 2 : 1;
}

// --- Main detector --------------------------------------------------------

/**
 * Scan `text` for runs of combining marks stacked on a single base character.
 *
 * @param {string} text
 * @returns {Array<{
 *   type: "combiningStack",
 *   severity: "warning"|"danger",
 *   base: string|null,
 *   baseCodePoint: number|null,
 *   stackDepth: number,
 *   position: number,
 *   context: string,
 *   message: string,
 * }>}
 */
export function detectCombiningChars(text) {
  const findings = [];
  if (typeof text !== "string" || text.length === 0) return findings;

  let i = 0;
  while (i < text.length) {
    const cp = text.codePointAt(i);
    if (cp === undefined) {
      i++;
      continue;
    }

    // Skip everything that isn't a base character followed by combiners.
    // We anchor on a NON-combining codepoint, then count any combiners that
    // immediately follow it.
    if (isCombiningMark(cp)) {
      // Combining mark with no preceding base = also worth measuring as a
      // run starting "standalone" (rare, but defensive). Treat as base=null.
      const runStart = i;
      let j = i;
      let stack = 0;
      while (j < text.length) {
        const c = text.codePointAt(j);
        if (c === undefined || !isCombiningMark(c)) break;
        stack++;
        j += charLen(c);
      }
      maybeEmit(findings, text, /*baseCp*/ null, /*basePos*/ runStart, stack, runStart);
      i = j;
      continue;
    }

    // `cp` is a base. Advance past it and count any trailing combiners.
    const baseCp = cp;
    const basePos = i;
    const baseLen = charLen(baseCp);
    let j = i + baseLen;
    let stack = 0;
    const stackStart = j;
    while (j < text.length) {
      const c = text.codePointAt(j);
      if (c === undefined || !isCombiningMark(c)) break;
      stack++;
      j += charLen(c);
    }

    if (stack > 0) {
      maybeEmit(findings, text, baseCp, basePos, stack, stackStart);
    }

    i = j;
  }

  return findings;
}

/**
 * Decide whether a (base, stackDepth) pair crosses the warning/danger
 * thresholds (with language-aware relaxation) and push a finding if so.
 *
 * `reportPos` is where we point the context window — the start of the
 * combining run, so the surrounding text gives a feel for the attack.
 */
function maybeEmit(findings, text, baseCp, basePos, stack, reportPos) {
  const bonus = depthRelaxationFor(baseCp);
  const warnThreshold = 8 + bonus;
  const dangerThreshold = 15 + bonus;

  if (stack < warnThreshold) return;

  const severity = stack >= dangerThreshold ? "danger" : "warning";
  const baseStr = baseCp === null ? null : String.fromCodePoint(baseCp);
  const baseLabel = baseCp === null ? "(none)" : formatCodePoint(baseCp);
  const relaxed = bonus > 0 ? ` [script-relaxed +${bonus}]` : "";

  findings.push({
    type: "combiningStack",
    severity,
    base: baseStr,
    baseCodePoint: baseCp,
    stackDepth: stack,
    position: basePos,
    context: getContext(text, reportPos, /*matchLen*/ 1),
    message:
      `Combining-mark stack of depth ${stack} on base ${baseLabel}${relaxed} — ` +
      (severity === "danger"
        ? "Zalgo-style stacked diacritics (likely abuse)."
        : "unusually dense combining marks (possible Zalgo/visual-noise attack)."),
  });
}

export default detectCombiningChars;
