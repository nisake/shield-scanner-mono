/**
 * Mathematical Alphanumeric Symbols bypass detection.
 *
 * Detects characters in the Unicode "Mathematical Alphanumeric Symbols" block
 * (U+1D400 - U+1D7FF, 996 assigned code points) used to visually mimic Latin
 * letters / digits while evading naive string matchers.
 *
 *   Example: '\u{1D421}\u{1D41A}\u{1D41C}\u{1D424}'  -> looks like 'hack'
 *            '\u{1D5F6}\u{1D5F4}\u{1D5FB}\u{1D5FC}\u{1D5FF}\u{1D5F2}'
 *                                                    -> looks like 'ignore'
 *
 * Severity rules (per run of consecutive math chars):
 *   - 1 char            -> "info"
 *   - 2 or 3 chars      -> "warning"
 *   - 4 or more chars   -> "danger"   (typical bypass payload pattern)
 *
 * Intent display:
 *   Each finding includes a `normalized` field showing what the run looks like
 *   after NFKC normalization (e.g. 'ignore'). This is for *display only* and is
 *   never fed back into the default sanitization pipeline (Risk #1: keeping
 *   NFKC out of the default pipeline avoids data corruption in legitimate
 *   Japanese / fullwidth text).
 *
 * Explicit non-targets (false-positive guards):
 *   - Enclosed Alphanumerics       U+2460 - U+24FF   (circled (1)(2)(3) etc.)
 *   - Halfwidth and Fullwidth Forms U+FF00 - U+FFEF  (half-kana, A1, etc.)
 *   These ranges are legitimately used in normal Japanese text and are
 *   intentionally NOT flagged here.
 */

import { getContext } from "./utils.js";

// Mathematical Alphanumeric Symbols block bounds (inclusive).
const MATH_BLOCK_START = 0x1d400;
const MATH_BLOCK_END = 0x1d7ff;

/**
 * Is the given code point inside the Mathematical Alphanumeric Symbols block?
 * Note: not every code point in [1D400, 1D7FF] is assigned (there are a few
 * historical "holes" reserved for letters that already exist elsewhere in
 * Unicode, e.g. italic h is at U+210E). We treat the whole range as in-scope:
 * the unassigned points won't actually appear in real text, and if they ever
 * do, flagging them is the safe behavior for an obfuscation detector.
 */
function isMathAlphanumeric(cp) {
  return cp >= MATH_BLOCK_START && cp <= MATH_BLOCK_END;
}

/**
 * Severity from run length.
 */
function severityForRunLength(len) {
  if (len >= 4) return "danger";
  if (len >= 2) return "warning";
  return "info";
}

/**
 * Format a code point as U+XXXXX (uppercase, zero-padded to at least 4 hex
 * digits — supplementary plane code points naturally extend to 5).
 */
function formatCodePoint(cp) {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * Walk `text` and yield runs of consecutive Math-Alphanumeric characters.
 * Each run is { start, chars: [{ cp, char, indexInText }] }.
 *
 * `start` is the UTF-16 index of the first char of the run in the input.
 * `indexInText` is the UTF-16 index of each individual char (each math char
 * occupies a surrogate pair, so indices step by 2).
 */
function findRuns(text) {
  const runs = [];
  let current = null;

  for (let i = 0; i < text.length; i++) {
    const cp = text.codePointAt(i);
    if (cp === undefined) continue;

    const isMath = isMathAlphanumeric(cp);
    if (isMath) {
      const char = String.fromCodePoint(cp);
      if (current === null) {
        current = { start: i, chars: [{ cp, char, indexInText: i }] };
      } else {
        current.chars.push({ cp, char, indexInText: i });
      }
    } else if (current !== null) {
      runs.push(current);
      current = null;
    }

    // Skip the low surrogate of a supplementary-plane code point.
    if (cp > 0xffff) i++;
  }

  if (current !== null) runs.push(current);
  return runs;
}

/**
 * Detect Mathematical Alphanumeric Symbol abuse in `text`.
 *
 * Each character in a flagged run produces its own finding (so the caller can
 * report per-character positions), but every finding inside a run shares the
 * same severity (calculated from run length) and the same `normalized` field
 * (the NFKC form of the whole run, for intent display).
 *
 * @param {string} text
 * @returns {Array<{
 *   type: string,
 *   severity: "info"|"warning"|"danger",
 *   char: string,
 *   codePoint: string,
 *   normalized: string,
 *   position: number,
 *   context: string,
 *   message: string,
 *   runLength: number,
 * }>}
 */
function detectMathBypass(text) {
  const findings = [];
  if (typeof text !== "string" || text.length === 0) return findings;

  const runs = findRuns(text);

  for (const run of runs) {
    const len = run.chars.length;
    const severity = severityForRunLength(len);

    // Reconstruct the raw run substring and compute its NFKC form for the
    // "what does this look like?" display field. NFKC is intentionally only
    // used here, never to mutate `text` itself (Risk #1).
    const rawRun = run.chars.map((c) => c.char).join("");
    let normalized;
    try {
      normalized = rawRun.normalize("NFKC");
    } catch {
      normalized = rawRun;
    }

    const baseMessage =
      len >= 4
        ? `Mathematical Alphanumeric run of ${len} chars looks like "${normalized}" — typical obfuscation payload`
        : len >= 2
        ? `Mathematical Alphanumeric run of ${len} chars looks like "${normalized}"`
        : `Mathematical Alphanumeric char looks like "${normalized}"`;

    for (const c of run.chars) {
      findings.push({
        type: "mathAlphanumeric",
        severity,
        char: c.char,
        codePoint: formatCodePoint(c.cp),
        normalized,
        position: c.indexInText,
        context: getContext(text, c.indexInText, 2), // surrogate pair = 2 UTF-16 units
        message: baseMessage,
        runLength: len,
      });
    }
  }

  return findings;
}

// Primary export — matches the existing ESM-style modules (control-chars.js,
// homoglyphs.js, etc.). A default export is also provided so consumers that
// prefer `import detectMathBypass from "./math-bypass.js"` work as well.
export { detectMathBypass };
export default detectMathBypass;
