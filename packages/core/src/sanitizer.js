/**
 * Text sanitization: remove detected threats from content.
 *
 * Order matters:
 *   1. Normalize homoglyphs to Latin
 *   2. Strip invisible Unicode
 *   3. Strip control chars
 *   4. Strip hidden HTML elements (if HTML)
 *   5. Redact suspicious patterns
 */

import { stripInvisibleUnicode } from "./invisible-unicode.js";
import { stripControlChars } from "./control-chars.js";
import { stripHiddenElements } from "./hidden-elements.js";
import { stripSuspiciousPatterns } from "./suspicious-patterns.js";
import { normalizeHomoglyphs } from "./homoglyphs.js";
import { ALL_CATEGORIES } from "./detector.js";
import {
  normalizeFormulaPrefix,
  normalizeXlfn,
} from "./opc-helpers.js";

/**
 * Sanitize content by removing/redacting detected threats.
 *
 * @param {string} content
 * @param {Object} options
 * @param {string} [options.fileType] - "text" or "html"
 * @param {string[]} [options.categories] - Which categories to sanitize
 * @returns {{ cleaned: string, removedCounts: Object }}
 */
export function sanitize(content, options = {}) {
  const {
    fileType = "text",
    categories = ALL_CATEGORIES,
  } = options;

  const wanted = new Set(categories);
  const removedCounts = {
    invisibleUnicode: 0,
    controlChars: 0,
    hiddenHtml: 0,
    suspiciousPatterns: 0,
    homoglyphs: 0,
  };

  let result = content;
  let before;

  if (wanted.has("homoglyphs")) {
    before = result;
    result = normalizeHomoglyphs(result);
    removedCounts.homoglyphs = countDiff(before, result);
  }

  if (wanted.has("invisibleUnicode")) {
    before = result;
    result = stripInvisibleUnicode(result);
    removedCounts.invisibleUnicode = before.length - result.length;
  }

  if (wanted.has("controlChars")) {
    before = result;
    result = stripControlChars(result);
    removedCounts.controlChars = before.length - result.length;
  }

  if (wanted.has("hiddenHtml") && fileType === "html") {
    before = result;
    result = stripHiddenElements(result);
    // Count replacements instead of char diff
    const replacements = (result.match(/\[REMOVED: hidden element\]/g) || [])
      .length;
    removedCounts.hiddenHtml = replacements;
  }

  // S10: CSV / XLSX formula-injection neutralization.
  //
  // Must run BEFORE stripSuspiciousPatterns: stripSuspiciousPatterns can match
  // text *inside* a formula body (e.g. an =HYPERLINK(...) that contains a
  // "system:" prompt-fragment) and replace it with [REMOVED]; if it runs first
  // the formula prefix would survive on a now-empty payload (`'=` after
  // redaction) and the round-trip test would still see a leading `=`. By
  // neutralizing the formula prefix FIRST we ensure every dangerous-cell line
  // gets a leading `'` (RFC 4180 escape convention) so a rescan of the
  // sanitized output emits zero formula-injection findings.
  if (wanted.has("suspiciousPatterns") &&
      (fileType === "csv" || fileType === "xlsx")) {
    before = result;
    const { text: stripped, replaced } = stripFormulaPrefix(result);
    result = stripped;
    // Fold the count into the suspiciousPatterns bucket — the formula
    // findings live there per R13, so the sanitize counter mirrors that.
    removedCounts.suspiciousPatterns += replaced;
  }

  if (wanted.has("suspiciousPatterns")) {
    before = result;
    result = stripSuspiciousPatterns(result);
    removedCounts.suspiciousPatterns += (result.match(/\[REMOVED\]/g) || [])
      .length;
  }

  return {
    cleaned: result,
    removedCounts,
  };
}

// ---------------------------------------------------------------------------
// stripFormulaPrefix — neutralize dangerous CSV / XLSX cell formulas.
// ---------------------------------------------------------------------------

const _DANGEROUS_PREFIX_CHARS = new Set([
  0x3d, // =
  0x2b, // +
  0x2d, // -
  0x40, // @
  0x09, // TAB
  0x0d, // CR
]);

/**
 * Prepend a single-quote (`'`) to every dangerous cell — the standard CSV /
 * Excel escape that converts a formula cell into a literal text cell on import.
 *
 * Walks the content line-by-line and inspects the cell-text portion (after a
 * parser-emitted `[Sheet 'Name'!A1] ` prefix, when present). A line is
 * neutralized when, after normalizeFormulaPrefix + normalizeXlfn, its first
 * char is one of `[= + - @ \t \r]`. The `'` is inserted at the original cell-
 * text start (BEFORE any leading whitespace), so a CSV import that strips
 * leading whitespace still sees the leading `'`.
 *
 * Round-trip contract: scan → sanitize → re-scan with the formula-injection
 * detector → expect 0 findings. The numeric / phone suppression keeps benign
 * negative numbers and phone strings untouched (we exit early via the same
 * normalization the detector uses).
 *
 * @param {string} content
 * @param {Object} [opts]
 * @returns {{ text: string, replaced: number }}
 */
export function stripFormulaPrefix(content, opts = {}) {
  if (typeof content !== "string" || content.length === 0) {
    return { text: content || "", replaced: 0 };
  }
  const out = [];
  let lineStart = 0;
  let i = 0;
  let replaced = 0;
  const len = content.length;
  // Pre-compiled shape regexes (mirror formula-injection.js suppression).
  const NUMERIC = /^[+-]?\d+(?:\.\d+)?$/;
  const DECIMAL = /^[+-]?\d*\.\d+$/;
  const PHONE = /^\+\d{1,3}[\d \-()]{5,}$/;

  while (i <= len) {
    if (i === len || content.charCodeAt(i) === 0x0a /* \n */) {
      const rawLine = content.slice(lineStart, i);
      // Preserve CR (so CRLF stays CRLF on round-trip); separate it from the
      // cell-text analysis so we don't pick up `\r` as a dangerous trailing
      // char on the previous line.
      let body = rawLine;
      let tail = "";
      if (body.length > 0 && body.charCodeAt(body.length - 1) === 0x0d) {
        tail = "\r";
        body = body.slice(0, -1);
      }

      // Separate `[...] ` parser prefix from cell text (defensive — only
      // when both `[` and `] ` are present at the very start).
      let prefix = "";
      let cellText = body;
      if (body.length > 0 && body.charCodeAt(0) === 0x5b) {
        const close = body.indexOf("] ");
        if (close > 0) {
          prefix = body.slice(0, close + 2);
          cellText = body.slice(close + 2);
        }
      }

      if (cellText.length > 0) {
        const norm = normalizeXlfn(normalizeFormulaPrefix(cellText));
        if (norm.length > 0 &&
            _DANGEROUS_PREFIX_CHARS.has(norm.charCodeAt(0)) &&
            !NUMERIC.test(norm) &&
            !DECIMAL.test(norm) &&
            !PHONE.test(norm)) {
          // Already-quoted cells must not be double-quoted (idempotent on
          // re-sanitize). The original cell-text begins with a `'` only when
          // the user typed one; check the RAW char at position 0 of cellText.
          if (cellText.charCodeAt(0) !== 0x27 /* ' */) {
            cellText = "'" + cellText;
            replaced++;
          }
        }
      }

      out.push(prefix + cellText + tail);
      if (i < len) out.push("\n");
      lineStart = i + 1;
    }
    i++;
  }

  return { text: out.join(""), replaced };
}

function countDiff(before, after) {
  // For homoglyph normalization, content length typically stays the same
  // Count character-level diffs
  let diff = 0;
  const len = Math.min(before.length, after.length);
  for (let i = 0; i < len; i++) {
    if (before[i] !== after[i]) diff++;
  }
  return diff;
}
