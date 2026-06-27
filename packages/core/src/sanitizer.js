/**
 * Text sanitization: remove detected threats from content.
 *
 * Order matters:
 *   1. Normalize homoglyphs to Latin
 *   2. Strip invisible Unicode
 *   3. Strip control chars
 *   4. Strip hidden HTML elements (if HTML)
 *   5. Redact suspicious patterns
 *
 * v1.19.0 C1 — Granular sanitize modes
 *   options.mode: "strip" (default, legacy) | "mask" | "placeholder"
 *     - "strip"       : remove invisible / control chars outright (legacy)
 *     - "mask"        : replace invisible / control chars with a VISIBLE
 *                       symbol so an auditor can see where the threat sat
 *                       (e.g. NULL → "␀" ␀, TAB → "␉" ␉, ZWSP → "[ZWSP]")
 *     - "placeholder" : replace with a category-tagged label such as
 *                       "[REDACTED:invisibleUnicode]" — the placeholder NEVER
 *                       carries raw user text (R12 compliant)
 *
 * In addition to `cleaned` + `removedCounts`, sanitize() now returns a
 * `meta.maskedRanges` sibling key — an array of
 *   [start, end, category, replacementLength]
 * tuples describing each rewrite.
 *
 * Positional semantics:
 *   - invisibleUnicode / controlChars / homoglyphs : start/end refer to the
 *     ORIGINAL input position of the rewritten span (these passes do a 1:1
 *     codepoint walk so the offsets are stable).
 *   - suspiciousPatterns / hiddenHtml : start/end refer to the position of
 *     the `[REMOVED]` / `[REMOVED: hidden element]` marker in the CLEANED
 *     output (these passes use regex replacement so original offsets aren't
 *     tracked through prior transforms). The replacementLength is the marker
 *     width in those cases.
 *
 * R13 byCategory routing is preserved exactly; maskedRanges is a sibling,
 * NOT a new byCategory bucket. R12: no raw user text in any maskedRanges
 * entry — only positions, category name (one of the 5 R13 buckets), and
 * the replacement label length.
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

const SUPPORTED_MODES = new Set(["strip", "mask", "placeholder"]);

// Mask-mode visible symbols for invisible / control characters.
//   * C0 controls   → Unicode Control Pictures block (U+2400 - U+241F)
//   * DEL (0x7F)    → U+2421 (SYMBOL FOR DELETE)
//   * C1 controls   → "[C1:U+00xx]" (no Control-Pictures glyph exists)
//   * Tags Block    → "[TAG:U+E0xxx]"
//   * Known invisible (zero-width, bidi, etc) → "[<short-name>]"
//
// These symbols are themselves printable, so a mask-mode result is visually
// "what was there", not a stripped result. R12: the symbol carries the
// codepoint label only — never raw user text from the surrounding span.
const INVISIBLE_MASK_LABELS = new Map([
  [0x00ad, "[SHY]"],     // soft hyphen
  [0x200b, "[ZWSP]"],    // zero-width space
  [0x200c, "[ZWNJ]"],    // zero-width non-joiner
  [0x200d, "[ZWJ]"],     // zero-width joiner
  [0x2060, "[WJ]"],      // word joiner
  [0xfeff, "[BOM]"],     // byte-order mark
  [0x180e, "[MVS]"],     // Mongolian vowel separator
  [0x2028, "[LSEP]"],    // line separator
  [0x2029, "[PSEP]"],    // paragraph separator
  // Bidi
  [0x202a, "[LRE]"],
  [0x202b, "[RLE]"],
  [0x202c, "[PDF]"],
  [0x202d, "[LRO]"],
  [0x202e, "[RLO]"],
  [0x2066, "[LRI]"],
  [0x2067, "[RLI]"],
  [0x2068, "[FSI]"],
  [0x2069, "[PDI]"],
]);

const PLACEHOLDER_LABELS = {
  invisibleUnicode: "[REDACTED:invisibleUnicode]",
  controlChars: "[REDACTED:controlChars]",
  hiddenHtml: "[REDACTED:hiddenHtml]",
  suspiciousPatterns: "[REDACTED:suspiciousPatterns]",
  homoglyphs: "[REDACTED:homoglyphs]",
};

// Hidden-elements placeholder used by stripHiddenElements (legacy strip mode).
// Mask / placeholder modes rewrite that marker to a category-tagged label so
// the maskedRanges audit trail is consistent across modes.
const HIDDEN_ELEM_LEGACY_MARKER = "<!-- [REMOVED: hidden element] -->";

/**
 * Sanitize content by removing/redacting detected threats.
 *
 * @param {string} content
 * @param {Object} options
 * @param {string} [options.fileType] - "text" or "html"
 * @param {string[]} [options.categories] - Which categories to sanitize
 * @param {string} [options.mode] - "strip" (default) | "mask" | "placeholder"
 * @returns {{ cleaned: string, removedCounts: Object, meta: { maskedRanges: Array } }}
 */
export function sanitize(content, options = {}) {
  const {
    fileType = "text",
    categories = ALL_CATEGORIES,
    mode = "strip",
  } = options;

  if (!SUPPORTED_MODES.has(mode)) {
    throw new Error(
      `sanitize: unsupported mode "${mode}" (expected one of strip / mask / placeholder)`
    );
  }

  const wanted = new Set(categories);
  const removedCounts = {
    invisibleUnicode: 0,
    controlChars: 0,
    hiddenHtml: 0,
    suspiciousPatterns: 0,
    homoglyphs: 0,
  };
  const maskedRanges = [];

  let result = content;
  let before;

  if (wanted.has("homoglyphs")) {
    before = result;
    result = normalizeHomoglyphs(result);
    removedCounts.homoglyphs = countDiff(before, result);
    // Homoglyph normalization is a 1:1 codepoint rewrite — every diff is a
    // single-codepoint replacement at the same offset. Surface those as
    // maskedRanges entries so the audit trail still describes the rewrite.
    if (mode !== "strip" || true) {
      // Always emit ranges (stable shape across modes).
      const minLen = Math.min(before.length, result.length);
      for (let i = 0; i < minLen; i++) {
        if (before[i] !== result[i]) {
          maskedRanges.push([i, i + 1, "homoglyphs", 1]);
        }
      }
    }
  }

  if (wanted.has("invisibleUnicode")) {
    before = result;
    if (mode === "strip") {
      result = stripInvisibleUnicode(result);
      removedCounts.invisibleUnicode = before.length - result.length;
      // Record ranges using the legacy strip behaviour: each invisible
      // codepoint produces a [pos, pos+codeUnits, "invisibleUnicode", 0]
      // tuple.
      const inv = findInvisibleSpans(before);
      for (const span of inv) {
        maskedRanges.push([span.start, span.end, "invisibleUnicode", 0]);
      }
    } else {
      const replaced = replaceInvisibleUnicode(before, mode);
      result = replaced.text;
      removedCounts.invisibleUnicode = replaced.count;
      for (const r of replaced.ranges) maskedRanges.push(r);
    }
  }

  if (wanted.has("controlChars")) {
    before = result;
    if (mode === "strip") {
      result = stripControlChars(result);
      removedCounts.controlChars = before.length - result.length;
      const ctrl = findControlSpans(before);
      for (const span of ctrl) {
        maskedRanges.push([span.start, span.end, "controlChars", 0]);
      }
    } else {
      const replaced = replaceControlChars(before, mode);
      result = replaced.text;
      removedCounts.controlChars = replaced.count;
      for (const r of replaced.ranges) maskedRanges.push(r);
    }
  }

  if (wanted.has("hiddenHtml") && fileType === "html") {
    before = result;
    result = stripHiddenElements(result);
    // Count replacements instead of char diff
    const replacements = (result.match(/\[REMOVED: hidden element\]/g) || [])
      .length;
    removedCounts.hiddenHtml = replacements;

    if (mode !== "strip" && replacements > 0) {
      // For mask / placeholder modes, rewrite the legacy hidden-element
      // marker into a category-tagged label so the audit trail is
      // consistent. R12: label contains category only.
      const label =
        mode === "placeholder"
          ? PLACEHOLDER_LABELS.hiddenHtml
          : "[MASKED:hiddenHtml]";
      const rewritten = [];
      let cursor = 0;
      let idx;
      while ((idx = result.indexOf(HIDDEN_ELEM_LEGACY_MARKER, cursor)) !== -1) {
        rewritten.push(result.slice(cursor, idx));
        rewritten.push(label);
        maskedRanges.push([
          idx,
          idx + HIDDEN_ELEM_LEGACY_MARKER.length,
          "hiddenHtml",
          label.length,
        ]);
        cursor = idx + HIDDEN_ELEM_LEGACY_MARKER.length;
      }
      rewritten.push(result.slice(cursor));
      result = rewritten.join("");
    } else {
      // strip mode: still emit maskedRanges entries pointing at the
      // post-strip marker positions (replacementLength = marker length).
      let cursor = 0;
      let idx;
      while ((idx = result.indexOf(HIDDEN_ELEM_LEGACY_MARKER, cursor)) !== -1) {
        maskedRanges.push([
          idx,
          idx + HIDDEN_ELEM_LEGACY_MARKER.length,
          "hiddenHtml",
          HIDDEN_ELEM_LEGACY_MARKER.length,
        ]);
        cursor = idx + HIDDEN_ELEM_LEGACY_MARKER.length;
      }
    }
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
    const matches = (result.match(/\[REMOVED\]/g) || []).length;
    removedCounts.suspiciousPatterns += matches;

    if (mode === "placeholder" && matches > 0) {
      // Rewrite plain [REMOVED] markers to category-tagged placeholders.
      const label = PLACEHOLDER_LABELS.suspiciousPatterns;
      const rewritten = [];
      let cursor = 0;
      let idx;
      while ((idx = result.indexOf("[REMOVED]", cursor)) !== -1) {
        rewritten.push(result.slice(cursor, idx));
        rewritten.push(label);
        maskedRanges.push([
          idx,
          idx + "[REMOVED]".length,
          "suspiciousPatterns",
          label.length,
        ]);
        cursor = idx + "[REMOVED]".length;
      }
      rewritten.push(result.slice(cursor));
      result = rewritten.join("");
    } else {
      // strip / mask modes: record each [REMOVED] marker position as a
      // maskedRange so the audit trail is uniform.
      let cursor = 0;
      let idx;
      while ((idx = result.indexOf("[REMOVED]", cursor)) !== -1) {
        maskedRanges.push([
          idx,
          idx + "[REMOVED]".length,
          "suspiciousPatterns",
          "[REMOVED]".length,
        ]);
        cursor = idx + "[REMOVED]".length;
      }
    }
  }

  return {
    cleaned: result,
    removedCounts,
    meta: { maskedRanges },
  };
}

// ---------------------------------------------------------------------------
// Invisible / control-char span helpers.
// ---------------------------------------------------------------------------

function isInvisibleCodePoint(cp) {
  if (cp === undefined) return false;
  // Unicode Tags Block
  if (cp >= 0xe0000 && cp <= 0xe007f) return true;
  // Known invisibles (the Map keys mirror the rules JSON loaded by
  // invisible-unicode.js — listing the canonical set here keeps the mask-mode
  // helper self-contained without re-importing the rules loader).
  if (INVISIBLE_MASK_LABELS.has(cp)) return true;
  return false;
}

function maskLabelForInvisible(cp) {
  if (cp >= 0xe0000 && cp <= 0xe007f) {
    const asciiEquiv = cp - 0xe0000;
    const readable =
      asciiEquiv >= 0x20 && asciiEquiv <= 0x7e
        ? `"${String.fromCharCode(asciiEquiv)}"`
        : `0x${asciiEquiv.toString(16)}`;
    return `[TAG:${readable}]`;
  }
  if (INVISIBLE_MASK_LABELS.has(cp)) {
    return INVISIBLE_MASK_LABELS.get(cp);
  }
  return `[U+${cp.toString(16).toUpperCase().padStart(4, "0")}]`;
}

/**
 * Find the span (start, end) of every invisible codepoint stripped by the
 * legacy stripInvisibleUnicode path. Used by strip-mode to populate
 * maskedRanges with the original-document offsets.
 */
function findInvisibleSpans(text) {
  const out = [];
  for (let i = 0; i < text.length; i++) {
    const cp = text.codePointAt(i);
    if (isInvisibleCodePoint(cp)) {
      const width = cp > 0xffff ? 2 : 1;
      out.push({ start: i, end: i + width });
      if (cp > 0xffff) i++;
    }
  }
  return out;
}

/**
 * Walk content, replacing invisible codepoints with either a category-tagged
 * placeholder or a per-codepoint visible label. Returns { text, count, ranges }
 * where ranges are tuples indexed against the ORIGINAL `text` argument.
 */
function replaceInvisibleUnicode(text, mode) {
  const out = [];
  const ranges = [];
  let count = 0;
  let i = 0;
  while (i < text.length) {
    const cp = text.codePointAt(i);
    const width = cp > 0xffff ? 2 : 1;
    if (isInvisibleCodePoint(cp)) {
      const label =
        mode === "placeholder"
          ? PLACEHOLDER_LABELS.invisibleUnicode
          : maskLabelForInvisible(cp);
      out.push(label);
      ranges.push([i, i + width, "invisibleUnicode", label.length]);
      count++;
      i += width;
      continue;
    }
    out.push(text.slice(i, i + width));
    i += width;
  }
  return { text: out.join(""), count, ranges };
}

function isControlCodePoint(cp) {
  if (cp === undefined) return false;
  const isC0 = cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d;
  const isC1 = cp >= 0x7f && cp <= 0x9f;
  return isC0 || isC1;
}

function maskLabelForControl(cp) {
  // C0 (0x00-0x1F minus tab/LF/CR) and DEL (0x7F) have a dedicated
  // Control-Pictures glyph; C1 (0x80-0x9F) does not, so use a labelled form.
  if (cp >= 0x00 && cp <= 0x1f) {
    return String.fromCodePoint(0x2400 + cp);
  }
  if (cp === 0x7f) {
    return "␡";
  }
  // C1 controls
  return `[C1:U+${cp.toString(16).toUpperCase().padStart(4, "0")}]`;
}

function findControlSpans(text) {
  const out = [];
  for (let i = 0; i < text.length; i++) {
    const cp = text.charCodeAt(i);
    if (isControlCodePoint(cp)) {
      out.push({ start: i, end: i + 1 });
    }
  }
  return out;
}

function replaceControlChars(text, mode) {
  const out = [];
  const ranges = [];
  let count = 0;
  for (let i = 0; i < text.length; i++) {
    const cp = text.charCodeAt(i);
    if (isControlCodePoint(cp)) {
      const label =
        mode === "placeholder"
          ? PLACEHOLDER_LABELS.controlChars
          : maskLabelForControl(cp);
      out.push(label);
      ranges.push([i, i + 1, "controlChars", label.length]);
      count++;
      continue;
    }
    out.push(text[i]);
  }
  return { text: out.join(""), count, ranges };
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
