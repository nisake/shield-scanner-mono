/**
 * S10 — CSV/XLSX formula-injection detector.
 *
 * Surfaces danger-tier hits for the dangerous-function blocklist (FI-01) AND
 * warning-tier hits for the leading-char prefix path with numeric/phone
 * suppression (FI-02). All findings land in the existing `suspiciousPatterns`
 * bucket (R13 5-key invariant — NO new top-level key). The `category` field
 * (`formula-injection` / `formula-prefix`) is for downstream routing / scoring
 * only and MUST NOT promote to a new byCategory key.
 *
 * Pipeline:
 *   1. Split content on \n (works for both raw CSV bodies and the
 *      parser-emitted `[Sheet 'Name'!A1] cell text` lines from xlsx.js).
 *   2. For each line, separate the parser-emitted bracket prefix (if any)
 *      from the cell text so the prefix is preserved as `contextLocation`
 *      and never matched against the formula-injection regexes.
 *   3. normalizeFormulaPrefix → leading whitespace strip + fullwidth-equals
 *      map (U+FF1D / U+FE66 / U+2E40 → '=').
 *   4. normalizeXlfn → strip _xlfn. / _xlfn._xlws. multi-prefix.
 *   5. If the normalized text's first char is one of [= + - @ \t \r]:
 *        - run formula-injection.json patterns → danger
 *          (category: 'formula-injection')
 *        - else if the cell does NOT look like a number / phone shape →
 *          warning (category: 'formula-prefix')
 *
 * R12: parser-emitted bracket prefix `[Sheet 'Name'!A1]` is detector-controlled
 * scaffolding (the parser knows the sheet name + cell ref). The matched cell
 * content is escaped via escapeForDisplay and clamped to a small slice — raw
 * user content never lands in a label / pattern / technique field.
 *
 * R18: loadRule is called INSIDE detectFormulaInjection (lazy), so module-load
 * order does not break setEnv() → loadRule() contract. The compiled rule
 * cache is keyed on the loaded JSON object identity to stay parity-safe across
 * resetEnv()/setEnv() cycles in tests.
 */

import { loadRule, getContext, escapeForDisplay } from "./utils.js";
import {
  normalizeFormulaPrefix,
  normalizeXlfn,
} from "./opc-helpers.js";

const DANGEROUS_PREFIX_CHARS = new Set([
  0x3d, // =
  0x2b, // +
  0x2d, // -
  0x40, // @
  0x09, // TAB
  0x0d, // CR
]);

// Numeric / phone suppression for FI-02. A cell whose normalized text is
// purely a numeric value (with optional sign / decimal) OR a phone-number
// shape (international '+', area codes, separators) MUST NOT fire the
// warning-tier prefix rule. This is the 'unship-on-FP' guardrail.
//
// Both regexes anchor at start/end of the WHOLE normalized cell text — we do
// NOT allow trailing junk after a numeric body (so `-123 ignore previous`
// still fires).
const NUMERIC_SHAPE_RE = /^[+-]?\d+(?:\.\d+)?$/;
const DECIMAL_SHAPE_RE = /^[+-]?\d*\.\d+$/;
const PHONE_SHAPE_RE = /^\+\d{1,3}[\d \-()]{5,}$/;

// Per-call rule cache: keyed on the JSON object identity returned by loadRule
// so swapping rule loaders (e.g. resetEnv() during tests) automatically
// invalidates compiled state.
let _ruleCache = null;
let _ruleKey = null;

function getCompiledRules() {
  const rule = loadRule("formula-injection.json");
  if (rule !== _ruleKey) {
    _ruleKey = rule;
    _ruleCache = (rule.patterns || []).map((p) => ({
      name: p.name,
      regex: new RegExp(p.pattern, p.flags || "i"),
      severity: p.severity === "warning" ? "warning" : "danger",
    }));
  }
  return _ruleCache;
}

/**
 * Detect formula-injection findings in CSV / XLSX text content.
 *
 * @param {string} content
 *   Raw CSV body (line-per-row) OR parser-emitted line stream where each
 *   line may carry a `[Sheet 'Name'!A1] ` or `[Row N, Col M] ` prefix.
 * @param {string} fileType - 'csv' | 'xlsx' (callers gate on this)
 * @param {Object} [opts]
 * @param {boolean} [opts.includePrefixWarnings=true]
 *   Set false to skip FI-02 (warning-tier prefix path). Used by sanitize
 *   round-trip pre-flight when only danger-tier matters.
 * @returns {Array} suspiciousPatterns-shaped findings
 */
export function detectFormulaInjection(content, fileType, opts = {}) {
  if (typeof content !== "string" || content.length === 0) return [];
  if (fileType !== "csv" && fileType !== "xlsx") return [];

  const includePrefixWarnings =
    opts.includePrefixWarnings === undefined
      ? true
      : Boolean(opts.includePrefixWarnings);

  const rules = getCompiledRules();
  const findings = [];

  // Walk line-by-line. Each finding's `position` is the absolute UTF-16 offset
  // of the cell-text portion (after the bracket prefix when present) in the
  // ORIGINAL `content` string.
  let lineStart = 0;
  const len = content.length;
  let i = 0;
  while (i <= len) {
    if (i === len || content.charCodeAt(i) === 0x0a /* \n */) {
      const rawLine = content.slice(lineStart, i);
      // Strip a trailing \r so CRLF-terminated CSV lines behave identically
      // to LF-terminated ones. We keep `cellOffset` consistent — the \r
      // never makes it into the analyzed cell text anyway.
      const line =
        rawLine.length > 0 && rawLine.charCodeAt(rawLine.length - 1) === 0x0d
          ? rawLine.slice(0, -1)
          : rawLine;

      // Separate parser-emitted bracket prefix from the cell text. We only
      // accept `[...] ` (closing bracket + at least one space) at the very
      // start of the line — defensive so we never mis-strip a literal CSV
      // cell that happens to begin with `[`.
      let cellText = line;
      let contextLocation = null;
      let cellOffsetInLine = 0;
      if (line.length > 0 && line.charCodeAt(0) === 0x5b /* '[' */) {
        const close = line.indexOf("] ");
        if (close > 0) {
          contextLocation = line.slice(1, close);
          cellText = line.slice(close + 2);
          cellOffsetInLine = close + 2;
        }
      }

      if (cellText.length > 0) {
        const finding = _checkCell(
          cellText,
          rules,
          includePrefixWarnings,
          content,
          lineStart + cellOffsetInLine,
          contextLocation,
        );
        if (finding) findings.push(finding);
      }

      lineStart = i + 1;
    }
    i++;
  }

  return findings;
}

/**
 * Inspect a single cell. Returns one finding or null.
 *
 * The cell is normalized via normalizeFormulaPrefix → normalizeXlfn, then:
 *   - if the first char is dangerous AND a function-blocklist regex matches
 *     → danger / category='formula-injection'
 *   - else if the first char is dangerous AND the cell is not a numeric /
 *     phone shape → warning / category='formula-prefix'
 *   - else null
 */
function _checkCell(
  cellText,
  rules,
  includePrefixWarnings,
  fullContent,
  cellPosition,
  contextLocation,
) {
  const norm = normalizeXlfn(normalizeFormulaPrefix(cellText));
  if (norm.length === 0) return null;

  const firstCp = norm.charCodeAt(0);
  if (!DANGEROUS_PREFIX_CHARS.has(firstCp)) return null;

  // Build a stable matched-slice preview from the normalized cell. We never
  // echo more than 200 chars (R12 — keep raw user payload out of UI labels;
  // only the pattern/technique fields are detector-controlled).
  const preview = norm.length > 200 ? norm.slice(0, 200) : norm;

  // FI-01: dangerous-function blocklist match.
  for (const { name, regex, severity } of rules) {
    regex.lastIndex = 0;
    const m = regex.exec(norm);
    if (m) {
      return _buildFinding({
        pattern: name,
        matched: preview,
        position: cellPosition,
        matchLen: cellText.length,
        context: getContext(fullContent, cellPosition, Math.max(1, cellText.length)),
        severity: severity || "danger",
        category: "formula-injection",
        technique: "CSV/XLSX formula injection",
        contextLocation,
      });
    }
  }

  if (!includePrefixWarnings) return null;

  // FI-02: prefix-only path — suppress numeric / phone shapes.
  // NOTE: TAB (0x09) and CR (0x0d) prefixes also count — they are bypass
  // variants of the '=' prefix and have no legitimate numeric interpretation,
  // so they never get suppressed.
  if (firstCp === 0x09 || firstCp === 0x0d) {
    return _buildFinding({
      pattern: "Formula-prefix control char",
      matched: preview,
      position: cellPosition,
      matchLen: cellText.length,
      context: getContext(fullContent, cellPosition, Math.max(1, cellText.length)),
      severity: "warning",
      category: "formula-prefix",
      technique: "CSV/XLSX formula prefix",
      contextLocation,
    });
  }

  // Sign-prefixed numeric / decimal / phone — suppress.
  if (
    NUMERIC_SHAPE_RE.test(norm) ||
    DECIMAL_SHAPE_RE.test(norm) ||
    PHONE_SHAPE_RE.test(norm)
  ) {
    return null;
  }

  return _buildFinding({
    pattern: "Formula prefix",
    matched: preview,
    position: cellPosition,
    matchLen: cellText.length,
    context: getContext(fullContent, cellPosition, Math.max(1, cellText.length)),
    severity: "warning",
    category: "formula-prefix",
    technique: "CSV/XLSX formula prefix",
    contextLocation,
  });
}

/**
 * Shape a finding to match the suspiciousPatterns bucket layout used by
 * suspicious-patterns.js (the consumer of `findings.suspiciousPatterns`).
 *
 * R12: only detector-controlled fields (`pattern`, `technique`, `category`,
 * `severity`) carry symbolic strings. `matched` and `context` come from the
 * original content but are escape-encoded for display.
 */
function _buildFinding(input) {
  const out = {
    pattern: input.pattern,
    matched: escapeForDisplay(input.matched),
    position: input.position,
    matchLen: input.matchLen,
    context: input.context,
    severity: input.severity,
    category: input.category,
    technique: input.technique,
  };
  if (input.contextLocation) out.contextLocation = input.contextLocation;
  return out;
}
