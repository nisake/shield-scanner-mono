/**
 * Suspicious pattern detection (prompt injection signatures).
 *
 * Matches 22+ regex patterns covering:
 * - Instruction overrides
 * - Role reassignments
 * - Prompt extractions
 * - Fake system messages
 * - SQL/code injection hints
 */

import { getContext, escapeForDisplay, loadRule } from "./utils.js";
import { mapSpanToOriginal } from "./shadow-copy.js";

// Load and compile patterns once.
// Each rule entry may carry an optional `severity` ("danger" | "warning").
// Default is "danger" — preserves legacy behavior for the 22 original entries
// that have no severity field. Warning-tier patterns let us add lower-
// confidence signals (e.g. generic 'Human:' turn markers) without inflating
// the danger count for legitimate transcripts / docs.
//
// v1.18.0 pre-compile contract: every RegExp instance we ever need at runtime
// lives on the module-scope arrays below. Per-call paths (detect*, strip*)
// MUST NOT allocate `new RegExp()` — the regex objects are reused across calls
// (with `lastIndex = 0` resets for the global-stateful detect paths). This
// eliminates the per-analyze() compile cost that previously scaled with the
// pattern count (currently 100+ rules).
const { patterns: PATTERN_DEFS } = loadRule("suspicious-patterns.json");
const COMPILED_PATTERNS = PATTERN_DEFS.map((p) => ({
  name: p.name,
  regex: new RegExp(p.pattern, p.flags || "g"),
  severity: p.severity === "warning" ? "warning" : "danger",
}));
// Separate strip-only regex instances so stripSuspiciousPatterns can run
// alongside detect* on the same module without sharing `lastIndex` state with
// the detection path. Still pre-compiled once at module load.
const COMPILED_STRIP_PATTERNS = PATTERN_DEFS.map((p) => ({
  regex: new RegExp(p.pattern, p.flags || "g"),
}));

/**
 * Scan text for prompt injection signatures.
 * @param {string} content
 * @returns {Array} findings
 */
export function detectSuspiciousPatterns(content) {
  const findings = [];

  for (const { name, regex, severity } of COMPILED_PATTERNS) {
    // Reset lastIndex because we reuse compiled regexes
    regex.lastIndex = 0;

    let m;
    while ((m = regex.exec(content)) !== null) {
      findings.push({
        pattern: name,
        matched: escapeForDisplay(m[0]),
        position: m.index,
        context: getContext(content, m.index, m[0].length),
        severity,
      });

      // Guard against zero-width matches causing infinite loop
      if (m.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  return findings;
}

/**
 * Scan a shadow buffer (invisibleStripped / nfkcNormalized) with the same
 * compiled patterns used for normal content, and translate every hit back to
 * the original text's UTF-16 positions via `shadowToOrig`.
 *
 * Findings are tagged with `type: "shadow:<sourceLabel>"` and `shadowSource`
 * so consumers can distinguish obfuscation-bypass hits from direct hits.
 * Severity stays "danger" — bypass-via-shadow is still a successful attack
 * signal; the tag lets UIs explain *why* it fired.
 *
 * `originalContent` is required so `context` (the human-readable surrounding
 * window in finding reports) is shown against the real text, not the shadow.
 *
 * @param {string} shadow - the derived buffer
 * @param {Uint32Array} shadowToOrig - per-UTF-16-unit index map
 * @param {string} sourceLabel - "invisibleStripped" | "nfkcNormalized"
 * @param {string} originalContent - the untouched source text
 * @returns {Array} findings
 */
export function scanShadowForSuspiciousPatterns(
  shadow,
  shadowToOrig,
  sourceLabel,
  originalContent
) {
  if (!shadow || !shadowToOrig || !originalContent) return [];

  const findings = [];

  for (const { name, regex, severity } of COMPILED_PATTERNS) {
    regex.lastIndex = 0;

    let m;
    while ((m = regex.exec(shadow)) !== null) {
      const span = mapSpanToOriginal(
        shadowToOrig,
        m.index,
        m.index + m[0].length
      );
      const matchLen = Math.max(1, span.end - span.start);

      // R12 (critical): NEVER echo the decoded shadow string back into the
      // response body. The shadow buffer is derived from NFKC normalization /
      // invisible-stripping of attacker-controlled text, so embedding it in
      // a JSON field would let Shield Scanner act as a *decoding oracle* —
      // a Math/ZWSP-obfuscated payload that no other component could read
      // would be served back in plaintext to the next LLM hop. We only emit
      // structural hints (`shadowLength`, `shadowSource`) and identify the
      // hit by its detector-controlled rule `pattern` name. `matched` /
      // `context` come from the *original* text (positions already mapped
      // back via mapSpanToOriginal), so the attacker can't sneak the decoded
      // form in via those either — the original slice is what the user typed.
      findings.push({
        pattern: name,
        matched: escapeForDisplay(originalContent.slice(span.start, span.end)),
        position: span.start,
        matchLen,
        context: getContext(originalContent, span.start, matchLen),
        severity,
        type: `shadow:${sourceLabel}`,
        shadowSource: sourceLabel,
        shadowLength: m[0].length,
      });

      // Guard against zero-width matches causing infinite loop
      if (m.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  return findings;
}

/**
 * Strip suspicious pattern matches from text (replace with [REMOVED]).
 *
 * v1.18.0: uses the pre-compiled COMPILED_STRIP_PATTERNS array (separate from
 * COMPILED_PATTERNS so the detection path's `lastIndex` state cannot interfere
 * with this caller). Per-invocation `new RegExp()` is gone.
 */
export function stripSuspiciousPatterns(content) {
  let result = content;
  for (const { regex } of COMPILED_STRIP_PATTERNS) {
    // String.prototype.replace ignores lastIndex on global regexes (it always
    // restarts from 0), so reusing the compiled object is safe here.
    result = result.replace(regex, "[REMOVED]");
  }
  return result;
}
