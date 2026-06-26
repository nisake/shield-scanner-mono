/**
 * Homoglyph detection.
 *
 * Detects Cyrillic/Fullwidth characters that visually impersonate Latin letters.
 * Only flags them when mixed with Latin text (to avoid false positives on
 * legitimate Cyrillic/Fullwidth content).
 */

import { getContext, loadRule } from "./utils.js";

const { map: HOMOGLYPH_MAP } = loadRule("homoglyphs.json");

/**
 * Load-time sanity check (S1ALPHA-004 regression guard).
 *
 * For every entry in HOMOGLYPH_MAP, the leading codepoint of `orig` MUST
 * equal the JSON key. If they disagree, the `orig` label displayed to the
 * user (and the leading char extracted for any downstream label-based
 * tooling) will refer to a different codepoint than the one that was
 * actually detected — which is how S1ALPHA-001/003/004 happened.
 *
 * We warn (via console.error → stderr) rather than throw so a single bad
 * rules-data row cannot brick the entire MCP at startup; the audit hook
 * is exposed as `auditHomoglyphMap()` so tests can pin the invariant
 * deterministically.
 *
 * @param {object} [map=HOMOGLYPH_MAP]
 * @returns {Array<{key: string, keyCp: string, origLeadCp: string, orig: string}>}
 *          List of mismatches (empty when the map is clean).
 */
export function auditHomoglyphMap(map = HOMOGLYPH_MAP) {
  const mismatches = [];
  for (const key of Object.keys(map)) {
    const entry = map[key];
    if (!entry || typeof entry.orig !== "string" || entry.orig.length === 0) {
      mismatches.push({
        key,
        keyCp: "U+" + key.codePointAt(0).toString(16).toUpperCase(),
        origLeadCp: "(missing)",
        orig: String(entry && entry.orig),
      });
      continue;
    }
    const keyCp = key.codePointAt(0);
    const origLeadCp = entry.orig.codePointAt(0);
    if (keyCp !== origLeadCp) {
      mismatches.push({
        key,
        keyCp: "U+" + keyCp.toString(16).toUpperCase(),
        origLeadCp: "U+" + origLeadCp.toString(16).toUpperCase(),
        orig: entry.orig,
      });
    }
  }
  return mismatches;
}

// Run the audit at module load. Warn-only: a stale rules row should not
// take the whole server down, but it should be very loud in the logs so
// the rules-data fix (S1ALPHA-002) is not silently re-broken.
{
  const _mismatches = auditHomoglyphMap();
  if (_mismatches.length > 0) {
    // eslint-disable-next-line no-console
    console.error(
      "[shield-scanner] homoglyphs.json sanity check: " +
        _mismatches.length +
        " entr" +
        (_mismatches.length === 1 ? "y has" : "ies have") +
        " an `orig` label whose leading codepoint does not match the map key. " +
        "normalizeHomoglyphs() may silently corrupt these characters. " +
        "Affected: " +
        _mismatches
          .map((m) => `${m.keyCp} (orig leads with ${m.origLeadCp})`)
          .join(", ")
    );
  }
}

/**
 * Scan text for homoglyph characters.
 * Only flags occurrences adjacent to Latin letters.
 * @param {string} content
 * @returns {Array} findings
 */
export function detectHomoglyphs(content) {
  const findings = [];

  // Skip entirely if no Latin letters (avoid false positives)
  if (!/[a-zA-Z]/.test(content)) return findings;

  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (!HOMOGLYPH_MAP[ch]) continue;

    const prev = i > 0 ? content[i - 1] : "";
    const next = i < content.length - 1 ? content[i + 1] : "";
    const nearLatin = /[a-zA-Z]/.test(prev) || /[a-zA-Z]/.test(next);

    if (nearLatin) {
      findings.push({
        original: HOMOGLYPH_MAP[ch].orig,
        replacement: HOMOGLYPH_MAP[ch].looks,
        position: i,
        context: getContext(content, i),
        severity: "warning",
      });
    }
  }

  return findings;
}

/**
 * Replace homoglyphs with their Latin equivalents (sanitizer).
 */
export function normalizeHomoglyphs(content) {
  if (!/[a-zA-Z]/.test(content)) return content;

  let result = "";
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    const mapping = HOMOGLYPH_MAP[ch];
    if (mapping) {
      const prev = i > 0 ? content[i - 1] : "";
      const next = i < content.length - 1 ? content[i + 1] : "";
      const nearLatin = /[a-zA-Z]/.test(prev) || /[a-zA-Z]/.test(next);
      if (nearLatin) {
        // Extract the Latin equivalent from "X (Latin)"
        const latinMatch = mapping.looks.match(/^(.)/);
        result += latinMatch ? latinMatch[1] : ch;
        continue;
      }
    }
    result += ch;
  }
  return result;
}
