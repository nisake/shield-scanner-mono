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

// v1.18.0 streaming gate — see invisible-unicode.js. Homoglyph entries are all
// single UTF-16 units (per homoglyphs.json) and the nearLatin lookahead is
// ±1 char, so the 2KB overlap window is more than enough to keep boundary
// findings intact.
const STREAM_THRESHOLD = 5 * 1024 * 1024;
const STREAM_CHUNK_SIZE = 1024 * 1024;
const STREAM_OVERLAP_SIZE = 2 * 1024;
const LATIN_RE = /[a-zA-Z]/;

/**
 * v1.18.0: returns true when the input is large enough to chunk.
 * Pure function.
 *
 * @param {string} content
 * @returns {boolean}
 */
export function shouldStream(content) {
  return typeof content === "string" && content.length > STREAM_THRESHOLD;
}

function scanHomoglyphsChunk(chunk, chunkOffset, fullContent) {
  const findings = [];
  for (let i = 0; i < chunk.length; i++) {
    const ch = chunk[i];
    if (!HOMOGLYPH_MAP[ch]) continue;

    // Use absolute lookahead/lookbehind from fullContent so the ±1 nearLatin
    // check still works across chunk boundaries (the 2KB overlap also covers
    // this, but reading from fullContent is the safer, simpler invariant).
    const absPos = chunkOffset + i;
    const prev = absPos > 0 ? fullContent[absPos - 1] : "";
    const next =
      absPos < fullContent.length - 1 ? fullContent[absPos + 1] : "";
    const nearLatin = LATIN_RE.test(prev) || LATIN_RE.test(next);

    if (nearLatin) {
      findings.push({
        original: HOMOGLYPH_MAP[ch].orig,
        replacement: HOMOGLYPH_MAP[ch].looks,
        position: absPos,
        context: getContext(fullContent, absPos),
        severity: "warning",
      });
    }
  }
  return findings;
}

/**
 * Scan text for homoglyph characters.
 * Only flags occurrences adjacent to Latin letters.
 *
 * v1.18.0: chunks content > 5MB into 1MB windows with 2KB overlap (see
 * invisible-unicode.js for the streaming contract). Behavior for small/medium
 * inputs is unchanged.
 *
 * @param {string} content
 * @returns {Array} findings
 */
export function detectHomoglyphs(content) {
  // Skip entirely if no Latin letters (avoid false positives). For streaming
  // inputs this short-circuit still helps: a 50MB pure-CJK / pure-Cyrillic
  // file pays only one regex test.
  if (!LATIN_RE.test(content)) return [];

  if (!shouldStream(content)) {
    return scanHomoglyphsChunk(content, 0, content);
  }

  const seen = new Set(); // dedup: `${absPos}|${original}`
  const out = [];
  let chunkStart = 0;
  while (chunkStart < content.length) {
    const chunkEnd = Math.min(
      content.length,
      chunkStart + STREAM_CHUNK_SIZE + STREAM_OVERLAP_SIZE,
    );
    const chunk = content.slice(chunkStart, chunkEnd);
    const chunkFindings = scanHomoglyphsChunk(chunk, chunkStart, content);
    for (const f of chunkFindings) {
      const key = `${f.position}|${f.original}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
    if (chunkEnd >= content.length) break;
    chunkStart += STREAM_CHUNK_SIZE;
  }
  return out;
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
