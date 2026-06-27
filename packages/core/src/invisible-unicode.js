/**
 * Invisible Unicode character detection.
 *
 * Detects:
 * - Unicode Tags Block (U+E0000 - U+E007F) — known prompt injection vector
 * - Bidi control characters (U+202A-U+202E, U+2066-U+2069) — Trojan Source vector
 *   - Override chars (U+202D LRO / U+202E RLO) single = danger
 *   - Embedding chars (U+202A LRE / U+202B RLE / U+202C PDF) single = warning
 *   - Isolate chars (U+2066-U+2069 LRI/RLI/FSI/PDI) single = warning
 *   - ANY Bidi family >= 3 in same text = all upgraded to danger (over-use signal)
 * - Known invisible chars (zero-width, soft hyphen, etc.)
 * - Private Use Areas (PUA)
 *
 * NOTE on signature: detectInvisibleUnicode(content) returns Array<Finding>.
 * Caller (detector.js) must not change. Bidi findings carry an extra
 * `category: "bidi-control"` field; existing categories' findings are unchanged.
 */

import { getContext, loadRule } from "./utils.js";

// Cache rule data at module load
const { chars: INVISIBLE_CHAR_LIST } = loadRule("invisible-chars.json");
const INVISIBLE_CHAR_MAP = new Map(
  INVISIBLE_CHAR_LIST.map((c) => [parseInt(c.code, 16), c.name])
);

// Bidi control characters — handled with category-specific severity rules.
// Map<codepoint, { name, baseSeverity, kind }>
//   kind: "override" | "embedding" | "isolate"
//   baseSeverity: severity when this char appears alone (single occurrence)
const BIDI_CONTROLS = new Map([
  [0x202a, { name: "Left-to-Right Embedding (LRE)", baseSeverity: "warning", kind: "embedding" }],
  [0x202b, { name: "Right-to-Left Embedding (RLE)", baseSeverity: "warning", kind: "embedding" }],
  [0x202c, { name: "Pop Directional Formatting (PDF)", baseSeverity: "warning", kind: "embedding" }],
  [0x202d, { name: "Left-to-Right Override (LRO)", baseSeverity: "danger", kind: "override" }],
  [0x202e, { name: "Right-to-Left Override (RLO)", baseSeverity: "danger", kind: "override" }],
  [0x2066, { name: "Left-to-Right Isolate (LRI)", baseSeverity: "warning", kind: "isolate" }],
  [0x2067, { name: "Right-to-Left Isolate (RLI)", baseSeverity: "warning", kind: "isolate" }],
  [0x2068, { name: "First Strong Isolate (FSI)", baseSeverity: "warning", kind: "isolate" }],
  [0x2069, { name: "Pop Directional Isolate (PDI)", baseSeverity: "warning", kind: "isolate" }],
]);

// Bidi over-use threshold: if total Bidi-family chars in the text reaches this
// number, ALL Bidi findings are escalated to "danger" (excessive-use signal).
const BIDI_OVERUSE_THRESHOLD = 3;

// v1.18.0 streaming gate: very large inputs (>5MB) are walked in 1MB chunks
// with a 2KB overlap so we (a) keep peak memory bounded for the linear codepoint
// scan and (b) never lose a finding whose codepoint sits exactly on a chunk
// boundary. The overlap is generous w.r.t. the largest single codepoint we
// detect (a 4-UTF-16-unit Plane-14 surrogate pair = 4 bytes), so a finding's
// full span is always present in at least one chunk. Findings emitted inside
// the overlap region of a later chunk are deduped by absolute position+char.
const STREAM_THRESHOLD = 5 * 1024 * 1024;
const STREAM_CHUNK_SIZE = 1024 * 1024;
const STREAM_OVERLAP_SIZE = 2 * 1024;

/**
 * v1.18.0: returns true when the input is large enough that the linear
 * codepoint walk should be split into overlapping chunks.
 *
 * Exposed for analyze() (detector.js) to wire `summary.streamed` /
 * `summary.chunkCount` siblings. Pure function — no allocations.
 *
 * @param {string} content
 * @returns {boolean}
 */
export function shouldStream(content) {
  return typeof content === "string" && content.length > STREAM_THRESHOLD;
}

/**
 * Internal: scan a single chunk and emit findings with positions offset by
 * `chunkOffset`. Identical detection logic to the non-streaming path — the
 * only difference is the absolute `position` writeback and the per-chunk
 * bidi-overuse count (which is intentionally per-chunk: 3 Bidi chars in one
 * 1MB window is still "over-use" within that locality, and a global pre-scan
 * would defeat the bounded-memory goal).
 *
 * @param {string} chunk
 * @param {number} chunkOffset - absolute offset of `chunk[0]` in the original
 * @param {string} fullContent - the original (used for context windows only)
 * @returns {Array} findings with absolute positions
 */
function scanInvisibleUnicodeChunk(chunk, chunkOffset, fullContent) {
  const findings = [];

  // First pass on the chunk: count Bidi-family occurrences.
  let bidiTotal = 0;
  for (let i = 0; i < chunk.length; i++) {
    const cp = chunk.codePointAt(i);
    if (cp === undefined) continue;
    if (BIDI_CONTROLS.has(cp)) bidiTotal++;
    if (cp > 0xffff) i++;
  }
  const bidiOverUse = bidiTotal >= BIDI_OVERUSE_THRESHOLD;

  for (let i = 0; i < chunk.length; i++) {
    const cp = chunk.codePointAt(i);
    if (cp === undefined) continue;
    const absPos = chunkOffset + i;

    // Unicode Tags Block (U+E0000 - U+E007F)
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      const asciiEquiv = cp - 0xe0000;
      const readable =
        asciiEquiv >= 0x20 && asciiEquiv <= 0x7e
          ? String.fromCharCode(asciiEquiv)
          : `0x${asciiEquiv.toString(16)}`;
      findings.push({
        char: `U+${cp.toString(16).toUpperCase().padStart(5, "0")}`,
        name: `Unicode Tag (ASCII: "${readable}")`,
        position: absPos,
        context: getContext(fullContent, absPos),
        severity: "danger",
      });
      if (cp > 0xffff) i++;
      continue;
    }

    if (BIDI_CONTROLS.has(cp)) {
      const spec = BIDI_CONTROLS.get(cp);
      const severity = bidiOverUse ? "danger" : spec.baseSeverity;
      findings.push({
        char: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        name: spec.name,
        category: "bidi-control",
        kind: spec.kind,
        position: absPos,
        context: getContext(fullContent, absPos),
        severity,
      });
      continue;
    }

    if (INVISIBLE_CHAR_MAP.has(cp)) {
      findings.push({
        char: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        name: INVISIBLE_CHAR_MAP.get(cp),
        position: absPos,
        context: getContext(fullContent, absPos),
        severity: "warning",
      });
    }

    if (
      (cp >= 0xe000 && cp <= 0xf8ff) ||
      (cp >= 0xf0000 && cp <= 0xffffd) ||
      (cp >= 0x100000 && cp <= 0x10fffd)
    ) {
      findings.push({
        char: `U+${cp.toString(16).toUpperCase()}`,
        name: "Private Use Area",
        position: absPos,
        context: getContext(fullContent, absPos),
        severity: "warning",
      });
    }

    if (cp > 0xffff) i++;
  }

  return findings;
}

/**
 * Scan text for invisible Unicode characters.
 *
 * v1.18.0: when `content.length > 5MB`, the scan is split into 1MB chunks
 * with a 2KB overlap so peak memory stays bounded and we don't drop findings
 * that straddle chunk boundaries. Overlap-region duplicates are removed by
 * absolute (position, char) dedup. Behavior for small/medium inputs is
 * unchanged (single linear pass).
 *
 * @param {string} content - The text to scan
 * @returns {Array} Array of finding objects
 */
export function detectInvisibleUnicode(content) {
  if (!shouldStream(content)) {
    // Fast path: single pass, identical to pre-v1.18.0 behavior.
    return scanInvisibleUnicodeChunk(content, 0, content);
  }

  // Streaming path: iterate non-overlapping advance window + overlap tail.
  const seen = new Set(); // dedup key: `${absPos}|${char}|${name}`
  const out = [];
  let chunkStart = 0;
  while (chunkStart < content.length) {
    const chunkEnd = Math.min(
      content.length,
      chunkStart + STREAM_CHUNK_SIZE + STREAM_OVERLAP_SIZE,
    );
    const chunk = content.slice(chunkStart, chunkEnd);
    const chunkFindings = scanInvisibleUnicodeChunk(chunk, chunkStart, content);
    for (const f of chunkFindings) {
      const key = `${f.position}|${f.char}|${f.name}`;
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
 * Remove all invisible Unicode characters from text.
 * Used by the sanitizer.
 */
export function stripInvisibleUnicode(content) {
  let result = content;

  // Remove Unicode Tags block
  result = result.replace(/[\u{E0000}-\u{E007F}]/gu, "");

  // Remove known invisible chars
  const codes = INVISIBLE_CHAR_LIST.map((c) => parseInt(c.code, 16));
  const regex = new RegExp(
    "[" +
      codes.map((c) => `\\u${c.toString(16).padStart(4, "0")}`).join("") +
      "]",
    "g"
  );
  result = result.replace(regex, "");

  return result;
}
