/**
 * Control character detection.
 *
 * Detects control characters (U+0000-U+001F excluding \t\n\r, U+007F-U+009F)
 * which can be used to hide malicious instructions or corrupt rendering.
 */

import { getControlCharName } from "./utils.js";

// v1.18.0 streaming gate — see invisible-unicode.js for the rationale. Control
// chars are all single UTF-16 units (BMP, code < 0x100) so the 2KB overlap is
// vastly larger than the largest possible single-char span; boundary findings
// can never be partial.
const STREAM_THRESHOLD = 5 * 1024 * 1024;
const STREAM_CHUNK_SIZE = 1024 * 1024;
const STREAM_OVERLAP_SIZE = 2 * 1024;

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

function scanControlCharsChunk(chunk, chunkOffset) {
  const findings = [];
  for (let i = 0; i < chunk.length; i++) {
    const cp = chunk.charCodeAt(i);
    const isC0 = cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d;
    const isC1 = cp >= 0x7f && cp <= 0x9f;

    if (isC0 || isC1) {
      findings.push({
        char: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        name: getControlCharName(cp),
        position: chunkOffset + i,
        severity: "warning",
      });
    }
  }
  return findings;
}

/**
 * Scan text for control characters.
 * Excludes normal whitespace (tab, LF, CR).
 *
 * v1.18.0: chunks content > 5MB into 1MB windows with 2KB overlap (see
 * invisible-unicode.js for the streaming contract). Behavior for small/medium
 * inputs is unchanged.
 *
 * @param {string} content
 * @returns {Array} findings
 */
export function detectControlChars(content) {
  if (!shouldStream(content)) {
    return scanControlCharsChunk(content, 0);
  }

  const seen = new Set(); // dedup: `${absPos}|${char}`
  const out = [];
  let chunkStart = 0;
  while (chunkStart < content.length) {
    const chunkEnd = Math.min(
      content.length,
      chunkStart + STREAM_CHUNK_SIZE + STREAM_OVERLAP_SIZE,
    );
    const chunk = content.slice(chunkStart, chunkEnd);
    const chunkFindings = scanControlCharsChunk(chunk, chunkStart);
    for (const f of chunkFindings) {
      const key = `${f.position}|${f.char}`;
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
 * Strip control characters from text (sanitizer helper).
 * Preserves tab, LF, CR.
 */
export function stripControlChars(content) {
  // \x00-\x08, \x0B, \x0C, \x0E-\x1F, \x7F-\x9F
  return content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, "");
}
