/**
 * v1.20.0 T6 — PDF /EmbeddedFile /Subtype raw-bytes extractor (helper, MCP).
 *
 * Context: pdf.js v4's `pdf.getAttachments()` returns a {filename, content,
 * description} shape but does NOT propagate the /Subtype name from the
 * EmbeddedFile stream dictionary on most PDFs. The v1.17.0 (T2) pdf-embedded-
 * html signal in pdf.js is wired through `att.subtype`, which means the path
 * is effectively dead for real-world PDFs (mocked tests still pass, on-disk
 * fixtures see undefined subtype). See pdf-s15.js fixture generator header
 * comment for the upstream limitation.
 *
 * This helper provides a parser-agnostic fallback: scan the raw PDF bytes
 * for `/EmbeddedFile` object dictionaries and pull their `/Subtype` name.
 * Handles the PDF Name-object hex-encoding form (`#2F` for `/`) so that
 * `/text#2Fhtml` decodes to `text/html`. The helper is deliberately scoped
 * to ONLY the EmbeddedFile-stream dictionary — it does not try to match
 * filenames or wire findings; the caller decides how to consume the result.
 *
 * v1.20.0 scope: helper + standalone test + fixture only. Wire-in to
 * packages/mcp/server/parsers/pdf.js is deferred to a later release so this
 * Theme does not collide with other Theme-owned files in v1.20.0.
 *
 * R12: this helper returns ONLY the canonical subtype string (e.g.
 * "text/html"). Raw PDF byte slices NEVER leave this module.
 */

const MAX_SCAN_BYTES = 5 * 1024 * 1024; // 5 MiB scan cap (matches PDF_MAX_ATTACHMENT_BYTES)
const MAX_DICT_LOOKAHEAD = 4096;        // bytes after /Type /EmbeddedFile to scan for /Subtype
const MAX_SUBTYPES_RETURNED = 16;       // upper bound on returned entries (defensive)

/**
 * Decode a PDF Name token (already stripped of leading "/"). PDF Names may
 * contain `#XX` hex escapes — `#2F` -> "/", `#2E` -> ".", etc. Any non-hex
 * `#` sequence is preserved as-is (defensive: real PDFs rarely abuse this).
 * @param {string} raw
 * @returns {string}
 */
function decodePdfName(raw) {
  if (!raw || raw.indexOf("#") < 0) return raw;
  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw.charCodeAt(i);
    if (ch === 0x23 /* # */ && i + 2 < raw.length) {
      const hi = raw.charCodeAt(i + 1);
      const lo = raw.charCodeAt(i + 2);
      if (isHex(hi) && isHex(lo)) {
        out += String.fromCharCode((hexVal(hi) << 4) | hexVal(lo));
        i += 2;
        continue;
      }
    }
    out += raw[i];
  }
  return out;
}

function isHex(c) {
  return (
    (c >= 0x30 && c <= 0x39) ||
    (c >= 0x41 && c <= 0x46) ||
    (c >= 0x61 && c <= 0x66)
  );
}

function hexVal(c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  return c - 0x61 + 10;
}

/**
 * Read a PDF Name token starting at byte offset `start` in `buf`. The leading
 * "/" must already have been consumed by the caller. Returns {raw, end} where
 * `raw` is the name body (still hex-encoded) and `end` is the byte offset
 * just past the name (the first delim / whitespace / EOF).
 *
 * PDF Name tokens are terminated by whitespace, delimiters `()<>[]{}/%`, or
 * EOF (ISO 32000-1 §7.3.5).
 * @param {Buffer|Uint8Array} buf
 * @param {number} start
 * @returns {{raw: string, end: number}}
 */
function readName(buf, start) {
  let end = start;
  while (end < buf.length) {
    const c = buf[end];
    // whitespace: NUL TAB LF FF CR SP
    if (c === 0x00 || c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d || c === 0x20) break;
    // delimiters: ( ) < > [ ] { } / %
    if (
      c === 0x28 || c === 0x29 || c === 0x3c || c === 0x3e ||
      c === 0x5b || c === 0x5d || c === 0x7b || c === 0x7d ||
      c === 0x2f || c === 0x25
    ) break;
    end++;
  }
  // raw ASCII-only slice — PDF Names are 7-bit ASCII per spec
  let raw = "";
  for (let i = start; i < end; i++) raw += String.fromCharCode(buf[i]);
  return { raw, end };
}

/**
 * Find the byte offset of the next occurrence of `needle` (an ASCII Buffer
 * or string) in `buf` starting from `from`. Returns -1 if not found.
 * Implemented as a plain forward scan — no regex, no allocation per call.
 * @param {Buffer|Uint8Array} buf
 * @param {string} needle
 * @param {number} from
 * @returns {number}
 */
function indexOfAscii(buf, needle, from) {
  const n = needle.length;
  const limit = Math.min(buf.length, MAX_SCAN_BYTES) - n;
  outer: for (let i = from; i <= limit; i++) {
    for (let j = 0; j < n; j++) {
      if (buf[i + j] !== needle.charCodeAt(j)) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * Scan a PDF byte buffer for EmbeddedFile-stream /Subtype names. Returns an
 * array of {subtype} entries (deduplicated, order-preserved). Caller can
 * cross-reference with `pdf.getAttachments()` results when filenames are
 * needed; this helper deliberately stays filename-agnostic so it can run
 * even when pdf.js fails to open the document.
 *
 * Algorithm:
 *   1. Find every `/EmbeddedFile` occurrence in the buffer (capped at
 *      MAX_SCAN_BYTES).
 *   2. For each hit, look up to MAX_DICT_LOOKAHEAD bytes ahead for the next
 *      `/Subtype` token, then read the immediately-following Name token.
 *   3. Decode `#XX` hex escapes in the Name and lower-case it.
 *   4. Stop the lookahead at the first `endobj` keyword (defensive: we don't
 *      want a /Subtype from a sibling object to leak).
 *
 * Limits / R12:
 *   - Scan is capped at 5 MiB (typical embedded-file dict is in the first
 *     few KiB of a stream object header).
 *   - Returned list is capped at MAX_SUBTYPES_RETURNED entries.
 *   - Only the decoded subtype string is returned. Raw PDF byte slices stay
 *     inside the helper.
 *
 * @param {Buffer|Uint8Array} buf
 * @returns {Array<{subtype: string}>}
 */
export function extractEmbeddedFileSubtypes(buf) {
  if (!buf || typeof buf.length !== "number" || buf.length < 8) return [];
  const out = [];
  const seen = new Set();
  const NEEDLE = "/EmbeddedFile";
  const SUBTYPE_NEEDLE = "/Subtype";
  const ENDOBJ_NEEDLE = "endobj";
  let cursor = 0;
  // Defensive overall bound: a 5 MiB PDF can hold a lot of dicts, but we cap
  // both the iteration count and the per-hit lookahead so we never blow up
  // on pathological inputs.
  while (out.length < MAX_SUBTYPES_RETURNED) {
    const hit = indexOfAscii(buf, NEEDLE, cursor);
    if (hit < 0) break;
    // Advance cursor past this hit so the next loop iteration moves forward
    // even if we don't find a /Subtype here.
    cursor = hit + NEEDLE.length;
    // Lookahead window — bounded.
    const lookEnd = Math.min(buf.length, cursor + MAX_DICT_LOOKAHEAD);
    // Stop the lookahead at the next `endobj` to keep the scan inside the
    // current PDF object.
    const objEnd = indexOfAscii(buf, ENDOBJ_NEEDLE, cursor);
    const windowEnd = objEnd > 0 ? Math.min(lookEnd, objEnd) : lookEnd;
    // Within the bounded window, scan for /Subtype.
    let scanFrom = cursor;
    while (scanFrom < windowEnd) {
      const subHit = indexOfAscii(buf, SUBTYPE_NEEDLE, scanFrom);
      if (subHit < 0 || subHit >= windowEnd) break;
      // The byte immediately after `/Subtype` must be whitespace or `/`,
      // otherwise this is a longer name like `/SubtypeSomethingElse`.
      const after = buf[subHit + SUBTYPE_NEEDLE.length];
      const isBoundary =
        after === 0x09 || after === 0x0a || after === 0x0c || after === 0x0d ||
        after === 0x20 || after === 0x2f;
      if (!isBoundary) {
        scanFrom = subHit + SUBTYPE_NEEDLE.length;
        continue;
      }
      // Skip whitespace, then expect `/` (Name token start).
      let p = subHit + SUBTYPE_NEEDLE.length;
      while (
        p < windowEnd &&
        (buf[p] === 0x09 || buf[p] === 0x0a || buf[p] === 0x0c ||
         buf[p] === 0x0d || buf[p] === 0x20)
      ) p++;
      if (p >= windowEnd || buf[p] !== 0x2f /* / */) {
        scanFrom = subHit + SUBTYPE_NEEDLE.length;
        continue;
      }
      const { raw, end } = readName(buf, p + 1);
      const decoded = decodePdfName(raw).toLowerCase();
      if (decoded && !seen.has(decoded)) {
        seen.add(decoded);
        out.push({ subtype: decoded });
        if (out.length >= MAX_SUBTYPES_RETURNED) return out;
      }
      scanFrom = end;
      // Only the FIRST /Subtype inside an EmbeddedFile dict is meaningful —
      // break out to the outer loop after recording it.
      break;
    }
  }
  return out;
}

/**
 * Convenience: return true if the buffer contains at least one EmbeddedFile
 * stream whose /Subtype maps to an HTML media type. The caller can use this
 * to gate a kebab signal (`pdf-embedded-html`) without re-scanning.
 *
 * Recognised HTML media types (case-insensitive after hex decode):
 *   - text/html
 *   - application/xhtml+xml
 *
 * @param {Buffer|Uint8Array} buf
 * @returns {boolean}
 */
export function hasEmbeddedHtmlSubtype(buf) {
  const subs = extractEmbeddedFileSubtypes(buf);
  for (const s of subs) {
    if (s.subtype === "text/html" || s.subtype === "application/xhtml+xml") return true;
  }
  return false;
}

// Exports kept minimal & explicit so future wire-in to pdf.js can import
// only what it needs (avoids accidental coupling to the internals).
export const __test__ = { decodePdfName, readName, indexOfAscii };
