/**
 * v1.20.0 T6 — Web-side stub mirror of pdf-attachment-subtype.js.
 *
 * This file is intentionally a near byte-for-byte copy of the MCP helper at
 * packages/mcp/server/parsers/pdf-attachment-subtype.js. The web bundle uses
 * its own parsers-web/ tree (no node:fs / no node imports), so we cannot
 * import the MCP version directly. The implementations stay in lock-step;
 * any drift between them should be caught by future parity-check additions.
 *
 * v1.20.0 scope: helper only, NOT wired into parsers-web/pdf.js. Wire-in is
 * deferred so this Theme does not collide with other v1.20.0 Theme-owned
 * files. The export is available for an opt-in future release.
 *
 * R12: only the canonical subtype string is returned. Raw PDF byte slices
 * stay inside this module.
 */

const MAX_SCAN_BYTES = 5 * 1024 * 1024;
const MAX_DICT_LOOKAHEAD = 4096;
const MAX_SUBTYPES_RETURNED = 16;

function decodePdfName(raw) {
  if (!raw || raw.indexOf("#") < 0) return raw;
  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw.charCodeAt(i);
    if (ch === 0x23 && i + 2 < raw.length) {
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

function readName(buf, start) {
  let end = start;
  while (end < buf.length) {
    const c = buf[end];
    if (c === 0x00 || c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d || c === 0x20) break;
    if (
      c === 0x28 || c === 0x29 || c === 0x3c || c === 0x3e ||
      c === 0x5b || c === 0x5d || c === 0x7b || c === 0x7d ||
      c === 0x2f || c === 0x25
    ) break;
    end++;
  }
  let raw = "";
  for (let i = start; i < end; i++) raw += String.fromCharCode(buf[i]);
  return { raw, end };
}

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

export function extractEmbeddedFileSubtypes(buf) {
  if (!buf || typeof buf.length !== "number" || buf.length < 8) return [];
  const out = [];
  const seen = new Set();
  const NEEDLE = "/EmbeddedFile";
  const SUBTYPE_NEEDLE = "/Subtype";
  const ENDOBJ_NEEDLE = "endobj";
  let cursor = 0;
  while (out.length < MAX_SUBTYPES_RETURNED) {
    const hit = indexOfAscii(buf, NEEDLE, cursor);
    if (hit < 0) break;
    cursor = hit + NEEDLE.length;
    const lookEnd = Math.min(buf.length, cursor + MAX_DICT_LOOKAHEAD);
    const objEnd = indexOfAscii(buf, ENDOBJ_NEEDLE, cursor);
    const windowEnd = objEnd > 0 ? Math.min(lookEnd, objEnd) : lookEnd;
    let scanFrom = cursor;
    while (scanFrom < windowEnd) {
      const subHit = indexOfAscii(buf, SUBTYPE_NEEDLE, scanFrom);
      if (subHit < 0 || subHit >= windowEnd) break;
      const after = buf[subHit + SUBTYPE_NEEDLE.length];
      const isBoundary =
        after === 0x09 || after === 0x0a || after === 0x0c || after === 0x0d ||
        after === 0x20 || after === 0x2f;
      if (!isBoundary) {
        scanFrom = subHit + SUBTYPE_NEEDLE.length;
        continue;
      }
      let p = subHit + SUBTYPE_NEEDLE.length;
      while (
        p < windowEnd &&
        (buf[p] === 0x09 || buf[p] === 0x0a || buf[p] === 0x0c ||
         buf[p] === 0x0d || buf[p] === 0x20)
      ) p++;
      if (p >= windowEnd || buf[p] !== 0x2f) {
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
      break;
    }
  }
  return out;
}

export function hasEmbeddedHtmlSubtype(buf) {
  const subs = extractEmbeddedFileSubtypes(buf);
  for (const s of subs) {
    if (s.subtype === "text/html" || s.subtype === "application/xhtml+xml") return true;
  }
  return false;
}

export const __test__ = { decodePdfName, readName, indexOfAscii };
