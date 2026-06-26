// Image parser (S12) - extracted from index.html L2175-L3257
// R14 mirror: _imgDecodeUtf8OrLatin1 + all _img* helpers kept Web-only because
// they wrap browser TextDecoder/DecompressionStream (no Node fallback).
// Depends on core: escapeForDisplay, looksLikeInstruction
import { escapeForDisplay, looksLikeInstruction } from '@shield-scanner/core';

// --- Image Parser (S12) ---------------------------------------------------
// Mirror of shield-scanner-mcp/server/parsers/image.js. The ALLOW maps and
// SEPARATOR string MUST stay byte-identical with the MCP copy — the
// image-parity test pins extracted-text equivalence across runtimes.
//
// Hard rules:
//  - R12 (no raw-text echo): hiddenFindings carry only structural hints
//    (sourceField / length / encoding), never the field value.
//  - R1  (no NFKC): bytes are decoded with TextDecoder('latin1' / 'utf-8' /
//    'utf-16le' / 'utf-16be'). No normalize() anywhere on this path.
//  - parseImage NEVER throws. On walker fault we return an empty `text`
//    plus a single warning finding.
//  - Two-layer instruction gate (per-field + aggregated joined blob) closes
//    the split-payload bypass.
//  - Zero new CDN deps — uses native Uint8Array / DataView / TextDecoder /
//    DecompressionStream only.
const IMG_SEPARATOR = '\n----- IMG_FIELD_BOUNDARY -----\n';
const IMG_MAX_INFLATED_BYTES = 5 * 1024 * 1024;
// S12-XR-04 amplification caps — mirror of MCP image.js. Three guardrails
// against the legitimate-shape DoS (many small valid metadata segments each
// carrying a copy of an injection token): input-byte cap, joined-text length
// cap, per-image hidden-finding cap. The original S12 spec hardened only the
// zTXt decompression bomb; this trio caps the rest of the amplification path.
const IMG_MAX_BYTES = 5 * 1024 * 1024;
const IMG_MAX_JOINED_TEXT_BYTES = 1 * 1024 * 1024;
const IMG_MAX_PER_FIELD_FINDINGS = 64;
const IMG_JPEG_TAG_ALLOW = new Map([
  [0x010d, 'DocumentName'],
  [0x010e, 'ImageDescription'],
  [0x010f, 'Make'],
  [0x0110, 'Model'],
  [0x0131, 'Software'],
  [0x013b, 'Artist'],
  [0x013c, 'HostComputer'],
  [0x8298, 'Copyright'],
  [0x9c9b, 'XPTitle'],
  [0x9c9c, 'XPComment'],
  [0x9c9d, 'XPAuthor'],
  [0x9c9e, 'XPKeywords'],
  [0x9c9f, 'XPSubject'],
  [0x02bc, '__XMP_IN_TIFF'],
  [0x83bb, '__IPTC_IN_TIFF'],
  [0x8769, '__SUBIFD'],
  [0x8825, '__GPSIFD'],
]);
const IMG_EXIF_SUBIFD_ALLOW = new Map([[0x9286, 'UserComment']]);
const IMG_GPS_IFD_ALLOW = new Map([
  [0x001b, 'GPSProcessingMethod'],
  [0x001c, 'GPSAreaInformation'],
]);
const IMG_IPTC_ALLOW = new Map([
  ['2:040', 'SpecialInstructions'],
  ['2:080', 'Byline'],
  ['2:105', 'Headline'],
  ['2:116', 'Copyright'],
  ['2:120', 'Caption'],
  ['2:025', 'Keywords'],
]);
const IMG_XMP_FIELD_ALLOW = [
  // Dublin Core free-text fields
  'dc:description',
  'dc:title',
  'dc:subject',
  'dc:rights',
  'dc:creator',
  'dc:relation',
  'dc:contributor',
  'dc:publisher',
  // Adobe XMP basic
  'xmp:CreatorTool',
  // Photoshop legacy IPTC mirror
  'photoshop:Instructions',
  'photoshop:Headline',
  'photoshop:Credit',
  'photoshop:Source',
  'photoshop:SupplementalCategories',
  // BYPASS-03 — xmpRights / IPTC4XMP / Camera Raw / TIFF-XMP / MicrosoftPhoto
  // free-text fields that Adobe Lightroom, Bridge, Premiere, and Windows
  // Explorer write on every save. Without these the allowlist was a public
  // bypass surface — attackers simply parked the injection in any non-listed
  // namespace and parseImage returned text='' / extraFindings=[]. Keep this
  // enumerative (NOT a namespace wildcard) so structural fields like
  // crs:WhiteBalance or exif:GPSLatitude don't leak into the detector.
  'xmpRights:UsageTerms',
  'xmpRights:WebStatement',
  'Iptc4xmpCore:Location',
  'crs:Comments',
  'crs:RawFileName',
  'tiff:ImageDescription',
  'tiff:Artist',
  'tiff:Copyright',
  'MicrosoftPhoto:LastKeywordIPTC',
];

// Browser-side byte helpers ------------------------------------------------
const _imgDecLatin1 = new TextDecoder('latin1');
const _imgDecUtf8 = new TextDecoder('utf-8', { fatal: false });
const _imgDecUtf8Strict = new TextDecoder('utf-8', { fatal: true });
const _imgDecUtf16le = new TextDecoder('utf-16le');
const _imgDecUtf16be = new TextDecoder('utf-16be');

function _imgU8(buf) {
  if (buf instanceof Uint8Array) return buf;
  if (buf instanceof ArrayBuffer) return new Uint8Array(buf);
  if (buf && buf.buffer instanceof ArrayBuffer) {
    return new Uint8Array(buf.buffer, buf.byteOffset || 0, buf.byteLength || buf.length || 0);
  }
  return new Uint8Array(buf || []);
}
function _imgSlice(u8, start, end) {
  return u8.subarray(start, end === undefined ? u8.length : end);
}
function _imgReadU16BE(u8, off) {
  return ((u8[off] << 8) | u8[off + 1]) >>> 0;
}
function _imgReadU16LE(u8, off) {
  return (u8[off] | (u8[off + 1] << 8)) >>> 0;
}
function _imgReadU32BE(u8, off) {
  return ((u8[off] * 0x1000000) + ((u8[off + 1] << 16) | (u8[off + 2] << 8) | u8[off + 3])) >>> 0;
}
function _imgReadU32LE(u8, off) {
  return ((u8[off] | (u8[off + 1] << 8) | (u8[off + 2] << 16)) + (u8[off + 3] * 0x1000000)) >>> 0;
}
function _imgLatin1(u8, start, end) {
  return _imgDecLatin1.decode(_imgSlice(u8, start, end));
}
function _imgIndexOf(u8, byte, fromIndex) {
  for (let i = fromIndex || 0; i < u8.length; i++) if (u8[i] === byte) return i;
  return -1;
}
function _imgConcat(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
function _imgDecodeUtf8OrLatin1(u8) {
  if (!u8 || u8.length === 0) return '';
  try {
    return _imgDecUtf8Strict.decode(u8);
  } catch {
    return _imgDecLatin1.decode(u8);
  }
}
function _imgDecodeUtf16(u8, le) {
  if (!u8 || u8.length < 2) return '';
  let start = 0;
  // Strip a leading UTF-16 BOM regardless of endianness — see _decodeUtf16
  // in MCP image.js for the BYPASS-04 rationale. A wrong-endian BOM is a
  // noncharacter that would otherwise leak as a literal U+FFFE in result.text.
  if (u8[0] === 0xff && u8[1] === 0xfe) start = 2;
  else if (u8[0] === 0xfe && u8[1] === 0xff) start = 2;
  const usableLen = (u8.length - start) & ~1;
  const body = _imgSlice(u8, start, start + usableLen);
  return (le ? _imgDecUtf16le : _imgDecUtf16be).decode(body);
}
// Returns `{ str, decoded }` where `decoded: true` means a UTF-16 transcode
// was applied (the source bytes do NOT directly contain ASCII attack tokens
// the way a latin1 reading would expose). UTF-8 paths (with or without BOM)
// leave the bytes as-is — they are not oracle leaks for ASCII content.
// R12 (S12 R12-IMG-002 fix; MCP parity with server/parsers/image.js).
function _imgDecodePacket(u8) {
  if (!u8 || u8.length === 0) return { str: '', decoded: false };
  if (u8.length >= 2 && u8[0] === 0xfe && u8[1] === 0xff) return { str: _imgDecodeUtf16(u8, false), decoded: true };
  if (u8.length >= 2 && u8[0] === 0xff && u8[1] === 0xfe) return { str: _imgDecodeUtf16(u8, true), decoded: true };
  if (u8.length >= 3 && u8[0] === 0xef && u8[1] === 0xbb && u8[2] === 0xbf) {
    return { str: _imgDecUtf8.decode(_imgSlice(u8, 3)), decoded: false };
  }
  return { str: _imgDecUtf8.decode(u8), decoded: false };
}
// PNG suggested-keyword allow-list (PNG 1.2 §11.3.4.2). Mirrors MCP
// parsers/image.js PNG_KEYWORD_ALLOW byte-for-byte. Guardrail R6:
// structural fields must be detector-controlled vocab only — without
// this allow-list, an attacker-controlled tEXt/zTXt/iTXt key would
// bleed up to 64 chars of raw prose into the location label (which
// flows into structural.sourceField, structural.segments[], the
// joined-text `[IMG png:tEXt:<key>]` prefix, and the imageMetadata
// section).
const IMG_PNG_KEYWORD_ALLOW = new Set([
  'Title',
  'Author',
  'Description',
  'Copyright',
  'Creation Time',
  'Software',
  'Disclaimer',
  'Warning',
  'Source',
  'Comment',
]);

function _imgSafeKey(s) {
  const raw = String(s == null ? '' : s);
  const trimmed = raw.replace(/^\s+|\s+$/g, '');
  // Empty-key passthrough preserves the `|| "__empty"` fallback at the
  // call sites (parity with MCP image.js).
  if (trimmed === '') return '';
  if (IMG_PNG_KEYWORD_ALLOW.has(trimmed)) {
    return trimmed.replace(/\s+/g, '_');
  }
  return 'other';
}

// Cross-runtime zlib inflate. Web uses DecompressionStream('deflate') with
// a streaming byte cap so a hostile zTXt cannot OOM the tab.
//
// Returns { bytes: Uint8Array, truncated: boolean } on success, or null on
// decode error / absent API / empty input.
//
// BYPASS-02 fix: on cap-exceeded we used to return null, which made the
// PNG walker silently drop the whole field — turning the DoS guard into a
// detection bypass. Now we keep the first IMG_MAX_INFLATED_BYTES bytes
// and flag `truncated:true`. Mirror of the MCP createInflate streaming
// path; parity-pinned by image-parity.test.js.
async function _imgInflateBytesCapped(bytes) {
  if (!bytes || bytes.length === 0) return null;
  if (typeof DecompressionStream === 'undefined') return null;
  try {
    const src = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
    const reader = src.getReader();
    const chunks = [];
    let total = 0;
    let truncated = false;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (total + value.length >= IMG_MAX_INFLATED_BYTES) {
        const need = IMG_MAX_INFLATED_BYTES - total;
        if (need > 0) chunks.push(value.subarray(0, need));
        total = IMG_MAX_INFLATED_BYTES;
        truncated = true;
        try { await reader.cancel(); } catch {}
        break;
      }
      chunks.push(value);
      total += value.length;
    }
    return { bytes: _imgConcat(chunks), truncated };
  } catch {
    return null;
  }
}

// TIFF type byte-size table (mirrors MCP _tiffTypeSize).
function _imgTiffTypeSize(type) {
  switch (type) {
    case 1: case 2: case 6: case 7: return 1;
    case 3: case 8: return 2;
    case 4: case 9: case 11: return 4;
    case 5: case 10: case 12: return 8;
    default: return 0;
  }
}

function _imgDecodeTiffValue(tag, type, bytes, le) {
  if (tag >= 0x9c9b && tag <= 0x9c9f && type === 1) {
    const str = _imgDecodeUtf16(bytes, true).replace(/[\0 ]+$/, '');
    return { value: str, encoding: 'utf-16le' };
  }
  if (type === 2) {
    // BYPASS-01 fix (MCP parity): spec is Latin-1, but real-world EXIF writers
    // and attackers commonly emit UTF-8 bytes. UTF-8-first preserves
    // attacker-supplied Unicode for the downstream invisibleUnicode /
    // homoglyph detectors. ASCII-only inputs round-trip unchanged.
    let end = bytes.length;
    while (end > 0 && bytes[end - 1] === 0) end--;
    const str = _imgDecodeUtf8OrLatin1(_imgSlice(bytes, 0, end));
    return { value: str, encoding: 'ascii' };
  }
  if (tag === 0x9286 && type === 7) {
    if (bytes.length < 8) return null;
    const code = _imgLatin1(bytes, 0, 8).replace(/\0+$/, '').trim();
    const body = _imgSlice(bytes, 8);
    // BYPASS-01 fix (MCP parity): UTF-8-first for ASCII/JIS/unknown charcode.
    if (code === 'ASCII') return { value: _imgDecodeUtf8OrLatin1(body), encoding: 'ascii' };
    if (code === 'UNICODE') return { value: _imgDecodeUtf16(body, le).replace(/[\0 ]+$/, ''), encoding: le ? 'utf-16le' : 'utf-16be' };
    if (code === 'JIS') return { value: _imgDecodeUtf8OrLatin1(body), encoding: 'jis-raw' };
    return { value: _imgDecodeUtf8OrLatin1(body), encoding: 'auto' };
  }
  if (type === 1 || type === 7) {
    // BYPASS-01 fix (MCP parity): generic BYTE/UNDEFINED fallback.
    return { value: _imgDecodeUtf8OrLatin1(bytes), encoding: 'auto' };
  }
  return null;
}

function _imgReadIfd(tiff, base, le, allow, srcLabel, depth) {
  const out = [];
  if (depth > 3) return out;
  if (base + 2 > tiff.length) return out;
  const n = le ? _imgReadU16LE(tiff, base) : _imgReadU16BE(tiff, base);
  const entriesStart = base + 2;
  if (entriesStart + n * 12 > tiff.length) return out;
  for (let i = 0; i < n; i++) {
    const off = entriesStart + i * 12;
    const tag = le ? _imgReadU16LE(tiff, off) : _imgReadU16BE(tiff, off);
    const type = le ? _imgReadU16LE(tiff, off + 2) : _imgReadU16BE(tiff, off + 2);
    const count = le ? _imgReadU32LE(tiff, off + 4) : _imgReadU32BE(tiff, off + 4);
    const valOff = off + 8;

    if (tag === 0x8769) {
      if (type !== 4 || count !== 1) continue;
      const sub = le ? _imgReadU32LE(tiff, valOff) : _imgReadU32BE(tiff, valOff);
      if (sub >= 8 && sub < tiff.length) {
        out.push(..._imgReadIfd(tiff, sub, le, IMG_EXIF_SUBIFD_ALLOW, srcLabel, depth + 1));
      }
      continue;
    }
    if (tag === 0x8825) {
      if (type !== 4 || count !== 1) continue;
      const sub = le ? _imgReadU32LE(tiff, valOff) : _imgReadU32BE(tiff, valOff);
      if (sub >= 8 && sub < tiff.length) {
        out.push(..._imgReadIfd(tiff, sub, le, IMG_GPS_IFD_ALLOW, srcLabel, depth + 1));
      }
      continue;
    }

    const typeSize = _imgTiffTypeSize(type);
    if (typeSize === 0) continue;
    const total = typeSize * count;
    let valueBytes;
    if (total <= 4) {
      valueBytes = _imgSlice(tiff, valOff, valOff + total);
    } else {
      const ptr = le ? _imgReadU32LE(tiff, valOff) : _imgReadU32BE(tiff, valOff);
      if (ptr + total > tiff.length || ptr < 0) continue;
      valueBytes = _imgSlice(tiff, ptr, ptr + total);
    }

    if (tag === 0x02bc) {
      out.push(..._imgExtractXmpFields(_imgDecodePacket(valueBytes), `${srcLabel}:`));
      continue;
    }
    if (tag === 0x83bb) {
      out.push(..._imgReadIptcIim(valueBytes));
      continue;
    }

    // Resolve the field name. Primary lookup = the IFD-scoped allow map.
    // Fallback: real-world EXIF writers (and some fixture builders) sometimes
    // flatten SubIFD / GPS-IFD tags onto IFD0 instead of routing through the
    // 0x8769 / 0x8825 pointers. Accept those tags here too so the field is
    // not silently dropped (parity with MCP image.js _readIfd).
    let name = allow.get(tag);
    if (typeof name !== 'string' || name.startsWith('__')) {
      if (allow !== IMG_EXIF_SUBIFD_ALLOW && IMG_EXIF_SUBIFD_ALLOW.has(tag)) {
        name = IMG_EXIF_SUBIFD_ALLOW.get(tag);
      } else if (allow !== IMG_GPS_IFD_ALLOW && IMG_GPS_IFD_ALLOW.has(tag)) {
        name = IMG_GPS_IFD_ALLOW.get(tag);
      } else {
        continue;
      }
    }

    const decoded = _imgDecodeTiffValue(tag, type, valueBytes, le);
    if (decoded && decoded.value) {
      // R12 (S12 R12-IMG-002 fix; MCP parity): UTF-16 paths (XP* tags,
      // UserComment UNICODE) decode 2-byte-per-char source bytes into
      // single JS characters — ASCII attack tokens are never visible in
      // the raw bytes. ASCII / Latin-1 / JIS paths leave the bytes as-is,
      // so they are not oracle leaks.
      out.push({
        location: `${srcLabel}:${name}`,
        value: decoded.value,
        encoding: decoded.encoding,
        decoded:
          decoded.encoding === 'utf-16le' || decoded.encoding === 'utf-16be',
      });
    }
  }
  return out;
}

function _imgReadTiff(tiff, srcLabel) {
  const out = [];
  if (!tiff || tiff.length < 8) return out;
  let le;
  if (tiff[0] === 0x49 && tiff[1] === 0x49) le = true;
  else if (tiff[0] === 0x4d && tiff[1] === 0x4d) le = false;
  else return out;
  const magic = le ? _imgReadU16LE(tiff, 2) : _imgReadU16BE(tiff, 2);
  if (magic !== 0x002a) return out;
  const ifd0 = le ? _imgReadU32LE(tiff, 4) : _imgReadU32BE(tiff, 4);
  if (ifd0 < 8 || ifd0 >= tiff.length) return out;

  // Walk the linked-list of top-level IFDs (IFD0 -> IFD1 -> …). After each
  // IFD's entry array, a u32 nextIFD pointer says where the next IFD begins
  // (0 = end of chain). Cap chain length at 4 to match the SubIFD/GPS depth
  // guard already in _imgReadIfd, and track visited offsets to short-circuit
  // any attacker-crafted cycle. Parity with MCP image.js _readTiff.
  const visited = new Set();
  let ifdOff = ifd0;
  for (let chainDepth = 0; chainDepth < 4; chainDepth++) {
    if (ifdOff < 8 || ifdOff + 2 > tiff.length) break;
    if (visited.has(ifdOff)) break;
    visited.add(ifdOff);

    out.push(..._imgReadIfd(tiff, ifdOff, le, IMG_JPEG_TAG_ALLOW, srcLabel, 0));

    const n = le ? _imgReadU16LE(tiff, ifdOff) : _imgReadU16BE(tiff, ifdOff);
    const nextOff = ifdOff + 2 + n * 12;
    if (nextOff + 4 > tiff.length) break;
    const nextIfd = le ? _imgReadU32LE(tiff, nextOff) : _imgReadU32BE(tiff, nextOff);
    if (nextIfd === 0) break;
    ifdOff = nextIfd;
  }
  return out;
}

function _imgReadIptcIim(iim) {
  const out = [];
  let utf8Mode = false;
  let p = 0;
  while (p + 5 <= iim.length) {
    if (iim[p] !== 0x1c) { p += 1; continue; }
    const rec = iim[p + 1];
    const ds = iim[p + 2];
    const len = _imgReadU16BE(iim, p + 3);
    p += 5;
    if (p + len > iim.length) break;
    const data = _imgSlice(iim, p, p + len);
    p += len;

    if (rec === 1 && ds === 90) {
      if (_imgLatin1(data, 0, data.length).includes('\x1b%G')) utf8Mode = true;
      continue;
    }
    if (rec !== 2) continue;
    const key = `${rec}:${String(ds).padStart(3, '0')}`;
    if (!IMG_IPTC_ALLOW.has(key)) continue;
    const name = IMG_IPTC_ALLOW.get(key);
    // BYPASS-01 fix (MCP parity): in default (non-utf8Mode) IPTC, spec is
    // Latin-1 but real-world writers and attackers commonly emit UTF-8 bytes.
    // UTF-8-first preserves attacker-supplied Unicode for the central detector.
    const value = utf8Mode ? _imgDecUtf8.decode(data) : _imgDecodeUtf8OrLatin1(data);
    // R12 (S12 R12-IMG-002 fix; MCP parity): utf8Mode is a mode-switch
    // decoder primitive — for ASCII attack tokens the bytes are still
    // visible, but non-ASCII multi-byte sequences synthesize plaintext that
    // latin1-rendered raw bytes don't expose. Mark utf8Mode entries as
    // decoded for safety. Non-utf8Mode is byte-as-is.
    out.push({ location: `iptc:${name}`, value, encoding: utf8Mode ? 'utf-8' : 'auto', decoded: utf8Mode });
  }
  return out;
}

function _imgReadApp13(seg) {
  const out = [];
  const marker = 'Photoshop 3.0\0';
  const segStr = _imgLatin1(seg, 0, seg.length);
  const idx = segStr.indexOf(marker);
  if (idx < 0) return out;
  let p = idx + marker.length;
  while (p + 11 <= seg.length) {
    if (_imgLatin1(seg, p, p + 4) !== '8BIM') break;
    p += 4;
    const resourceId = _imgReadU16BE(seg, p);
    p += 2;
    const nameLen = seg[p];
    let nameTotal = 1 + nameLen;
    if (nameTotal & 1) nameTotal += 1;
    p += nameTotal;
    if (p + 4 > seg.length) break;
    const dataLen = _imgReadU32BE(seg, p);
    p += 4;
    if (p + dataLen > seg.length) break;
    const data = _imgSlice(seg, p, p + dataLen);
    if (resourceId === 0x0404) {
      out.push(..._imgReadIptcIim(data));
    }
    let dataPadded = dataLen;
    if (dataPadded & 1) dataPadded += 1;
    p += dataPadded;
  }
  return out;
}

const _IMG_XML_ENTITY_MAP = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
function _imgDecodeXmlEntities(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (_m, body) => {
    if (body[0] === '#') {
      const cp = body[1] === 'x' || body[1] === 'X'
        ? parseInt(body.slice(2), 16)
        : parseInt(body.slice(1), 10);
      if (Number.isFinite(cp) && cp >= 0 && cp <= 0x10ffff) {
        try { return String.fromCodePoint(cp); } catch { return ''; }
      }
      return '';
    }
    return _IMG_XML_ENTITY_MAP[body] != null ? _IMG_XML_ENTITY_MAP[body] : `&${body};`;
  });
}
function _imgXmpExtractLeafValues(body) {
  const liRe = /<rdf:li\b[^>]*?(?:\/>|>([\s\S]*?)<\/rdf:li>)/g;
  const out = [];
  let any = false;
  let m;
  while ((m = liRe.exec(body)) !== null) {
    any = true;
    if (m[1] != null) out.push(m[1]);
  }
  if (any) return out;
  return [body.replace(/<\/?rdf:(?:Alt|Bag|Seq)\b[^>]*>/g, '').trim()];
}
function _imgExtractXmpFields(rdfPacket, prefix, packetDecoded) {
  prefix = prefix || '';
  packetDecoded = packetDecoded === true;
  const out = [];
  // R12 (S12 R12-IMG-002 fix): callers may pass either a bare string
  // (legacy) or the new tri-state `{ str, decoded }` returned by
  // `_imgDecodePacket`. Unwrap the object form and remember whether the
  // packet was UTF-16-transcoded (so every emitted field inherits the
  // decoded flag even if its own value didn't contain XML entities).
  if (rdfPacket && typeof rdfPacket === 'object' && typeof rdfPacket.str === 'string') {
    packetDecoded = Boolean(rdfPacket.decoded);
    rdfPacket = rdfPacket.str;
  }
  if (typeof rdfPacket !== 'string' || rdfPacket.length === 0) return out;
  // PARSE-006: strip XML comments so commented-out example tags are not
  // extracted as live values (mirrors MCP _extractXmpFields).
  rdfPacket = rdfPacket.replace(/<!--[\s\S]*?-->/g, '');
  // PARSE-005 dedupe (Web parity with MCP): a single logical XMP field
  // (e.g. dc:description) can be hit by the element-body, double-quoted attr,
  // and single-quoted attr passes simultaneously when the source uses both
  // forms on the same / nested element. Dedupe by (location, value) per call
  // so one attacker-controlled field cannot inflate raw.length from 1 → 2 and
  // trip the split-payload aggregate threshold via attribute shorthand alone.
  // S12 R12-IMG-002: if duplicates disagree on `decoded`, the more
  // conservative `true` wins (any pass that synthesized plaintext counts).
  const seenIdx = new Map();
  const pushUnique = (location, value, decoded) => {
    const key = `${location}\x00${value}`;
    const prev = seenIdx.get(key);
    if (prev !== undefined) {
      if (decoded && !out[prev].decoded) out[prev].decoded = true;
      return;
    }
    seenIdx.set(key, out.length);
    out.push({ location, value, encoding: 'utf-8', decoded });
  };
  for (const fname of IMG_XMP_FIELD_ALLOW) {
    const escName = fname.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const elRe = new RegExp(`<${escName}\\b[^>]*?(?:/>|>([\\s\\S]*?)</${escName}>)`, 'g');
    let m;
    while ((m = elRe.exec(rdfPacket)) !== null) {
      const body = m[1];
      if (body == null) continue;
      const values = _imgXmpExtractLeafValues(body);
      for (const v of values) {
        const trimmedV = v.trim();
        const decodedStr = _imgDecodeXmlEntities(v).trim();
        if (decodedStr) {
          pushUnique(
            `${prefix}xmp:${fname}`,
            decodedStr,
            packetDecoded || decodedStr !== trimmedV
          );
        }
      }
    }
    const attrRe = new RegExp(`\\s${escName}\\s*=\\s*"([^"]*)"`, 'g');
    while ((m = attrRe.exec(rdfPacket)) !== null) {
      const raw = m[1];
      const trimmedRaw = raw.trim();
      const decodedStr = _imgDecodeXmlEntities(raw).trim();
      if (decodedStr) {
        pushUnique(
          `${prefix}xmp:${fname}`,
          decodedStr,
          packetDecoded || decodedStr !== trimmedRaw
        );
      }
    }
    const attrRe2 = new RegExp(`\\s${escName}\\s*=\\s*'([^']*)'`, 'g');
    while ((m = attrRe2.exec(rdfPacket)) !== null) {
      const raw = m[1];
      const trimmedRaw = raw.trim();
      const decodedStr = _imgDecodeXmlEntities(raw).trim();
      if (decodedStr) {
        pushUnique(
          `${prefix}xmp:${fname}`,
          decodedStr,
          packetDecoded || decodedStr !== trimmedRaw
        );
      }
    }
  }
  return out;
}

function _imgWalkJpeg(buf) {
  const out = [];
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return out;
  let p = 2;
  while (p + 1 < buf.length) {
    if (buf[p] !== 0xff) { p++; continue; }
    while (p + 1 < buf.length && buf[p + 1] === 0xff) p++;
    const marker = buf[p + 1];
    p += 2;
    if (marker === 0x00 || marker === 0xff) continue;
    if (marker === 0xd8 || marker === 0xd9) continue;
    if (marker >= 0xd0 && marker <= 0xd7) continue;
    if (p + 1 >= buf.length) break;
    const segLen = _imgReadU16BE(buf, p);
    if (segLen < 2 || p + segLen > buf.length) break;
    const segStart = p + 2;
    const segEnd = p + segLen;
    const seg = _imgSlice(buf, segStart, segEnd);

    if (marker === 0xfe) {
      // R12 (MCP parity): COM payload bytes are already cleartext (UTF-8 /
      // Latin-1); pick a decoder but no plaintext synthesis happens for
      // ASCII attack tokens. decoded:false.
      out.push({ location: 'jpeg:COM', value: _imgDecodeUtf8OrLatin1(seg), encoding: 'auto', decoded: false });
    } else if (marker === 0xe1) {
      if (seg.length >= 6 && seg[0] === 0x45 && seg[1] === 0x78 && seg[2] === 0x69 && seg[3] === 0x66 && seg[4] === 0x00 && seg[5] === 0x00) {
        const tiff = _imgSlice(seg, 6);
        out.push(..._imgReadTiff(tiff, 'exif'));
      } else {
        const ns = 'http://ns.adobe.com/xap/1.0/\0';
        if (seg.length >= ns.length && _imgLatin1(seg, 0, ns.length) === ns) {
          const xmpBytes = _imgSlice(seg, ns.length);
          // Spec Test 4: inline JPEG APP1 XMP unwraps to bare `xmp:<field>`.
          out.push(..._imgExtractXmpFields(_imgDecodePacket(xmpBytes), ''));
        }
      }
    } else if (marker === 0xed) {
      out.push(..._imgReadApp13(seg));
    }

    p = segEnd;
    if (marker === 0xda) break;
  }
  return out;
}

async function _imgWalkPng(buf) {
  const out = [];
  if (buf.length < 8) return out;
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  for (let i = 0; i < 8; i++) if (buf[i] !== sig[i]) return out;
  let p = 8;
  while (p + 8 <= buf.length) {
    const len = _imgReadU32BE(buf, p);
    const type = _imgLatin1(buf, p + 4, p + 8);
    const dataStart = p + 8;
    const dataEnd = dataStart + len;
    if (dataEnd + 4 > buf.length) break;
    const data = _imgSlice(buf, dataStart, dataEnd);

    if (type === 'tEXt') {
      const sep = _imgIndexOf(data, 0, 0);
      // PARSE-003 fix: accept sep===0 (empty key). A 1-byte NUL prefix
      // otherwise bypasses all PNG-tEXt detection in this pipeline. Synthetic
      // '__empty' key keeps the location string tokenic and parity-aligned
      // with the MCP parser.
      if (sep >= 0) {
        const key = _imgLatin1(data, 0, sep);
        // BYPASS-01 fix (MCP parity): spec is Latin-1, but real-world writers
        // and attackers commonly emit UTF-8 bytes here. UTF-8-first preserves
        // attacker-supplied Unicode (RLO/ZWSP/Cyrillic homoglyphs) so the
        // downstream invisibleUnicode/homoglyph detectors can fire.
        const value = _imgDecodeUtf8OrLatin1(_imgSlice(data, sep + 1, data.length));
        // R12 (MCP parity): tEXt bytes already contain the cleartext.
        out.push({ location: `png:tEXt:${_imgSafeKey(key) || '__empty'}`, value, encoding: 'auto', decoded: false });
      }
    } else if (type === 'zTXt') {
      const sep = _imgIndexOf(data, 0, 0);
      // PARSE-003 fix: empty-key parity with tEXt.
      if (sep >= 0 && data.length >= sep + 2) {
        const key = _imgLatin1(data, 0, sep);
        const method = data[sep + 1];
        if (method === 0) {
          const inflated = await _imgInflateBytesCapped(_imgSlice(data, sep + 2));
          if (inflated) {
            // BYPASS-01 fix (MCP parity): see PNG tEXt comment above.
            // R12 (S12 R12-IMG-002 fix; MCP parity): zlib inflation
            // synthesizes plaintext from compressed source bytes — the
            // attack tokens do not appear in the .png on disk. Mark
            // decoded:true so the post-analyze redactor blanks
            // matched/context for any suspicious-pattern hit landing
            // inside this field's value.
            out.push({ location: `png:zTXt:${_imgSafeKey(key) || '__empty'}`, value: _imgDecodeUtf8OrLatin1(inflated.bytes), encoding: 'auto', decoded: true, truncated: inflated.truncated });
          }
        }
      }
    } else if (type === 'iTXt') {
      const sep1 = _imgIndexOf(data, 0, 0);
      // PARSE-003 fix: empty-key parity with tEXt.
      if (sep1 >= 0 && data.length >= sep1 + 4) {
        const key = _imgLatin1(data, 0, sep1);
        const compFlag = data[sep1 + 1];
        const compMethod = data[sep1 + 2];
        let q = sep1 + 3;
        const sep2 = _imgIndexOf(data, 0, q);
        if (sep2 < 0) { p = dataEnd + 4; continue; }
        q = sep2 + 1;
        const sep3 = _imgIndexOf(data, 0, q);
        if (sep3 < 0) { p = dataEnd + 4; continue; }
        let textBytes = _imgSlice(data, sep3 + 1);
        let iTxtInflated = false;
        let iTxtTruncated = false;
        if (compFlag === 1) {
          if (compMethod === 0) {
            const inflated = await _imgInflateBytesCapped(textBytes);
            if (!inflated) { p = dataEnd + 4; continue; }
            textBytes = inflated.bytes;
            iTxtInflated = true;
            iTxtTruncated = inflated.truncated === true;
          } else {
            p = dataEnd + 4; continue;
          }
        }
        if (key === 'XML:com.adobe.xmp') {
          // Spec Test 8: PNG iTXt XMP unwraps to bare `xmp:<field>` —
          // no png:xmp:... container framing in the surfaced location.
          // BYPASS-02 (MCP parity): propagate truncation onto the first
          // surfaced XMP field so the call site can emit a single
          // structural warning even when the carrier iTXt was capped.
          const xmpFields = _imgExtractXmpFields(_imgDecodePacket(textBytes), '');
          if (iTxtTruncated && xmpFields.length > 0) {
            xmpFields[0].truncated = true;
          }
          out.push(...xmpFields);
        } else {
          // R12 (MCP parity): plaintext iTXt has bytes == value, but the
          // compressed form synthesizes plaintext from compressed bytes.
          out.push({ location: `png:iTXt:${_imgSafeKey(key)}`, value: _imgDecUtf8.decode(textBytes), encoding: 'utf-8', decoded: iTxtInflated, truncated: iTxtTruncated });
        }
      }
    } else if (type === 'eXIf') {
      out.push(..._imgReadTiff(data, 'png:eXIf'));
    } else if (type === 'IEND') {
      break;
    }

    p = dataEnd + 4;
  }
  return out;
}

function _imgWalkRiff(buf) {
  const out = [];
  if (buf.length < 12) return out;
  if (_imgLatin1(buf, 0, 4) !== 'RIFF') return out;
  if (_imgLatin1(buf, 8, 12) !== 'WEBP') return out;
  // NOTE: bytes 4..7 hold the RIFF master chunk size. We deliberately ignore
  // it and walk to physical EOF, bounded only by the per-chunk size guard
  // (`payEnd > buf.length` below). This is anti-evasion, not a bug — tolerant
  // decoders (libwebp / Chromium / Pillow) walk past a too-small master size,
  // so honoring it as a hard outer bound would create an evasion vector where
  // an attacker sets RIFF size=1 and appends a malicious XMP chunk past byte 9.
  // Mirror of server/parsers/image.js _walkRiff. Pinned by the MCP regression
  // "WebP RIFF master size lie is ignored (anti-evasion)".
  let p = 12;
  while (p + 8 <= buf.length) {
    const fourCC = _imgLatin1(buf, p, p + 4);
    const size = _imgReadU32LE(buf, p + 4);
    const payStart = p + 8;
    const payEnd = payStart + size;
    if (payEnd > buf.length) break;
    const payload = _imgSlice(buf, payStart, payEnd);

    if (fourCC === 'EXIF') {
      out.push(..._imgReadTiff(payload, 'webp:exif'));
    } else if (fourCC === 'XMP ') {
      out.push(..._imgExtractXmpFields(_imgDecodePacket(payload), 'webp:'));
    }

    p = payEnd + (size & 1);
  }
  return out;
}

function _imgReadGifSubBlocks(buf, p) {
  const chunks = [];
  while (p < buf.length) {
    const n = buf[p];
    p += 1;
    if (n === 0) break;
    if (p + n > buf.length) break;
    chunks.push(_imgSlice(buf, p, p + n));
    p += n;
  }
  return { data: _imgConcat(chunks), next: p };
}

function _imgWalkGif(buf) {
  const out = [];
  if (buf.length < 13) return out;
  const sig = _imgLatin1(buf, 0, 6);
  if (sig !== 'GIF87a' && sig !== 'GIF89a') return out;
  const packed = buf[10];
  const gctFlag = (packed >> 7) & 1;
  const gctSize = gctFlag ? 3 * (1 << ((packed & 0x07) + 1)) : 0;
  let p = 13 + gctSize;

  while (p < buf.length) {
    const tag = buf[p];
    if (tag === 0x3b) break;
    if (tag === 0x21) {
      if (p + 2 > buf.length) break;
      const label = buf[p + 1];
      p += 2;
      if (label === 0xfe) {
        const { data, next } = _imgReadGifSubBlocks(buf, p);
        out.push({ location: 'gif:Comment', value: _imgDecodeUtf8OrLatin1(data), encoding: 'auto', decoded: false });
        p = next;
      } else if (label === 0xff) {
        if (p >= buf.length) break;
        const blockSize = buf[p];
        if (p + 1 + blockSize > buf.length) break;
        const appHeader = _imgLatin1(buf, p + 1, p + 1 + blockSize);
        p += 1 + blockSize;
        const { data, next } = _imgReadGifSubBlocks(buf, p);
        p = next;
        if (appHeader.startsWith('XMP DataXMP')) {
          // PARSE-004: prefix-match the canonical 11-byte AppID so a
          // non-canonical blockSize (e.g. 15) cannot bypass extraction
          // while lenient downstream parsers still surface the XMP packet.
          let xmpEnd = data.length;
          if (xmpEnd >= 258) xmpEnd -= 258;
          const xmpBytes = _imgSlice(data, 0, xmpEnd);
          out.push(..._imgExtractXmpFields(_imgDecodePacket(xmpBytes), 'gif:'));
        }
      } else if (label === 0x01) {
        if (p >= buf.length) break;
        const blockSize = buf[p];
        if (p + 1 + blockSize > buf.length) break;
        p += 1 + blockSize;
        const { data, next } = _imgReadGifSubBlocks(buf, p);
        out.push({ location: 'gif:PlainText', value: _imgDecodeUtf8OrLatin1(data), encoding: 'auto', decoded: false });
        p = next;
      } else if (label === 0xf9) {
        const { next } = _imgReadGifSubBlocks(buf, p);
        p = next;
      } else {
        const { next } = _imgReadGifSubBlocks(buf, p);
        p = next;
      }
    } else if (tag === 0x2c) {
      if (p + 10 > buf.length) break;
      const idPacked = buf[p + 9];
      const lctFlag = (idPacked >> 7) & 1;
      const lctSize = lctFlag ? 3 * (1 << ((idPacked & 0x07) + 1)) : 0;
      p += 10 + lctSize;
      if (p >= buf.length) break;
      p += 1;
      const { next } = _imgReadGifSubBlocks(buf, p);
      p = next;
    } else {
      break;
    }
  }
  return out;
}

// Public entry point. `buffer` may be ArrayBuffer | Uint8Array | Blob.
// Returns the parsePdf-shaped {text, hiddenFindings} so the existing pipeline
// merges findings without special-casing. Never throws.
async function parseImage(buffer, ext) {
  let buf;
  try {
    if (typeof Blob !== 'undefined' && buffer instanceof Blob) {
      buf = new Uint8Array(await buffer.arrayBuffer());
    } else {
      buf = _imgU8(buffer);
    }
  } catch {
    return { text: '', hiddenFindings: [{ element: 'Image', severity: 'warning', category: 'suspiciousPatterns', label: 'parseError', technique: 'image-metadata-parse-failed', contextLocation: 'IMG', structural: { error: 'parse_throw' } }], decodedRanges: [] };
  }

  // S12-XR-04 cap #1: reject oversize input upfront so the walker never
  // touches it. Mirrors MCP image.js. `bytes` is structural-only — no raw
  // image bytes leak through.
  if (buf && buf.length > IMG_MAX_BYTES) {
    return {
      text: '',
      hiddenFindings: [{
        element: 'Image',
        severity: 'warning',
        category: 'suspiciousPatterns',
        label: 'imageOversize',
        technique: 'image-metadata-oversize',
        contextLocation: 'IMG',
        structural: { bytes: buf.length, cap: IMG_MAX_BYTES },
      }],
      decodedRanges: [],
    };
  }

  let raw = [];
  try {
    const e = String(ext || '').toLowerCase().replace(/^\./, '');
    if (e === 'jpg' || e === 'jpeg') raw = _imgWalkJpeg(buf);
    else if (e === 'png') raw = await _imgWalkPng(buf);
    else if (e === 'webp') raw = _imgWalkRiff(buf);
    else if (e === 'gif') raw = _imgWalkGif(buf);
    else if (e === 'tif' || e === 'tiff') raw = _imgReadTiff(buf, 'tiff');
    else return { text: '', hiddenFindings: [], decodedRanges: [] };
  } catch {
    return { text: '', hiddenFindings: [{ element: 'Image', severity: 'warning', category: 'suspiciousPatterns', label: 'parseError', technique: 'image-metadata-parse-failed', contextLocation: 'IMG', structural: { error: 'parse_throw' } }], decodedRanges: [] };
  }

  raw = raw.filter(r => r && typeof r.value === 'string' && r.value.trim().length > 0);

  const perFieldSurvivors = raw.filter(r => looksLikeInstruction(r.value));

  // S12-XR-04 cap #3: per-image hidden-finding count. Survivor overflow
  // collapses into a single `imageMetadataFieldFlood` warning rather than
  // emitting N near-identical findings.
  const survivorsKept = perFieldSurvivors.slice(0, IMG_MAX_PER_FIELD_FINDINGS);
  const survivorsOverflowed = perFieldSurvivors.length - survivorsKept.length;
  const hiddenFindings = survivorsKept.map(s => ({
    element: 'Image Metadata',
    severity: 'warning',
    category: 'suspiciousPatterns',
    label: 'imageMetadataInjection',
    technique: 'image-metadata-injection',
    contextLocation: `IMG ${s.location}`,
    structural: { sourceField: s.location, length: s.value.length, encoding: s.encoding },
  }));
  if (survivorsOverflowed > 0) {
    hiddenFindings.push({
      element: 'Image Metadata (flood)',
      severity: 'warning',
      category: 'suspiciousPatterns',
      label: 'imageMetadataFieldFlood',
      technique: 'image-metadata-field-flood',
      contextLocation: 'IMG aggregate',
      structural: {
        total: perFieldSurvivors.length,
        kept: survivorsKept.length,
        suppressed: survivorsOverflowed,
        cap: IMG_MAX_PER_FIELD_FINDINGS,
      },
    });
  }

  // BYPASS-02 fix (MCP parity): emit one structural warning per zTXt/iTXt
  // field that streaming-inflate truncated at IMG_MAX_INFLATED_BYTES. Reuses
  // the `imageMetadataTruncated` label (joined-text overflow uses it too)
  // but tags the decompression case via structural.decompression so the
  // call site can distinguish. The field value is already in the joined
  // text and may have tripped LAYER 1 / LAYER 2 — this warning is an
  // additional breadcrumb, not a replacement for the injection finding.
  for (const r of raw) {
    if (r && r.truncated === true) {
      hiddenFindings.push({
        element: 'Image Metadata (truncated)',
        severity: 'warning',
        category: 'suspiciousPatterns',
        label: 'imageMetadataTruncated',
        technique: 'image-metadata-zlib-truncated',
        contextLocation: `IMG ${r.location}`,
        structural: {
          sourceField: r.location,
          decompression: 'truncated',
          cap: IMG_MAX_INFLATED_BYTES,
        },
      });
    }
  }

  // S12-XR-04 cap #2: joined-text length. Stop appending once we'd cross
  // IMG_MAX_JOINED_TEXT_BYTES and emit a structural `imageMetadataTruncated`
  // warning. Bounds the work the central detector does on this single image.
  //
  // R12 (S12 R12-IMG-002 fix): while building the joined blob we record the
  // character ranges of each VALUE that was synthesized by a decoder (XML
  // entities, UTF-16, zlib, IPTC UTF-8 mode-switch). `decodedRanges` is
  // consumed by the post-analyze redactor at the file-input handler so
  // suspicious-pattern hits inside decoder-synthesized text never echo
  // their `matched` / `context` strings back into the response body —
  // matching MCP behaviour and the shadow-buffer R12 hardening that already
  // covers NFKC / invisibleStripped shadow paths.
  const parts = [];
  const decodedRanges = [];
  let cursor = 0;
  let joinedTruncated = false;
  let fieldsKept = 0;
  for (let i = 0; i < raw.length; i++) {
    const r = raw[i];
    const prefix = `[IMG ${r.location}] `;
    const segment = prefix + r.value;
    const sepLen = parts.length > 0 ? IMG_SEPARATOR.length : 0;
    if (cursor + sepLen + segment.length > IMG_MAX_JOINED_TEXT_BYTES) {
      joinedTruncated = true;
      break;
    }
    cursor += sepLen;
    parts.push(segment);
    if (r.decoded === true) {
      const valStart = cursor + prefix.length;
      const valEnd = valStart + r.value.length;
      decodedRanges.push({
        start: valStart,
        end: valEnd,
        location: r.location,
        encoding: r.encoding,
      });
    }
    fieldsKept++;
    cursor += segment.length;
  }
  const joinedText = parts.join(IMG_SEPARATOR);
  // Gate on fieldsKept >= 1 so a single oversized field (handled by the
  // per-field inflate cap) does not double-fire here. Matches MCP gating.
  if (joinedTruncated && fieldsKept >= 1) {
    hiddenFindings.push({
      element: 'Image Metadata (truncated)',
      severity: 'warning',
      category: 'suspiciousPatterns',
      label: 'imageMetadataTruncated',
      technique: 'image-metadata-truncated',
      contextLocation: 'IMG aggregate',
      structural: {
        totalFields: raw.length,
        keptFields: fieldsKept,
        joinedTextLength: joinedText.length,
        cap: IMG_MAX_JOINED_TEXT_BYTES,
      },
    });
  }

  if (raw.length >= 2 && looksLikeInstruction(joinedText) && perFieldSurvivors.length < raw.length) {
    hiddenFindings.push({
      element: 'Image Metadata (aggregate)',
      severity: 'danger',
      category: 'suspiciousPatterns',
      label: 'imageMetadataSplitPayload',
      technique: 'image-metadata-split-payload',
      contextLocation: 'IMG aggregate',
      structural: { fieldCount: raw.length, segments: raw.map(r => r.location) },
    });
  }

  return { text: joinedText, hiddenFindings, decodedRanges };
}

// R12 (S12 R12-IMG-002 fix; Web mirror of MCP server/core/decoded-redaction.js).
// Mutate the central analyze() result's suspiciousPatterns bucket so any
// finding whose `position` lands inside a parser-flagged decoded range has
// its `matched` / `context` strings scrubbed to a structural placeholder —
// otherwise the decoder-synthesized cleartext (XML entities, UTF-16, zlib,
// IPTC UTF-8 mode) would echo back into the rendered report and turn Shield
// Scanner into a decoding oracle. Pattern name and severity are preserved
// so the alert still surfaces; only the verbatim quote is removed.
function _imgRedactDecodedFindings(scanResult, decodedRanges) {
  if (!scanResult || typeof scanResult !== 'object') return scanResult;
  if (!Array.isArray(decodedRanges) || decodedRanges.length === 0) return scanResult;
  const arr = scanResult.suspiciousPatterns;
  if (!Array.isArray(arr) || arr.length === 0) return scanResult;
  for (let i = 0; i < arr.length; i++) {
    const f = arr[i];
    if (!f || typeof f.position !== 'number') continue;
    const matchLen =
      (typeof f.matchLen === 'number' && f.matchLen) ||
      (typeof f.matched === 'string' && f.matched.length) ||
      1;
    const hitStart = f.position;
    const hitEnd = f.position + matchLen;
    const hostRange = decodedRanges.find(r =>
      r && typeof r.start === 'number' && typeof r.end === 'number' &&
      hitStart >= r.start && hitEnd <= r.end
    );
    if (!hostRange) continue;
    const placeholder = `[REDACTED — decoded from ${hostRange.location} (${hostRange.encoding || 'decoded'})]`;
    arr[i] = Object.assign({}, f, {
      matched: placeholder,
      context: placeholder,
      decodedSource: hostRange.location,
      decodedEncoding: hostRange.encoding || null,
      r12Redacted: true,
    });
  }
  return scanResult;
}

// --- PPTX helpers (QW4) ---------------------------------------------------
// Decode the five XML predefined entities for <a:t> body / cNvPr attrs.

export { parseImage, _imgRedactDecodedFindings, _imgDecodeUtf8OrLatin1 };
