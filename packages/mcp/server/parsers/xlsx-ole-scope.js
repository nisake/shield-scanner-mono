// =============================================================
//  Shield Scanner — v1.20.0 T8-XLSX-OLE
//  XLSX Embedded OLE scope-specific helpers (standalone)
// =============================================================
//
// Standalone helper module for inspecting an XLSX embedded OLE object
// (xl/embeddings/*.bin) and emitting three scope-specific kebab IDs:
//
//   - xlsx-ole-oversize        : embedded blob > OFFICE_MEDIA_MAX_BYTES (5 MB)
//                                Severity = warning. Today the main xlsx.js
//                                parser already short-circuits with
//                                'oversize-embedded-object'; this helper offers
//                                the same data through a kebab id stable across
//                                v1.20+ refactors so downstream policy can pin
//                                on the OLE-specific scope.
//   - xlsx-ole-encrypted       : CFB body that contains the well-known
//                                'EncryptedPackage' stream (DRMS / agile
//                                encryption). Severity = warning. Encrypted
//                                packages cannot be inspected further, so we
//                                surface the structural presence and let
//                                downstream tooling decide whether to block.
//   - xlsx-ole-macro-bearing   : CFB body that carries '_VBA_PROJECT' or the
//                                companion 'dir' / 'PROJECTwm' / 'VBA' stream
//                                names. Severity = danger. Distinct from the
//                                xl/vbaProject.bin top-level macro signal —
//                                this fires when a workbook embeds another OLE
//                                container that itself carries macros (e.g.
//                                an embedded .doc / .xls inside a .xlsx).
//
// This helper is intentionally NOT wired into xlsx.js for v1.20.0 — it ships
// as a stable export + standalone test set, allowing v1.20.x parser wiring to
// land separately without re-touching the new kebab contract. Pattern mirrors
// pdf-embedded-html (T6) and other "kebab-first / parser-followup" rollouts.
//
// R12: filename / scope strings escape via escapeForDisplay before any
// content field. Raw decoded OLE stream bytes never leak.
// R13: findings carry `category: 'hiddenHtml'` (oversize / encrypted are
// structural) or `category: 'suspiciousPatterns'` (macro-bearing is an
// execution signal) — both routable to the canonical 5-key set without
// inventing a new bucket.
// R14: no third-party CFB parser. Stream-name detection is byte-window
// scan + magic check only.
// R18: env-abstract — only @shield-scanner/core escapeForDisplay imported,
// no loadRule at module load.
// =============================================================

import { escapeForDisplay } from '@shield-scanner/core';

// Office Compound File Binary (CFB) magic — D0 CF 11 E0 A1 B1 1A E1.
const CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

// Shared oversize threshold (mirrors xlsx.js OFFICE_MEDIA_MAX_BYTES).
export const XLSX_OLE_OVERSIZE_THRESHOLD = 5 * 1024 * 1024;

// Stream-name byte windows (UTF-16LE encoded ASCII — CFB directory entries
// store names as null-terminated UTF-16LE). We scan the raw buffer for the
// UTF-16LE encoding of each string. Lowercase comparison is NOT used because
// CFB stream names are case-sensitive in practice.
const ENCRYPTED_STREAM_NAME = 'EncryptedPackage';
const VBA_PROJECT_STREAM_NAME = '_VBA_PROJECT';
const VBA_PROJECTWM_NAME = 'PROJECTwm';
const VBA_DIR_NAME_LOWER = 'vba';

// Synchronously check the CFB magic. Returns true iff buf has the 8-byte
// signature at offset 0.
function hasCfbMagic(buf) {
  if (!buf || buf.length < 8) return false;
  for (let i = 0; i < 8; i++) {
    if (buf[i] !== CFB_MAGIC[i]) return false;
  }
  return true;
}

// Encode an ASCII string to UTF-16LE bytes (each character becomes [low, 0]).
// CFB directory entries store stream names as UTF-16LE so we need to match the
// little-endian byte pattern, not the raw ASCII.
function utf16leBytes(s) {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    out[i * 2] = s.charCodeAt(i) & 0xff;
    out[i * 2 + 1] = (s.charCodeAt(i) >> 8) & 0xff;
  }
  return out;
}

// Boyer-Moore-lite — small needle, large haystack. We don't need anything
// fancy because the needles are 24-32 bytes and buffers are <= 5 MB.
function indexOfBytes(haystack, needle) {
  if (!haystack || !needle || needle.length === 0) return -1;
  if (haystack.length < needle.length) return -1;
  const end = haystack.length - needle.length;
  outer: for (let i = 0; i <= end; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * Inspect an XLSX embedded OLE blob and return scope-specific findings.
 *
 * @param {Uint8Array|Buffer} buffer  Raw bytes of xl/embeddings/*.bin
 * @param {Object} [opts]
 * @param {string} [opts.memberName]  Zip member path (for contextLocation /
 *                                    finding content). Defaults to
 *                                    'xl/embeddings/oleObject.bin'.
 * @returns {Array<Object>} Array of finding objects with shape
 *   { element, technique, content, severity, category, contextLocation, meta }
 */
export function scanXlsxOleScope(buffer, opts = {}) {
  const findings = [];
  if (!buffer || typeof buffer.length !== 'number') return findings;

  // Normalize to a Uint8Array view for byte-level scans without copy.
  const buf =
    buffer instanceof Uint8Array
      ? buffer
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  const memberName =
    opts && typeof opts.memberName === 'string' && opts.memberName.length > 0
      ? opts.memberName
      : 'xl/embeddings/oleObject.bin';
  const safeName = escapeForDisplay(memberName.slice(0, 200));

  // ---- xlsx-ole-oversize ----------------------------------------------
  if (buf.length > XLSX_OLE_OVERSIZE_THRESHOLD) {
    findings.push({
      element: 'XLSX Embedded OLE',
      technique: 'xlsx-ole-oversize',
      content: safeName,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: safeName,
      meta: {
        scope: 'embeddedOle',
        sizeBytes: buf.length,
        maxBytes: XLSX_OLE_OVERSIZE_THRESHOLD,
      },
    });
    // Oversize blobs are not further inspected — return early to keep the
    // scan cheap (mirrors xlsx.js scanEmbeddings short-circuit pattern).
    return findings;
  }

  // CFB magic gate — the encrypted / macro-bearing signals require a
  // structurally valid CFB container. Non-CFB blobs (Package / OLE10Native
  // wrappers etc.) are out of scope here.
  if (!hasCfbMagic(buf)) return findings;

  // ---- xlsx-ole-encrypted ---------------------------------------------
  // CFB-protected packages embed an 'EncryptedPackage' stream in the
  // directory entries (UTF-16LE). Presence = workbook is wrapped in agile /
  // standard MS-OFFCRYPTO encryption; inspection is not possible.
  const encNeedle = utf16leBytes(ENCRYPTED_STREAM_NAME);
  if (indexOfBytes(buf, encNeedle) !== -1) {
    findings.push({
      element: 'XLSX Embedded OLE',
      technique: 'xlsx-ole-encrypted',
      content: safeName,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: safeName,
      meta: {
        scope: 'embeddedOle',
        streamName: ENCRYPTED_STREAM_NAME,
      },
    });
  }

  // ---- xlsx-ole-macro-bearing -----------------------------------------
  // _VBA_PROJECT / PROJECTwm / VBA dir stream names indicate the embedded
  // OLE object carries a VBA project of its own. This is distinct from the
  // top-level xl/vbaProject.bin signal (which is workbook-level).
  const vbaNeedle = utf16leBytes(VBA_PROJECT_STREAM_NAME);
  const projectWmNeedle = utf16leBytes(VBA_PROJECTWM_NAME);
  const hasVbaProject = indexOfBytes(buf, vbaNeedle) !== -1;
  const hasProjectWm = indexOfBytes(buf, projectWmNeedle) !== -1;

  // Lower-cased 'vba' directory stream name (UTF-16LE) — covers the standard
  // 'VBA' / 'vba' dir entry that CFB containers use for the macro folder.
  // Match is case-sensitive against the UTF-16LE bytes (we test both casings).
  const vbaDirUpper = utf16leBytes('VBA');
  const vbaDirLower = utf16leBytes(VBA_DIR_NAME_LOWER);
  const hasVbaDir =
    indexOfBytes(buf, vbaDirUpper) !== -1 || indexOfBytes(buf, vbaDirLower) !== -1;

  if (hasVbaProject || hasProjectWm || (hasVbaDir && hasVbaProject)) {
    const matched = hasVbaProject
      ? VBA_PROJECT_STREAM_NAME
      : hasProjectWm
        ? VBA_PROJECTWM_NAME
        : 'VBA';
    findings.push({
      element: 'XLSX Embedded OLE',
      technique: 'xlsx-ole-macro-bearing',
      content: safeName,
      severity: 'danger',
      category: 'suspiciousPatterns',
      contextLocation: safeName,
      meta: {
        scope: 'embeddedOle',
        streamName: matched,
        hasVbaProject,
        hasProjectWm,
      },
    });
  }

  return findings;
}

// Re-export the threshold so callers can pin against the same constant.
export const XLSX_OLE_SCOPE_KEBABS = Object.freeze([
  'xlsx-ole-oversize',
  'xlsx-ole-encrypted',
  'xlsx-ole-macro-bearing',
]);
