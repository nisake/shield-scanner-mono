// =============================================================
//  Shield Scanner Web — v1.20.0 T8-XLSX-OLE
//  XLSX Embedded OLE scope helper (web mirror of MCP)
// =============================================================
//
// Byte-identical mirror of packages/mcp/server/parsers/xlsx-ole-scope.js.
// See the MCP file for the full design / kebab contract / R12-R18 notes.
//
// This module is exported so future v1.20.x web parser-wiring can call into
// the same helper without duplicating the CFB byte-window scan. For v1.20.0
// the helper is shipped standalone (no xlsx.js wire-in) to keep dist neutral.
// =============================================================

import { escapeForDisplay } from '@shield-scanner/core';

const CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

export const XLSX_OLE_OVERSIZE_THRESHOLD = 5 * 1024 * 1024;

const ENCRYPTED_STREAM_NAME = 'EncryptedPackage';
const VBA_PROJECT_STREAM_NAME = '_VBA_PROJECT';
const VBA_PROJECTWM_NAME = 'PROJECTwm';
const VBA_DIR_NAME_LOWER = 'vba';

function hasCfbMagic(buf) {
  if (!buf || buf.length < 8) return false;
  for (let i = 0; i < 8; i++) {
    if (buf[i] !== CFB_MAGIC[i]) return false;
  }
  return true;
}

function utf16leBytes(s) {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    out[i * 2] = s.charCodeAt(i) & 0xff;
    out[i * 2 + 1] = (s.charCodeAt(i) >> 8) & 0xff;
  }
  return out;
}

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

export function scanXlsxOleScope(buffer, opts = {}) {
  const findings = [];
  if (!buffer || typeof buffer.length !== 'number') return findings;

  const buf =
    buffer instanceof Uint8Array
      ? buffer
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  const memberName =
    opts && typeof opts.memberName === 'string' && opts.memberName.length > 0
      ? opts.memberName
      : 'xl/embeddings/oleObject.bin';
  const safeName = escapeForDisplay(memberName.slice(0, 200));

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
    return findings;
  }

  if (!hasCfbMagic(buf)) return findings;

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

  const vbaNeedle = utf16leBytes(VBA_PROJECT_STREAM_NAME);
  const projectWmNeedle = utf16leBytes(VBA_PROJECTWM_NAME);
  const hasVbaProject = indexOfBytes(buf, vbaNeedle) !== -1;
  const hasProjectWm = indexOfBytes(buf, projectWmNeedle) !== -1;

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

export const XLSX_OLE_SCOPE_KEBABS = Object.freeze([
  'xlsx-ole-oversize',
  'xlsx-ole-encrypted',
  'xlsx-ole-macro-bearing',
]);
