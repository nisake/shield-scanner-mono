// Archive (ZIP) parser (S13) — Web mirror of packages/mcp/server/parsers/archive.js.
//
// Depends on global: JSZip (CDN-loaded in index.template.html L25)
// Depends on core:
//   - escapeForDisplay / looksLikeInstruction (utils)
//   - detectZipSlip / classifySuspiciousExt / isOfficePackageRename /
//     detectMagicBytesIsZip / computeBombRatio / ARCHIVE_CAPS (S13 helpers)
//
// R12 (no shadow-leak): raw entry names / decoded content always pass through
//   escapeForDisplay before reaching a UI-bound field. Bracket-prefix scaffolding
//   like `ZIP entry:<name> > <existing>` is detector-controlled.
// R13: AR-03 (zip slip) / AR-05 (suspicious ext) / AR-06 (Office rename) fold
//   into suspiciousPatterns. Bomb / depth / encrypted / entryCap live on the
//   sibling `summary.archive` shape returned to app.js as `archive`.
// R18 (env-abstract order contract): core helpers used here are env-free
//   (archive-detection.js is a pure module). NO loadRule at module-load time.
//
// Defensive caps (Web — lowered vs MCP to defend tab OOM):
//   WEB_ARCHIVE_TOTAL_DECOMPRESSED = 50 MB   (MCP uses 100 MB)
//   WEB_ARCHIVE_PER_ENTRY          = 25 MB   (same as MCP / ClamAV)
//   WEB_ARCHIVE_ENTRY_COUNT        = 10000   (same as MCP / ClamAV)
//   WEB_ARCHIVE_RECURSION_DEPTH    = 3       (same as MCP)
//   WEB_ARCHIVE_RATIO_WARN         = 100     (OWASP)
//   WEB_ARCHIVE_RATIO_BLOCK        = 1000    (OWASP)
//   WEB_ARCHIVE_BUFFER_SHORTCIRCUIT = 50 MB  (early-out on the outer buffer)

import {
  escapeForDisplay,
  detectZipSlip,
  classifySuspiciousExt,
  isOfficePackageRename,
  detectMagicBytesIsZip,
  computeBombRatio,
} from '@shield-scanner/core';
import { parseImage } from './image.js';
import { parseDocx } from './docx.js';
import { parsePptx } from './pptx.js';
import { parseXlsx } from './xlsx.js';
import { parseCsv } from './csv.js';
import { parsePdf } from './pdf.js';

// --- Web caps (lowered for browser tab) ---------------------------------------
const WEB_ARCHIVE_TOTAL_DECOMPRESSED = 50 * 1024 * 1024;
const WEB_ARCHIVE_PER_ENTRY = 25 * 1024 * 1024;
const WEB_ARCHIVE_ENTRY_COUNT = 10000;
const WEB_ARCHIVE_RECURSION_DEPTH = 3;
const WEB_ARCHIVE_RATIO_WARN = 100;
const WEB_ARCHIVE_RATIO_BLOCK = 1000;
const WEB_ARCHIVE_BUFFER_SHORTCIRCUIT = 50 * 1024 * 1024;

// Image / nested-recursion extensions (mirror of dispatchBuffer routing).
const _ARCHIVE_IMAGE_EXTS = new Set(['jpg', 'jpeg', 'png', 'webp', 'gif', 'tiff', 'tif']);
const _ARCHIVE_TEXT_EXTS = new Set([
  'txt', 'md', 'mdc', 'cursorrules', 'json',
  'html', 'htm', 'xml', 'svg',
]);
const _ARCHIVE_OFFICE_EXTS = new Set(['docx', 'pptx', 'xlsx', 'csv', 'pdf']);

function _extOf(name) {
  const base = name.split(/[\\/]/).pop() || '';
  const dot = base.lastIndexOf('.');
  if (dot < 0 || dot === base.length - 1) return '';
  return base.slice(dot + 1).toLowerCase();
}

function _emptyArchiveSummary() {
  return {
    scanned: 0,
    bomb: 0,
    depth: 0,
    protected: 0,
    entryCap: 0,
    maxRatio: 0,
    maxDepth: 0,
    totalEntries: 0,
    totalUncompressedBytes: 0,
    skippedEntries: 0,
  };
}

function _mergeArchive(into, from) {
  if (!from) return;
  into.scanned += from.scanned || 0;
  into.bomb += from.bomb || 0;
  into.depth += from.depth || 0;
  into.protected += from.protected || 0;
  into.entryCap += from.entryCap || 0;
  into.totalEntries += from.totalEntries || 0;
  into.totalUncompressedBytes += from.totalUncompressedBytes || 0;
  into.skippedEntries += from.skippedEntries || 0;
  if ((from.maxRatio || 0) > into.maxRatio) into.maxRatio = from.maxRatio || 0;
  if ((from.maxDepth || 0) > into.maxDepth) into.maxDepth = from.maxDepth || 0;
}

function _normalizeBuffer(buffer) {
  if (buffer instanceof Uint8Array) return buffer;
  if (buffer && typeof buffer.byteLength === 'number') {
    return new Uint8Array(buffer);
  }
  return new Uint8Array(0);
}

// Encrypted-entry detection: JSZip 3.x stores per-file flag bit 0x0001.
// Some entries expose `options.encrypted` directly; otherwise scan the parsed
// general-purpose bit flag if available.
function _isEntryEncrypted(file) {
  if (!file) return false;
  if (file.options && file.options.encrypted === true) return true;
  if (file._data && typeof file._data.compressedContent === 'object') {
    // Nothing reliable here — fall through.
  }
  // JSZip stores it on the internal file header via `bitFlag` in some versions.
  if (typeof file.bitFlag === 'number' && (file.bitFlag & 0x0001) === 0x0001) {
    return true;
  }
  return false;
}

// Internal recursive ext dispatcher. Reads entry payload through the right
// parsers-web/* module and returns a normalized {text, hiddenFindings} shape so
// the caller can fold findings into the existing 5 buckets.
async function _dispatchEntryBuffer(buf, ext, depth) {
  const u8 = _normalizeBuffer(buf);
  try {
    if (ext === 'zip') {
      // Nested ZIP — recurse. Returns {text, hiddenFindings, archive, fileType}.
      return await parseArchiveBuffer(u8, { depth: depth + 1 });
    }
    if (ext === 'docx') return await parseDocx(u8);
    if (ext === 'pptx') return await parsePptx(u8);
    if (ext === 'xlsx') return await parseXlsx(u8);
    if (ext === 'csv') return await parseCsv(u8);
    if (ext === 'pdf') return await parsePdf(u8);
    if (_ARCHIVE_IMAGE_EXTS.has(ext)) return await parseImage(u8, ext);
    if (_ARCHIVE_TEXT_EXTS.has(ext)) {
      // Lenient UTF-8 decode — same envelope used by csv.js fallback.
      const text = new TextDecoder('utf-8', { fatal: false }).decode(u8);
      return { text, hiddenFindings: [] };
    }
  } catch (_e) {
    return null;
  }
  return null;
}

/**
 * Parse a ZIP buffer (S13). Returns the same shape other parsers-web/* return,
 * plus a sibling `archive` summary object the caller surfaces on
 * `summary.archive` via analyze()/mergeFindings.
 *
 * @param {Buffer|Uint8Array|ArrayBuffer} buffer
 * @param {object} options
 * @param {number} options.depth - current recursion depth (0 at entry)
 */
async function parseArchiveBuffer(buffer, options) {
  const depth = options && typeof options.depth === 'number' ? options.depth : 0;
  const u8 = _normalizeBuffer(buffer);
  const texts = [];
  const hiddenFindings = [];
  const archive = _emptyArchiveSummary();
  archive.scanned = 1;
  archive.maxDepth = depth;

  // 0. Outer-buffer short-circuit (tab OOM guard).
  if (u8.byteLength > WEB_ARCHIVE_BUFFER_SHORTCIRCUIT) {
    hiddenFindings.push({
      element: 'ZIP archive',
      technique: `ZIP exceeds scan limits — buffer > ${WEB_ARCHIVE_BUFFER_SHORTCIRCUIT} bytes (skipped)`,
      content: '(oversize archive)',
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'ZIP',
    });
    return { text: '', hiddenFindings, archive, fileType: 'zip' };
  }

  // 1. Magic-bytes early reject — AR-06 extension-spoof detector.
  if (!detectMagicBytesIsZip(u8)) {
    hiddenFindings.push({
      element: 'ZIP archive',
      technique: 'Archive missing ZIP magic bytes (extension spoof?)',
      content: '(not a ZIP)',
      severity: 'warning',
      category: 'suspiciousPatterns',
      contextLocation: 'ZIP',
    });
    return { text: '', hiddenFindings, archive, fileType: 'zip' };
  }

  // 2. AR-02 depth cap — recursion limit reached.
  if (depth >= WEB_ARCHIVE_RECURSION_DEPTH) {
    archive.depth += 1;
    hiddenFindings.push({
      element: 'ZIP archive',
      technique: `Archive nest depth > ${WEB_ARCHIVE_RECURSION_DEPTH} — contents not scanned`,
      content: `(depth=${depth})`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: `ZIP depth=${depth}`,
    });
    return { text: '', hiddenFindings, archive, fileType: 'zip' };
  }

  // 3. Load the archive. JSZip 3.x throws on encrypted ZIPs at loadAsync.
  let zip;
  try {
    zip = await JSZip.loadAsync(u8);
  } catch (err) {
    const msg = String(err && err.message ? err.message : err);
    const isEncrypted = /encrypted/i.test(msg);
    if (isEncrypted) {
      archive.protected += 1;
      hiddenFindings.push({
        element: 'ZIP archive',
        technique: 'Encrypted ZIP (cannot inspect contents)',
        content: escapeForDisplay(msg.slice(0, 200)),
        severity: 'warning',
        category: 'hiddenHtml',
        contextLocation: 'ZIP',
      });
    } else {
      hiddenFindings.push({
        element: 'ZIP archive',
        technique: 'Unsupported or corrupt ZIP (load failed)',
        content: escapeForDisplay(msg.slice(0, 200)),
        severity: 'warning',
        category: 'hiddenHtml',
        contextLocation: 'ZIP',
      });
    }
    return { text: '', hiddenFindings, archive, fileType: 'zip' };
  }

  // 4. Central-directory enumeration.
  const fileNames = Object.keys(zip.files);
  archive.totalEntries = fileNames.length;

  // 4a. AR-07 entry-count cap.
  if (fileNames.length > WEB_ARCHIVE_ENTRY_COUNT) {
    archive.entryCap += 1;
    hiddenFindings.push({
      element: 'ZIP archive',
      technique: `Archive entry count > ${WEB_ARCHIVE_ENTRY_COUNT} (partial scan)`,
      content: `(entries=${fileNames.length})`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'ZIP',
    });
  }

  // 4b. AR-06 Office package rename (Office Open XML in `.zip` wrapper).
  if (isOfficePackageRename(fileNames)) {
    hiddenFindings.push({
      element: 'ZIP archive',
      technique: 'Possible Office package renamed to .zip ([Content_Types].xml present)',
      content: '([Content_Types].xml found inside .zip)',
      severity: 'warning',
      category: 'suspiciousPatterns',
      contextLocation: 'ZIP',
    });
  }

  // 5. Entry walk.
  let totalUncompressed = 0;
  let totalCompressed = 0;
  let entriesProcessed = 0;
  let bombRaised = false;
  let totalCapHit = false;

  for (const name of fileNames) {
    if (entriesProcessed >= WEB_ARCHIVE_ENTRY_COUNT) break;
    entriesProcessed++;

    const file = zip.files[name];
    if (!file) continue;

    // Per-entry encryption check (separate from archive-level encryption).
    if (_isEntryEncrypted(file)) {
      archive.protected += 1;
      hiddenFindings.push({
        element: `ZIP entry '${escapeForDisplay(name.slice(0, 200))}'`,
        technique: 'Encrypted ZIP entry (cannot inspect)',
        content: '(encrypted entry)',
        severity: 'warning',
        category: 'hiddenHtml',
        contextLocation: `ZIP entry:${name.slice(0, 200)}`,
      });
      continue;
    }

    // AR-03 zip-slip — fold into suspiciousPatterns.
    const slip = detectZipSlip(name);
    if (slip) {
      hiddenFindings.push({
        element: 'ZIP entry',
        technique: `Zip slip (${slip}) — entry name attempts path escape`,
        content: escapeForDisplay(name.slice(0, 200)),
        severity: 'danger',
        category: 'suspiciousPatterns',
        contextLocation: `ZIP entry:${name.slice(0, 200)}`,
      });
    }

    // AR-05 suspicious extension — fold into suspiciousPatterns.
    const dangerousLabel = classifySuspiciousExt(name);
    if (dangerousLabel) {
      hiddenFindings.push({
        element: 'ZIP entry',
        technique: `Suspicious archive entry: ${dangerousLabel}`,
        content: escapeForDisplay(name.slice(0, 200)),
        severity: 'warning',
        category: 'suspiciousPatterns',
        contextLocation: `ZIP entry:${name.slice(0, 200)}`,
      });
    }

    if (file.dir) continue;

    // Per-entry / total uncompressed accounting. JSZip exposes the central-
    // directory header sizes via `_data.uncompressedSize` (best effort).
    const declaredUncompressed =
      file._data && typeof file._data.uncompressedSize === 'number'
        ? file._data.uncompressedSize
        : 0;
    const declaredCompressed =
      file._data && typeof file._data.compressedSize === 'number'
        ? file._data.compressedSize
        : 0;

    if (declaredUncompressed > WEB_ARCHIVE_PER_ENTRY) {
      archive.skippedEntries += 1;
      hiddenFindings.push({
        element: 'ZIP entry',
        technique: `Entry exceeds per-entry cap (${WEB_ARCHIVE_PER_ENTRY} bytes) — skipped`,
        content: escapeForDisplay(name.slice(0, 200)),
        severity: 'warning',
        category: 'hiddenHtml',
        contextLocation: `ZIP entry:${name.slice(0, 200)}`,
      });
      // Still count toward the bomb ratio so an attacker can't bypass by
      // splitting one giant entry across the cap line.
      totalUncompressed += declaredUncompressed;
      totalCompressed += declaredCompressed;
      continue;
    }

    if (totalUncompressed + declaredUncompressed > WEB_ARCHIVE_TOTAL_DECOMPRESSED) {
      if (!totalCapHit) {
        archive.bomb += 1;
        bombRaised = true;
        totalCapHit = true;
        hiddenFindings.push({
          element: 'ZIP archive',
          technique: `Total uncompressed size > ${WEB_ARCHIVE_TOTAL_DECOMPRESSED} bytes (zip-bomb suspect)`,
          content: `(declared total > ${WEB_ARCHIVE_TOTAL_DECOMPRESSED} bytes)`,
          severity: 'danger',
          category: 'hiddenHtml',
          contextLocation: 'ZIP',
        });
      }
      break;
    }

    totalUncompressed += declaredUncompressed;
    totalCompressed += declaredCompressed;

    // Extract entry payload + dispatch.
    const ext = _extOf(name);

    // Only attempt to read payload for known extensions to avoid wasting
    // decompression effort on arbitrary blobs.
    const isRecursive =
      ext === 'zip' ||
      _ARCHIVE_OFFICE_EXTS.has(ext) ||
      _ARCHIVE_IMAGE_EXTS.has(ext) ||
      _ARCHIVE_TEXT_EXTS.has(ext);

    if (!isRecursive) continue;

    let entryBuf;
    try {
      entryBuf = await file.async('uint8array');
    } catch {
      continue;
    }

    // Re-check actual size against per-entry cap (in case the declared header
    // was a lie — bomb detection).
    if (entryBuf.byteLength > WEB_ARCHIVE_PER_ENTRY) {
      archive.skippedEntries += 1;
      continue;
    }

    const sub = await _dispatchEntryBuffer(entryBuf, ext, depth);
    if (!sub) continue;

    // Hoist nested archive summary if present.
    if (sub.archive) _mergeArchive(archive, sub.archive);

    // Append text with a ZIP-entry header so downstream pattern scans can
    // attribute findings.
    if (sub.text && sub.text.trim()) {
      texts.push(`[ZIP entry:${name}]`);
      texts.push(sub.text);
    }

    // Hoist hiddenFindings with location prefix (mirrors docx/pptx media
    // recursion pattern).
    if (Array.isArray(sub.hiddenFindings)) {
      for (const f of sub.hiddenFindings) {
        const existing = typeof f.contextLocation === 'string' ? f.contextLocation : '';
        hiddenFindings.push({
          ...f,
          contextLocation: existing
            ? `ZIP entry:${name} > ${existing}`
            : `ZIP entry:${name}`,
        });
      }
    }
  }

  // 6. AR-01 zip-bomb ratio check (post-walk).
  const ratio = computeBombRatio(totalUncompressed, totalCompressed);
  if (Number.isFinite(ratio)) {
    if (ratio > archive.maxRatio) archive.maxRatio = ratio;
  } else if (totalUncompressed > 0) {
    archive.maxRatio = Infinity;
  }
  archive.totalUncompressedBytes += totalUncompressed;

  if (!bombRaised && ratio > WEB_ARCHIVE_RATIO_BLOCK) {
    archive.bomb += 1;
    hiddenFindings.push({
      element: 'ZIP archive',
      technique: `Zip-bomb suspect: compression ratio ${ratio.toFixed(0)}:1 > ${WEB_ARCHIVE_RATIO_BLOCK}:1`,
      content: `(uncompressed=${totalUncompressed}, compressed=${totalCompressed})`,
      severity: 'danger',
      category: 'hiddenHtml',
      contextLocation: 'ZIP',
    });
  } else if (!bombRaised && ratio > WEB_ARCHIVE_RATIO_WARN) {
    hiddenFindings.push({
      element: 'ZIP archive',
      technique: `High compression ratio ${ratio.toFixed(0)}:1 (> ${WEB_ARCHIVE_RATIO_WARN}:1)`,
      content: `(uncompressed=${totalUncompressed}, compressed=${totalCompressed})`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'ZIP',
    });
  }

  return {
    text: texts.join('\n'),
    hiddenFindings,
    archive,
    fileType: 'zip',
  };
}

export { parseArchiveBuffer };
