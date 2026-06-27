// v1.20.0 T9-ARCHIVE-EXT — multi-format archive recognizer (Web mirror).
//
// Mirror of packages/mcp/server/parsers/archive-multi.js. Recognition-only
// pathway for .7z / .tar.gz / .rar by magic bytes. No JSZip / no deep walk —
// pulling in node-7z / unrar in the browser bundle would blow past the dist
// budget. We emit a single "recognized but skipped" warning per archive so
// downstream tooling sees the format identification without us decompressing
// anything.
//
// R12: `content` field is a static string — no input bytes ever leak through.
// R13: every finding folds into `hiddenHtml` (no new top-level byCategory key).
// R18: zero env coupling — pure detector.
//
// Kebab IDs (parity with MCP):
//   archive-7z-recognized
//   archive-targz-recognized
//   archive-rar-recognized

// --- Magic-bytes signatures --------------------------------------------------
const SIG_7Z = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const SIG_GZIP = [0x1f, 0x8b];
// RARv4 = 52 61 72 21 1A 07 00, RARv5 = 52 61 72 21 1A 07 01 00. The shared
// 6-byte `Rar!\x1A\x07` prefix is what we match (so both versions classify
// as 'rar').
const SIG_RAR_PREFIX = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07];

function _hasSig(u8, sig) {
  if (!u8 || u8.length < sig.length) return false;
  for (let i = 0; i < sig.length; i += 1) {
    if (u8[i] !== sig[i]) return false;
  }
  return true;
}

/**
 * @param {Uint8Array|ArrayBuffer} buffer
 * @returns {'7z'|'targz'|'rar'|null}
 */
export function recognizeArchiveType(buffer) {
  if (!buffer) return null;
  const u8 =
    buffer instanceof Uint8Array
      ? buffer
      : (buffer && typeof buffer.byteLength === 'number')
        ? new Uint8Array(buffer)
        : new Uint8Array(0);
  if (_hasSig(u8, SIG_7Z)) return '7z';
  if (_hasSig(u8, SIG_RAR_PREFIX)) return 'rar';
  if (_hasSig(u8, SIG_GZIP)) return 'targz';
  return null;
}

const KEBAB_BY_KIND = Object.freeze({
  '7z': 'archive-7z-recognized',
  targz: 'archive-targz-recognized',
  rar: 'archive-rar-recognized',
});

const LABEL_BY_KIND = Object.freeze({
  '7z': '7-Zip archive',
  targz: 'gzip / tar.gz archive',
  rar: 'RAR archive',
});

/**
 * @param {Uint8Array|ArrayBuffer} buffer
 * @returns {Promise<null|{text:string,fileType:string,extraFindings:Array,archiveSummary:object}>}
 */
export async function parseArchiveMultiBuffer(buffer) {
  const kind = recognizeArchiveType(buffer);
  if (!kind) return null;

  const finding = {
    element: LABEL_BY_KIND[kind],
    technique: KEBAB_BY_KIND[kind],
    content: '(recognized; deep walk deferred — v1.20.x)',
    severity: 'warning',
    category: 'hiddenHtml',
    contextLocation: LABEL_BY_KIND[kind],
    meta: { archiveKind: kind },
  };

  return {
    text: '',
    fileType: 'archive-multi',
    extraFindings: [finding],
    archiveSummary: {
      scanned: 1,
      bomb: 0,
      depth: 0,
      protected: 0,
      entryCap: 0,
      maxRatio: 0,
      maxDepth: 0,
      totalEntries: 0,
      totalUncompressedBytes: 0,
      skippedEntries: 1,
    },
  };
}

export const ARCHIVE_MULTI_KEBABS = KEBAB_BY_KIND;
