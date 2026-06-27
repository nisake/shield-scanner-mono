/**
 * v1.20.0 T9-ARCHIVE-EXT — multi-format archive recognizer (MCP).
 *
 * Lightweight magic-bytes based recognition for non-ZIP archive containers
 * we don't yet have a deep parser for:
 *
 *   - .7z       (7-Zip)        magic: 37 7A BC AF 27 1C
 *   - .tar.gz   (gzipped TAR)  magic: 1F 8B (gzip header)
 *   - .rar      (RAR archive)  magic: 52 61 72 21 1A 07 00 (RARv4)
 *                              and:   52 61 72 21 1A 07 01 00 (RARv5 — first 7 bytes match)
 *
 * Why a separate helper file:
 *   - archive.js (the JSZip-backed parser) is owned by a different theme this
 *     cycle; we keep this strictly isolated.
 *   - Pulling in node-7z / yauzl / unrar deps for deep walk would balloon the
 *     web bundle far beyond the dist budget. v1.20.0 ships RECOGNIZE ONLY:
 *     we emit a single "recognized but skipped" warning with a stable kebab
 *     id so downstream tooling (and i18n.js, deferred) can surface the
 *     archive type without us actually decompressing it.
 *
 * R12: no user-supplied byte sequence is ever surfaced in `content`. The
 *      finding `content` field is a static "(recognized; deep walk deferred)"
 *      string; no input bytes leak through.
 * R13: every emitted finding routes through the `hiddenHtml` bucket — no new
 *      top-level byCategory key. (Matches archive.js's existing "unsupported
 *      or corrupt ZIP" pathway.)
 * R18: no loadRule / no env coupling here — this is a pure detector.
 *
 * Kebab IDs (stable, mirrored in Web parser):
 *   - archive-7z-recognized
 *   - archive-targz-recognized
 *   - archive-rar-recognized
 */

import { readFile } from "node:fs/promises";

// ---------------------------------------------------------------------------
// Magic-bytes signatures.
// ---------------------------------------------------------------------------

const SIG_7Z = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const SIG_GZIP = [0x1f, 0x8b];
const SIG_RAR = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]; // RARv4 (7 bytes)
// RARv5 differs in the 8th byte (0x01). We match on the leading 6 bytes of
// the shared prefix `Rar!\x1A\x07` so both RARv4 (\x00) and RARv5 (\x01)
// classify as 'rar'.
const SIG_RAR_PREFIX = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07];

function _hasSig(u8, sig) {
  if (!u8 || u8.length < sig.length) return false;
  for (let i = 0; i < sig.length; i += 1) {
    if (u8[i] !== sig[i]) return false;
  }
  return true;
}

/**
 * Classify a buffer's leading bytes against the four recognized archive
 * containers. Returns null for anything else (caller should fall through to
 * the existing parsers / unknown-ext skip).
 *
 * Note: a `.tar.gz` and a plain `.gz` are indistinguishable from the gzip
 * magic alone (both start with `1F 8B`). For v1.20.0 we surface both as
 * `'targz'` because the security signal is identical (opaque compressed
 * payload we cannot scan). Future expansions can read the inner TAR header
 * at offset 10+N (after the optional FNAME / FCOMMENT fields) to split them.
 *
 * @param {Buffer|Uint8Array} buffer
 * @returns {'7z'|'targz'|'rar'|null}
 */
export function recognizeArchiveType(buffer) {
  if (!buffer) return null;
  const u8 =
    buffer instanceof Uint8Array
      ? buffer
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  if (_hasSig(u8, SIG_7Z)) return "7z";
  if (_hasSig(u8, SIG_RAR_PREFIX)) return "rar";
  if (_hasSig(u8, SIG_GZIP)) return "targz";
  return null;
}

// ---------------------------------------------------------------------------
// Public API: recognize + emit a single skipped-but-recognized finding.
// ---------------------------------------------------------------------------

const KEBAB_BY_KIND = Object.freeze({
  "7z": "archive-7z-recognized",
  targz: "archive-targz-recognized",
  rar: "archive-rar-recognized",
});

const LABEL_BY_KIND = Object.freeze({
  "7z": "7-Zip archive",
  targz: "gzip / tar.gz archive",
  rar: "RAR archive",
});

/**
 * Parse a buffer that is suspected to be a non-ZIP archive. Returns a parser-
 * shape result mirroring the rest of the MCP parser contract:
 *
 *   {
 *     text: '',
 *     fileType: 'archive-multi',
 *     extraFindings: Array<Finding>,
 *     archiveSummary: Object,
 *   }
 *
 * If the buffer doesn't match any recognized magic, returns null so the caller
 * can fall through to existing parsers (e.g. parseArchiveBuffer for raw .zip).
 *
 * Recognized buffer => exactly one finding (the recognized-skip warning).
 *
 * R13 fold: category = 'hiddenHtml'.
 *
 * @param {Buffer|Uint8Array} buffer
 * @returns {Promise<null | {
 *   text: '',
 *   fileType: 'archive-multi',
 *   extraFindings: Array,
 *   archiveSummary: Object,
 * }>}
 */
export async function parseArchiveMultiBuffer(buffer) {
  const kind = recognizeArchiveType(buffer);
  if (!kind) return null;

  const kebab = KEBAB_BY_KIND[kind];
  const label = LABEL_BY_KIND[kind];

  const finding = {
    element: label,
    technique: kebab,
    content: "(recognized; deep walk deferred — v1.20.x)",
    severity: "warning",
    category: "hiddenHtml",
    contextLocation: label,
    meta: { archiveKind: kind },
  };

  return {
    text: "",
    fileType: "archive-multi",
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

/**
 * File-path wrapper: read the buffer and delegate to parseArchiveMultiBuffer.
 *
 * @param {string} filePath
 * @returns {Promise<null | object>}
 */
export async function parseArchiveMulti(filePath) {
  const buffer = await readFile(filePath);
  return parseArchiveMultiBuffer(buffer);
}

// Exported kebab id table — consumed by tests and (in a future cycle) by
// parsers/index.js when we wire the .7z/.tar.gz/.rar extensions.
export const ARCHIVE_MULTI_KEBABS = KEBAB_BY_KIND;
