/**
 * S13 — Archive (ZIP) parser.
 *
 * Recursive scanner for raw `.zip` containers (NOT Office .docx/.xlsx/.pptx —
 * those have their own dedicated parsers and stay on the non-archive route).
 * The parser does the following at each recursion level:
 *
 *   1. Magic-bytes gate (early reject extension-spoofed `.zip`s).
 *   2. JSZip.loadAsync (encrypted ZIPs throw → counted as AR-04).
 *   3. Entry-count cap (AR-07) → early break.
 *   4. Office-package-rename detection (AR-06) → suspiciousPatterns.
 *   5. Per-entry walk:
 *        - zip-slip classification (AR-03) → suspiciousPatterns
 *        - dangerous extension hint (AR-05) → suspiciousPatterns
 *        - per-entry uncompressed-size cap (AR-01 per-entry)
 *        - total-decompressed cap (AR-01 total)
 *        - ratio bomb (AR-01 ratio)
 *        - recursive dispatch:
 *            * `.zip` → parseArchiveBuffer (depth+1; depth cap AR-02)
 *            * known text/binary parser ext → dispatchBuffer
 *            * everything else → skip
 *   6. Aggregate child findings into 5-bucket extraFindings (category-tagged
 *      so scan-file routes them into the canonical buckets — R13 maintained).
 *   7. Aggregate child archiveSummary up via mergeArchiveSummaries shape.
 *
 * Return shape (matches the rest of the MCP parser contract):
 *
 *   {
 *     text: string,                  // entry text concatenated for outer analyze()
 *     fileType: "archive",
 *     extraFindings: Array<Finding>, // every finding category-tagged
 *     archiveSummary: ArchiveSummary // {scanned, bomb, depth, protected, ...}
 *   }
 *
 * Caps live in `@shield-scanner/core` (ARCHIVE_CAPS). Web parser overrides the
 * total-decompressed cap to 50 MB; MCP keeps the 100 MB default.
 *
 * R12: every echoed string (entry name, error message, joined text fragment)
 * passes through escapeForDisplay before landing in `content` /
 * `contextLocation`. Entry names are user-controlled and may carry RTLO /
 * control chars, so this matters more than usual here.
 *
 * R13: no new byCategory key. AR-03 / AR-05 / AR-06 fold into
 * suspiciousPatterns; AR-01 / AR-02 / AR-04 / AR-07 live on the sibling
 * `summary.archive` key (consumed by scan-file → mergeFindings → buildSummary
 * — wiring in core/src/detector.js).
 *
 * R18: imports from `@shield-scanner/core` only env-abstract helpers
 * (detectZipSlip / classifySuspiciousExt / isOfficePackageRename /
 * detectMagicBytesIsZip / computeBombRatio / ARCHIVE_CAPS /
 * enrichFindingsLocation / escapeForDisplay). No loadRule at module load.
 *
 * Circular-import note: parsers/index.js imports parseArchive +
 * parseArchiveBuffer from here. We import dispatchBuffer from there for
 * per-entry recursion. Node ESM resolves this lazily — dispatchBuffer is a
 * named export that resolves at call-time, not at module evaluation time —
 * so the loop is safe. If a future refactor breaks the loop, switch to
 *   `const { dispatchBuffer } = await import("./index.js")` inside the entry
 * walk to defer the lookup.
 */

import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import JSZip from "jszip";
import {
  escapeForDisplay,
  detectZipSlip,
  classifySuspiciousExt,
  isOfficePackageRename,
  detectMagicBytesIsZip,
  computeBombRatio,
  ARCHIVE_CAPS,
  enrichFindingsLocation,
} from "@shield-scanner/core";
import { dispatchBuffer, BUFFER_DISPATCHABLE } from "./index.js";

// ---------------------------------------------------------------------------
// Constants — buckets we route entry findings into.
// ---------------------------------------------------------------------------

const BUCKET_KEYS = [
  "invisibleUnicode",
  "controlChars",
  "hiddenHtml",
  "suspiciousPatterns",
  "homoglyphs",
];

// Max entry-name length we echo back in content / contextLocation (cap echo so
// a 30 KB pathological filename can't blow the report up).
const MAX_NAME_ECHO = 200;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function parseArchive(filePath) {
  const buffer = await readFile(filePath);
  return parseArchiveBuffer(buffer, { depth: 0 });
}

/**
 * Parse a ZIP archive from a Buffer / Uint8Array.
 *
 * @param {Buffer|Uint8Array} buffer
 * @param {Object} [options]
 * @param {number} [options.depth=0]   Current recursion depth (0 at top level).
 * @returns {Promise<{
 *   text: string,
 *   fileType: 'archive',
 *   extraFindings: Array,
 *   archiveSummary: Object
 * }>}
 */
export async function parseArchiveBuffer(buffer, options) {
  const depth = (options && Number.isFinite(options.depth) ? options.depth : 0) | 0;

  const summary = _emptyArchiveSummary();
  summary.scanned = 1;
  summary.maxDepth = depth;

  const extraFindings = [];
  const textsOut = [];

  // Normalize to Uint8Array for the magic check; JSZip accepts either shape.
  const u8 =
    buffer instanceof Uint8Array
      ? buffer
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  // 1) magic-bytes gate ---------------------------------------------------
  if (!detectMagicBytesIsZip(u8)) {
    extraFindings.push({
      element: "ZIP Archive",
      technique: "Archive missing ZIP magic",
      content: "(first 4 bytes do not match ZIP signature; not parsed)",
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "ZIP Archive",
    });
    return _result(textsOut, extraFindings, summary);
  }

  // 2) depth cap (AR-02) — we still emit `scanned: 1` for the level we
  // entered, but skip enumerating children. AR-02 is sibling-key only.
  if (depth >= ARCHIVE_CAPS.MAX_RECURSION_DEPTH) {
    summary.depth += 1;
    extraFindings.push({
      element: "ZIP Archive",
      technique: "Archive recursion depth cap reached",
      content: `(depth ${depth} >= cap ${ARCHIVE_CAPS.MAX_RECURSION_DEPTH}; nested entries not scanned)`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "ZIP Archive",
    });
    return _result(textsOut, extraFindings, summary);
  }

  // 3) JSZip.loadAsync. Encrypted archives throw a known string here —
  // catch and tally as AR-04.
  let zip;
  try {
    zip = await JSZip.loadAsync(u8);
  } catch (err) {
    const msg = err && err.message ? err.message : "JSZip parse error";
    const isEncrypted = /encrypted/i.test(msg);
    if (isEncrypted) {
      summary.protected += 1;
      extraFindings.push({
        element: "ZIP Archive",
        technique: "Encrypted archive (cannot scan contents)",
        content: escapeForDisplay(msg.slice(0, MAX_NAME_ECHO)),
        severity: "warning",
        category: "hiddenHtml",
        contextLocation: "ZIP Archive",
      });
    } else {
      extraFindings.push({
        element: "ZIP Archive",
        technique: "Unsupported or corrupt ZIP archive",
        content: escapeForDisplay(msg.slice(0, MAX_NAME_ECHO)),
        severity: "warning",
        category: "hiddenHtml",
        contextLocation: "ZIP Archive",
      });
    }
    return _result(textsOut, extraFindings, summary);
  }

  const memberNames = Object.keys(zip.files);

  // 4) entry-count cap (AR-07).
  if (memberNames.length > ARCHIVE_CAPS.MAX_ENTRY_COUNT) {
    summary.entryCap += 1;
    extraFindings.push({
      element: "ZIP Archive",
      technique: "Archive entry count exceeds cap",
      content: `(${memberNames.length} entries > cap ${ARCHIVE_CAPS.MAX_ENTRY_COUNT}; archive not enumerated)`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "ZIP Archive",
    });
    return _result(textsOut, extraFindings, summary);
  }

  // 5) Office package rename (AR-06) — `[Content_Types].xml` in central dir.
  if (isOfficePackageRename(memberNames)) {
    extraFindings.push({
      element: "ZIP Archive",
      technique: "Office package renamed to .zip (extension spoofing)",
      content: "(central directory contains [Content_Types].xml)",
      severity: "warning",
      category: "suspiciousPatterns",
      contextLocation: "ZIP Archive",
    });
  }

  // 6) Per-entry walk.
  let totalUncompressed = 0;
  let totalCompressed = 0;
  let entriesWalked = 0;
  let totalCapTripped = false;

  for (const name of memberNames) {
    const entry = zip.files[name];
    if (!entry || entry.dir) {
      // Still apply zip-slip / suspicious-ext checks against directory names
      // (an attacker can encode the traversal in a directory entry too).
      _checkNameHazards(name, extraFindings);
      continue;
    }

    entriesWalked += 1;
    summary.totalEntries += 1;

    // Name-level hazards (AR-03 / AR-05).
    _checkNameHazards(name, extraFindings);

    // Per-entry size cap (AR-01 per-entry).
    const uncompressedSize = _safeUncompressedSize(entry);
    const compressedSize = _safeCompressedSize(entry);

    if (
      Number.isFinite(uncompressedSize) &&
      uncompressedSize > ARCHIVE_CAPS.MAX_PER_ENTRY
    ) {
      summary.bomb += 1;
      summary.skippedEntries += 1;
      extraFindings.push({
        element: `ZIP entry '${escapeForDisplay(name.slice(0, MAX_NAME_ECHO))}'`,
        technique: "ZIP entry exceeds per-entry decompressed cap",
        content: `(uncompressed ${uncompressedSize} > cap ${ARCHIVE_CAPS.MAX_PER_ENTRY} bytes; entry skipped)`,
        severity: "danger",
        category: "hiddenHtml",
        contextLocation: `ZIP entry:${escapeForDisplay(name.slice(0, MAX_NAME_ECHO))}`,
      });
      // Still add to the totals for ratio calc so a bomb-by-many-medium-entries
      // shape still trips the ratio gate.
      if (Number.isFinite(uncompressedSize)) totalUncompressed += uncompressedSize;
      if (Number.isFinite(compressedSize)) totalCompressed += compressedSize;
      continue;
    }

    if (Number.isFinite(uncompressedSize)) totalUncompressed += uncompressedSize;
    if (Number.isFinite(compressedSize)) totalCompressed += compressedSize;

    // Total-decompressed cap (AR-01 total).
    if (totalUncompressed > ARCHIVE_CAPS.MAX_TOTAL_DECOMPRESSED) {
      if (!totalCapTripped) {
        totalCapTripped = true;
        summary.bomb += 1;
        extraFindings.push({
          element: "ZIP Archive",
          technique: "Archive total decompressed size exceeds cap",
          content: `(total ${totalUncompressed} > cap ${ARCHIVE_CAPS.MAX_TOTAL_DECOMPRESSED} bytes; remaining entries skipped)`,
          severity: "danger",
          category: "hiddenHtml",
          contextLocation: "ZIP Archive",
        });
      }
      summary.skippedEntries += 1;
      break;
    }

    // Recursive dispatch by extension.
    const ext = extname(name).slice(1).toLowerCase();
    let entryBuf = null;

    if (ext === "zip") {
      // Read out the entry bytes and recurse.
      try {
        entryBuf = await entry.async("nodebuffer");
      } catch {
        continue;
      }
      const childResult = await parseArchiveBuffer(entryBuf, { depth: depth + 1 });
      _absorbChild(name, childResult, extraFindings, textsOut, summary);
    } else if (BUFFER_DISPATCHABLE.has(ext)) {
      try {
        entryBuf = await entry.async("nodebuffer");
      } catch {
        continue;
      }
      let sub;
      try {
        sub = await dispatchBuffer(entryBuf, ext);
      } catch {
        sub = null;
      }
      if (sub) {
        _absorbDispatchedEntry(name, sub, extraFindings, textsOut);
      }
    } else {
      // Unknown ext — skip silently. Name-level hazards already counted.
    }
  }

  // 7) Ratio bomb (AR-01).
  summary.totalUncompressedBytes += totalUncompressed;
  const ratio = computeBombRatio(totalUncompressed, totalCompressed);
  if (Number.isFinite(ratio) || ratio === Infinity) {
    if (ratio > summary.maxRatio) summary.maxRatio = ratio === Infinity ? -1 : ratio;
  }
  if (entriesWalked > 0 && ratio >= ARCHIVE_CAPS.RATIO_BLOCK) {
    summary.bomb += 1;
    extraFindings.push({
      element: "ZIP Archive",
      technique: "Archive compression ratio exceeds bomb threshold",
      content: `(ratio ${ratio === Infinity ? "Infinity" : Math.round(ratio)}:1 > block ${ARCHIVE_CAPS.RATIO_BLOCK}:1)`,
      severity: "danger",
      category: "hiddenHtml",
      contextLocation: "ZIP Archive",
    });
  } else if (entriesWalked > 0 && ratio >= ARCHIVE_CAPS.RATIO_WARN) {
    extraFindings.push({
      element: "ZIP Archive",
      technique: "Archive compression ratio elevated",
      content: `(ratio ${Math.round(ratio)}:1 > warn ${ARCHIVE_CAPS.RATIO_WARN}:1)`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "ZIP Archive",
    });
  }

  return _result(textsOut, extraFindings, summary);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _result(textsOut, extraFindings, archiveSummary) {
  return {
    text: textsOut.join("\n"),
    fileType: "archive",
    extraFindings,
    archiveSummary,
  };
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

/**
 * Push AR-03 / AR-05 findings for an entry name (used for both file entries
 * and directory entries — both can encode path-traversal).
 */
function _checkNameHazards(name, extraFindings) {
  const slip = detectZipSlip(name);
  if (slip) {
    extraFindings.push({
      element: "ZIP entry name",
      technique: `Path-traversal entry name (${slip})`,
      content: escapeForDisplay(name.slice(0, MAX_NAME_ECHO)),
      severity: "danger",
      category: "suspiciousPatterns",
      contextLocation: `ZIP entry:${escapeForDisplay(name.slice(0, MAX_NAME_ECHO))}`,
    });
  }
  const suspExt = classifySuspiciousExt(name);
  if (suspExt) {
    extraFindings.push({
      element: "ZIP entry name",
      technique: `Suspicious archive entry extension — ${suspExt}`,
      content: escapeForDisplay(name.slice(0, MAX_NAME_ECHO)),
      severity: "warning",
      category: "suspiciousPatterns",
      contextLocation: `ZIP entry:${escapeForDisplay(name.slice(0, MAX_NAME_ECHO))}`,
    });
  }
}

/**
 * Try to pull uncompressedSize from the JSZip internal `_data` first (cheap —
 * read directly from the central-directory header). Falls back to NaN; the
 * caller treats NaN as "unknown" and skips the per-entry cap check rather
 * than over-counting. We deliberately don't fall through to async expansion
 * here — a malicious central-directory header that claims 0 would otherwise
 * force us to actually decompress the entry to learn the truth, which
 * defeats the whole point of the cap.
 */
function _safeUncompressedSize(entry) {
  try {
    const data = entry && entry._data;
    if (data && typeof data.uncompressedSize === "number") {
      return data.uncompressedSize;
    }
  } catch {
    /* swallow — JSZip internals are best-effort */
  }
  return NaN;
}

function _safeCompressedSize(entry) {
  try {
    const data = entry && entry._data;
    if (data && typeof data.compressedSize === "number") {
      return data.compressedSize;
    }
  } catch {
    /* swallow */
  }
  return NaN;
}

/**
 * Fold a child archive's findings + summary into the current level.
 *
 * - Child extraFindings get a `ZIP entry:<name>` location prefix.
 * - Child text gets a labeled separator line so the outer analyze() can still
 *   walk the entry's textual content.
 * - Child summary aggregates field-by-field (peaks for maxRatio / maxDepth).
 */
function _absorbChild(name, childResult, extraFindings, textsOut, summary) {
  if (!childResult) return;
  const label = `ZIP entry:${name.slice(0, MAX_NAME_ECHO)}`;
  const enriched = enrichFindingsLocation(
    Array.isArray(childResult.extraFindings) ? childResult.extraFindings : [],
    { label },
  );
  for (const f of enriched) extraFindings.push(f);

  if (childResult.text && typeof childResult.text === "string" && childResult.text.length > 0) {
    textsOut.push(`[${label}]`);
    textsOut.push(childResult.text);
  }

  const childSummary = childResult.archiveSummary;
  if (childSummary && typeof childSummary === "object") {
    summary.scanned += childSummary.scanned || 0;
    summary.bomb += childSummary.bomb || 0;
    summary.depth += childSummary.depth || 0;
    summary.protected += childSummary.protected || 0;
    summary.entryCap += childSummary.entryCap || 0;
    summary.totalEntries += childSummary.totalEntries || 0;
    summary.totalUncompressedBytes += childSummary.totalUncompressedBytes || 0;
    summary.skippedEntries += childSummary.skippedEntries || 0;
    if ((childSummary.maxRatio || 0) > summary.maxRatio) {
      summary.maxRatio = childSummary.maxRatio;
    }
    if ((childSummary.maxDepth || 0) > summary.maxDepth) {
      summary.maxDepth = childSummary.maxDepth;
    }
  }
}

/**
 * Fold a non-archive dispatched entry result into the current level.
 *
 * The dispatched parser already category-tagged its extraFindings (or left
 * them untagged — in which case scan-file's `extrasByBucket` defaults them
 * to hiddenHtml, same as today). We just enrich with the ZIP entry prefix
 * and forward.
 */
function _absorbDispatchedEntry(name, sub, extraFindings, textsOut) {
  const label = `ZIP entry:${name.slice(0, MAX_NAME_ECHO)}`;
  const enriched = enrichFindingsLocation(
    Array.isArray(sub.extraFindings) ? sub.extraFindings : [],
    { label },
  );
  for (const f of enriched) extraFindings.push(f);

  if (sub.text && typeof sub.text === "string" && sub.text.length > 0) {
    textsOut.push(`[${label}]`);
    textsOut.push(sub.text);
  }
}

// Re-export the bucket key list so future scan-file changes can stay in
// lock-step with the parser without re-deriving the canonical set.
export const ARCHIVE_BUCKET_KEYS = Object.freeze([...BUCKET_KEYS]);
