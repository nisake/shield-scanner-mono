/**
 * S13 — Archive (ZIP) detection primitives.
 *
 * Pure-logic helpers used by `packages/mcp/server/parsers/archive.js` and
 * `packages/web/src/parsers-web/archive.js`. No fs / JSZip / env dependencies
 * — this module is safe to import from any environment and from tests without
 * setEnv() wiring.
 *
 * Surfaces:
 *   - detectZipSlip(name) → false | 'dotdot' | 'absolute' | 'drive' | 'nullbyte'
 *   - classifySuspiciousExt(name) → null | string (label e.g. "Windows executable")
 *   - isOfficePackageRename(centralDirNames) → boolean
 *   - detectMagicBytesIsZip(uint8) → boolean
 *   - computeBombRatio(uncompressedTotal, compressedTotal) → number (Infinity on /0)
 *   - ARCHIVE_CAPS — default Node/MCP cap values; Web parser overrides per cap
 *   - DANGEROUS_ARCHIVE_EXTS — Set<string> of lowercase extensions
 *
 * Routing rules (parsers — not enforced here):
 *   - AR-03 (zip slip), AR-05 (suspicious ext), AR-06 (Office rename) → fold into
 *     suspiciousPatterns. R13: NO new byCategory key.
 *   - AR-01 bomb, AR-02 depth, AR-04 encrypted, AR-07 entry-count cap → sibling
 *     `summary.archive` (mirrors `summary.bidiControl` / `summary.topFindings`).
 *   - AR-08 entry findings → enrichFindingsLocation + mergeFindings into the
 *     existing 5 buckets.
 */

// Default caps (MCP / Node). Web parser overrides these per-call because the
// browser tab OOM threshold is tighter than ClamAV MaxScanSize. Centralizing
// the Node defaults here keeps unit tests and parsers in sync.
export const ARCHIVE_CAPS = Object.freeze({
  MAX_TOTAL_DECOMPRESSED: 100 * 1024 * 1024, // 100 MB
  MAX_PER_ENTRY: 25 * 1024 * 1024, // 25 MB
  MAX_ENTRY_COUNT: 10000,
  MAX_RECURSION_DEPTH: 3,
  RATIO_WARN: 100,
  RATIO_BLOCK: 1000,
});

// Lowercase extensions that should always raise an AR-05 warning when found
// inside an archive entry name. Exported as a Set for O(1) membership.
export const DANGEROUS_ARCHIVE_EXTS = new Set([
  "exe",
  "bat",
  "cmd",
  "com",
  "scr",
  "msi",
  "dll",
  "lnk",
  "scf",
  "hta",
  "vbs",
  "ps1",
  "jar",
]);

// Per-extension label used by classifySuspiciousExt. Kept in sync with
// `archive-detection.json#suspiciousExtensions` — the JSON is the source of
// truth for tooling / rule-version pinning; this map is the in-code fallback so
// classifySuspiciousExt stays pure (no loadRule call required).
const SUSPICIOUS_EXT_LABEL = Object.freeze({
  exe: "Windows executable",
  bat: "Windows batch script",
  cmd: "Windows command script",
  com: "DOS command executable",
  scr: "Windows screensaver executable",
  msi: "Windows installer",
  dll: "Windows dynamic library",
  lnk: "Windows shortcut",
  scf: "Windows Explorer command file",
  hta: "HTML application",
  vbs: "VBScript",
  ps1: "PowerShell script",
  jar: "Java archive",
});

/**
 * Classify a single archive entry name as a zip-slip vector, or return false
 * when the name is path-safe.
 *
 * Returns one of: `false | 'dotdot' | 'absolute' | 'drive' | 'nullbyte'`.
 *
 * Order matters: null byte > drive letter > absolute > dotdot. We pick the
 * "highest-shock" classification so a single finding string in suspiciousPatterns
 * is unambiguous. Callers may push one finding per classification — that is
 * fine; the dedup key on (pattern, position) keeps the suspicious-patterns
 * bucket clean.
 */
export function detectZipSlip(entryName) {
  if (typeof entryName !== "string" || entryName.length === 0) return false;

  // Null-byte first — it almost never appears in benign paths and is the
  // classic C-string truncation bypass.
  if (entryName.indexOf("\u0000") !== -1) return "nullbyte";

  // Normalize backslashes so a Windows-style "..\..\evil" path is caught by
  // the same dotdot check that handles POSIX "../..".
  const normalized = entryName.replace(/\\/g, "/");

  // Windows drive letter: "C:\\..." or "C:/..." or bare "C:" prefix.
  if (/^[A-Za-z]:[/\\]?/.test(entryName)) return "drive";

  // Absolute POSIX path. We check the normalized form so backslash-prefixed
  // entries ("\\evil.txt") also resolve as absolute, matching how a Windows
  // extractor would treat them.
  if (normalized.startsWith("/")) return "absolute";

  // Any `..` path segment — start, middle, or trailing.
  const segments = normalized.split("/");
  for (const seg of segments) {
    if (seg === "..") return "dotdot";
  }

  return false;
}

/**
 * Map an entry name's extension to a suspicious-extension label, or null when
 * the extension is not dangerous.
 *
 * Returns the human-readable label (e.g. "Windows executable") so parsers can
 * use it directly in a finding's `pattern` / `technique` / matched-display
 * field. The label is detector-controlled scaffolding, so it is safe to expose
 * verbatim (R12).
 */
export function classifySuspiciousExt(entryName) {
  if (typeof entryName !== "string" || entryName.length === 0) return null;
  // Strip path. Use the last "/" or "\" — whichever comes later.
  const lastSlash = Math.max(entryName.lastIndexOf("/"), entryName.lastIndexOf("\\"));
  const base = lastSlash >= 0 ? entryName.slice(lastSlash + 1) : entryName;
  // Trim trailing whitespace / NULs (defensive — already caught by detectZipSlip
  // but we don't want a dangling " " or "\u0000" to defeat the ext check).
  const trimmed = base.replace(/[\u0000-\s]+$/g, "");
  const dot = trimmed.lastIndexOf(".");
  if (dot < 0 || dot === trimmed.length - 1) return null;
  const ext = trimmed.slice(dot + 1).toLowerCase();
  if (!DANGEROUS_ARCHIVE_EXTS.has(ext)) return null;
  return SUSPICIOUS_EXT_LABEL[ext] || `Dangerous archive entry (.${ext})`;
}

/**
 * Detect whether the archive's central-directory member list contains the
 * Office Open XML package marker (`[Content_Types].xml`). When this returns
 * true on a `.zip` (not `.docx` / `.xlsx` / `.pptx`), the file is likely an
 * Office package renamed to `.zip` to bypass content-type / extension policy.
 *
 * Accepts an Array<string> OR a Set<string>. Case-sensitive — the spec marker
 * is exact-case.
 */
export function isOfficePackageRename(centralDirNames) {
  if (!centralDirNames) return false;
  const marker = "[Content_Types].xml";
  if (centralDirNames instanceof Set) return centralDirNames.has(marker);
  if (Array.isArray(centralDirNames)) {
    for (const name of centralDirNames) {
      if (name === marker) return true;
    }
    return false;
  }
  // Iterable fallback (e.g. Map.keys()).
  if (typeof centralDirNames[Symbol.iterator] === "function") {
    for (const name of centralDirNames) {
      if (name === marker) return true;
    }
  }
  return false;
}

/**
 * Detect ZIP magic-bytes signature in the first 4 bytes of a Uint8Array /
 * Buffer / Array-like. Recognized signatures:
 *
 *   - 50 4B 03 04 — local file header (normal ZIP)
 *   - 50 4B 05 06 — end-of-central-dir (empty ZIP)
 *   - 50 4B 07 08 — spanned/split ZIP marker
 *
 * Returns false on short inputs or non-array-like values. Used by parsers as
 * an early reject before handing the buffer to JSZip — extension-spoofing
 * (e.g. a `.zip` that is actually a renamed `.exe`) trips here.
 */
export function detectMagicBytesIsZip(uint8) {
  if (!uint8 || typeof uint8 !== "object") return false;
  if (typeof uint8.length !== "number" || uint8.length < 4) return false;
  const b0 = uint8[0];
  const b1 = uint8[1];
  const b2 = uint8[2];
  const b3 = uint8[3];
  if (b0 !== 0x50 || b1 !== 0x4b) return false;
  // (b2,b3) ∈ { (3,4), (5,6), (7,8) }
  if (b2 === 0x03 && b3 === 0x04) return true;
  if (b2 === 0x05 && b3 === 0x06) return true;
  if (b2 === 0x07 && b3 === 0x08) return true;
  return false;
}

/**
 * Compute the compression ratio uncompressed / compressed.
 *
 * Returns Infinity when compressedTotal <= 0 (so the caller can treat a
 * zero-compressed archive as bomb-suspect without a divide-by-zero branch).
 * Returns 0 when uncompressedTotal <= 0. Negative inputs are clamped to 0.
 */
export function computeBombRatio(uncompressedTotal, compressedTotal) {
  const u = typeof uncompressedTotal === "number" && uncompressedTotal > 0
    ? uncompressedTotal
    : 0;
  const c = typeof compressedTotal === "number" && compressedTotal > 0
    ? compressedTotal
    : 0;
  if (u === 0) return 0;
  if (c === 0) return Infinity;
  return u / c;
}

// Default export bundles the helpers for callers that prefer namespace-import.
// Matches the dual-export pattern used by other core modules (e.g. priority.js).
export default {
  detectZipSlip,
  classifySuspiciousExt,
  isOfficePackageRename,
  detectMagicBytesIsZip,
  computeBombRatio,
  ARCHIVE_CAPS,
  DANGEROUS_ARCHIVE_EXTS,
};
