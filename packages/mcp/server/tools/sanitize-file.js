/**
 * Tool: sanitize_file
 *
 * Create a sanitized copy of a file with detected threats removed.
 *
 * For text/html/xml/svg: preserves original format.
 * For docx/pdf/pptx/eml: extracts text, sanitizes it, writes as .txt output
 *   (preserving original binary structure is not feasible without format-specific
 *    reconstruction, which is out of scope for v1.0).
 *
 * `verbosity` (QW3):
 *   - "compact"  : path + total removed only (one-line summary)
 *   - "normal"   : existing shape (default, backward compatible)
 *   - "detailed" : same as normal — file output is the deliverable here
 */

import { extname, dirname, basename, join } from "node:path";
import { readFile, writeFile } from "node:fs/promises";
import { sanitize } from "@shield-scanner/core";
import { parseFile } from "../parsers/index.js";

const TEXT_PRESERVING_EXTS = new Set([
  "txt",
  "md",
  "csv",
  "json",
  "html",
  "htm",
  "xml",
  "svg",
]);

export async function sanitizeFile({
  file_path,
  output_path,
  categories,
  verbosity = "normal",
}) {
  if (!file_path || typeof file_path !== "string") {
    throw new Error("'file_path' is required");
  }

  const ext = extname(file_path).slice(1).toLowerCase();
  let content;
  let fileType = "text";
  let outputExt = ext;

  // S13: ZIP archives have no meaningful in-place sanitized form — we can't
  // rewrite a ZIP central directory + per-entry deflated payloads from a
  // flattened text view. Reject early so the caller gets a clear "not
  // supported" signal rather than a `.txt` containing the joined entry text
  // (which would silently drop the archive structure).
  if (ext === "zip") {
    return {
      verbosity,
      cleaned_path: null,
      original_path: file_path,
      original_extension: ext,
      output_extension: null,
      format_preserved: false,
      removed_counts: {},
      error: "archive sanitize unsupported (ZIP cannot be sanitized in-place)",
    };
  }

  if (TEXT_PRESERVING_EXTS.has(ext)) {
    // Read original content and sanitize in-place
    content = await readFile(file_path, "utf8");
    fileType = ["html", "htm", "xml", "svg"].includes(ext) ? "html" : "text";
  } else {
    // Binary format — extract text via parser, output as .txt
    const parsed = await parseFile(file_path);
    content = parsed.text;
    fileType = parsed.fileType;
    outputExt = "txt";
  }

  const { cleaned, removedCounts } = sanitize(content, { fileType, categories });

  // Determine output path
  let outPath = output_path;
  if (!outPath) {
    const dir = dirname(file_path);
    const base = basename(file_path, extname(file_path));
    outPath = join(dir, `${base}_sanitized.${outputExt}`);
  }

  await writeFile(outPath, cleaned, "utf8");

  if (verbosity === "compact") {
    const total = Object.values(removedCounts || {}).reduce(
      (a, n) => a + (typeof n === "number" ? n : 0),
      0
    );
    return {
      verbosity: "compact",
      cleaned_path: outPath,
      total_removed: total,
      one_line: `🧹 ${total} item(s) removed → ${outPath}`,
    };
  }

  return {
    verbosity,
    cleaned_path: outPath,
    original_path: file_path,
    original_extension: ext,
    output_extension: outputExt,
    format_preserved: TEXT_PRESERVING_EXTS.has(ext),
    removed_counts: removedCounts,
  };
}
