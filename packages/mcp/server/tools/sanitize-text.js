/**
 * Tool: sanitize_text
 * Return a cleaned version of text with detected threats removed.
 *
 * `verbosity` (QW3):
 *   - "compact"  : removed counts + length deltas only (cleaned_text omitted)
 *   - "normal"   : existing shape (default, backward compatible)
 *   - "detailed" : normal + per-category breakdown (currently same as normal —
 *                  sanitizer.js only returns counts, no per-finding context)
 */

import { sanitize } from "@shield-scanner/core";

export async function sanitizeText({ text, categories, verbosity = "normal" }) {
  if (typeof text !== "string") {
    throw new Error("'text' must be a string");
  }

  const fileType = /<[a-z][\s\S]*>/i.test(text) ? "html" : "text";
  const { cleaned, removedCounts } = sanitize(text, { fileType, categories });

  if (verbosity === "compact") {
    const total = Object.values(removedCounts || {}).reduce(
      (a, n) => a + (typeof n === "number" ? n : 0),
      0
    );
    return {
      verbosity: "compact",
      total_removed: total,
      removed_counts: removedCounts,
      original_length: text.length,
      cleaned_length: cleaned.length,
      one_line: `🧹 removed ${total} item(s), ${text.length}→${cleaned.length} chars`,
    };
  }

  return {
    verbosity,
    cleaned_text: cleaned,
    removed_counts: removedCounts,
    original_length: text.length,
    cleaned_length: cleaned.length,
  };
}
