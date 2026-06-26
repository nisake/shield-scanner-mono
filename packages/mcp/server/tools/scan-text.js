/**
 * Tool: scan_text
 * Scan raw text for prompt injection threats.
 *
 * `verbosity` (QW3 — LLM context-budget control):
 *   - "compact"  : counts + max severity only (no findings array, no report)
 *   - "normal"   : existing shape (default, backward compatible)
 *   - "detailed" : normal + per-finding wider context window
 */

import { analyze, formatReport } from "@shield-scanner/core";
import { compactSummary, expandFindingsContext } from "@shield-scanner/core";

export async function scanText({ text, categories, verbosity = "normal" }) {
  if (typeof text !== "string") {
    throw new Error("'text' must be a string");
  }

  // Auto-detect if it looks like HTML
  const fileType = /<[a-z][\s\S]*>/i.test(text) ? "html" : "text";

  const result = analyze(text, { fileType, categories });

  if (verbosity === "compact") {
    return {
      verbosity: "compact",
      ...compactSummary(result),
    };
  }

  const report = formatReport(result, {
    fileName: "(direct text input)",
    scannedAt: new Date().toISOString(),
  });

  const findings =
    verbosity === "detailed"
      ? expandFindingsContext(result.findings, text)
      : result.findings;

  return {
    verbosity,
    summary: result.summary,
    findings,
    report,
  };
}
