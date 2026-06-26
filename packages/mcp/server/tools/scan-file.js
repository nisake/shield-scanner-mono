/**
 * Tool: scan_file
 * Scan a file for prompt injection threats.
 * Supports: txt, md, csv, json, html, htm, xml, svg, docx, pdf, pptx, eml
 *
 * `verbosity` (QW3): "compact" | "normal" (default) | "detailed"
 */

import { analyze, mergeFindings, formatReport } from "@shield-scanner/core";
import { parseFile } from "../parsers/index.js";
import { compactSummary, expandFindingsContext } from "@shield-scanner/core";
import { redactDecodedFindings } from "@shield-scanner/core";

export async function scanFile({ file_path, categories, verbosity = "normal" }) {
  if (!file_path || typeof file_path !== "string") {
    throw new Error("'file_path' is required");
  }

  const parsed = await parseFile(file_path);
  const { text, fileType, extraFindings, fileInfo, decodedRanges } = parsed;

  // Run base analyze on extracted text
  const baseResult = analyze(text, { fileType, categories });

  // R12 (S12 R12-IMG-002 fix): if the parser flagged any character ranges as
  // decoder-synthesized (XML entities, UTF-16, zlib, IPTC UTF-8 mode), redact
  // matched/context on any suspicious-pattern hit landing inside those
  // ranges. Without this, an attacker can embed an attack token in a form
  // the source bytes don't contain (e.g. `&#x49;gnore…` in XMP) and Shield
  // Scanner echoes the decoded cleartext back to the LLM consumer, acting
  // as a decoding oracle. The redaction preserves the pattern name +
  // severity (the alert is real), only the verbatim quote is scrubbed.
  if (Array.isArray(decodedRanges) && decodedRanges.length > 0) {
    redactDecodedFindings(baseResult.findings, decodedRanges);
  }

  // Split parser extras by their claimed category. Most parsers (PDF, DOCX,
  // EML, …) emit extras without a `category` field and historically those
  // route into the `hiddenHtml` bucket. S12's image parser tags each extra
  // with an explicit `category` (e.g. "suspiciousPatterns") so image-metadata
  // findings fold into the canonical 5-key set rather than always landing in
  // hiddenHtml. mergeFindings only knows how to splice into `hiddenHtml`, so
  // we hand it the legacy hiddenHtml extras, then post-merge we splice the
  // categorized extras into their declared buckets and rebuild the summary
  // counts via a re-merge with an empty base.
  const extrasByBucket = {
    invisibleUnicode: [],
    controlChars: [],
    hiddenHtml: [],
    suspiciousPatterns: [],
    homoglyphs: [],
  };
  for (const f of extraFindings || []) {
    const cat = f && typeof f.category === "string" ? f.category : null;
    if (cat && Object.prototype.hasOwnProperty.call(extrasByBucket, cat)) {
      extrasByBucket[cat].push(f);
    } else {
      extrasByBucket.hiddenHtml.push(f);
    }
  }

  // First pass: merge legacy hiddenHtml extras through mergeFindings so its
  // priority + summary recomputation happens with the canonical inputs.
  let merged = mergeFindings(baseResult, { hiddenHtml: extrasByBucket.hiddenHtml });

  // Second pass: splice the category-tagged extras (suspiciousPatterns,
  // invisibleUnicode, controlChars, homoglyphs) into their declared buckets,
  // then re-run mergeFindings against an empty base so priorities + summary
  // counts (status, byCategory, bySeverity, topFindings) all stay consistent.
  const hasCategorized =
    extrasByBucket.suspiciousPatterns.length > 0 ||
    extrasByBucket.invisibleUnicode.length > 0 ||
    extrasByBucket.controlChars.length > 0 ||
    extrasByBucket.homoglyphs.length > 0;
  if (hasCategorized) {
    const splicedBase = {
      findings: {
        invisibleUnicode: [
          ...merged.findings.invisibleUnicode,
          ...extrasByBucket.invisibleUnicode,
        ],
        controlChars: [
          ...merged.findings.controlChars,
          ...extrasByBucket.controlChars,
        ],
        hiddenHtml: [...merged.findings.hiddenHtml],
        suspiciousPatterns: [
          ...merged.findings.suspiciousPatterns,
          ...extrasByBucket.suspiciousPatterns,
        ],
        homoglyphs: [
          ...merged.findings.homoglyphs,
          ...extrasByBucket.homoglyphs,
        ],
      },
      contentLength: (baseResult && baseResult.contentLength) || (text ? text.length : 0),
    };
    merged = mergeFindings(splicedBase, {});
  }

  if (verbosity === "compact") {
    return {
      verbosity: "compact",
      fileInfo,
      ...compactSummary(merged),
    };
  }

  const report = formatReport(merged, {
    fileName: fileInfo.name,
    scannedAt: new Date().toISOString(),
  });

  const findings =
    verbosity === "detailed"
      ? expandFindingsContext(merged.findings, text)
      : merged.findings;

  return {
    verbosity,
    summary: merged.summary,
    findings,
    fileInfo,
    report,
  };
}
