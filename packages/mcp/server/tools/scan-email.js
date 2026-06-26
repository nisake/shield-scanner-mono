/**
 * Tool: scan_email
 *
 * Scan an .eml file or raw email text.
 * Analyzes headers, body, and HTML parts SEPARATELY so you can see which
 * section contains the threat.
 *
 * M4: Attachments are now parsed recursively (PDF / DOCX / PPTX / HTML / text
 * / nested EML up to depth 3) and reported as separate sections labeled
 * "attachment[i]: <filename>". Filename + count are still reported for
 * backward compatibility.
 *
 * Accepts either eml_path or raw_text (but not both).
 */

import { analyze, enrichFindingsLocation } from "@shield-scanner/core";
import { parseEmlFile, parseEmlContent } from "../parsers/eml.js";
import { compactSummary, expandFindingsContext } from "@shield-scanner/core";
import { redactDecodedFindings } from "@shield-scanner/core";

export async function scanEmail({ eml_path, raw_text, verbosity = "normal" }) {
  if (!eml_path && !raw_text) {
    throw new Error("Either 'eml_path' or 'raw_text' is required");
  }
  if (eml_path && raw_text) {
    throw new Error("Provide either 'eml_path' OR 'raw_text', not both");
  }

  const parsed = eml_path
    ? await parseEmlFile(eml_path)
    : await parseEmlContent(raw_text);

  const { sections, metadata, extraFindings, attachmentScans } = parsed;

  // --- Scan each top-level section ---
  // S20: tag each section's findings with a contextLocation label so consumers
  // (and tests) can tell which part of the email a finding came from.
  const headersResult = analyze(sections.headers || "", { fileType: "text" });
  headersResult.findings = enrichFindingsLocation(headersResult.findings, {
    kind: "eml-section",
    label: "Headers",
  });
  // S11: extended-headers (Reply-To / Return-Path / Sender / X-* etc.)
  const extendedHeadersResult = sections.extendedHeaders
    ? analyze(sections.extendedHeaders, { fileType: "text" })
    : { findings: emptyFindings(), summary: emptySummary() };
  extendedHeadersResult.findings = enrichFindingsLocation(
    extendedHeadersResult.findings,
    { kind: "eml-section", label: "Extended Headers" }
  );
  const bodyResult = analyze(sections.body || "", { fileType: "text" });
  bodyResult.findings = enrichFindingsLocation(bodyResult.findings, {
    kind: "eml-section",
    label: "Body",
  });
  const htmlResult = sections.html
    ? analyze(sections.html, { fileType: "html" })
    : { findings: emptyFindings(), summary: emptySummary() };
  htmlResult.findings = enrichFindingsLocation(htmlResult.findings, {
    kind: "eml-section",
    label: "HTML Body",
  });
  const attachmentsResult = sections.attachmentNames
    ? analyze(sections.attachmentNames, { fileType: "text" })
    : { findings: emptyFindings(), summary: emptySummary() };
  attachmentsResult.findings = enrichFindingsLocation(
    attachmentsResult.findings,
    { kind: "eml-section", label: "Attachment names" }
  );

  // --- Scan each attachment (M4) ---
  // Each attachment can itself be multipart (an EML attachment contains
  // headers/body/html). We walk the parsed tree and run analyze() per leaf
  // section, then aggregate.
  const attachmentResults = []; // [{ label, sections: { name: scanResult }, structural: [], aggregate: {status, dangerCount, warningCount} }]
  for (const att of attachmentScans || []) {
    if (att.skipped) {
      // No scanning to do; the skip reason was already recorded in extraFindings.
      attachmentResults.push({
        label: att.label,
        filename: att.filename,
        extension: att.extension,
        size: att.size,
        skipped: true,
        skipReason: att.skipReason,
        error: att.error || null,
        sections: {},
        structural: [],
        aggregate: { status: "safe", dangerCount: 0, warningCount: 0, total: 0 },
      });
      continue;
    }

    const subSections = scanParsedContent(att.parsed, att.label, {
      attachmentFilename: att.filename,
    });
    // Enrich with attachment metadata so consumers (and tests) can read it
    // off the same object alongside the scan results.
    subSections.filename = att.filename;
    subSections.extension = att.extension;
    subSections.size = att.size;
    subSections.contentType = att.contentType || null;
    attachmentResults.push(subSections);
  }

  // --- Aggregate summary across top-level + all attachments + structural ---
  const subSummaries = attachmentResults.map((a) => a.aggregate);

  const combinedSummary = {
    status: worstStatus([
      headersResult.summary.status,
      extendedHeadersResult.summary.status,
      bodyResult.summary.status,
      htmlResult.summary.status,
      attachmentsResult.summary.status,
      ...subSummaries.map((s) => s.status),
    ]),
    dangerCount:
      headersResult.summary.dangerCount +
      extendedHeadersResult.summary.dangerCount +
      bodyResult.summary.dangerCount +
      htmlResult.summary.dangerCount +
      attachmentsResult.summary.dangerCount +
      extraFindings.filter((f) => f.severity === "danger").length +
      subSummaries.reduce((a, s) => a + s.dangerCount, 0),
    warningCount:
      headersResult.summary.warningCount +
      extendedHeadersResult.summary.warningCount +
      bodyResult.summary.warningCount +
      htmlResult.summary.warningCount +
      attachmentsResult.summary.warningCount +
      extraFindings.filter((f) => f.severity === "warning").length +
      subSummaries.reduce((a, s) => a + s.warningCount, 0),
  };
  combinedSummary.total =
    combinedSummary.dangerCount + combinedSummary.warningCount;

  // --- Build human-readable report ---
  const reportLines = [
    "=== Shield Scanner Email Report ===",
    `Source: ${eml_path || "(raw text)"}`,
    `Subject: ${metadata.subject || "(none)"}`,
    `From: ${metadata.from || "(none)"}`,
    `Date: ${metadata.date || "(none)"}`,
    `Attachments: ${metadata.attachmentCount}`,
    "",
    `Overall Status: ${combinedSummary.status.toUpperCase()}`,
    `Total findings: ${combinedSummary.total} (danger: ${combinedSummary.dangerCount}, warning: ${combinedSummary.warningCount})`,
    "",
    "--- Headers ---",
    formatReportCompact(headersResult),
    "--- Extended headers (Reply-To / Return-Path / Sender / X-*) ---",
    formatReportCompact(extendedHeadersResult),
    "--- Body ---",
    formatReportCompact(bodyResult),
    "--- HTML part ---",
    formatReportCompact(htmlResult),
    "--- Attachment names ---",
    formatReportCompact(attachmentsResult),
  ];

  for (const a of attachmentResults) {
    reportLines.push(`--- ${a.label} ---`);
    if (a.skipped) {
      reportLines.push(`  (skipped: ${a.skipReason}${a.error ? ` — ${a.error}` : ""})`);
      continue;
    }
    for (const [name, res] of Object.entries(a.sections)) {
      reportLines.push(`  [${name}]`);
      reportLines.push(indent(formatReportCompact(res), 2));
    }
    if (a.structural && a.structural.length > 0) {
      reportLines.push(`  [structural]`);
      for (const f of a.structural) {
        reportLines.push(`    - [${f.severity}] ${f.technique}: ${f.content}`);
      }
    }
  }

  reportLines.push("--- Structural findings (email-specific) ---");
  reportLines.push(
    extraFindings.length === 0
      ? "  (none)"
      : extraFindings
          .map((f) => `  - [${f.severity}] ${f.technique}: ${f.content}`)
          .join("\n")
  );

  const threatsBySection = {
    headers: headersResult.findings,
    extended_headers: extendedHeadersResult.findings,
    body: bodyResult.findings,
    html: htmlResult.findings,
    attachment_names: attachmentsResult.findings,
    structural: extraFindings,
  };

  if (verbosity === "compact") {
    // Build a tiny aggregate without findings arrays — safe to return as the
    // sole payload to an LLM without context blow-up.
    const compact = compactSummary({
      summary: {
        ...combinedSummary,
        // compactSummary prefers byCategory when present; we don't have one at
        // this aggregate level, so let it walk threats_by_section instead.
      },
      threats_by_section: threatsBySection,
    });
    return {
      verbosity: "compact",
      metadata,
      attachment_count: attachmentResults.length,
      ...compact,
    };
  }

  // For "detailed", widen the per-finding context window of every section.
  let sectionsOut = threatsBySection;
  if (verbosity === "detailed") {
    sectionsOut = {
      headers: expandFindingsContext(headersResult.findings, sections.headers || ""),
      extended_headers: expandFindingsContext(
        extendedHeadersResult.findings,
        sections.extendedHeaders || ""
      ),
      body: expandFindingsContext(bodyResult.findings, sections.body || ""),
      html: expandFindingsContext(htmlResult.findings, sections.html || ""),
      attachment_names: expandFindingsContext(
        attachmentsResult.findings,
        sections.attachmentNames || ""
      ),
      structural: extraFindings,
    };
  }

  return {
    verbosity,
    summary: combinedSummary,
    metadata,
    threats_by_section: sectionsOut,
    attachment_scans: attachmentResults.map((a) => ({
      label: a.label,
      filename: a.filename,
      extension: a.extension,
      size: a.size,
      skipped: a.skipped || false,
      skipReason: a.skipReason || null,
      threats_by_section: Object.fromEntries(
        Object.entries(a.sections || {}).map(([k, v]) => [k, v.findings])
      ),
      structural: a.structural || [],
      summary: a.aggregate,
    })),
    report: reportLines.join("\n"),
  };
}

/**
 * Run the detector across whatever shape parsedContent has:
 *   - { sections: { headers, body, html, attachmentNames }, extraFindings }
 *     → recursive EML attachment. Treat sections individually. (Note: we do
 *       NOT walk this attachment's own nested attachments here — that is
 *       handled inside eml.js by recursing parseEmlBuffer with bumped depth,
 *       and currently we surface only the first level of nested-EML sections.
 *       Going deeper would need to descend into att.parsed.attachmentScans
 *       too.)
 *   - { text, fileType, extraFindings }
 *     → leaf file (pdf/docx/pptx/html/text). One analyze() call.
 *
 * Returns: { label, filename, sections, structural, aggregate }
 */
function scanParsedContent(parsedContent, label, opts = {}) {
  const sectionsOut = {};
  const structural = [];
  // The friendly attachment / chain prefix (e.g. "Attachment evil.jpg" or
  // "Attachment L2.eml > attachment[0]: L3.eml") used for contextLocation
  // prefix-join on structural findings emitted by the leaf parser or bubbled
  // up from a nested-EML recursion.
  //
  // Two equivalent ways to supply it:
  //   - opts.attachmentFilename: a bare filename (top-level callers); we
  //     wrap it as "Attachment <filename>" — preserves the historical shape.
  //   - opts.locationPrefix: a fully-formed breadcrumb (recursive callers
  //     pass this so depth-N findings inherit the full chain, fixing
  //     S12-XR-05). Takes precedence over attachmentFilename when both
  //     are set.
  //
  // Falls back to no prefix if neither is supplied.
  const attachmentPrefix =
    opts && typeof opts.locationPrefix === "string" && opts.locationPrefix.length > 0
      ? opts.locationPrefix
      : opts && typeof opts.attachmentFilename === "string" && opts.attachmentFilename.length > 0
      ? `Attachment ${opts.attachmentFilename}`
      : null;

  function pushStructural(extras) {
    if (!extras) return;
    for (const f of extras) {
      if (attachmentPrefix && f && typeof f === "object") {
        const existing = f.contextLocation;
        if (typeof existing === "string" && existing.length > 0) {
          if (existing === attachmentPrefix || existing.startsWith(`${attachmentPrefix} > `)) {
            structural.push(f);
          } else {
            structural.push({ ...f, contextLocation: `${attachmentPrefix} > ${existing}` });
          }
        } else {
          structural.push({ ...f, contextLocation: attachmentPrefix });
        }
      } else {
        structural.push(f);
      }
    }
  }

  // Detect "nested EML" vs leaf file. We can't gate on `parsedContent.sections`
  // alone because non-EML parsers (e.g. parseImage) also return a `sections`
  // dict (imageMetadata: [...]) that's structural-only — none of the
  // EML section keys (headers/body/html/attachmentNames) appear. Without this
  // discrimination, image attachments fall into the EML branch and produce
  // an empty sectionsOut, hiding the actual joined-text analysis.
  const looksLikeEml =
    parsedContent.sections &&
    typeof parsedContent.sections === "object" &&
    ("headers" in parsedContent.sections ||
      "body" in parsedContent.sections ||
      "html" in parsedContent.sections ||
      "attachmentNames" in parsedContent.sections ||
      "extendedHeaders" in parsedContent.sections);

  if (looksLikeEml) {
    // Nested EML
    const s = parsedContent.sections;
    if (s.headers) sectionsOut.headers = analyze(s.headers, { fileType: "text" });
    // S11: extended headers also scanned for nested EMLs
    if (s.extendedHeaders)
      sectionsOut.extended_headers = analyze(s.extendedHeaders, { fileType: "text" });
    if (s.body) sectionsOut.body = analyze(s.body, { fileType: "text" });
    if (s.html) sectionsOut.html = analyze(s.html, { fileType: "html" });
    if (s.attachmentNames)
      sectionsOut.attachment_names = analyze(s.attachmentNames, { fileType: "text" });
    pushStructural(parsedContent.extraFindings);
    // Recurse for nested-EML's own attachments (so depth-2 EML attachments
    // still get their sub-attachments scanned, up to MAX_DEPTH which is
    // enforced inside eml.js).
    //
    // S12-XR-05 fix: when recursing, pass a fully-built `locationPrefix` so
    // the inner pushStructural prefixes leaf findings (image extraFindings,
    // depth-limit warnings, etc.) with the WHOLE chain — not just the
    // immediate parent. Without this, structural findings emitted at depth ≥ 2
    // bubbled up unprefixed (or stuck on the literal "Email > Attachments"
    // set by eml.js's depth-guard) and operators had no breadcrumb to trace
    // which nested attachment they came from.
    if (parsedContent.attachmentScans && parsedContent.attachmentScans.length) {
      for (const sub of parsedContent.attachmentScans) {
        if (sub.skipped) {
          // Surface skip as a structural note on the parent. Route through
          // pushStructural so it inherits the chain prefix too.
          pushStructural([
            {
              element: sub.label,
              technique: `Nested attachment skipped (${sub.skipReason})`,
              content: sub.filename || "(unnamed)",
              severity: "warning",
            },
          ]);
          continue;
        }
        // Build the breadcrumb for the recursive call: outer chain + this
        // sub-attachment's label. When attachmentPrefix is null (caller didn't
        // supply one), we still seed the chain with sub.label so depth-N
        // findings get at least some breadcrumb.
        const childPrefix = attachmentPrefix
          ? `${attachmentPrefix} > ${sub.label}`
          : sub.label;
        const subScan = scanParsedContent(sub.parsed, sub.label, {
          locationPrefix: childPrefix,
        });
        // Flatten into our sectionsOut under a prefixed key so the report
        // shows the path. (e.g. "attachment[0]: nested.eml > headers")
        for (const [k, v] of Object.entries(subScan.sections)) {
          sectionsOut[`${sub.label} > ${k}`] = v;
        }
        // subScan.structural already carries the full chain prefix because
        // we passed locationPrefix into the recursive call — no re-prefix
        // needed here (and re-prefixing would double-up).
        structural.push(...subScan.structural);
      }
    }
  } else {
    // Leaf file
    const fileType = parsedContent.fileType || "text";
    sectionsOut.content = analyze(parsedContent.text || "", { fileType });
    // R12 (S12 R12-IMG-002 fix): if this leaf was an image attachment whose
    // parser flagged decoder-synthesized ranges (XML entities, UTF-16, zlib,
    // IPTC UTF-8 mode), redact matched/context on any suspicious-pattern hit
    // landing inside those ranges. Mirrors the scan-file.js behaviour so
    // an attack image attached to an EML doesn't leak the decoded payload
    // back through email.attachments[i].sections.content.findings.
    if (
      Array.isArray(parsedContent.decodedRanges) &&
      parsedContent.decodedRanges.length > 0
    ) {
      redactDecodedFindings(
        sectionsOut.content.findings,
        parsedContent.decodedRanges
      );
    }
    pushStructural(parsedContent.extraFindings);
  }

  // Aggregate
  const sectionSummaries = Object.values(sectionsOut).map((r) => r.summary);
  const dangerCount =
    sectionSummaries.reduce((a, s) => a + s.dangerCount, 0) +
    structural.filter((f) => f.severity === "danger").length;
  const warningCount =
    sectionSummaries.reduce((a, s) => a + s.warningCount, 0) +
    structural.filter((f) => f.severity === "warning").length;
  const aggregate = {
    status: worstStatus(sectionSummaries.map((s) => s.status).concat(
      dangerCount > 0 ? ["danger"] : warningCount > 0 ? ["warning"] : ["safe"]
    )),
    dangerCount,
    warningCount,
    total: dangerCount + warningCount,
  };

  return {
    label,
    sections: sectionsOut,
    structural,
    aggregate,
  };
}

function indent(text, n) {
  const pad = " ".repeat(n);
  return text
    .split("\n")
    .map((l) => pad + l)
    .join("\n");
}

function emptyFindings() {
  return {
    invisibleUnicode: [],
    controlChars: [],
    hiddenHtml: [],
    suspiciousPatterns: [],
    homoglyphs: [],
  };
}

function emptySummary() {
  return {
    status: "safe",
    total: 0,
    dangerCount: 0,
    warningCount: 0,
    byCategory: {
      invisibleUnicode: 0,
      controlChars: 0,
      hiddenHtml: 0,
      suspiciousPatterns: 0,
      homoglyphs: 0,
    },
  };
}

function worstStatus(statuses) {
  if (statuses.includes("danger")) return "danger";
  if (statuses.includes("warning")) return "warning";
  return "safe";
}

function formatReportCompact(result) {
  const { summary, findings } = result;
  if (summary.total === 0) return "  (clean)";
  const lines = [
    `  Status: ${summary.status}, findings: ${summary.total}`,
  ];
  for (const [cat, items] of Object.entries(findings)) {
    if (items.length === 0) continue;
    lines.push(`  [${cat}] ${items.length}:`);
    for (const item of items.slice(0, 5)) {
      const desc =
        item.pattern ||
        item.technique ||
        item.name ||
        (item.original && `${item.original} -> ${item.replacement}`) ||
        "(unknown)";
      lines.push(`    - ${desc}`);
    }
    if (items.length > 5) {
      lines.push(`    ...and ${items.length - 5} more`);
    }
  }
  return lines.join("\n");
}
