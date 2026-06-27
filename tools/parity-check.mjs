#!/usr/bin/env node
/**
 * parity-check.mjs (Step 8 — Web route wired)
 *
 * Runs every attack fixture through both:
 *   - MCP route : packages/mcp/server/tools/scan-text.js -> @shield-scanner/core
 *                 (analyze called with no env injected = Node fs fallback)
 *   - Web route : @shield-scanner/core analyze() called AFTER injecting the
 *                 Web env (rulesLoader = createWebRulesLoader). This is the
 *                 same code path the browser bundle takes for the analyze
 *                 surface (DOMParser is not required because the html parser
 *                 adapter is currently only wired through cheerio in
 *                 hidden-elements.js — see html-parser.js comment).
 *
 * Then diffs the results to detect parity drift between routes.
 *
 * Exit code:
 *   0  = no drift
 *   1  = drift detected (or other failure)
 *
 * Output:
 *   summary line + (on drift) per-fixture diff dumped to stderr
 *
 * Env hooks (testing):
 *   SHIELD_PARITY_INJECT_BUG=1   force a synthetic diff on fixture 01 (proves
 *                                the drift detector still fires)
 */

import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

import { scanText as scanTextMcp } from "../packages/mcp/server/tools/scan-text.js";
import { analyze } from "@shield-scanner/core";
import { setEnv, resetEnv } from "@shield-scanner/core/env";
import { createWebRulesLoader } from "@shield-scanner/core/env/web";

// S13 archive parity: MCP-side parseArchiveBuffer + Web-side parseArchiveBuffer
// are exercised directly on .zip fixtures. Their shapes differ (MCP returns
// {text, extraFindings, archiveSummary}; Web returns {text, hiddenFindings,
// archive}), but the canonical fingerprint we compare is the normalized list
// of {category, severity, technique} triples + the archive summary counters.
import { parseArchiveBuffer as parseArchiveBufferMcp } from "../packages/mcp/server/parsers/archive.js";
import { parseArchiveBuffer as parseArchiveBufferWeb } from "../packages/web/src/parsers-web/archive.js";
import JSZip from "jszip";

// Theme D (v1.10.0) — PDF struct-tree parity: MCP parsePdfBuffer() + Web
// parsePdf() are exercised on tagged-PDF fixtures whose StructTreeRoot
// contains a Figure element with an /Alt payload. The fingerprint is the
// normalized {text-derived structtree headers, extraFindings} pair — see
// `runPdfStructParity()` below.
import { parsePdfBuffer as parsePdfBufferMcp } from "../packages/mcp/server/parsers/pdf.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const FIXTURE_DIR = resolve(
  __dirname,
  "..",
  "packages",
  "mcp",
  "test",
  "fixtures",
  "attacks",
);

// ─── Web route ─────────────────────────────────────────────────────────────
// We inject ONLY the rulesLoader (no DOMParser-backed htmlParser) because
// the analyze() surface that hits this parity check resolves HTML via cheerio
// inside hidden-elements.js — see html-parser.js for the migration note.
// This keeps the parity check runnable under Node while still routing rule
// lookups through the Web-side bundled JSON modules.
function buildWebEnv() {
  return { rulesLoader: createWebRulesLoader() };
}

async function scanTextWeb({ text }, fixtureName) {
  resetEnv();
  setEnv(buildWebEnv());
  try {
    // Mirror scan-text.js: auto-detect HTML so fileType matches MCP route.
    const fileType = /<[a-z][\s\S]*>/i.test(text) ? "html" : "text";
    const result = analyze(text, { fileType });
    const shaped = {
      verbosity: "normal",
      summary: result.summary,
      findings: result.findings,
    };

    if (
      process.env.SHIELD_PARITY_INJECT_BUG === "1" &&
      fixtureName === "01-zwsp-injection.txt"
    ) {
      return {
        ...shaped,
        summary: { ...shaped.summary, total: -999 },
      };
    }
    return shaped;
  } finally {
    resetEnv();
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────
function flattenFindings(findings) {
  if (!findings || typeof findings !== "object") return [];
  const out = [];
  for (const category of Object.keys(findings).sort()) {
    const list = findings[category];
    if (!Array.isArray(list)) continue;
    for (const f of list) {
      // Preserve the full finding for deep-equal (everything except volatile
      // text/report fields, which we don't include here). Sort by category
      // then position so order is deterministic across routes.
      out.push({ category, ...f });
    }
  }
  out.sort((a, b) => {
    if (a.category !== b.category) return a.category < b.category ? -1 : 1;
    const pa = a.position ?? a.index ?? 0;
    const pb = b.position ?? b.index ?? 0;
    return pa - pb;
  });
  return out;
}

function normalizeForCompare(result) {
  // Strip volatile fields (timestamps, formatted report) so the comparison
  // stays meaningful across MCP and Web routes. Keep the full per-finding
  // shape (categories, severity, position, name, message, etc.) for a real
  // deep-equal.
  return {
    summary: {
      status: result.summary?.status,
      total: result.summary?.total,
      dangerCount: result.summary?.dangerCount,
      warningCount: result.summary?.warningCount,
      byCategory: result.summary?.byCategory,
    },
    findings: flattenFindings(result.findings),
  };
}

function countFindings(result) {
  if (typeof result.summary?.total === "number") return result.summary.total;
  return flattenFindings(result.findings).length;
}

function diffResults(a, b) {
  const sa = JSON.stringify(normalizeForCompare(a));
  const sb = JSON.stringify(normalizeForCompare(b));
  if (sa === sb) return null;
  return { mcp: sa, web: sb };
}

// ─── S13 Archive parity ────────────────────────────────────────────────────
// MCP parser returns {text, fileType, extraFindings, archiveSummary}.
// Web parser returns {text, hiddenFindings, archive, fileType}.
// We fold both shapes into a normalized
//   {summary: {scanned,bomb,depth,protected,entryCap},
//    findings: [{category,severity,technique}, ...]}
// fingerprint and deep-equal compare. Bracket-prefix in `content` and
// `contextLocation` is detector-controlled but differs in detail wording
// across MCP/Web, so we compare on the (category, severity, technique)
// triple — the SAME compromise the smoke + harness layers use.
// {dir, file}: archive fixtures live in packages/mcp/test/fixtures/{attacks,benign}/.
const ARCHIVE_FIXTURES = [
  { dir: "benign", file: "archive_benign_single_txt.zip" },
  { dir: "attacks", file: "archive_zip_bomb_high_ratio.zip" },
  { dir: "attacks", file: "archive_path_traversal_dotdot.zip" },
  { dir: "attacks", file: "archive_suspicious_ext_exe.zip" },
];
const ARCHIVE_FIXTURE_ROOT = resolve(
  __dirname,
  "..",
  "packages",
  "mcp",
  "test",
  "fixtures",
);

function normalizeArchiveSummary(s) {
  if (!s) return null;
  return {
    scanned: s.scanned || 0,
    bomb: s.bomb || 0,
    depth: s.depth || 0,
    protected: s.protected || 0,
    entryCap: s.entryCap || 0,
  };
}

// MCP and Web archive parsers carry intentionally distinct UX wording on
// `technique` (the strings surface in user-facing reports and i18n diverges).
// Parity for S13 is therefore defined on the structural triple
//   (category, severity, AR-rule kind)
// where AR-rule kind is a fingerprint extracted from the technique string —
// e.g. "zip-slip", "suspicious-ext", "bomb-ratio", "depth-cap".
// This keeps the safety contract (same logical detection on both routes) while
// allowing the two parsers' wording to evolve independently.
function _archiveRuleKind(tech) {
  const t = String(tech || "").toLowerCase();
  if (/zip.?slip|path.?traversal|path escape/.test(t)) return "zip-slip";
  if (/(suspicious.*entry|entry.*suspicious|dangerous.*ext)/.test(t)) return "suspicious-ext";
  if (/compression ratio|zip-bomb|zip bomb|bomb threshold|bomb suspect|total uncompressed|total decompressed/.test(t))
    return "bomb";
  if (/depth/.test(t)) return "depth-cap";
  if (/encrypted/.test(t)) return "encrypted";
  if (/missing zip magic/.test(t)) return "no-magic";
  if (/entry count/.test(t)) return "entry-count-cap";
  if (/office package|content_types/.test(t)) return "office-rename";
  if (/per-entry|per entry/.test(t)) return "per-entry-cap";
  if (/load failed|corrupt|unsupported/.test(t)) return "parse-error";
  if (/buffer >|exceeds scan limits/.test(t)) return "buffer-shortcircuit";
  return "other";
}

function normalizeArchiveFindings(findings) {
  if (!Array.isArray(findings)) return [];
  const out = findings.map((f) => ({
    category: f.category || "",
    severity: f.severity || "",
    kind: _archiveRuleKind(f.technique),
  }));
  out.sort((a, b) => {
    if (a.category !== b.category) return a.category < b.category ? -1 : 1;
    if (a.severity !== b.severity) return a.severity < b.severity ? -1 : 1;
    return a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0;
  });
  return out;
}

function normalizeArchiveResult(result, route) {
  const findings = route === "mcp" ? result.extraFindings : result.hiddenFindings;
  const summary = route === "mcp" ? result.archiveSummary : result.archive;
  return {
    summary: normalizeArchiveSummary(summary),
    findings: normalizeArchiveFindings(findings),
  };
}

function diffArchiveResults(mcp, web, fixtureName) {
  let mcpNorm = normalizeArchiveResult(mcp, "mcp");
  let webNorm = normalizeArchiveResult(web, "web");

  // Background-truth synthetic drift — verifies the archive diff detector
  // still fires when something genuinely changes.
  if (
    process.env.SHIELD_PARITY_INJECT_BUG === "1" &&
    fixtureName === "archive_benign_single_txt.zip"
  ) {
    webNorm = { ...webNorm, summary: { ...webNorm.summary, bomb: 999 } };
  }

  const sa = JSON.stringify(mcpNorm);
  const sb = JSON.stringify(webNorm);
  if (sa === sb) return null;
  return { mcp: sa, web: sb };
}

async function runArchiveParity() {
  // Web parser uses globalThis.JSZip (CDN-loaded in the browser build).
  // Install the Node-resolved JSZip onto globalThis so parsers-web/archive.js
  // resolves it the same way at call-time.
  const prevJSZip = globalThis.JSZip;
  globalThis.JSZip = JSZip;
  try {
    let totalMcp = 0;
    let totalWeb = 0;
    let drift = 0;
    const driftDetails = [];

    for (const { dir, file } of ARCHIVE_FIXTURES) {
      const buffer = await readFile(join(ARCHIVE_FIXTURE_ROOT, dir, file));
      resetEnv();
      const mcpResult = await parseArchiveBufferMcp(buffer, { depth: 0 });
      const webResult = await parseArchiveBufferWeb(buffer, { depth: 0 });

      totalMcp += (mcpResult.extraFindings || []).length;
      totalWeb += (webResult.hiddenFindings || []).length;

      const d = diffArchiveResults(mcpResult, webResult, file);
      if (d) {
        drift += 1;
        driftDetails.push({ fixture: `${dir}/${file}`, ...d });
      }
    }

    return { count: ARCHIVE_FIXTURES.length, totalMcp, totalWeb, drift, driftDetails };
  } finally {
    if (prevJSZip === undefined) {
      delete globalThis.JSZip;
    } else {
      globalThis.JSZip = prevJSZip;
    }
  }
}

// ─── Theme D (v1.10.0): PDF struct-tree parity ─────────────────────────────
// MCP parsePdfBuffer() and Web parsePdf() both emit
//   `[PDF page=N kind=structtree role=R field=Alt] <body>`
// headers into their .text channel when a tagged PDF carries a Figure struct
// element with /Alt. Parity here is defined as:
//   1. The sorted list of structtree headers extracted from .text matches
//      byte-for-byte across the two routes.
//   2. The normalized (category, severity, technique) triples in
//      extraFindings / hiddenFindings match.
// This is intentionally narrower than the text-fixture diff: page content
// streams pdf.js extracts on the two routes can differ in whitespace and
// font-fallback rendering, so we don't compare the page text body itself —
// only the detector-controlled structtree headers + extraFinding triples.
const PDF_STRUCT_FIXTURES = [
  { dir: "benign", file: "pdf_struct_benign.pdf" },
  { dir: "attacks", file: "pdf_struct_attack_instructions.pdf" },
  // v1.12.0 Theme D additions
  { dir: "benign", file: "pdf_struct_formula_benign.pdf" },
  { dir: "attacks", file: "pdf_struct_depth_boundary_attack.pdf" },
  // v1.13.0: Form role + longer UI descriptor coverage.
  { dir: "benign", file: "pdf_struct_form_benign.pdf" },
  // v1.15.0 Theme C: Sect / L / Table role coverage. Narrower fingerprint
  // (kind=structtree match) is role-agnostic so these ride the existing
  // extractStructTreeHeaders / normalizePdfFindings contract — R22 preserved.
  { dir: "benign", file: "pdf_struct_section_benign.pdf" },
  { dir: "benign", file: "pdf_struct_list_benign.pdf" },
  { dir: "attacks", file: "pdf_struct_table_attack.pdf" },
  // v1.16.0 Theme T-B: Caption / TOC / TOCI / Index / LI / Note coverage.
  // 4 benign + 3 attack fixtures, each single-leaf depth=1. The narrower
  // fingerprint (R22) is role-agnostic by construction (greps 'kind=structtree'
  // literal, not role= value), so new roles auto-lift without code changes.
  // R13 fold: all 7 fixtures stay within the 5 existing byCategory buckets —
  // the only struct-tree extraFinding technique remains 'struct-tree-cap-
  // exceeded' (untripped in all 7 new fixtures), so the (category, severity,
  // technique) triple sets stay byte-identical across MCP and Web routes.
  { dir: "benign", file: "pdf_struct_caption_benign.pdf" },
  { dir: "attacks", file: "pdf_struct_caption_attack.pdf" },
  { dir: "benign", file: "pdf_struct_toc_benign.pdf" },
  { dir: "attacks", file: "pdf_struct_toci_attack.pdf" },
  { dir: "benign", file: "pdf_struct_index_benign.pdf" },
  { dir: "benign", file: "pdf_struct_li_benign.pdf" },
  { dir: "attacks", file: "pdf_struct_note_attack.pdf" },
  // v1.19.0 A3: H1-H6 heading + BlockQuote / Quote / Span role coverage. 9
  // attack + 3 benign = 12 fixtures, each single-leaf depth=1. The narrower
  // fingerprint (R22) is role-agnostic by construction (greps 'kind=structtree'
  // literal, not role= value), so new roles auto-lift without code changes.
  // R13 fold: all 12 fixtures stay within the 5 existing byCategory buckets —
  // the only struct-tree extraFinding technique remains 'struct-tree-cap-
  // exceeded' (untripped in all 12 new fixtures), so the (category, severity,
  // technique) triple sets stay byte-identical across MCP and Web routes.
  { dir: "attacks", file: "pdf_struct_h1_attack.pdf" },
  { dir: "attacks", file: "pdf_struct_h2_attack.pdf" },
  { dir: "attacks", file: "pdf_struct_h3_attack.pdf" },
  { dir: "attacks", file: "pdf_struct_h4_attack.pdf" },
  { dir: "attacks", file: "pdf_struct_h5_attack.pdf" },
  { dir: "attacks", file: "pdf_struct_h6_attack.pdf" },
  { dir: "attacks", file: "pdf_struct_blockquote_attack.pdf" },
  { dir: "attacks", file: "pdf_struct_quote_attack.pdf" },
  { dir: "attacks", file: "pdf_struct_span_attack.pdf" },
  { dir: "benign", file: "pdf_struct_h1_legit_doc.pdf" },
  { dir: "benign", file: "pdf_struct_blockquote_legit.pdf" },
  { dir: "benign", file: "pdf_struct_span_legit.pdf" },
  // v1.18.0 S16: 6 attack + 2 benign non-JS high-risk action / multimedia
  // fixtures. The narrower fingerprint (R22) compares normalized
  // (category, severity, technique) triples in extraFindings, which
  // covers the new pdf-{submit-form,goto-remote,richmedia,3d,sound,movie}
  // signals byte-identically across MCP and Web routes. RichMedia / 3D /
  // Sound / Movie attacks DO emit the kebab through the real pdfjs path;
  // SubmitForm / GoToR attacks are silent in pdf.js v4 (no triple emitted)
  // and therefore byte-identical across routes by construction. R13 fold
  // stays clean because every new extraFinding rides 'suspiciousPatterns'.
  { dir: "attacks", file: "pdf_s16_submit_form_attack.pdf" },
  { dir: "attacks", file: "pdf_s16_goto_remote_attack.pdf" },
  { dir: "attacks", file: "pdf_s16_richmedia_attack.pdf" },
  { dir: "attacks", file: "pdf_s16_3d_attack.pdf" },
  { dir: "attacks", file: "pdf_s16_sound_attack.pdf" },
  { dir: "attacks", file: "pdf_s16_movie_attack.pdf" },
  { dir: "benign", file: "pdf_s16_widget_no_action_benign.pdf" },
  { dir: "benign", file: "pdf_s16_plain_text_benign.pdf" },
];
const PDF_FIXTURE_ROOT = ARCHIVE_FIXTURE_ROOT;

function extractStructTreeHeaders(text) {
  if (typeof text !== "string" || !text) return [];
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("[PDF ") && line.includes("kind=structtree")) {
      out.push(line);
    }
  }
  out.sort();
  return out;
}

function normalizePdfFindings(findings) {
  if (!Array.isArray(findings)) return [];
  const out = findings.map((f) => ({
    category: f.category || "",
    severity: f.severity || "",
    technique: String(f.technique || ""),
  }));
  out.sort((a, b) => {
    if (a.category !== b.category) return a.category < b.category ? -1 : 1;
    if (a.severity !== b.severity) return a.severity < b.severity ? -1 : 1;
    return a.technique < b.technique ? -1 : a.technique > b.technique ? 1 : 0;
  });
  return out;
}

function normalizePdfStructResult(result, route) {
  const findings = route === "mcp" ? result.extraFindings : result.hiddenFindings;
  return {
    structHeaders: extractStructTreeHeaders(result.text),
    findings: normalizePdfFindings(findings),
  };
}

function diffPdfStructResults(mcp, web, fixtureName) {
  let mcpNorm = normalizePdfStructResult(mcp, "mcp");
  let webNorm = normalizePdfStructResult(web, "web");
  if (
    process.env.SHIELD_PARITY_INJECT_BUG === "1" &&
    fixtureName === "pdf_struct_benign.pdf"
  ) {
    webNorm = {
      ...webNorm,
      structHeaders: [...webNorm.structHeaders, "[PDF synthetic-bug header]"],
    };
  }
  const sa = JSON.stringify(mcpNorm);
  const sb = JSON.stringify(webNorm);
  if (sa === sb) return null;
  return { mcp: sa, web: sb };
}

async function runPdfStructParity() {
  // Web parser uses globalThis.pdfjsLib (CDN-loaded in the browser build).
  // Install the Node-resolved pdfjs-dist legacy build onto globalThis so
  // parsers-web/pdf.js resolves it the same way it would in a browser tab.
  const prevPdfjs = globalThis.pdfjsLib;
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  globalThis.pdfjsLib = pdfjs;

  // R18 (env-abstract order contract): set Web env BEFORE the dynamic import
  // of parsers-web/pdf.js so module-side rule loads see the bundled rules
  // loader. Matches the runPdfStructParity ordering used by the harness.
  resetEnv();
  setEnv(buildWebEnv());
  let parsePdfWeb;
  try {
    ({ parsePdf: parsePdfWeb } = await import(
      "../packages/web/src/parsers-web/pdf.js"
    ));
  } finally {
    // Leave env set for the actual scans below; we'll reset at the end. (The
    // module import only needed the env at module-evaluation time; the parser
    // call itself doesn't read setEnv state, but we're conservative.)
  }

  try {
    let totalMcp = 0;
    let totalWeb = 0;
    let drift = 0;
    const driftDetails = [];

    for (const { dir, file } of PDF_STRUCT_FIXTURES) {
      const buffer = await readFile(join(PDF_FIXTURE_ROOT, dir, file));
      // Cycle env between routes: MCP path doesn't need the Web env, but
      // resetting keeps each fixture's measurement independent.
      resetEnv();
      const mcpResult = await parsePdfBufferMcp(buffer);
      setEnv(buildWebEnv());
      const webResult = await parsePdfWeb(buffer);

      totalMcp += (mcpResult.extraFindings || []).length;
      totalWeb += (webResult.hiddenFindings || []).length;

      const d = diffPdfStructResults(mcpResult, webResult, file);
      if (d) {
        drift += 1;
        driftDetails.push({ fixture: `${dir}/${file}`, ...d });
      }
    }

    return {
      count: PDF_STRUCT_FIXTURES.length,
      totalMcp,
      totalWeb,
      drift,
      driftDetails,
    };
  } finally {
    resetEnv();
    if (prevPdfjs === undefined) {
      delete globalThis.pdfjsLib;
    } else {
      globalThis.pdfjsLib = prevPdfjs;
    }
  }
}

// ─── v1.18.0 Follina — Office (DOCX/PPTX) parity ───────────────────────────
// MCP parseDocxBuffer / parsePptxBuffer vs Web parseDocx / parsePptx must
// agree on the (category, severity, technique) triple set for the v1.18.0
// Follina kebab ids (docx-attached-template-remote /
// docx-websettings-external-load / docx-customxml-instruction /
// office-embedded-ole-cfb / pptx-attached-template-remote). The fingerprint
// is intentionally narrower than the text-fixture diff — meta.templateUrl
// is sanitized differently across routes only in label dictionaries, not
// in the parser output, so triple-equality covers the contract.
//
// {dir, file, parser}: parser='docx'|'pptx' selects which loader pair.
import { parseDocxBuffer as parseDocxBufferMcp } from "../packages/mcp/server/parsers/docx.js";
import { parsePptxBuffer as parsePptxBufferMcp } from "../packages/mcp/server/parsers/pptx.js";

// v1.18.0 Theme — XLSX deep-execution surface parity. MCP parseXlsxBuffer +
// Web parseXlsx run on the new attack + benign corpus added in v1.18.0
// (Power Query / data connection / ActiveX / customUI), folded into the same
// drift counter as PDF / archive / office-follina sections.
import { parseXlsxBuffer as parseXlsxBufferMcp } from "../packages/mcp/server/parsers/xlsx.js";

// v1.19.0 B1 — Polyglot-SVG parity. MCP parseSvgBuffer + Web parseSvg run on
// the shared SVG corpus (6 attack + 2 benign). Drift counter is shared with
// the rest of the parity-check; (category, severity, technique) triple
// equality on the polyglot kebab ids is the contract.
import { parseSvgBuffer as parseSvgBufferMcp } from "../packages/mcp/server/parsers/svg.js";

// v1.19.0 B2 — RTF parity. MCP parseRtfBuffer / Web parseRtf surface 6 kebab
// ids (rtf-ole-object / rtf-field-hyperlink / rtf-hidden-text-v / rtf-
// microscopic-font / rtf-binary-block / rtf-unknown-destination) on the
// shared mcp/test/fixtures/{attacks,benign}/rtf_*.rtf corpus. Parity is the
// normalized (category, severity, technique) triple set — same fingerprint
// shape as the SVG / office-follina / xlsx-deep sections above.
import { parseRtfBuffer as parseRtfBufferMcp } from "../packages/mcp/server/parsers/rtf.js";

// v1.19.0 B3 — Jupyter Notebook (.ipynb) parity. MCP parseIpynbBuffer /
// Web parseIpynb cover the 4 kebab ids (ipynb-output-html-injection /
// ipynb-hidden-cell-instruction / ipynb-metadata-tag-smuggle /
// ipynb-untrusted-signature) on the shared mcp/test/fixtures/{attacks,benign}/
// ipynb_*.ipynb corpus. Same (category, severity, technique) triple shape as
// SVG / RTF / office sections above.
import { parseIpynbBuffer as parseIpynbBufferMcp } from "../packages/mcp/server/parsers/ipynb.js";

const OFFICE_FOLLINA_FIXTURES = [
  { dir: "attacks", file: "docx_attached_template_remote.docx", parser: "docx" },
  { dir: "attacks", file: "docx_websettings_external_frame.docx", parser: "docx" },
  { dir: "attacks", file: "docx_customxml_item_instruction.docx", parser: "docx" },
  { dir: "attacks", file: "docx_embedded_ole_cfb.docx", parser: "docx" },
  { dir: "attacks", file: "pptx_attached_template_remote.pptx", parser: "pptx" },
  { dir: "attacks", file: "pptx_embedded_ole_equation.pptx", parser: "pptx" },
  { dir: "benign", file: "benign_docx_legit_local_dotm.docx", parser: "docx" },
  { dir: "benign", file: "benign_docx_customxml_sharepoint.docx", parser: "docx" },
];
const OFFICE_FIXTURE_ROOT = ARCHIVE_FIXTURE_ROOT;

function normalizeOfficeFindings(findings) {
  if (!Array.isArray(findings)) return [];
  const out = findings.map((f) => ({
    category: f.category || "",
    severity: f.severity || "",
    technique: String(f.technique || ""),
  }));
  out.sort((a, b) => {
    if (a.category !== b.category) return a.category < b.category ? -1 : 1;
    if (a.severity !== b.severity) return a.severity < b.severity ? -1 : 1;
    return a.technique < b.technique ? -1 : a.technique > b.technique ? 1 : 0;
  });
  return out;
}

function diffOfficeResults(mcp, web) {
  const mcpNorm = normalizeOfficeFindings(mcp.extraFindings);
  const webNorm = normalizeOfficeFindings(web.hiddenFindings);
  const sa = JSON.stringify(mcpNorm);
  const sb = JSON.stringify(webNorm);
  if (sa === sb) return null;
  return { mcp: sa, web: sb };
}

// v1.18.0 XLSX deep-execution fixtures. Strict (category, severity, technique)
// triple parity — MCP and Web ship byte-identical scanners for the 4 new
// kebab ids + the v5 oleLink / oversize-embedded-object bridges.
const XLSX_DEEP_FIXTURES = [
  { dir: "attacks", file: "xlsx_power_query_webcontents.xlsx" },
  { dir: "attacks", file: "xlsx_data_connection_oledb_cmd.xlsx" },
  { dir: "attacks", file: "xlsx_activex_equation_editor.xlsx" },
  { dir: "attacks", file: "xlsx_custom_ui_onload_callback.xlsx" },
  { dir: "benign", file: "benign_xlsx_legit_connections_https.xlsx" },
  { dir: "benign", file: "benign_xlsx_pivot_table_query.xlsx" },
];

function diffXlsxResults(mcp, web) {
  // Reuse normalizeOfficeFindings — same (category, severity, technique)
  // triple shape — defined just above in the office-follina section.
  const mcpNorm = normalizeOfficeFindings(mcp.extraFindings);
  const webNorm = normalizeOfficeFindings(web.hiddenFindings);
  const sa = JSON.stringify(mcpNorm);
  const sb = JSON.stringify(webNorm);
  if (sa === sb) return null;
  return { mcp: sa, web: sb };
}

async function runXlsxDeepParity() {
  // Web parser uses globalThis.JSZip — install the Node-resolved JSZip so
  // parsers-web/xlsx.js loadAsync resolves the same way it does in browser.
  const prevJSZip = globalThis.JSZip;
  globalThis.JSZip = JSZip;
  resetEnv();
  setEnv(buildWebEnv());
  let parseXlsxWeb;
  try {
    ({ parseXlsx: parseXlsxWeb } = await import(
      "../packages/web/src/parsers-web/xlsx.js"
    ));
  } finally {
    // Leave env set; reset at the end.
  }
  try {
    let totalMcp = 0;
    let totalWeb = 0;
    let drift = 0;
    const driftDetails = [];

    for (const { dir, file } of XLSX_DEEP_FIXTURES) {
      const buffer = await readFile(join(OFFICE_FIXTURE_ROOT, dir, file));
      resetEnv();
      const mcpResult = await parseXlsxBufferMcp(buffer);
      setEnv(buildWebEnv());
      const webResult = await parseXlsxWeb(buffer);

      totalMcp += (mcpResult.extraFindings || []).length;
      totalWeb += (webResult.hiddenFindings || []).length;

      const d = diffXlsxResults(mcpResult, webResult);
      if (d) {
        drift += 1;
        driftDetails.push({ fixture: `${dir}/${file}`, ...d });
      }
    }

    return {
      count: XLSX_DEEP_FIXTURES.length,
      totalMcp,
      totalWeb,
      drift,
      driftDetails,
    };
  } finally {
    resetEnv();
    if (prevJSZip === undefined) {
      delete globalThis.JSZip;
    } else {
      globalThis.JSZip = prevJSZip;
    }
  }
}

// ─── v1.19.0 B1 — Polyglot-SVG parity ──────────────────────────────────────
// MCP parseSvgBuffer / Web parseSvg surface 6 polyglot kebab ids
// (svg-script-element / svg-event-handler / svg-javascript-href /
//  svg-foreignobject-html / svg-cdata-section / svg-use-external-ref) on
// the shared mcp/test/fixtures/{attacks,benign}/svg_*.svg corpus. Parity is
// defined on the normalized (category, severity, technique) triple set —
// same fingerprint shape as the office-follina and xlsx-deep sections.
const SVG_FIXTURES = [
  { dir: "attacks", file: "svg_script_tag.svg" },
  { dir: "attacks", file: "svg_onerror_handler.svg" },
  { dir: "attacks", file: "svg_javascript_href.svg" },
  { dir: "attacks", file: "svg_foreignobject_prompt.svg" },
  { dir: "attacks", file: "svg_cdata_instruction.svg" },
  { dir: "attacks", file: "svg_use_external_ref.svg" },
  { dir: "benign", file: "benign_svg_logo.svg" },
  { dir: "benign", file: "benign_svg_inline_style.svg" },
];

function diffSvgResults(mcp, web) {
  // Reuse normalizeOfficeFindings — same (category, severity, technique)
  // triple shape. MCP carries `extraFindings`; Web carries `hiddenFindings`.
  const mcpNorm = normalizeOfficeFindings(mcp.extraFindings);
  const webNorm = normalizeOfficeFindings(web.hiddenFindings);
  const sa = JSON.stringify(mcpNorm);
  const sb = JSON.stringify(webNorm);
  if (sa === sb) return null;
  return { mcp: sa, web: sb };
}

async function runSvgParity() {
  // SVG parsers have no native binary deps (no JSZip / pdfjs), so plumbing is
  // minimal: import the Web parser once, iterate fixtures, diff the triples.
  resetEnv();
  setEnv(buildWebEnv());
  let parseSvgWeb;
  try {
    ({ parseSvg: parseSvgWeb } = await import(
      "../packages/web/src/parsers-web/svg.js"
    ));
  } finally {
    // Leave env set for the actual scans; reset at the end.
  }
  try {
    let totalMcp = 0;
    let totalWeb = 0;
    let drift = 0;
    const driftDetails = [];

    for (const { dir, file } of SVG_FIXTURES) {
      const buffer = await readFile(join(OFFICE_FIXTURE_ROOT, dir, file));
      resetEnv();
      const mcpResult = await parseSvgBufferMcp(buffer);
      setEnv(buildWebEnv());
      const webResult = await parseSvgWeb(buffer);

      totalMcp += (mcpResult.extraFindings || []).length;
      totalWeb += (webResult.hiddenFindings || []).length;

      const d = diffSvgResults(mcpResult, webResult);
      if (d) {
        drift += 1;
        driftDetails.push({ fixture: `${dir}/${file}`, ...d });
      }
    }

    return {
      count: SVG_FIXTURES.length,
      totalMcp,
      totalWeb,
      drift,
      driftDetails,
    };
  } finally {
    resetEnv();
  }
}

// ─── v1.19.0 B2 — RTF parity ───────────────────────────────────────────────
// 5 attack + 2 benign fixtures. Each MCP+Web pair must agree on the
// normalized (category, severity, technique) triple set — kebab id leak /
// R12 violation / R13 fold mistake all exit non-zero exactly the same way
// the SVG / office / xlsx-deep sections do.
const RTF_FIXTURES = [
  { dir: "attacks", file: "rtf_objdata_ole.rtf" },
  { dir: "attacks", file: "rtf_field_hyperlink_exfil.rtf" },
  { dir: "attacks", file: "rtf_hidden_v_instruction.rtf" },
  { dir: "attacks", file: "rtf_microscopic_fs6.rtf" },
  { dir: "attacks", file: "rtf_bin_payload.rtf" },
  { dir: "benign", file: "benign_rtf_plain_letter.rtf" },
  { dir: "benign", file: "benign_rtf_with_image.rtf" },
];

function diffRtfResults(mcp, web) {
  // Reuse normalizeOfficeFindings — same (category, severity, technique)
  // triple shape. MCP carries `extraFindings`; Web carries `hiddenFindings`.
  const mcpNorm = normalizeOfficeFindings(mcp.extraFindings);
  const webNorm = normalizeOfficeFindings(web.hiddenFindings);
  const sa = JSON.stringify(mcpNorm);
  const sb = JSON.stringify(webNorm);
  if (sa === sb) return null;
  return { mcp: sa, web: sb };
}

async function runRtfParity() {
  // RTF parsers have no native binary deps (no JSZip / pdfjs), so plumbing is
  // minimal: import the Web parser once, iterate fixtures, diff the triples.
  resetEnv();
  setEnv(buildWebEnv());
  let parseRtfWeb;
  try {
    ({ parseRtf: parseRtfWeb } = await import(
      "../packages/web/src/parsers-web/rtf.js"
    ));
  } finally {
    // Leave env set for the actual scans; reset at the end.
  }
  try {
    let totalMcp = 0;
    let totalWeb = 0;
    let drift = 0;
    const driftDetails = [];

    for (const { dir, file } of RTF_FIXTURES) {
      const buffer = await readFile(join(OFFICE_FIXTURE_ROOT, dir, file));
      resetEnv();
      const mcpResult = await parseRtfBufferMcp(buffer);
      setEnv(buildWebEnv());
      const webResult = await parseRtfWeb(buffer);

      totalMcp += (mcpResult.extraFindings || []).length;
      totalWeb += (webResult.hiddenFindings || []).length;

      const d = diffRtfResults(mcpResult, webResult);
      if (d) {
        drift += 1;
        driftDetails.push({ fixture: `${dir}/${file}`, ...d });
      }
    }

    return {
      count: RTF_FIXTURES.length,
      totalMcp,
      totalWeb,
      drift,
      driftDetails,
    };
  } finally {
    resetEnv();
  }
}

// ─── v1.19.0 B3 — Jupyter Notebook (.ipynb) parity ────────────────────────
// 4 attack + 2 benign fixtures. Each MCP+Web pair must agree on the
// normalized (category, severity, technique) triple set — kebab id leak,
// R12 violation, R13 fold mistake all exit non-zero the same way the
// other parser sections do.
const IPYNB_FIXTURES = [
  { dir: "attacks", file: "ipynb_output_html_injection.ipynb" },
  { dir: "attacks", file: "ipynb_hide_input_instruction.ipynb" },
  { dir: "attacks", file: "ipynb_metadata_tag_smuggle.ipynb" },
  { dir: "attacks", file: "ipynb_untrusted_signature.ipynb" },
  { dir: "benign", file: "benign_ipynb_data_analysis.ipynb" },
  { dir: "benign", file: "benign_ipynb_markdown_only.ipynb" },
];

function diffIpynbResults(mcp, web) {
  // Reuse normalizeOfficeFindings — same (category, severity, technique)
  // triple shape. MCP carries `extraFindings`; Web carries `hiddenFindings`.
  const mcpNorm = normalizeOfficeFindings(mcp.extraFindings);
  const webNorm = normalizeOfficeFindings(web.hiddenFindings);
  const sa = JSON.stringify(mcpNorm);
  const sb = JSON.stringify(webNorm);
  if (sa === sb) return null;
  return { mcp: sa, web: sb };
}

async function runIpynbParity() {
  // ipynb parsers are pure JSON walkers — no JSZip / no pdfjs — so plumbing
  // is minimal: dynamic-import the Web parser once, iterate fixtures, diff
  // the triples. R18: setEnv → analyze (none here — parser-only) → resetEnv.
  resetEnv();
  setEnv(buildWebEnv());
  let parseIpynbWeb;
  try {
    ({ parseIpynb: parseIpynbWeb } = await import(
      "../packages/web/src/parsers-web/ipynb.js"
    ));
  } finally {
    // Leave env set for the actual scans; reset at the end.
  }
  try {
    let totalMcp = 0;
    let totalWeb = 0;
    let drift = 0;
    const driftDetails = [];

    for (const { dir, file } of IPYNB_FIXTURES) {
      const buffer = await readFile(join(OFFICE_FIXTURE_ROOT, dir, file));
      resetEnv();
      const mcpResult = await parseIpynbBufferMcp(buffer);
      setEnv(buildWebEnv());
      const webResult = await parseIpynbWeb(buffer);

      totalMcp += (mcpResult.extraFindings || []).length;
      totalWeb += (webResult.hiddenFindings || []).length;

      const d = diffIpynbResults(mcpResult, webResult);
      if (d) {
        drift += 1;
        driftDetails.push({ fixture: `${dir}/${file}`, ...d });
      }
    }

    return {
      count: IPYNB_FIXTURES.length,
      totalMcp,
      totalWeb,
      drift,
      driftDetails,
    };
  } finally {
    resetEnv();
  }
}

async function runOfficeFollinaParity() {
  // Web parsers use globalThis.JSZip — install the Node-resolved JSZip onto
  // globalThis so parsers-web/{docx,pptx}.js resolve it the same way at
  // call-time. Mirrors runArchiveParity's plumbing.
  const prevJSZip = globalThis.JSZip;
  globalThis.JSZip = JSZip;
  // R18 (env-abstract order contract): set Web env BEFORE the dynamic import
  // of parsers-web modules so any module-side rule loads see the bundled
  // rules loader.
  resetEnv();
  setEnv(buildWebEnv());
  let parseDocxWeb;
  let parsePptxWeb;
  try {
    ({ parseDocx: parseDocxWeb } = await import(
      "../packages/web/src/parsers-web/docx.js"
    ));
    ({ parsePptx: parsePptxWeb } = await import(
      "../packages/web/src/parsers-web/pptx.js"
    ));
  } finally {
    // Leave env set for the actual scans below; reset at the end.
  }
  try {
    let totalMcp = 0;
    let totalWeb = 0;
    let drift = 0;
    const driftDetails = [];

    for (const { dir, file, parser } of OFFICE_FOLLINA_FIXTURES) {
      const buffer = await readFile(join(OFFICE_FIXTURE_ROOT, dir, file));
      resetEnv();
      const mcpResult =
        parser === "docx"
          ? await parseDocxBufferMcp(buffer)
          : await parsePptxBufferMcp(buffer);
      setEnv(buildWebEnv());
      const webResult =
        parser === "docx"
          ? await parseDocxWeb(buffer)
          : await parsePptxWeb(buffer);

      totalMcp += (mcpResult.extraFindings || []).length;
      totalWeb += (webResult.hiddenFindings || []).length;

      const d = diffOfficeResults(mcpResult, webResult);
      if (d) {
        drift += 1;
        driftDetails.push({ fixture: `${dir}/${file}`, ...d });
      }
    }

    return {
      count: OFFICE_FOLLINA_FIXTURES.length,
      totalMcp,
      totalWeb,
      drift,
      driftDetails,
    };
  } finally {
    resetEnv();
    if (prevJSZip === undefined) {
      delete globalThis.JSZip;
    } else {
      globalThis.JSZip = prevJSZip;
    }
  }
}

// ─── v1.19.0 B4 — Structured-text (YAML / TOML / JSON-LD) parity ──────────
// 5 attack + 3 benign fixtures. The detector is pure-core (no env hooks /
// no JSZip / no pdfjs / no DOMParser), so MCP and Web both call
// `detectStructuredTextFrontmatter()` directly. Drift here would mean a
// shared-module regression — by construction both routes import the same
// `@shield-scanner/core` build. Keeping the section so any future MCP/Web
// surface divergence (e.g. one route wraps the detector with extra
// post-processing) trips the drift counter.
//
// R12: technique stays a fixed kebab id; meta carries sanitized scalars only.
// R13: every finding folds to category='suspiciousPatterns'.
const STRUCTURED_TEXT_FIXTURES = [
  { dir: "attacks", file: "md_frontmatter_yaml_inject.md", format: "auto" },
  { dir: "attacks", file: "md_frontmatter_toml_inject.md", format: "auto" },
  { dir: "attacks", file: "yaml_python_object_tag.yaml", format: "yaml" },
  { dir: "attacks", file: "yaml_anchor_billion_laughs.yaml", format: "yaml" },
  { dir: "attacks", file: "jsonld_description_inject.html", format: "auto" },
  { dir: "benign", file: "benign_md_blog_frontmatter.md", format: "auto" },
  { dir: "benign", file: "benign_yaml_config.yaml", format: "yaml" },
  { dir: "benign", file: "benign_jsonld_article.html", format: "auto" },
];

function normalizeStructuredFindings(findings) {
  if (!Array.isArray(findings)) return [];
  // Compare on (technique, severity, sorted meta key set). Meta values are
  // detector-controlled scalars — bringing the values into the fingerprint
  // would inflate noise without adding contract coverage; the meta KEY set
  // is what nails down the R12/R13 contract.
  const out = findings.map((f) => ({
    category: f.category || "",
    severity: f.severity || "",
    technique: String(f.technique || ""),
    metaKeys:
      f.meta && typeof f.meta === "object"
        ? Object.keys(f.meta).sort().join(",")
        : "",
  }));
  out.sort((a, b) => {
    if (a.technique !== b.technique) return a.technique < b.technique ? -1 : 1;
    if (a.severity !== b.severity) return a.severity < b.severity ? -1 : 1;
    return a.metaKeys < b.metaKeys ? -1 : a.metaKeys > b.metaKeys ? 1 : 0;
  });
  return out;
}

function diffStructuredResults(mcpFindings, webFindings) {
  const sa = JSON.stringify(normalizeStructuredFindings(mcpFindings));
  const sb = JSON.stringify(normalizeStructuredFindings(webFindings));
  if (sa === sb) return null;
  return { mcp: sa, web: sb };
}

async function runStructuredTextParity() {
  // Detector is env-free; we still cycle setEnv to mirror the surrounding
  // sections' R18 ordering contract.
  resetEnv();
  const { detectStructuredTextFrontmatter: detectMcp } = await import(
    "@shield-scanner/core"
  );
  resetEnv();
  setEnv(buildWebEnv());
  const { detectStructuredTextFrontmatter: detectWeb } = await import(
    "@shield-scanner/core"
  );

  try {
    let totalMcp = 0;
    let totalWeb = 0;
    let drift = 0;
    const driftDetails = [];

    for (const { dir, file, format } of STRUCTURED_TEXT_FIXTURES) {
      const path = join(OFFICE_FIXTURE_ROOT, dir, file);
      const text = await readFile(path, "utf8");
      const opts = format && format !== "auto" ? { format } : undefined;
      resetEnv();
      const mcpFindings = detectMcp(text, opts);
      setEnv(buildWebEnv());
      const webFindings = detectWeb(text, opts);

      totalMcp += (mcpFindings || []).length;
      totalWeb += (webFindings || []).length;

      const d = diffStructuredResults(mcpFindings, webFindings);
      if (d) {
        drift += 1;
        driftDetails.push({ fixture: `${dir}/${file}`, ...d });
      }
    }

    return {
      count: STRUCTURED_TEXT_FIXTURES.length,
      totalMcp,
      totalWeb,
      drift,
      driftDetails,
    };
  } finally {
    resetEnv();
  }
}

// ─── Main ──────────────────────────────────────────────────────────────────
async function main() {
  const entries = await readdir(FIXTURE_DIR);
  const fixtures = entries
    .filter((n) => n.endsWith(".txt"))
    .sort();

  let totalMcpFindings = 0;
  let totalWebFindings = 0;
  let drift = 0;
  const driftDetails = [];

  for (const name of fixtures) {
    const full = join(FIXTURE_DIR, name);
    const text = await readFile(full, "utf8");

    // Run MCP first with env unset (Node fallback). scanTextWeb resets env in
    // its finally{} so subsequent MCP calls also see env=null.
    resetEnv();
    const mcpResult = await scanTextMcp({ text });
    const webResult = await scanTextWeb({ text }, name);

    totalMcpFindings += countFindings(mcpResult);
    totalWebFindings += countFindings(webResult);

    const d = diffResults(mcpResult, webResult);
    if (d) {
      drift += 1;
      driftDetails.push({ fixture: name, ...d });
    }
  }

  // S13 archive parity (4 .zip fixtures: bomb / zipslip / suspicious-ext /
  // benign). Folded into the same drift counter so the script still exits
  // non-zero on any divergence.
  const archive = await runArchiveParity();
  drift += archive.drift;
  for (const d of archive.driftDetails) {
    driftDetails.push(d);
  }

  // Theme D (v1.10.0) — PDF struct-tree parity (2 .pdf fixtures: benign /
  // attack-instructions). Same drift counter — any structtree-header or
  // extraFinding-triple divergence between MCP and Web exits non-zero.
  const pdfStruct = await runPdfStructParity();
  drift += pdfStruct.drift;
  for (const d of pdfStruct.driftDetails) {
    driftDetails.push(d);
  }

  // v1.18.0 Follina — Office (DOCX/PPTX) attachedTemplate + customXml +
  // embeddings OLE parity (8 fixtures: 6 attack + 2 benign). Drift counter is
  // shared so any divergence (kebab id leak / R12 violation / R13 fold mistake)
  // exits non-zero.
  const office = await runOfficeFollinaParity();
  drift += office.drift;
  for (const d of office.driftDetails) {
    driftDetails.push(d);
  }

  // v1.18.0 XLSX deep-execution — Power Query / data connection / ActiveX /
  // customUI parity (6 fixtures: 4 attack + 2 benign). Same drift counter.
  const xlsxDeep = await runXlsxDeepParity();
  drift += xlsxDeep.drift;
  for (const d of xlsxDeep.driftDetails) {
    driftDetails.push(d);
  }

  // v1.19.0 B1 Polyglot-SVG — 6 attack + 2 benign fixtures. Drift counter is
  // shared so a kebab-id leak / R12 violation / R13 fold mistake all exit
  // non-zero exactly the same way the office / xlsx-deep sections do.
  const svg = await runSvgParity();
  drift += svg.drift;
  for (const d of svg.driftDetails) {
    driftDetails.push(d);
  }

  // v1.19.0 B2 RTF — 5 attack + 2 benign fixtures. Drift counter shared so a
  // kebab-id leak / R12 raw-text echo / R13 5-bucket fold mistake all exit
  // non-zero exactly the same way the SVG section does.
  const rtf = await runRtfParity();
  drift += rtf.drift;
  for (const d of rtf.driftDetails) {
    driftDetails.push(d);
  }

  // v1.19.0 B3 Jupyter Notebook — 4 attack + 2 benign fixtures. Same triple-
  // equality fingerprint. Appended after rtf so the printed summary preserves
  // left-to-right section order and lands the ipynb count at the end.
  const ipynb = await runIpynbParity();
  drift += ipynb.drift;
  for (const d of ipynb.driftDetails) {
    driftDetails.push(d);
  }

  // v1.19.0 B4 Structured-text (YAML / TOML / JSON-LD) — 5 attack + 3 benign
  // fixtures. The detector is pure-core so MCP and Web import the same
  // module; drift here would mean a cross-route surface divergence, not a
  // detector regression.
  const structuredText = await runStructuredTextParity();
  drift += structuredText.drift;
  for (const d of structuredText.driftDetails) {
    driftDetails.push(d);
  }

  const totalFixtures =
    fixtures.length +
    archive.count +
    pdfStruct.count +
    office.count +
    xlsxDeep.count +
    svg.count +
    rtf.count +
    ipynb.count +
    structuredText.count;
  const totalMcp =
    totalMcpFindings +
    archive.totalMcp +
    pdfStruct.totalMcp +
    office.totalMcp +
    xlsxDeep.totalMcp +
    svg.totalMcp +
    rtf.totalMcp +
    ipynb.totalMcp +
    structuredText.totalMcp;
  const totalWeb =
    totalWebFindings +
    archive.totalWeb +
    pdfStruct.totalWeb +
    office.totalWeb +
    xlsxDeep.totalWeb +
    svg.totalWeb +
    rtf.totalWeb +
    ipynb.totalWeb +
    structuredText.totalWeb;

  console.log(
    `${totalFixtures} fixtures scanned (${fixtures.length} text + ${archive.count} archive + ${pdfStruct.count} pdf-struct + ${office.count} office-follina + ${xlsxDeep.count} xlsx-deep + ${svg.count} svg-polyglot + ${rtf.count} rtf + ${ipynb.count} ipynb + ${structuredText.count} structured-text) / MCP findings: ${totalMcp} / Web findings: ${totalWeb} / parity drift: ${drift}`,
  );

  if (drift > 0) {
    console.error("\n--- parity drift details ---");
    for (const d of driftDetails) {
      console.error(`\n[${d.fixture}]`);
      console.error("  MCP:", d.mcp);
      console.error("  WEB:", d.web);
    }
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("parity-check failed:", err);
  process.exit(1);
});
