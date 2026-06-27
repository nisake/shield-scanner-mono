/**
 * Parser dispatcher.
 *
 * Routes a file to the appropriate parser based on its extension.
 */

import { extname, basename } from "node:path";
import { stat } from "node:fs/promises";
import { parseText, parseTextBuffer } from "./text.js";
import { parseHtml, parseHtmlBuffer } from "./html.js";
import { parseSvg, parseSvgBuffer } from "./svg.js";
import { parseDocx, parseDocxBuffer } from "./docx.js";
import { parsePdf, parsePdfBuffer } from "./pdf.js";
import { parsePptx, parsePptxBuffer } from "./pptx.js";
import { parseEmlFile, parseEmlBuffer } from "./eml.js";
import { parseImage, parseImageBuffer } from "./image.js";
import { parseXlsx, parseXlsxBuffer } from "./xlsx.js";
import { parseCsv, parseCsvBuffer } from "./csv.js";
import { parseArchive, parseArchiveBuffer } from "./archive.js";
import { parseRtf, parseRtfBuffer } from "./rtf.js";
// v1.19.0 B3 — Jupyter notebook (.ipynb). Imported last so concurrent
// B1/B2/B3 parser additions land on separate lines and Edit's atomic write
// resolves the race deterministically.
import { parseIpynb, parseIpynbBuffer } from "./ipynb.js";
// v1.20.0 T3-ODP: OpenDocument Presentation (.odp) parser. Imported last so
// concurrent T1 / T2 ODF parser additions land on independent lines and Edit's
// atomic write resolves the race deterministically.
import { parseOdp, parseOdpBuffer } from "./odp.js";
// v1.20.0 T1-ODT: OpenDocument Text (.odt) parser. Imported after odp so the
// ODF cluster sits together at the tail of the import block; concurrent T2
// additions land on independent lines.
import { parseOdt, parseOdtBuffer } from "./odt.js";
// v1.20.0 T2-ODS: OpenDocument Spreadsheet (.ods) parser. Imported after odt
// so the ODF cluster (odp/odt/ods) sits together at the tail of the import
// block.
import { parseOds, parseOdsBuffer } from "./ods.js";

export const SUPPORTED_EXTENSIONS = [
  "txt",
  "md",
  // QW5: Cursor-style rule files also contain markdown / instruction text and
  // can hide prompt-injection payloads inside HTML comments, so we treat them
  // as scannable text and route them through the markdown branch below.
  "mdc",
  "cursorrules",
  "csv",
  "json",
  "html",
  "htm",
  "xml",
  "svg",
  "docx",
  "pdf",
  "pptx",
  "xlsx",
  "eml",
  // v1.19.0 B2: RTF gets a dedicated parser. Before this, EML attachments and
  // ZIP entries with `.rtf` extension fell through the unknown-extension
  // silent-skip path, so a malicious .docx renamed to .rtf bypassed the
  // scanner. CVE-2023-21716 (RTF font-table heap overflow) + Equation Editor
  // OLE chain remain active vectors.
  "rtf",
  // S13 — raw ZIP archive (Office .docx/.xlsx/.pptx stay on their own routes).
  "zip",
  "jpg",
  "jpeg",
  "png",
  "webp",
  "gif",
  "tiff",
  "tif",
  // v1.19.0 B3 — Jupyter Notebook (.ipynb). Quiet attack surface for
  // AI/data-analysis pipelines: cell metadata.tags / hide_input flags, output
  // text/html + application/javascript MIME blobs, and unsigned notebooks all
  // smuggle prompt-injection payloads past LLM ingestion. Appended last to
  // avoid collisions with concurrent B1/B2 list edits.
  "ipynb",
  // v1.20.0 T3-ODP — OpenDocument Presentation. OpenOffice / LibreOffice
  // equivalent of PPTX; quiet attack surface for ODF-native pipelines.
  // Appended after ipynb so concurrent T1 / T2 list edits stay independent.
  "odp",
  // v1.20.0 T1-ODT — OpenDocument Text. OpenOffice / LibreOffice equivalent
  // of DOCX. Appended after odp so the ODF cluster (odp/odt) sits together
  // at the tail of the ext list and concurrent T2 edits stay independent.
  "odt",
  // v1.20.0 T2-ODS — OpenDocument Spreadsheet. OpenOffice / LibreOffice
  // equivalent of XLSX. Appended after odt so the ODF cluster (odp/odt/ods)
  // sits together at the tail of the ext list.
  "ods",
];

// S10: 'csv' moves out of the generic text route into the dedicated CSV parser
// so per-cell formula-injection findings carry [Row N, Col M] contextLocation
// and the numeric / phone suppression regexes anchor on cell text rather than
// full rows.
const TEXT_EXTS = new Set(["txt", "json"]);
const IMAGE_EXTS = new Set(["jpg", "jpeg", "png", "webp", "gif", "tiff", "tif"]);
// Markdown-family files: parsed as plain text but tagged fileType="markdown"
// so the detector still runs hidden-element / HTML-comment sweeps on them.
const MARKDOWN_EXTS = new Set(["md", "mdc", "cursorrules"]);
const HTML_EXTS = new Set(["html", "htm", "xml", "svg"]);
// v1.19.0 B1: SVG gets its own dispatch so the Polyglot-SVG detector (script /
// event-handler / javascript-href / foreignObject / CDATA / external use) runs
// even when the file lands here directly (standalone .svg drop) and not just
// nested inside a DOCX/PPTX/EML attachment. .svg stays inside HTML_EXTS so the
// MIME-recognize check below (image/svg+xml) keeps routing through this branch
// from buffer dispatch as well.
const SVG_EXTS = new Set(["svg"]);
// MIME → extension mapping for buffer dispatch (EML attachments etc.). Listed
// alongside the SVG ext set so a future Content-Type-driven path can resolve
// `image/svg+xml` → `svg` without a string-compare scattered across the file.
export const MIME_EXT_MAP = new Map([
  ["image/svg+xml", "svg"],
]);
// S10: tabular formats route through dedicated parsers (csv.js / xlsx.js).
// Listed explicitly so future extensions (xls binary, xlsm, etc.) have an
// obvious home and don't accidentally re-enter the generic text route.
const TABULAR_EXTS = new Set(["csv", "xlsx"]);
// S13: raw ZIP route — Office packages keep their dedicated parsers; this set
// is matched AFTER the Office ext checks, so .docx / .xlsx / .pptx never land
// here. Listed as a Set so future archive formats have an obvious home.
const ARCHIVE_EXTS = new Set(["zip"]);
// v1.19.0 B2: RTF route. Dedicated parser detects \objdata / \objclass OLE,
// \field HYPERLINK exfil, \v hidden text, \fs microscopic, \bin binary blob,
// and \* unknown-destination smuggling. All findings fold to
// suspiciousPatterns (R13 5-key invariant intact).
const RTF_EXTS = new Set(["rtf"]);
// v1.19.0 B3: Jupyter notebook route. JSON parse only — no JSZip / no MIME
// negotiation — so the parser is a pure helper. Findings fold to
// suspiciousPatterns (R13 5-key invariant intact).
const IPYNB_EXTS = new Set(["ipynb"]);

/**
 * Extensions that dispatchBuffer can route. EML supported with depth tracking.
 */
export const BUFFER_DISPATCHABLE = new Set([
  ...TEXT_EXTS,
  ...MARKDOWN_EXTS,
  ...HTML_EXTS,
  ...TABULAR_EXTS,
  ...ARCHIVE_EXTS,
  ...RTF_EXTS,
  "docx",
  "pdf",
  "pptx",
  "eml",
  ...IMAGE_EXTS,
  ...IPYNB_EXTS,
  // v1.20.0 T3-ODP — odp buffer dispatch (ZIP-entry / EML-attachment route).
  "odp",
  // v1.20.0 T1-ODT — odt buffer dispatch (ZIP-entry / EML-attachment route).
  "odt",
  // v1.20.0 T2-ODS — ods buffer dispatch (ZIP-entry / EML-attachment route).
  "ods",
]);

/**
 * Parse a file based on its extension.
 *
 * @param {string} filePath - Absolute path to the file
 * @returns {Promise<{ text: string, fileType: string, extraFindings: Array, fileInfo: Object, sections?: Object }>}
 */
export async function parseFile(filePath) {
  const ext = extname(filePath).slice(1).toLowerCase();
  if (!SUPPORTED_EXTENSIONS.includes(ext)) {
    throw new Error(`Unsupported file extension: .${ext}`);
  }

  const stats = await stat(filePath);
  const fileInfo = {
    name: basename(filePath),
    path: filePath,
    size: stats.size,
    extension: ext,
  };

  let result;
  if (TEXT_EXTS.has(ext)) {
    result = await parseText(filePath);
  } else if (MARKDOWN_EXTS.has(ext)) {
    // Read as plain text but tag as markdown so the detector enables the
    // hidden-element / HTML-comment sweeps (QW5).
    const base = await parseText(filePath);
    result = { ...base, fileType: "markdown" };
  } else if (SVG_EXTS.has(ext)) {
    // v1.19.0 B1 Polyglot-SVG: dedicated parser. parseHtml shares the same
    // detectSvgInjection scan for inline <svg> blocks pasted into HTML, so
    // the html/htm/xml branch below stays consistent.
    result = await parseSvg(filePath);
  } else if (HTML_EXTS.has(ext)) {
    result = await parseHtml(filePath);
  } else if (ext === "docx") {
    result = await parseDocx(filePath);
  } else if (ext === "pdf") {
    result = await parsePdf(filePath);
  } else if (ext === "pptx") {
    result = await parsePptx(filePath);
  } else if (ext === "xlsx") {
    result = await parseXlsx(filePath);
  } else if (ext === "csv") {
    result = await parseCsv(filePath);
  } else if (RTF_EXTS.has(ext)) {
    result = await parseRtf(filePath);
  } else if (IPYNB_EXTS.has(ext)) {
    // v1.19.0 B3 Jupyter notebook: dedicated parser walks cells / outputs /
    // metadata.tags and emits ipynb-* kebab ids folded to suspiciousPatterns.
    result = await parseIpynb(filePath);
  } else if (ARCHIVE_EXTS.has(ext)) {
    result = await parseArchive(filePath);
  } else if (IMAGE_EXTS.has(ext)) {
    result = await parseImage(filePath);
  } else if (ext === "eml") {
    const emlResult = await parseEmlFile(filePath);
    // Compose email sections into a single text blob for unified scanning
    const combined = [
      emlResult.sections.headers,
      emlResult.sections.body,
      emlResult.sections.html,
      emlResult.sections.attachmentNames &&
        `[ATTACHMENTS]\n${emlResult.sections.attachmentNames}`,
    ]
      .filter(Boolean)
      .join("\n\n---\n\n");

    result = {
      text: combined,
      fileType: emlResult.sections.html ? "html" : "text",
      extraFindings: emlResult.extraFindings,
      sections: emlResult.sections,
      emailMeta: emlResult.metadata,
    };
  } else if (ext === "odp") {
    // v1.20.0 T3-ODP: OpenDocument Presentation. Appended last so concurrent
    // T1 / T2 ODF parser additions stay merge-clean.
    result = await parseOdp(filePath);
  } else if (ext === "odt") {
    // v1.20.0 T1-ODT: OpenDocument Text. Appended after odp so the ODF
    // cluster (odp/odt) sits together at the tail of the dispatch chain
    // and concurrent T2 additions stay merge-clean.
    result = await parseOdt(filePath);
  } else if (ext === "ods") {
    // v1.20.0 T2-ODS: OpenDocument Spreadsheet. Appended after odt so the
    // ODF cluster (odp/odt/ods) sits together at the tail of the dispatch
    // chain.
    result = await parseOds(filePath);
  }

  return { ...result, fileInfo };
}

/**
 * Parse a Buffer based on a given extension. Used for recursive scanning of
 * EML attachments (and any future buffer-only sources).
 *
 * Note: For ext === "eml", the caller is responsible for tracking recursion
 * depth; this dispatcher just forwards the buffer to the EML parser.
 *
 * @param {Buffer} buffer
 * @param {string} ext - Lowercase extension WITHOUT leading dot
 * @returns {Promise<{ text: string, fileType: string, extraFindings: Array, sections?: Object, emailMeta?: Object } | null>}
 *   Returns null if extension is not buffer-dispatchable.
 */
export async function dispatchBuffer(buffer, ext) {
  const e = (ext || "").toLowerCase();
  if (!BUFFER_DISPATCHABLE.has(e)) return null;

  if (TEXT_EXTS.has(e)) return parseTextBuffer(buffer);
  if (MARKDOWN_EXTS.has(e)) {
    const base = await parseTextBuffer(buffer);
    return { ...base, fileType: "markdown" };
  }
  if (SVG_EXTS.has(e)) return parseSvgBuffer(buffer);
  if (HTML_EXTS.has(e)) return parseHtmlBuffer(buffer);
  if (e === "docx") return parseDocxBuffer(buffer);
  if (e === "pdf") return parsePdfBuffer(buffer);
  if (e === "pptx") return parsePptxBuffer(buffer);
  if (e === "xlsx") return parseXlsxBuffer(buffer);
  if (e === "csv") return parseCsvBuffer(buffer);
  if (e === "rtf") return parseRtfBuffer(buffer);
  if (e === "zip") return parseArchiveBuffer(buffer, { depth: 0 });
  if (IMAGE_EXTS.has(e)) return parseImageBuffer(buffer, e);
  if (e === "eml") return parseEmlBuffer(buffer);
  // v1.19.0 B3: Jupyter notebook buffer dispatch (EML attachments / ZIP entries
  // with `.ipynb` extension). Added last so the case sits below all other ext
  // checks and B1/B2 dispatch cases stay independent.
  if (e === "ipynb") return parseIpynbBuffer(buffer);
  // v1.20.0 T3-ODP: OpenDocument Presentation buffer dispatch. Appended below
  // ipynb so concurrent T1 / T2 ODF dispatch cases stay merge-clean.
  if (e === "odp") return parseOdpBuffer(buffer);
  // v1.20.0 T1-ODT: OpenDocument Text buffer dispatch. Appended below odp so
  // the ODF cluster (odp/odt/ods) sits together at the tail of the dispatch
  // chain and concurrent T2 additions stay merge-clean.
  if (e === "odt") return parseOdtBuffer(buffer);
  // v1.20.0 T2-ODS: OpenDocument Spreadsheet buffer dispatch.
  if (e === "ods") return parseOdsBuffer(buffer);
  // v1.20.0 T1-ODT: OpenDocument Text buffer dispatch. Appended below odp so
  // the ODF cluster (odp/odt) sits together at the tail of the dispatch chain.
  if (e === "odt") return parseOdtBuffer(buffer);
  return null;
}

// ---------------------------------------------------------------------------
// v1.19.0 B4: Structured-text dispatch (.yml / .yaml / .toml).
//
// These standalone formats reuse the plain-text parser but tag the buffer with
// a dedicated fileType ("yaml" / "toml") so detector.js's analyze() pipeline
// engages the structured-text-frontmatter detector with the correct format
// hint. R13 fold: every finding routes through the existing suspiciousPatterns
// bucket — no new top-level byCategory key. Appended at file end to stay
// conflict-free with concurrent B1 / B2 / B3 parser additions above.
// ---------------------------------------------------------------------------
const STRUCTURED_YAML_EXTS = new Set(["yml", "yaml"]);
const STRUCTURED_TOML_EXTS = new Set(["toml"]);
const STRUCTURED_TEXT_EXTS = new Set([
  ...STRUCTURED_YAML_EXTS,
  ...STRUCTURED_TOML_EXTS,
]);

export async function parseFileStructuredText(filePath) {
  const ext = extname(filePath).slice(1).toLowerCase();
  if (!STRUCTURED_TEXT_EXTS.has(ext)) return null;
  const stats = await stat(filePath);
  const fileInfo = {
    name: basename(filePath),
    path: filePath,
    size: stats.size,
    extension: ext,
  };
  const base = await parseText(filePath);
  const fileType = STRUCTURED_YAML_EXTS.has(ext) ? "yaml" : "toml";
  return { ...base, fileType, fileInfo };
}

export async function dispatchBufferStructuredText(buffer, ext) {
  const e = (ext || "").toLowerCase();
  if (!STRUCTURED_TEXT_EXTS.has(e)) return null;
  const base = await parseTextBuffer(buffer);
  const fileType = STRUCTURED_YAML_EXTS.has(e) ? "yaml" : "toml";
  return { ...base, fileType };
}

export const STRUCTURED_TEXT_DISPATCH = Object.freeze({
  exts: Array.from(STRUCTURED_TEXT_EXTS),
  yamlExts: Array.from(STRUCTURED_YAML_EXTS),
  tomlExts: Array.from(STRUCTURED_TOML_EXTS),
});

// ---------------------------------------------------------------------------
// v1.20.0 T3-ODP: OpenDocument Presentation (.odp) parser surface.
//
// OpenOffice / LibreOffice equivalent of PPTX — same prompt-injection surfaces
// (speaker notes, slide transitions with macro links, embedded OLE objects,
// master-slide instruction bodies, Pictures/* image binaries). The ext set is
// declared at file-end so concurrent T1 / T2 parser additions stay merge-
// clean. All findings fold to suspiciousPatterns (R13 5-key invariant intact).
// Note: the ext dispatch branches are also appended at the tail of the
// existing parseFile / dispatchBuffer if-chains above to keep this exported
// surface self-contained for tests and future ODF-parity tooling.
// ---------------------------------------------------------------------------
const ODP_EXTS = new Set(["odp"]);

export const ODP_DISPATCH = Object.freeze({
  exts: Array.from(ODP_EXTS),
});

// ---------------------------------------------------------------------------
// v1.20.0 T1-ODT: OpenDocument Text (.odt) parser surface.
//
// OpenOffice / LibreOffice equivalent of DOCX — same prompt-injection surfaces
// (meta.xml dc:* fields, settings.xml macro / auto-exec flags, content.xml
// office:event-listeners with remote hrefs, Basic/ StarBasic macros, embedded
// CFB OLE blobs under Object N/ and ObjectReplacements/). The ext set is
// declared at file-end so concurrent T2 / T3 parser additions stay merge-
// clean. All findings fold to suspiciousPatterns (R13 5-key invariant intact).
// ODT_DISPATCH is exported for the regression harness and for any future ODF-
// parity tooling that wants a single canonical ext list.
// ---------------------------------------------------------------------------
const ODT_EXTS = new Set(["odt"]);

export const ODT_DISPATCH = Object.freeze({
  exts: Array.from(ODT_EXTS),
});

// ---------------------------------------------------------------------------
// v1.20.0 T2-ODS: OpenDocument Spreadsheet (.ods) parser surface.
//
// Calc / LibreOffice / Apple Numbers ingestion path. Dedicated parser walks
// content.xml table:formula nodes (re-using the shared CSV/XLSX formula-
// injection ruleset), settings.xml DDE / external command refs, hidden /
// protected sheet bodies, and Basic/ macro presence. Appended at file end so
// concurrent T1 ODT / T3 ODP additions stay merge-clean. All findings fold to
// suspiciousPatterns (R13 5-key invariant intact). ODS_DISPATCH is exported
// for the regression harness; the main parseFile / dispatchBuffer if-chains
// above already route the 'ods' ext to parseOds / parseOdsBuffer.
// ---------------------------------------------------------------------------
const ODS_EXTS = new Set(["ods"]);

export const ODS_DISPATCH = Object.freeze({
  exts: Array.from(ODS_EXTS),
});
