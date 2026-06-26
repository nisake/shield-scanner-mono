/**
 * Parser dispatcher.
 *
 * Routes a file to the appropriate parser based on its extension.
 */

import { extname, basename } from "node:path";
import { stat } from "node:fs/promises";
import { parseText, parseTextBuffer } from "./text.js";
import { parseHtml, parseHtmlBuffer } from "./html.js";
import { parseDocx, parseDocxBuffer } from "./docx.js";
import { parsePdf, parsePdfBuffer } from "./pdf.js";
import { parsePptx, parsePptxBuffer } from "./pptx.js";
import { parseEmlFile, parseEmlBuffer } from "./eml.js";
import { parseImage, parseImageBuffer } from "./image.js";
import { parseXlsx, parseXlsxBuffer } from "./xlsx.js";
import { parseCsv, parseCsvBuffer } from "./csv.js";
import { parseArchive, parseArchiveBuffer } from "./archive.js";

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
  // S13 — raw ZIP archive (Office .docx/.xlsx/.pptx stay on their own routes).
  "zip",
  "jpg",
  "jpeg",
  "png",
  "webp",
  "gif",
  "tiff",
  "tif",
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
// S10: tabular formats route through dedicated parsers (csv.js / xlsx.js).
// Listed explicitly so future extensions (xls binary, xlsm, etc.) have an
// obvious home and don't accidentally re-enter the generic text route.
const TABULAR_EXTS = new Set(["csv", "xlsx"]);
// S13: raw ZIP route — Office packages keep their dedicated parsers; this set
// is matched AFTER the Office ext checks, so .docx / .xlsx / .pptx never land
// here. Listed as a Set so future archive formats have an obvious home.
const ARCHIVE_EXTS = new Set(["zip"]);

/**
 * Extensions that dispatchBuffer can route. EML supported with depth tracking.
 */
export const BUFFER_DISPATCHABLE = new Set([
  ...TEXT_EXTS,
  ...MARKDOWN_EXTS,
  ...HTML_EXTS,
  ...TABULAR_EXTS,
  ...ARCHIVE_EXTS,
  "docx",
  "pdf",
  "pptx",
  "eml",
  ...IMAGE_EXTS,
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
  if (HTML_EXTS.has(e)) return parseHtmlBuffer(buffer);
  if (e === "docx") return parseDocxBuffer(buffer);
  if (e === "pdf") return parsePdfBuffer(buffer);
  if (e === "pptx") return parsePptxBuffer(buffer);
  if (e === "xlsx") return parseXlsxBuffer(buffer);
  if (e === "csv") return parseCsvBuffer(buffer);
  if (e === "zip") return parseArchiveBuffer(buffer, { depth: 0 });
  if (IMAGE_EXTS.has(e)) return parseImageBuffer(buffer, e);
  if (e === "eml") return parseEmlBuffer(buffer);
  return null;
}
