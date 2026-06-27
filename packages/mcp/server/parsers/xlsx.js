/**
 * S10 — XLSX (OOXML SpreadsheetML) parser using JSZip + regex.
 *
 * Mirrors the docx.js / pptx.js shape: JSZip.loadAsync on the input archive,
 * walk the relevant zip members with hand-rolled regex extraction (R14 library
 * trap — NO fast-xml-parser / cheerio / SheetJS / ExcelJS). The parser emits a
 * line-stream where every non-empty cell is one line prefixed with
 * `[Sheet 'Name'!A1] ` so the downstream `detectFormulaInjection` walker (wired
 * into core analyze() when fileType === 'xlsx') can keep per-cell numeric /
 * phone suppression anchored.
 *
 * Detection responsibilities split across the pipeline:
 *   - parser (here)  — structural / OPC-level findings (SC-02, FI-03, MV-04,
 *     MD-05, MD-06, MV-07, MD-08, ER-03, MV-09, OL-10). Emitted as
 *     `extraFindings` carrying explicit `category: 'suspiciousPatterns' |
 *     'hiddenHtml'` so scan-file.js can route into the canonical 5-key set
 *     without inventing new buckets (R13).
 *   - core analyze() — text-pattern findings (FI-01 / FI-02 formula-injection
 *     via detectFormulaInjection, plus the usual invisible-unicode / homoglyph
 *     / control-char sweeps on the JOINED text — MD-11 wiring).
 *
 * Defensive caps (mandatory zip-bomb defense — see s10-spec risks):
 *   - XLSX_MAX_ARCHIVE_BYTES   = 15 MB (whole .xlsx file)
 *   - XLSX_MAX_INFLATED_PER_PART = 8 MB (per zip member after .async('string'))
 *   - XLSX_MAX_SHEETS           = 50
 *   - XLSX_MAX_CELLS_PER_SHEET  = 50 000
 * Over-cap → emit warning extraFinding 'XLSX exceeds scan limits — partial
 * scan' and short-circuit the affected pass (or the whole archive when the
 * 15 MB cap is hit).
 *
 * Output shape:
 *   { text, fileType: 'xlsx', extraFindings, fileInfo }
 *
 * R12: sheet names, member names, and cell text portions are escape-encoded
 * via escapeForDisplay before any `content` / `contextLocation` use. The
 * `[Sheet 'Name'!A1] ` prefix is detector-controlled scaffolding (the parser
 * knows the sheet + ref), not user payload.
 *
 * R18: this module imports `parseRelationships` / `parseContentTypes` /
 * `normalizeXlfn` / `normalizeFormulaPrefix` from `@shield-scanner/core`, all
 * of which are env-abstract pure helpers. No `loadRule` at module-load.
 */

import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import JSZip from "jszip";
import {
  escapeForDisplay,
  looksLikeInstruction,
  parseRelationships,
  parseContentTypes,
} from "@shield-scanner/core";
import { parseImageBuffer } from "./image.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const XLSX_MAX_ARCHIVE_BYTES = 15 * 1024 * 1024;
const XLSX_MAX_INFLATED_PER_PART = 8 * 1024 * 1024;
const XLSX_MAX_SHEETS = 50;
const XLSX_MAX_CELLS_PER_SHEET = 50000;

// Embedded image recursion caps — shared by docx.js / pptx.js (S12-XR-02 envelope).
const OFFICE_IMAGE_EXTS = new Set(["jpg", "jpeg", "png", "webp", "gif", "tiff", "tif"]);
const OFFICE_MEDIA_MAX_BYTES = 5 * 1024 * 1024;
const OFFICE_MEDIA_MAX_COUNT = 50;

// FI-03 — definedName names that indicate an auto-run entrypoint.
const AUTO_OPEN_NAME_RE =
  /^_xlnm\.?(Auto_Open|Auto_Close|Auto_Activate|Auto_Deactivate)$|^Auto_Open$|^Workbook_Open$/i;

// Dangerous function blocklist (FI-03 mirror — keep in sync with
// packages/core/data/formula-injection.json). Used to upgrade definedName
// bodies that don't reference a hidden sheet but still carry a danger token.
const DANGEROUS_FN_RE =
  /\b(?:HYPERLINK|WEBSERVICE|FILTERXML|IMPORTXML|IMPORTHTML|IMPORTDATA|IMPORTFEED|IMPORTRANGE|CALL|REGISTER|EXEC|RTD|DDE|DDEAUTO)\b|cmd\||powershell|mshta|wscript|cscript|rundll32|regsvr32/i;

// DDE service name blocklist (FI-03 ddeLink companion).
const DDE_SERVICE_BLOCKLIST_RE =
  /^(?:cmd|powershell|mshta|wscript|cscript|rundll32|regsvr32)$/i;

// MV-04 — macroEnabled content types.
const MACRO_ENABLED_CONTENT_TYPE_RE = /macroEnabled/i;

// Office Compound File Binary (CFB) magic — D0 CF 11 E0 A1 B1 1A E1.
const CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const DANGEROUS_EMBED_EXT_RE = /\.(exe|scr|bat|lnk|hta|cmd|com|js|jse|vbs|vbe|ps1|wsf|wsh)$/i;

// MV-09 oversize anomaly threshold.
const CUSTOM_XML_OVERSIZE_THRESHOLD = 8 * 1024;

// v1.18.0 — Power Query / data connection / customUI deep-execution surface.
// Power Query M expressions inside customXml/item*.xml that fetch over HTTP.
const POWER_QUERY_WEBCONTENTS_RE =
  /\b(?:Web\.Contents|Web\.BrowserContents|Csv\.Document\s*\(\s*Web\.Contents|Json\.Document\s*\(\s*Web\.Contents|Xml\.Tables\s*\(\s*Web\.Contents)\b/i;

// xl/connections.xml OLEDB/ODBC connection string carrying shell-runner tokens.
const DATA_CONNECTION_SHELL_RE =
  /\b(?:cmd(?:\.exe)?|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)\b/i;

// customUI/customUI*.xml ribbon callback attribute names (onLoad / onAction etc.).
const CUSTOM_UI_CALLBACK_RE =
  /\b(onLoad|onAction|getEnabled|getVisible|getLabel|getImage|getContent)\s*=\s*"([^"]+)"/gi;

// XML entity decoder (sufficient for the OOXML payloads we touch).
function decodeXmlEntities(s) {
  if (typeof s !== "string" || s.length === 0) return s;
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

// Pull a single attribute value out of an attribute-bearing fragment.
function attr(attrFragment, name) {
  if (!attrFragment) return "";
  const reD = new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, "i");
  const md = reD.exec(attrFragment);
  if (md) return decodeXmlEntities(md[1]);
  const reS = new RegExp(`\\b${name}\\s*=\\s*'([^']*)'`, "i");
  const ms = reS.exec(attrFragment);
  if (ms) return decodeXmlEntities(ms[1]);
  return "";
}

// Convert a 1-based column index to A1-style column letters.
function colNumToLetters(n) {
  if (!Number.isFinite(n) || n <= 0) return "";
  let s = "";
  let v = n;
  while (v > 0) {
    const rem = (v - 1) % 26;
    s = String.fromCharCode(65 + rem) + s;
    v = Math.floor((v - 1) / 26);
  }
  return s;
}

// Parse an A1-style cell ref ("AB12" -> { col: 28, row: 12 }). Returns null on
// malformed input (we still emit the cell — the contextLocation falls back to
// the raw ref string).
function parseA1Ref(ref) {
  if (typeof ref !== "string") return null;
  const m = /^([A-Z]+)(\d+)$/i.exec(ref);
  if (!m) return null;
  const letters = m[1].toUpperCase();
  let col = 0;
  for (let i = 0; i < letters.length; i++) {
    col = col * 26 + (letters.charCodeAt(i) - 64);
  }
  return { col, row: parseInt(m[2], 10) };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function parseXlsx(filePath) {
  const buffer = await readFile(filePath);
  return parseXlsxBuffer(buffer);
}

/**
 * Parse XLSX from a Buffer / Uint8Array.
 *
 * @param {Buffer|Uint8Array} buffer
 * @param {Object} [opts]
 * @returns {Promise<{text:string, fileType:'xlsx', extraFindings:Array}>}
 */
export async function parseXlsxBuffer(buffer, opts = {}) {
  const texts = [];
  const extraFindings = [];

  // Normalize to Uint8Array for the size check; JSZip accepts both shapes.
  const u8 =
    buffer instanceof Uint8Array
      ? buffer
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  // --- Defensive cap: archive bytes ---
  if (u8.byteLength > XLSX_MAX_ARCHIVE_BYTES) {
    extraFindings.push({
      element: "XLSX Archive",
      technique: "xlsx-scan-limit",
      content: `(archive > ${XLSX_MAX_ARCHIVE_BYTES} bytes; not scanned)`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "XLSX Archive",
      meta: { scope: "archive", limitBytes: XLSX_MAX_ARCHIVE_BYTES },
    });
    return { text: "", fileType: "xlsx", extraFindings };
  }

  // --- Load zip (fail-soft on corrupt / mis-extensioned input) ---
  let zip;
  try {
    zip = await JSZip.loadAsync(u8);
  } catch (err) {
    const errMsg = escapeForDisplay(
      (err && err.message ? err.message : "JSZip parse error").slice(0, 64),
    );
    extraFindings.push({
      element: "XLSX Archive",
      technique: "xlsx-corrupt-zip",
      content: escapeForDisplay(
        (err && err.message ? err.message : "JSZip parse error").slice(0, 200),
      ),
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "XLSX Archive",
      meta: { errorMessage: errMsg },
    });
    return { text: "", fileType: "xlsx", extraFindings };
  }

  // ------------------------------------------------------------------
  // [Content_Types].xml + zip member listing → MV-04 detection
  // ------------------------------------------------------------------
  const allMemberNames = Object.keys(zip.files);
  // Surface zip member names through the main text blob so the unicode
  // pipeline catches RTLO / homoglyphs in zip member names (MD-11).
  if (allMemberNames.length > 0) {
    texts.push("[XLSX members] " + allMemberNames.join(" "));
  }

  let contentTypesXml = "";
  const contentTypesEntry = zip.file("[Content_Types].xml");
  if (contentTypesEntry) {
    contentTypesXml = await readPartString(contentTypesEntry, extraFindings, "[Content_Types].xml");
  }
  const overrides = contentTypesXml ? parseContentTypes(contentTypesXml) : [];
  const hasMacroContentType = overrides.some((o) =>
    MACRO_ENABLED_CONTENT_TYPE_RE.test(o.contentType || ""),
  );

  // MV-04: vbaProject.bin / vbaProjectSignature.bin presence.
  const hasVbaProject = allMemberNames.includes("xl/vbaProject.bin");
  const hasVbaSignature = allMemberNames.includes("xl/vbaProjectSignature.bin");
  if (hasVbaProject || hasVbaSignature) {
    extraFindings.push({
      element: "XLSX Archive",
      technique: "vba-macro-project",
      content: hasVbaProject ? "xl/vbaProject.bin" : "xl/vbaProjectSignature.bin",
      severity: "danger",
      category: "hiddenHtml",
      contextLocation: "xl/vbaProject.bin",
      meta: { hasSignature: hasVbaSignature },
    });
  }

  // MV-04: extension/content-type mismatch — opts.fileNameHint lets callers
  // pass the original extension when invoking parseXlsxBuffer directly.
  const fileNameHint = (opts && typeof opts.fileNameHint === "string"
    ? opts.fileNameHint
    : "").toLowerCase();
  const isXlsxExt = fileNameHint.endsWith(".xlsx") || !fileNameHint;
  if (isXlsxExt && hasMacroContentType) {
    extraFindings.push({
      element: "XLSX Archive",
      technique: "extension-content-type-mismatch",
      content: "macroEnabled content type declared but extension is .xlsx",
      severity: "danger",
      category: "hiddenHtml",
      contextLocation: "[Content_Types].xml",
    });
  }

  // MV-04: xl/macrosheets/ presence (XLM 4.0).
  const hasMacrosheets = allMemberNames.some((n) =>
    /^xl\/macrosheets\/[^/]+$/i.test(n),
  );
  if (hasMacrosheets) {
    extraFindings.push({
      element: "XLSX Archive",
      technique: "xlm-macrosheet",
      content: "xl/macrosheets/",
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "xl/macrosheets/",
    });
  }

  // ------------------------------------------------------------------
  // xl/workbook.xml → sheet state map + definedNames + externalLinks ref
  // ------------------------------------------------------------------
  /** @type {Array<{name:string, state:string, sheetId:string, rId:string}>} */
  let sheets = [];
  /** @type {Array<{name:string, body:string}>} */
  let definedNames = [];

  const workbookEntry = zip.file("xl/workbook.xml");
  if (workbookEntry) {
    const wbXml = await readPartString(workbookEntry, extraFindings, "xl/workbook.xml");

    // <sheets><sheet name=... state=... sheetId=... r:id=...>
    const sheetTagRe = /<sheet\b([^/>]*)\/?>/gi;
    let sm;
    while ((sm = sheetTagRe.exec(wbXml)) !== null) {
      const attrs = sm[1] || "";
      const name = attr(attrs, "name");
      const state = attr(attrs, "state") || "visible";
      const sheetId = attr(attrs, "sheetId");
      const rId = attr(attrs, "r:id") || attr(attrs, "id");
      if (name) sheets.push({ name, state, sheetId, rId });
    }

    // SC-02: emit per-sheet state findings.
    for (const s of sheets) {
      const stateLower = (s.state || "").toLowerCase();
      if (stateLower === "visible" || stateLower === "") continue;
      let severity;
      let technique;
      let meta;
      if (stateLower === "hidden") {
        severity = "warning";
        technique = "hidden-sheet";
        meta = undefined;
      } else if (stateLower === "veryhidden") {
        severity = "danger";
        technique = "veryhidden-sheet";
        meta = undefined;
      } else {
        severity = "warning";
        technique = "sheet-state-confusion";
        meta = { stateValue: escapeForDisplay(String(s.state).slice(0, 64)) };
      }
      const finding = {
        element: `Sheet '${escapeForDisplay(s.name.slice(0, 60))}'`,
        technique,
        content: escapeForDisplay(`state="${s.state}"`.slice(0, 200)),
        severity,
        category: "hiddenHtml",
        contextLocation: `xl/workbook.xml > sheet '${escapeForDisplay(s.name.slice(0, 60))}'`,
      };
      if (meta) finding.meta = meta;
      extraFindings.push(finding);
    }

    // <definedNames><definedName name=...>body</definedName>
    const dnRe = /<definedName\b([^>]*)>([\s\S]*?)<\/definedName>/gi;
    let dm;
    while ((dm = dnRe.exec(wbXml)) !== null) {
      const dnName = attr(dm[1], "name");
      const dnBody = decodeXmlEntities(dm[2] || "").trim();
      if (dnName) definedNames.push({ name: dnName, body: dnBody });
    }

    // FI-03: auto-run definedNames referencing hidden sheets or carrying
    // dangerous function tokens.
    for (const dn of definedNames) {
      if (!AUTO_OPEN_NAME_RE.test(dn.name)) continue;
      // Reference shape: 'SheetName'!$A$1 OR SheetName!$A$1
      const refMatch = /^'([^']+)'!|^([A-Za-z_][^!]*)!/i.exec(dn.body);
      const refSheetName = refMatch ? (refMatch[1] || refMatch[2] || "") : "";
      const refSheet = refSheetName
        ? sheets.find((s) => s.name === refSheetName)
        : null;
      const refsHidden =
        refSheet &&
        (refSheet.state || "").toLowerCase() !== "visible" &&
        (refSheet.state || "").toLowerCase() !== "";
      const hasDangerToken = DANGEROUS_FN_RE.test(dn.body);
      const severity = refsHidden || hasDangerToken ? "danger" : "warning";
      const variant = refsHidden
        ? "hiddenSheet"
        : hasDangerToken
          ? "dangerToken"
          : "present";
      const meta = { variant, name: escapeForDisplay(dn.name.slice(0, 64)) };
      if (refsHidden && refSheet) {
        meta.targetSheet = escapeForDisplay(String(refSheet.name).slice(0, 64));
        meta.targetState = (refSheet.state || "").toLowerCase();
      }
      extraFindings.push({
        element: `definedName '${escapeForDisplay(dn.name.slice(0, 60))}'`,
        technique: "auto-run-defined-name",
        content: escapeForDisplay(dn.body.slice(0, 200)),
        severity,
        category: "suspiciousPatterns",
        contextLocation: `xl/workbook.xml > definedName '${escapeForDisplay(dn.name.slice(0, 60))}'`,
        meta,
      });
    }
  }

  // ------------------------------------------------------------------
  // xl/externalLinks/_rels/externalLink*.xml.rels + externalLink*.xml
  // → FI-03 (ddeLink ddeService blocklist) + ER-03 (External relationships)
  // ------------------------------------------------------------------
  const externalLinkXmlFiles = allMemberNames.filter((f) =>
    /^xl\/externalLinks\/externalLink\d+\.xml$/i.test(f),
  );
  for (const elFile of externalLinkXmlFiles) {
    const elXml = await readPartString(zip.file(elFile), extraFindings, elFile);
    // <ddeLink ddeService="cmd" ddeTopic="...">
    const ddeRe = /<ddeLink\b([^>]*)\/?>/gi;
    let ddeM;
    while ((ddeM = ddeRe.exec(elXml)) !== null) {
      const svc = attr(ddeM[1], "ddeService");
      const topic = attr(ddeM[1], "ddeTopic");
      if (!svc) continue;
      const isBlocked = DDE_SERVICE_BLOCKLIST_RE.test(svc.trim());
      const ddeMeta = {
        svc: escapeForDisplay(String(svc).slice(0, 64)),
        blocked: isBlocked,
      };
      if (topic) ddeMeta.topic = escapeForDisplay(String(topic).slice(0, 64));
      extraFindings.push({
        element: "DDE Link",
        technique: "dde-link",
        content: escapeForDisplay(`ddeService="${svc}" ddeTopic="${topic}"`.slice(0, 200)),
        severity: isBlocked ? "danger" : "warning",
        category: "suspiciousPatterns",
        contextLocation: `${elFile} > ddeLink`,
        meta: ddeMeta,
      });
    }
    // <oleLink progId="cmd" .../> — similar surface area; treat as warning.
    const oleRe = /<oleLink\b([^>]*)\/?>/gi;
    let oleM;
    while ((oleM = oleRe.exec(elXml)) !== null) {
      const progId = attr(oleM[1], "progId");
      if (!progId) continue;
      extraFindings.push({
        element: "OLE Link",
        technique: "external-ole-link",
        content: escapeForDisplay(`progId="${progId}"`.slice(0, 200)),
        severity: "warning",
        category: "suspiciousPatterns",
        contextLocation: `${elFile} > oleLink`,
        meta: { progId: escapeForDisplay(String(progId).slice(0, 64)) },
      });
    }
  }

  // ------------------------------------------------------------------
  // ER-03: walk every xl/**/_rels/*.rels for TargetMode=External
  // ------------------------------------------------------------------
  await walkExternalRelationships(zip, extraFindings, allMemberNames);

  // ------------------------------------------------------------------
  // xl/sharedStrings.xml → index → text map
  // ------------------------------------------------------------------
  /** @type {string[]} */
  const sharedStrings = [];
  /** @type {boolean[]} */
  const sharedStringsLooksInstr = [];
  const ssEntry = zip.file("xl/sharedStrings.xml");
  if (ssEntry) {
    const ssXml = await readPartString(ssEntry, extraFindings, "xl/sharedStrings.xml");
    // <si>...<t...>text</t>...</si>  — concatenate <t> children inside each <si>.
    const siRe = /<si\b[^>]*>([\s\S]*?)<\/si>/gi;
    let siM;
    while ((siM = siRe.exec(ssXml)) !== null) {
      const siBody = siM[1];
      const tRe = /<t\b[^>]*>([\s\S]*?)<\/t>/gi;
      const parts = [];
      let tM;
      while ((tM = tRe.exec(siBody)) !== null) {
        parts.push(decodeXmlEntities(tM[1]));
      }
      const joined = parts.join("");
      sharedStrings.push(joined);
      sharedStringsLooksInstr.push(joined ? looksLikeInstruction(joined) : false);
    }
  }

  // ------------------------------------------------------------------
  // xl/styles.xml → MD-08 numFmt ';;;' + white-font detection
  // ------------------------------------------------------------------
  /** @type {Set<number>} */
  const hiddenStyleIds = new Set();
  /** @type {Set<number>} */
  const whiteFontIds = new Set();
  /** @type {Set<number>} */
  const cellXfsHidden = new Set();
  /** @type {Set<number>} */
  const cellXfsWhiteFont = new Set();

  const stylesEntry = zip.file("xl/styles.xml");
  if (stylesEntry) {
    const stylesXml = await readPartString(stylesEntry, extraFindings, "xl/styles.xml");

    // numFmts: <numFmt numFmtId="N" formatCode="..."/>
    const numFmtsBlock = (/<numFmts\b[^>]*>([\s\S]*?)<\/numFmts>/i.exec(stylesXml) || [])[1] || "";
    const nfRe = /<numFmt\b([^>]*)\/?>/gi;
    let nfM;
    while ((nfM = nfRe.exec(numFmtsBlock)) !== null) {
      const id = parseInt(attr(nfM[1], "numFmtId"), 10);
      const code = attr(nfM[1], "formatCode");
      if (!Number.isFinite(id) || !code) continue;
      if (isHiddenNumFmt(code)) hiddenStyleIds.add(id);
    }

    // fonts: index-based — <fonts><font>... <color rgb="FFFFFFFF"/> ...</font>...</fonts>
    const fontsBlock = (/<fonts\b[^>]*>([\s\S]*?)<\/fonts>/i.exec(stylesXml) || [])[1] || "";
    const fontRe = /<font\b[^>]*>([\s\S]*?)<\/font>/gi;
    let fontIdx = 0;
    let fontM;
    while ((fontM = fontRe.exec(fontsBlock)) !== null) {
      const body = fontM[1];
      if (/<color\b[^>]*\brgb\s*=\s*"(?:FF)?FFFFFF"/i.test(body)) {
        whiteFontIds.add(fontIdx);
      }
      fontIdx++;
    }

    // cellXfs: <cellXfs><xf numFmtId fontId .../></cellXfs> — index-keyed.
    const cellXfsBlock = (/<cellXfs\b[^>]*>([\s\S]*?)<\/cellXfs>/i.exec(stylesXml) || [])[1] || "";
    const xfRe = /<xf\b([^/>]*)\/?>/gi;
    let xfIdx = 0;
    let xfM;
    while ((xfM = xfRe.exec(cellXfsBlock)) !== null) {
      const attrs = xfM[1] || "";
      const numFmtId = parseInt(attr(attrs, "numFmtId"), 10);
      const fontId = parseInt(attr(attrs, "fontId"), 10);
      if (Number.isFinite(numFmtId) && hiddenStyleIds.has(numFmtId)) {
        cellXfsHidden.add(xfIdx);
      }
      if (Number.isFinite(fontId) && whiteFontIds.has(fontId)) {
        cellXfsWhiteFont.add(xfIdx);
      }
      xfIdx++;
    }
  }

  // ------------------------------------------------------------------
  // xl/worksheets/sheet*.xml → cell walk (with sharedString + style cross-ref)
  // ------------------------------------------------------------------
  const sheetFiles = allMemberNames
    .filter((f) => /^xl\/worksheets\/sheet\d+\.xml$/i.test(f))
    .sort((a, b) => {
      const na = parseInt((a.match(/sheet(\d+)/) || [, "0"])[1], 10);
      const nb = parseInt((b.match(/sheet(\d+)/) || [, "0"])[1], 10);
      return na - nb;
    });

  let sheetsScanned = 0;
  for (const sheetFile of sheetFiles) {
    if (sheetsScanned >= XLSX_MAX_SHEETS) {
      extraFindings.push({
        element: "XLSX Archive",
        technique: "xlsx-scan-limit",
        content: `(sheet count > ${XLSX_MAX_SHEETS}; trailing sheets skipped)`,
        severity: "warning",
        category: "hiddenHtml",
        contextLocation: "XLSX Archive",
        meta: { scope: "sheets", limitCount: XLSX_MAX_SHEETS },
      });
      break;
    }
    sheetsScanned++;

    // Resolve human-readable sheet name. Sheet ordinals in worksheets/sheetN.xml
    // are 1-based and align with the order in workbook.xml <sheets>.
    const sheetOrdinal = parseInt(
      (sheetFile.match(/sheet(\d+)/) || [, "0"])[1],
      10,
    );
    const sheetName =
      sheets[sheetOrdinal - 1] && sheets[sheetOrdinal - 1].name
        ? sheets[sheetOrdinal - 1].name
        : `Sheet${sheetOrdinal}`;

    const xml = await readPartString(zip.file(sheetFile), extraFindings, sheetFile);
    if (!xml) continue;

    // Surface the sheet name through the joined text — MD-11 wiring catches
    // RTLO / homoglyphs in sheet names.
    texts.push(`[Sheet name] ${sheetName}`);

    // Walk <c r="A1" t="..." s="N"><f>...</f><v>...</v></c> or
    // <c r="A1" t="inlineStr"><is><t>...</t></is></c>.
    const cellRe = /<c\b([^>]*)\/?>([\s\S]*?)<\/c>|<c\b([^/>]*)\/>/gi;
    let cellsEmitted = 0;
    let capWarned = false;
    let cm;
    while ((cm = cellRe.exec(xml)) !== null) {
      if (cellsEmitted >= XLSX_MAX_CELLS_PER_SHEET) {
        if (!capWarned) {
          capWarned = true;
          extraFindings.push({
            element: `Sheet '${escapeForDisplay(sheetName.slice(0, 60))}'`,
            technique: "xlsx-scan-limit",
            content: `(cell count > ${XLSX_MAX_CELLS_PER_SHEET}; trailing cells skipped)`,
            severity: "warning",
            category: "hiddenHtml",
            contextLocation: `${sheetFile}`,
            meta: { scope: "cells", limitCount: XLSX_MAX_CELLS_PER_SHEET },
          });
        }
        break;
      }

      const attrs = cm[1] || cm[3] || "";
      const body = cm[2] || "";
      const ref = attr(attrs, "r");
      const t = attr(attrs, "t");
      const styleId = parseInt(attr(attrs, "s"), 10);

      let cellText = "";
      let isFormula = false;
      let formulaBody = "";

      // <f> formula child (if any).
      const fM = /<f\b[^>]*>([\s\S]*?)<\/f>/i.exec(body);
      if (fM) {
        isFormula = true;
        formulaBody = decodeXmlEntities(fM[1] || "").trim();
      }

      if (t === "s") {
        // sharedStrings index — <v>123</v>
        const vM = /<v\b[^>]*>([\s\S]*?)<\/v>/i.exec(body);
        const idx = vM ? parseInt(vM[1], 10) : NaN;
        if (Number.isFinite(idx) && idx >= 0 && idx < sharedStrings.length) {
          cellText = sharedStrings[idx];
        }
      } else if (t === "inlineStr") {
        const inlineRe = /<t\b[^>]*>([\s\S]*?)<\/t>/gi;
        const parts = [];
        let tM;
        while ((tM = inlineRe.exec(body)) !== null) {
          parts.push(decodeXmlEntities(tM[1]));
        }
        cellText = parts.join("");
      } else if (t === "str") {
        // Cached formula string result.
        const vM = /<v\b[^>]*>([\s\S]*?)<\/v>/i.exec(body);
        if (vM) cellText = decodeXmlEntities(vM[1] || "");
      } else if (isFormula) {
        // Numeric / boolean cells with a formula — the formula body is what
        // we want to surface for FI-01/FI-02. The cached <v> is benign.
        // (We still also emit the formula body below.)
      } else {
        // t='n' (numeric) / 'b' (boolean) / 'd' (ISO date) / 'e' (error) /
        // empty (default numeric). Just take the literal <v> text — it
        // never carries a formula injection payload but may still be useful
        // context for the line stream.
        const vM = /<v\b[^>]*>([\s\S]*?)<\/v>/i.exec(body);
        if (vM) cellText = decodeXmlEntities(vM[1] || "");
      }

      const a1 = ref || "?";

      // Emit the formula body (if any) as the cell line — this is the FI-01
      // surface. XLSX `<f>` nodes carry the formula body WITHOUT the leading
      // `=` (Excel strips it on save: `<f>cmd|'/c calc'!A1</f>` represents
      // `=cmd|'/c calc'!A1` when re-rendered). Re-prepend `=` so the core
      // formula-injection detector's leading-char gate fires — the gate keys
      // off `[= + - @ \t \r]` and would otherwise miss every benign-looking
      // `<f>` body. Bodies that ALREADY start with `=` (rare but legal in
      // hand-rolled OOXML) are left untouched. Stash the cached <v> only in
      // the texts blob when it's a distinct, non-empty string cell.
      if (isFormula && formulaBody.length > 0) {
        const emitBody = formulaBody.charCodeAt(0) === 0x3d
          ? formulaBody
          : `=${formulaBody}`;
        const line = `[Sheet '${sheetName}'!${a1}] ${emitBody}`;
        texts.push(line);
        cellsEmitted++;
      } else if (cellText && cellText.length > 0) {
        const line = `[Sheet '${sheetName}'!${a1}] ${cellText}`;
        texts.push(line);
        cellsEmitted++;
      }

      // MD-08: hidden numFmt / white-font upgrade rule.
      if (Number.isFinite(styleId) && (cellXfsHidden.has(styleId) || cellXfsWhiteFont.has(styleId))) {
        const candidateText = cellText && cellText.length > 0
          ? cellText
          : (isFormula ? formulaBody : "");
        if (candidateText && candidateText.trim()) {
          const isInstr = looksLikeInstruction(candidateText);
          const severity = isInstr ? "danger" : "warning";
          const techStyle = cellXfsHidden.has(styleId)
            ? "Hidden cell (numFmt ';;;') carries text"
            : "White-on-white font carries text";
          extraFindings.push({
            element: `Sheet '${escapeForDisplay(sheetName.slice(0, 60))}'!${a1}`,
            technique: techStyle,
            content: escapeForDisplay(candidateText.slice(0, 200)),
            severity,
            category: "hiddenHtml",
            contextLocation: `Sheet '${escapeForDisplay(sheetName.slice(0, 60))}'!${a1}`,
          });
        }
      }
    }

    // SC-02 sibling: hidden rows / cols whose cells carry instruction-like text.
    // We do a light pass — scope: row hidden="1" with sharedString cells whose
    // text looksLikeInstruction. Cheap because cells are walked above; here we
    // just bag the row outline state and re-walk the row blocks.
    const hiddenRowRe = /<row\b([^>]*)>([\s\S]*?)<\/row>/gi;
    let hrM;
    while ((hrM = hiddenRowRe.exec(xml)) !== null) {
      const rowAttrs = hrM[1] || "";
      if (!/\bhidden\s*=\s*"1"/i.test(rowAttrs)) continue;
      const rowBody = hrM[2] || "";
      // Resolve each <c r=...> cell — limit to sharedStrings + inlineStr text
      // (formula bodies are already covered above).
      const innerRe = /<c\b([^>]*)\/?>([\s\S]*?)<\/c>/gi;
      let icM;
      while ((icM = innerRe.exec(rowBody)) !== null) {
        const innerAttrs = icM[1] || "";
        const innerT = attr(innerAttrs, "t");
        const innerBody = icM[2] || "";
        let resolved = "";
        if (innerT === "s") {
          const vM = /<v\b[^>]*>([\s\S]*?)<\/v>/i.exec(innerBody);
          const idx = vM ? parseInt(vM[1], 10) : NaN;
          if (Number.isFinite(idx) && idx >= 0 && idx < sharedStrings.length) {
            resolved = sharedStrings[idx];
          }
        } else if (innerT === "inlineStr") {
          const parts = [];
          const inlineRe = /<t\b[^>]*>([\s\S]*?)<\/t>/gi;
          let tM;
          while ((tM = inlineRe.exec(innerBody)) !== null) {
            parts.push(decodeXmlEntities(tM[1]));
          }
          resolved = parts.join("");
        }
        if (resolved && looksLikeInstruction(resolved)) {
          const ref = attr(innerAttrs, "r") || "?";
          extraFindings.push({
            element: `Sheet '${escapeForDisplay(sheetName.slice(0, 60))}'!${ref}`,
            technique: "Hidden row contains instruction-like text",
            content: escapeForDisplay(resolved.slice(0, 200)),
            severity: "warning",
            category: "hiddenHtml",
            contextLocation: `Sheet '${escapeForDisplay(sheetName.slice(0, 60))}'!${ref}`,
          });
        }
      }
    }
  }

  // ------------------------------------------------------------------
  // docProps/core.xml + docProps/app.xml → MD-05 + MD-06
  // ------------------------------------------------------------------
  await scanDocProps(zip, extraFindings);

  // ------------------------------------------------------------------
  // Comments + threaded comments + persons → MV-07
  // ------------------------------------------------------------------
  await scanComments(zip, allMemberNames, extraFindings);

  // ------------------------------------------------------------------
  // customXml/ → MV-09
  // ------------------------------------------------------------------
  await scanCustomXml(zip, allMemberNames, extraFindings);

  // ------------------------------------------------------------------
  // xl/embeddings/oleObject*.bin → OL-10
  // ------------------------------------------------------------------
  await scanEmbeddings(zip, allMemberNames, extraFindings);

  // ------------------------------------------------------------------
  // v1.18.0 deep-execution surface: Power Query / data connections /
  // ActiveX / customUI ribbon callbacks.
  // ------------------------------------------------------------------
  await scanPowerQuery(zip, allMemberNames, extraFindings);
  await scanDataConnections(zip, allMemberNames, extraFindings);
  await scanActiveX(zip, allMemberNames, extraFindings);
  await scanCustomUi(zip, allMemberNames, extraFindings);

  // ------------------------------------------------------------------
  // xl/media/* → reuse parseImageBuffer (mirrors docx / pptx)
  // ------------------------------------------------------------------
  await scanMedia(zip, allMemberNames, texts, extraFindings);

  return {
    text: texts.join("\n"),
    fileType: "xlsx",
    extraFindings,
  };
}

// ---------------------------------------------------------------------------
// Internal scanners
// ---------------------------------------------------------------------------

/**
 * Read a zip member as a string with the per-part inflation cap. Emits a
 * warning extraFinding if the inflated size exceeds XLSX_MAX_INFLATED_PER_PART
 * and returns the leading slice.
 */
async function readPartString(entry, extraFindings, partLabel) {
  if (!entry) return "";
  let s;
  try {
    s = await entry.async("string");
  } catch {
    return "";
  }
  if (s.length > XLSX_MAX_INFLATED_PER_PART) {
    extraFindings.push({
      element: partLabel,
      technique: "xlsx-scan-limit",
      content: `(${partLabel} inflated > ${XLSX_MAX_INFLATED_PER_PART} bytes; scanning leading slice only)`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: partLabel,
      meta: {
        scope: "part",
        limitBytes: XLSX_MAX_INFLATED_PER_PART,
        partLabel: String(partLabel),
      },
    });
    s = s.slice(0, XLSX_MAX_INFLATED_PER_PART);
  }
  return s;
}

function isHiddenNumFmt(formatCode) {
  if (typeof formatCode !== "string") return false;
  const trimmed = formatCode.trim();
  if (trimmed === ";;;") return true;
  // Every section between semicolons is empty (e.g. ";;;;" or " ; ; ; ").
  if (/^;+$/.test(trimmed)) return true;
  // [White] / [#FFFFFF] color section.
  if (/\[(?:White|#FFFFFF|#FFF)\]/i.test(trimmed)) return true;
  return false;
}

async function walkExternalRelationships(zip, extraFindings, allMemberNames) {
  // Every .rels file under xl/ or its root counterparts. Dedup by Target so we
  // emit one finding per unique URL.
  const seenTargets = new Set();
  const relsFiles = allMemberNames.filter((f) =>
    /^xl\/[^]+\.rels$/i.test(f) || /^_rels\/\.rels$/i.test(f),
  );
  for (const relsFile of relsFiles) {
    const xml = await readPartString(zip.file(relsFile), extraFindings, relsFile);
    if (!xml) continue;
    const rels = parseRelationships(xml);
    for (const r of rels) {
      if (!r.target) continue;
      if ((r.targetMode || "").toLowerCase() !== "external") continue;
      const targetKey = `${relsFile}::${r.target}`;
      if (seenTargets.has(targetKey)) continue;
      seenTargets.add(targetKey);
      const verdict = classifyExternalTarget(r.target);
      if (!verdict) continue;
      extraFindings.push({
        element: "OPC Relationship",
        technique: "external-relationship",
        content: escapeForDisplay(r.target.slice(0, 200)),
        severity: verdict.severity,
        category: "suspiciousPatterns",
        contextLocation: `${relsFile} > ${escapeForDisplay(r.id || "Relationship")}`,
        meta: { scheme: verdict.scheme },
      });
    }
  }
}

function classifyExternalTarget(target) {
  if (typeof target !== "string" || target.length === 0) return null;
  // UNC (\\host\share\...) — Windows-style network paths. RFC-encoded `file://`
  // URLs may also normalize to UNC.
  if (/^\\\\[^\\]+\\/.test(target) || /^file:\/\/\/?\\\\/i.test(target)) {
    return { severity: "danger", scheme: "unc" };
  }
  if (/^javascript:/i.test(target) || /^data:/i.test(target)) {
    return { severity: "danger", scheme: "jsOrData" };
  }
  if (/^https?:\/\//i.test(target)) {
    return { severity: "warning", scheme: "http" };
  }
  // file:// to a non-UNC location — note but don't elevate.
  if (/^file:/i.test(target)) {
    return { severity: "warning", scheme: "file" };
  }
  return null;
}

async function scanDocProps(zip, extraFindings) {
  // core.xml
  const coreEntry = zip.file("docProps/core.xml");
  if (coreEntry) {
    const xml = await readPartString(coreEntry, extraFindings, "docProps/core.xml");
    const fields = [
      "dc:title",
      "dc:subject",
      "dc:description",
      "cp:keywords",
      "cp:category",
      "dc:creator",
      "cp:lastModifiedBy",
    ];
    for (const field of fields) {
      const re = new RegExp(`<${field}\\b[^>]*>([\\s\\S]*?)</${field}>`, "i");
      const m = re.exec(xml);
      if (!m) continue;
      const val = decodeXmlEntities(m[1] || "").trim();
      if (!val) continue;
      if (!looksLikeInstruction(val)) continue;
      extraFindings.push({
        element: `docProps core:${field}`,
        technique: "docprops-prompt-injection",
        content: escapeForDisplay(val.slice(0, 200)),
        severity: "warning",
        category: "suspiciousPatterns",
        contextLocation: `docProps/core.xml > ${field}`,
        meta: { source: "core", field: String(field) },
      });
    }
  }
  // app.xml
  const appEntry = zip.file("docProps/app.xml");
  if (appEntry) {
    const xml = await readPartString(appEntry, extraFindings, "docProps/app.xml");
    const fields = ["Manager", "Company", "HeadingPairs", "TitlesOfParts"];
    for (const field of fields) {
      const re = new RegExp(`<${field}\\b[^>]*>([\\s\\S]*?)</${field}>`, "i");
      const m = re.exec(xml);
      if (!m) continue;
      const val = decodeXmlEntities(m[1] || "").trim();
      if (!val) continue;
      if (!looksLikeInstruction(val)) continue;
      extraFindings.push({
        element: `docProps app:${field}`,
        technique: "docprops-prompt-injection",
        content: escapeForDisplay(val.slice(0, 200)),
        severity: "warning",
        category: "suspiciousPatterns",
        contextLocation: `docProps/app.xml > ${field}`,
        meta: { source: "app", field: String(field) },
      });
    }

    // MD-06: HyperlinkBase silent rewrite.
    const hbM = /<HyperlinkBase\b[^>]*>([\s\S]*?)<\/HyperlinkBase>/i.exec(xml);
    if (hbM) {
      const hbVal = decodeXmlEntities(hbM[1] || "").trim();
      if (hbVal) {
        if (
          /^https?:\/\//i.test(hbVal) ||
          /^file:/i.test(hbVal) ||
          /^\\\\/.test(hbVal)
        ) {
          extraFindings.push({
            element: "docProps app:HyperlinkBase",
            technique: "hyperlink-base-rewrite",
            content: escapeForDisplay(hbVal.slice(0, 200)),
            severity: "danger",
            category: "suspiciousPatterns",
            contextLocation: "docProps/app.xml > HyperlinkBase",
          });
        }
      }
    }
  }
}

async function scanComments(zip, allMemberNames, extraFindings) {
  // Persons map — used to surface displayName via contextLocation.
  /** @type {Map<string,string>} */
  const personById = new Map();
  const personFiles = allMemberNames.filter((f) =>
    /^xl\/persons\/person\d*\.xml$/i.test(f),
  );
  for (const pf of personFiles) {
    const xml = await readPartString(zip.file(pf), extraFindings, pf);
    if (!xml) continue;
    const personRe = /<person\b([^>]*)\/?>/gi;
    let pm;
    while ((pm = personRe.exec(xml)) !== null) {
      const attrs = pm[1] || "";
      const id = attr(attrs, "id");
      const dn = attr(attrs, "displayName");
      if (id && dn) personById.set(id, dn);
    }
  }

  // Classic comments — xl/comments*.xml
  const commentFiles = allMemberNames.filter((f) =>
    /^xl\/comments\d*\.xml$/i.test(f),
  );
  for (const cf of commentFiles) {
    const xml = await readPartString(zip.file(cf), extraFindings, cf);
    if (!xml) continue;
    const cmtRe = /<comment\b([^>]*)>([\s\S]*?)<\/comment>/gi;
    let cm;
    while ((cm = cmtRe.exec(xml)) !== null) {
      const cmtAttrs = cm[1] || "";
      const cmtBody = cm[2] || "";
      const ref = attr(cmtAttrs, "ref");
      const authorId = attr(cmtAttrs, "authorId");
      const tRe = /<t\b[^>]*>([\s\S]*?)<\/t>/gi;
      const parts = [];
      let tM;
      while ((tM = tRe.exec(cmtBody)) !== null) {
        parts.push(decodeXmlEntities(tM[1]));
      }
      const text = parts.join(" ").trim();
      if (!text) continue;
      if (!looksLikeInstruction(text)) continue;
      const persona = personById.get(authorId) || "";
      extraFindings.push({
        element: "XLSX Comment",
        technique: "instruction-shaped-comment",
        content: escapeForDisplay(text.slice(0, 200)),
        severity: "warning",
        category: "hiddenHtml",
        contextLocation: persona
          ? `${cf} > comment ref='${escapeForDisplay(ref)}' persona='${escapeForDisplay(persona.slice(0, 60))}'`
          : `${cf} > comment ref='${escapeForDisplay(ref)}'`,
        meta: { threaded: false },
      });
    }
  }

  // Threaded comments — xl/threadedComments/threadedComment*.xml
  const threadedFiles = allMemberNames.filter((f) =>
    /^xl\/threadedComments\/threadedComment\d*\.xml$/i.test(f),
  );
  for (const tf of threadedFiles) {
    const xml = await readPartString(zip.file(tf), extraFindings, tf);
    if (!xml) continue;
    const tcRe = /<threadedComment\b([^>]*)>([\s\S]*?)<\/threadedComment>/gi;
    let tcM;
    while ((tcM = tcRe.exec(xml)) !== null) {
      const tcAttrs = tcM[1] || "";
      const tcBody = tcM[2] || "";
      const personId = attr(tcAttrs, "personId") || attr(tcAttrs, "id");
      const ref = attr(tcAttrs, "ref");
      const textM = /<text\b[^>]*>([\s\S]*?)<\/text>/i.exec(tcBody);
      if (!textM) continue;
      const text = decodeXmlEntities(textM[1] || "").trim();
      if (!text) continue;
      if (!looksLikeInstruction(text)) continue;
      const persona = personById.get(personId) || "";
      extraFindings.push({
        element: "XLSX Threaded Comment",
        technique: "instruction-shaped-comment",
        content: escapeForDisplay(text.slice(0, 200)),
        severity: "warning",
        category: "hiddenHtml",
        contextLocation: persona
          ? `${tf} > threadedComment ref='${escapeForDisplay(ref)}' persona='${escapeForDisplay(persona.slice(0, 60))}'`
          : `${tf} > threadedComment ref='${escapeForDisplay(ref)}'`,
        meta: { threaded: true },
      });
    }
  }
}

async function scanCustomXml(zip, allMemberNames, extraFindings) {
  const customFiles = allMemberNames.filter((f) =>
    /^customXml\/(?:item|itemProps)\d*\.xml$/i.test(f),
  );
  let totalBytes = 0;
  for (const cf of customFiles) {
    const xml = await readPartString(zip.file(cf), extraFindings, cf);
    if (!xml) continue;
    totalBytes += xml.length;
    // Strip tags / collect text nodes.
    const textOnly = xml.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
    if (textOnly && looksLikeInstruction(textOnly)) {
      extraFindings.push({
        element: "CustomXML Part",
        technique: "CustomXML prompt-injection payload",
        content: escapeForDisplay(textOnly.slice(0, 200)),
        severity: "warning",
        category: "hiddenHtml",
        contextLocation: cf,
      });
    }
  }
  if (totalBytes > CUSTOM_XML_OVERSIZE_THRESHOLD) {
    extraFindings.push({
      element: "CustomXML Bundle",
      technique: "Oversize CustomXML (structural anomaly)",
      content: `(total customXml/ text > ${CUSTOM_XML_OVERSIZE_THRESHOLD} bytes)`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "customXml/",
    });
  }
}

async function scanEmbeddings(zip, allMemberNames, extraFindings) {
  const embedFiles = allMemberNames.filter((f) =>
    /^xl\/embeddings\/[^/]+\.bin$/i.test(f),
  );
  for (const ef of embedFiles) {
    const entry = zip.file(ef);
    if (!entry) continue;
    let buf;
    try {
      buf = await entry.async("nodebuffer");
    } catch {
      continue;
    }
    if (buf.length > OFFICE_MEDIA_MAX_BYTES) {
      extraFindings.push({
        element: "XLSX Embedded Object",
        technique: "oversize-embedded-object",
        content: escapeForDisplay(ef.slice(0, 200)),
        severity: "warning",
        category: "hiddenHtml",
        contextLocation: ef,
        meta: { maxBytes: OFFICE_MEDIA_MAX_BYTES },
      });
      continue;
    }
    // CFB / OLE2 magic check + filename hint.
    let hasCfbMagic = false;
    if (buf.length >= 8) {
      hasCfbMagic = true;
      for (let i = 0; i < 8; i++) {
        if (buf[i] !== CFB_MAGIC[i]) {
          hasCfbMagic = false;
          break;
        }
      }
    }
    const hasDangerousExtHint = DANGEROUS_EMBED_EXT_RE.test(ef);
    if (hasCfbMagic && hasDangerousExtHint) {
      extraFindings.push({
        element: "XLSX Embedded OLE",
        technique: "Embedded OLE object (CFB magic + dangerous ext hint)",
        content: escapeForDisplay(ef.slice(0, 200)),
        severity: "danger",
        category: "hiddenHtml",
        contextLocation: ef,
      });
    } else {
      extraFindings.push({
        element: "XLSX Embedded OLE",
        technique: "Embedded OLE object present",
        content: escapeForDisplay(ef.slice(0, 200)),
        severity: "warning",
        category: "hiddenHtml",
        contextLocation: ef,
      });
    }
  }
}

// v1.18.0 — Power Query M expressions embedded in customXml that fetch over
// HTTP (Web.Contents / Csv.Document(Web.Contents(...)) / Json.Document etc.).
// These run at refresh time without macro consent and are a classic data-pull
// / exfil channel.
async function scanPowerQuery(zip, allMemberNames, extraFindings) {
  const customFiles = allMemberNames.filter((f) =>
    /^customXml\/(?:item|itemProps)\d*\.xml$/i.test(f),
  );
  for (const cf of customFiles) {
    const xml = await readPartString(zip.file(cf), extraFindings, cf);
    if (!xml) continue;
    if (!POWER_QUERY_WEBCONTENTS_RE.test(xml)) continue;
    const m = POWER_QUERY_WEBCONTENTS_RE.exec(xml);
    const fnName = m ? m[0] : "Web.Contents";
    extraFindings.push({
      element: "Power Query M",
      technique: "xlsx-power-query-webcontents",
      content: escapeForDisplay(
        `${fnName} reference in ${cf}`.slice(0, 200),
      ),
      severity: "danger",
      category: "suspiciousPatterns",
      contextLocation: `${cf} > Power Query`,
      meta: {
        connectionType: "powerQuery",
        callbackName: escapeForDisplay(String(fnName).slice(0, 64)),
      },
    });
  }
}

// xl/connections.xml carries OLEDB / ODBC connection strings. A shell-runner
// token inside the connection string (or its command/initial-catalog property)
// indicates a code-execution data connection — e.g. OLEDB Shell provider that
// runs cmd at refresh.
async function scanDataConnections(zip, allMemberNames, extraFindings) {
  if (!allMemberNames.includes("xl/connections.xml")) return;
  const entry = zip.file("xl/connections.xml");
  if (!entry) return;
  const xml = await readPartString(entry, extraFindings, "xl/connections.xml");
  if (!xml) return;
  // Iterate every <connection ...> tag and inspect its child connection-string
  // / command attributes.
  const connRe = /<connection\b([^>]*)>([\s\S]*?)<\/connection>|<connection\b([^/>]*)\/>/gi;
  let cm;
  while ((cm = connRe.exec(xml)) !== null) {
    const attrs = cm[1] || cm[3] || "";
    const body = cm[2] || "";
    const haystack = `${attrs} ${body}`;
    if (!DATA_CONNECTION_SHELL_RE.test(haystack)) continue;
    const tokenMatch = DATA_CONNECTION_SHELL_RE.exec(haystack);
    const token = tokenMatch ? tokenMatch[0] : "shell";
    // Infer connection type from db type attribute if present.
    const dbType =
      /\bdbCommand\b/i.test(haystack) || /OLEDB/i.test(haystack)
        ? "OLEDB"
        : /ODBC/i.test(haystack)
          ? "ODBC"
          : "other";
    extraFindings.push({
      element: "Data Connection",
      technique: "xlsx-data-connection-shell",
      content: escapeForDisplay(
        `${dbType} connection carries shell-runner token`.slice(0, 200),
      ),
      severity: "danger",
      category: "suspiciousPatterns",
      contextLocation: "xl/connections.xml > connection",
      meta: {
        connectionType: dbType,
        hasShellKeyword: true,
        callbackName: escapeForDisplay(String(token).slice(0, 64)),
      },
    });
  }
}

// xl/activeX/activeX*.bin — presence of an ActiveX control is a useful signal
// (Equation Editor CVE-2017-11882 / CVE-2018-0802 family). We don't unpack the
// CFB body, just surface the presence with a kebab id so downstream tooling
// can warn.
async function scanActiveX(zip, allMemberNames, extraFindings) {
  const activeXFiles = allMemberNames.filter((f) =>
    /^xl\/activeX\/activeX\d*\.bin$/i.test(f),
  );
  for (const af of activeXFiles) {
    const entry = zip.file(af);
    if (!entry) continue;
    let buf;
    try {
      buf = await entry.async("nodebuffer");
    } catch {
      continue;
    }
    // CFB / OLE2 magic check — Equation-Editor objects ship as CFB.
    let hasCfbMagic = false;
    if (buf.length >= 8) {
      hasCfbMagic = true;
      for (let i = 0; i < 8; i++) {
        if (buf[i] !== CFB_MAGIC[i]) {
          hasCfbMagic = false;
          break;
        }
      }
    }
    extraFindings.push({
      element: "ActiveX Control",
      technique: "xlsx-activex-control",
      content: escapeForDisplay(af.slice(0, 200)),
      severity: "warning",
      category: "suspiciousPatterns",
      contextLocation: af,
      meta: {
        connectionType: hasCfbMagic ? "cfb" : "binary",
        hasShellKeyword: false,
      },
    });
  }
}

// customUI/customUI*.xml / customUI/customUI14.xml — Office ribbon
// customization. Callback attributes (onLoad / onAction / getEnabled ...)
// name VBA procedure entrypoints triggered without further user consent.
async function scanCustomUi(zip, allMemberNames, extraFindings) {
  const customUiFiles = allMemberNames.filter((f) =>
    /^customUI\/customUI(?:\d+)?\.xml$/i.test(f),
  );
  for (const uf of customUiFiles) {
    const xml = await readPartString(zip.file(uf), extraFindings, uf);
    if (!xml) continue;
    const seen = new Set();
    let m;
    CUSTOM_UI_CALLBACK_RE.lastIndex = 0;
    while ((m = CUSTOM_UI_CALLBACK_RE.exec(xml)) !== null) {
      const attrName = m[1];
      const cbName = (m[2] || "").trim();
      if (!cbName) continue;
      const key = `${attrName}::${cbName}`;
      if (seen.has(key)) continue;
      seen.add(key);
      extraFindings.push({
        element: "CustomUI Callback",
        technique: "xlsx-custom-ui-callback",
        content: escapeForDisplay(
          `${attrName}="${cbName}"`.slice(0, 200),
        ),
        severity: "warning",
        category: "suspiciousPatterns",
        contextLocation: `${uf} > ${attrName}`,
        meta: {
          connectionType: "customUI",
          callbackName: escapeForDisplay(String(cbName).slice(0, 64)),
          hasShellKeyword: false,
        },
      });
    }
  }
}

async function scanMedia(zip, allMemberNames, texts, extraFindings) {
  const mediaFiles = allMemberNames.filter((f) => /^xl\/media\/[^/]+$/.test(f));
  let mediaProcessed = 0;
  for (const mediaPath of mediaFiles) {
    if (mediaProcessed >= OFFICE_MEDIA_MAX_COUNT) break;
    const ext = extname(mediaPath).slice(1).toLowerCase();
    if (!OFFICE_IMAGE_EXTS.has(ext)) continue;
    const entry = zip.file(mediaPath);
    if (!entry) continue;
    const mediaName = mediaPath.replace(/^xl\/media\//, "");
    let buf;
    try {
      buf = await entry.async("nodebuffer");
    } catch {
      continue;
    }
    if (buf.length === 0) {
      extraFindings.push({
        element: "XLSX Embedded Image",
        technique: "empty-embedded-image",
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: "warning",
        contextLocation: `XLSX media:${mediaName}`,
      });
      mediaProcessed++;
      continue;
    }
    if (buf.length > OFFICE_MEDIA_MAX_BYTES) {
      extraFindings.push({
        element: "XLSX Embedded Image",
        technique: "oversize-embedded-image",
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: "warning",
        contextLocation: `XLSX media:${mediaName}`,
        meta: { maxBytes: OFFICE_MEDIA_MAX_BYTES },
      });
      mediaProcessed++;
      continue;
    }
    let sub;
    try {
      sub = await parseImageBuffer(buf, ext);
    } catch {
      mediaProcessed++;
      continue;
    }
    mediaProcessed++;
    if (!sub) continue;
    if (sub.text && sub.text.trim()) {
      texts.push(`[XLSX media:${mediaName}]`);
      texts.push(sub.text);
    }
    if (Array.isArray(sub.extraFindings)) {
      for (const f of sub.extraFindings) {
        const existing =
          typeof f.contextLocation === "string" ? f.contextLocation : "";
        extraFindings.push({
          ...f,
          contextLocation: existing
            ? `XLSX media:${mediaName} > ${existing}`
            : `XLSX media:${mediaName}`,
        });
      }
    }
  }
}
