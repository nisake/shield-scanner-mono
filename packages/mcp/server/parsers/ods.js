/**
 * v1.20.0 Theme T2 — OpenDocument Spreadsheet (.ods) parser.
 *
 * LibreOffice / Calligra Sheets / Apple Numbers ingestion path. .ods is a ZIP
 * archive carrying:
 *   - content.xml    — sheet/row/cell payload (<table:table>/<table:table-row>/
 *                      <table:table-cell> with optional table:formula="of:=…").
 *   - settings.xml   — view + persistent settings, including <config:config-item>
 *                      entries that smuggle DDE / external command refs.
 *   - meta.xml       — document metadata (author / title / description).
 *   - manifest.xml   — file manifest (no MIME negotiation; matched literally).
 *   - Basic/*        — LibreOffice Basic macro scripts (auto-run candidates).
 *
 * Surfaces:
 *   - ods-formula-injection         — <table:formula> bodies that match the
 *                                     shared core formula-injection ruleset
 *                                     (HYPERLINK / WEBSERVICE / IMPORTXML /
 *                                     DDE() / cmd|powershell shell tokens,
 *                                     etc.). Reuses the CSV/XLSX detector
 *                                     so the rule corpus stays single-source.
 *   - ods-external-dde-link         — content.xml DDE LINK formula
 *                                     (=DDE("svc";"topic";"item") ) targeting
 *                                     a shell runner, OR a settings.xml
 *                                     config-item referencing a remote
 *                                     external command / hyperlink-base.
 *   - ods-hidden-sheet-instruction  — table tagged table:display="false"
 *                                     (Calc hidden sheet) or
 *                                     table:protected="true" carrying an
 *                                     instruction-shaped cell body. LLM
 *                                     ingestion still walks the XML so the
 *                                     hidden sheet is a quiet stash spot.
 *   - ods-macro-bearing             — Basic/ directory present OR
 *                                     office:scripts node with a Basic /
 *                                     JavaScript event-listener referencing
 *                                     a macro entry. The .ods extension
 *                                     does NOT change for macro-bearing
 *                                     spreadsheets (unlike .xlsm vs .xlsx)
 *                                     so this is the only signal a viewer
 *                                     gets pre-open.
 *
 * Defensive caps (mirror xlsx.js envelope):
 *   - ODS_MAX_ARCHIVE_BYTES   = 15 MB (whole .ods file)
 *   - ODS_MAX_INFLATED_PER_PART = 8 MB (per zip member after .async('string'))
 *   - ODS_MAX_SHEETS           = 50
 *   - ODS_MAX_CELLS_PER_SHEET  = 50 000
 *
 * R12: sheet names, member names, formula bodies are escape-encoded via
 * `escapeForDisplay` before any `content` / `contextLocation` use. The
 * `[ODS Sheet 'Name'!A1] ` scaffolding is detector-controlled — the parser
 * knows the sheet name + cell coordinates from the OpenDocument grammar.
 * R13: every new kebab id folds into `category: 'suspiciousPatterns'` (or
 * `category: 'hiddenHtml'` for scan-limit / corrupt-zip warnings, matching
 * the xlsx.js envelope) — NO new top-level byCategory key.
 * R18: loadRule is NOT called at module-load. `detectFormulaInjection` is
 * imported from `@shield-scanner/core` and engages lazily (its own
 * `loadRule` call happens inside the detector).
 *
 * Output shape:
 *   { text, fileType: 'ods', extraFindings, fileInfo? }
 */

import { readFile } from "node:fs/promises";
import JSZip from "jszip";
import {
  escapeForDisplay,
  looksLikeInstruction,
  detectFormulaInjection,
} from "@shield-scanner/core";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ODS_MAX_ARCHIVE_BYTES = 15 * 1024 * 1024;
const ODS_MAX_INFLATED_PER_PART = 8 * 1024 * 1024;
const ODS_MAX_SHEETS = 50;
const ODS_MAX_CELLS_PER_SHEET = 50000;

// DDE() formula service-name shell-runner blocklist.
const ODS_DDE_SHELL_RE =
  /\b(?:cmd(?:\.exe)?|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)\b/i;

// settings.xml config-item bodies that reference a remote external command.
const ODS_SETTINGS_EXTERNAL_CMD_RE =
  /(?:https?:\/\/|\\\\[^\s"<>]+\\[^\s"<>]+|cmd(?:\.exe)?|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)/i;

// office:scripts macro-bearing event listener regex.
const ODS_SCRIPT_EVENT_LISTENER_RE =
  /<script:event-listener\b[^/>]*\bscript:language\s*=\s*["']ooo:script["'][^/>]*>/i;

// content.xml namespace-tag regex helpers.
// NOTE 1: `<table:table` overlaps with `<table:table-row>` / `<table:table-cell>`
// because `\b` does not treat `-` as a word boundary in JS regexen. Match the
// trailing space/tab/slash/gt to disambiguate the bare-table tag from its
// hyphenated descendants.
// NOTE 2: Attribute fragments can legally carry `/` inside attribute values
// (e.g. `table:formula="of:=cmd|'/c calc.exe'!A1"`), so the attr capture
// excludes `>` only — self-closing tags are detected via the captured
// fragment ending in `/`.
const TABLE_OPEN_RE = /<table:table(?=[\s/>])([^>]*?)\/?>/gi;
const TABLE_CLOSE_RE = /<\/table:table>/gi;
const ROW_OPEN_RE = /<table:table-row\b([^>]*?)>/gi;
const CELL_RE = /<table:table-cell\b([^>]*?)(?:\/>|>([\s\S]*?)<\/table:table-cell>)/gi;
const FORMULA_ATTR_RE = /\btable:formula\s*=\s*"([^"]*)"/i;
const NUMBER_COLS_REPEATED_RE = /\btable:number-columns-repeated\s*=\s*"(\d+)"/i;

// XML entity decoder (sufficient for the OpenDocument payloads we touch).
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

// Convert 1-based column index to A1-style letters.
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

// Strip XML tags to leave inline text (used for <text:p> cell body extraction).
function stripXmlTags(s) {
  if (typeof s !== "string" || s.length === 0) return "";
  return decodeXmlEntities(s.replace(/<[^>]*>/g, ""));
}

// Strip OpenDocument formula namespace prefix (of:= / oooc:= / msoxl:=).
function stripOdfFormulaPrefix(s) {
  if (typeof s !== "string" || s.length === 0) return s;
  return s.replace(/^(?:of|oooc|msoxl):/i, "");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function parseOds(filePath) {
  const buffer = await readFile(filePath);
  return parseOdsBuffer(buffer);
}

/**
 * Parse ODS from a Buffer / Uint8Array.
 *
 * @param {Buffer|Uint8Array} buffer
 * @param {Object} [opts]
 * @returns {Promise<{text:string, fileType:'ods', extraFindings:Array}>}
 */
export async function parseOdsBuffer(buffer, opts = {}) {
  const texts = [];
  const extraFindings = [];

  const u8 =
    buffer instanceof Uint8Array
      ? buffer
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  // --- Defensive cap: archive bytes ---
  if (u8.byteLength > ODS_MAX_ARCHIVE_BYTES) {
    extraFindings.push({
      element: "ODS Archive",
      technique: "ods-scan-limit",
      content: `(archive > ${ODS_MAX_ARCHIVE_BYTES} bytes; not scanned)`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "ODS Archive",
      meta: { scope: "archive", maxBytes: ODS_MAX_ARCHIVE_BYTES, byteLen: u8.byteLength },
    });
    return { text: "", fileType: "ods", extraFindings };
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
      element: "ODS Archive",
      technique: "ods-corrupt-zip",
      content: escapeForDisplay(
        (err && err.message ? err.message : "JSZip parse error").slice(0, 200),
      ),
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "ODS Archive",
      meta: { errorMessage: errMsg },
    });
    return { text: "", fileType: "ods", extraFindings };
  }

  const allMemberNames = Object.keys(zip.files);
  if (allMemberNames.length > 0) {
    texts.push("[ODS members] " + allMemberNames.join(" "));
  }

  // --- ods-macro-bearing: Basic/ directory or office:scripts node ---
  const hasBasicDir = allMemberNames.some((n) => /^Basic\/[^/]+/i.test(n));
  if (hasBasicDir) {
    extraFindings.push({
      element: "ODS Archive",
      technique: "ods-macro-bearing",
      content: "Basic/ macro directory present",
      severity: "danger",
      category: "suspiciousPatterns",
      contextLocation: "Basic/",
      meta: { source: "basic-dir" },
    });
  }

  // --- content.xml walk ---
  const contentEntry = zip.file("content.xml");
  let contentXml = "";
  if (contentEntry) {
    contentXml = await readPartString(contentEntry, extraFindings, "content.xml");
  }

  // office:scripts event-listener — surfaced even without Basic/ dir present
  // (e.g. macros stored as JavaScript inline in scripts node).
  if (contentXml && ODS_SCRIPT_EVENT_LISTENER_RE.test(contentXml) && !hasBasicDir) {
    extraFindings.push({
      element: "ODS content.xml",
      technique: "ods-macro-bearing",
      content: "office:scripts event-listener (script:language=\"ooo:script\")",
      severity: "danger",
      category: "suspiciousPatterns",
      contextLocation: "content.xml office:scripts",
      meta: { source: "office-scripts" },
    });
  }

  // Walk sheets / rows / cells.
  if (contentXml) {
    walkContent(contentXml, texts, extraFindings);
  }

  // --- settings.xml: external command / DDE reference scan ---
  const settingsEntry = zip.file("settings.xml");
  if (settingsEntry) {
    const settingsXml = await readPartString(settingsEntry, extraFindings, "settings.xml");
    if (settingsXml) {
      scanSettingsForExternalCmd(settingsXml, extraFindings);
    }
  }

  // --- meta.xml / META-INF/manifest.xml: stream metadata into the text blob ---
  // (No structural findings here — analyze() catches RTLO / homoglyphs in
  //  author / title / description fields via the unified pipeline.)
  for (const metaName of ["meta.xml", "META-INF/manifest.xml"]) {
    const ent = zip.file(metaName);
    if (!ent) continue;
    const xml = await readPartString(ent, extraFindings, metaName);
    if (xml) texts.push(`[ODS ${metaName}]\n${stripXmlTags(xml)}`);
  }

  // --- Run formula-injection on the joined cell stream ---
  // The walker emits each formula on its own line prefixed
  // `[ODS Sheet 'Name'!A1] =FORMULABODY`. The shared detector understands
  // this prefix shape (mirrors xlsx.js) so the contextLocation is preserved.
  // R13: every finding lands in suspiciousPatterns (the detector tags it).
  const formulaText = texts.filter((l) => l.startsWith("[ODS Sheet ")).join("\n");
  if (formulaText.length > 0) {
    try {
      // Pass fileType:'xlsx' to engage the shared detector — the rule corpus
      // is single-source across CSV/XLSX/ODS and the detector's per-line
      // bracket-prefix stripper handles `[ODS Sheet 'Name'!A1] =FORMULA`
      // identically to the XLSX `[Sheet 'Name'!A1] =FORMULA` shape.
      const fi = detectFormulaInjection(formulaText, "xlsx");
      if (Array.isArray(fi)) {
        for (const f of fi) {
          // Re-stamp the kebab id to the ODS-namespaced one — the rule corpus
          // is shared with CSV/XLSX so we own the surface kebab here.
          extraFindings.push({
            element: f.element || "ODS formula",
            technique: "ods-formula-injection",
            content: f.content || "",
            severity: f.severity || "danger",
            category: "suspiciousPatterns",
            contextLocation: f.contextLocation || "ODS formula",
            meta: {
              ...(f.meta || {}),
              originalTechnique: f.technique || "formula-injection",
            },
          });
        }
      }
    } catch {
      // detector failure must NOT abort parser — R18 envelope.
    }
  }

  return {
    text: texts.join("\n\n"),
    fileType: "ods",
    extraFindings,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function readPartString(entry, extraFindings, partName) {
  try {
    const s = await entry.async("string");
    if (typeof s !== "string") return "";
    if (s.length > ODS_MAX_INFLATED_PER_PART) {
      extraFindings.push({
        element: "ODS part",
        technique: "ods-scan-limit",
        content: `(${escapeForDisplay(partName)} > ${ODS_MAX_INFLATED_PER_PART} bytes; truncated)`,
        severity: "warning",
        category: "hiddenHtml",
        contextLocation: escapeForDisplay(partName),
        meta: {
          scope: "part",
          partName: escapeForDisplay(partName),
          maxBytes: ODS_MAX_INFLATED_PER_PART,
        },
      });
      return s.slice(0, ODS_MAX_INFLATED_PER_PART);
    }
    return s;
  } catch (err) {
    const msg = err && err.message ? err.message : "decompress error";
    extraFindings.push({
      element: "ODS part",
      technique: "ods-corrupt-zip",
      content: escapeForDisplay(msg.slice(0, 200)),
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: escapeForDisplay(partName),
      meta: { partName: escapeForDisplay(partName), errorMessage: escapeForDisplay(msg.slice(0, 64)) },
    });
    return "";
  }
}

/**
 * Walk content.xml — for each <table:table>, walk rows + cells, surface
 * formula bodies + cell text, and emit ods-hidden-sheet-instruction /
 * ods-external-dde-link findings.
 */
function walkContent(xml, texts, extraFindings) {
  // Slice into per-table fragments so we keep sheet attribution.
  // We do a simple split on the close tag — sufficient for the OpenDocument
  // grammar (no nested table:table inside another). pdfdom-style namespace
  // collisions are not a concern here.
  const tableOpens = [];
  let m;
  TABLE_OPEN_RE.lastIndex = 0;
  while ((m = TABLE_OPEN_RE.exec(xml)) !== null) {
    tableOpens.push({ start: m.index, end: m.index + m[0].length, attrs: m[1] || "" });
  }

  const tableCloses = [];
  TABLE_CLOSE_RE.lastIndex = 0;
  while ((m = TABLE_CLOSE_RE.exec(xml)) !== null) {
    tableCloses.push(m.index);
  }

  const sheetCount = Math.min(tableOpens.length, ODS_MAX_SHEETS);
  if (tableOpens.length > ODS_MAX_SHEETS) {
    extraFindings.push({
      element: "ODS content.xml",
      technique: "ods-scan-limit",
      content: `(sheet count ${tableOpens.length} > ${ODS_MAX_SHEETS}; trailing sheets skipped)`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "content.xml",
      meta: { scope: "sheets", maxSheets: ODS_MAX_SHEETS, sheetCount: tableOpens.length },
    });
  }

  for (let s = 0; s < sheetCount; s++) {
    const open = tableOpens[s];
    const close = tableCloses[s] || xml.length;
    const sheetName = attr(open.attrs, "table:name") || `Sheet${s + 1}`;
    const sheetDisplay = attr(open.attrs, "table:display");
    const sheetProtected = attr(open.attrs, "table:protected");
    const sheetBody = xml.slice(open.end, close);
    const isHidden = sheetDisplay === "false";
    const isProtected = sheetProtected === "true";

    // Walk rows + cells.
    let rowIndex = 0;
    let cellCount = 0;
    let cappedHere = false;
    ROW_OPEN_RE.lastIndex = 0;
    let rowMatch;
    const rowSplits = [];
    while ((rowMatch = ROW_OPEN_RE.exec(sheetBody)) !== null) {
      rowSplits.push(rowMatch.index + rowMatch[0].length);
    }
    // For simplicity, iterate cells per row via slice between row open and
    // next row open (or end of sheet body).
    for (let r = 0; r < rowSplits.length; r++) {
      if (cappedHere) break;
      rowIndex++;
      const rowStart = rowSplits[r];
      const rowEnd = r + 1 < rowSplits.length ? rowSplits[r + 1] : sheetBody.length;
      const rowFragment = sheetBody.slice(rowStart, rowEnd);

      let colIndex = 0;
      CELL_RE.lastIndex = 0;
      let cm;
      while ((cm = CELL_RE.exec(rowFragment)) !== null) {
        if (cellCount >= ODS_MAX_CELLS_PER_SHEET) {
          extraFindings.push({
            element: `ODS Sheet '${escapeForDisplay(sheetName)}'`,
            technique: "ods-scan-limit",
            content: `(cell count > ${ODS_MAX_CELLS_PER_SHEET}; trailing cells skipped)`,
            severity: "warning",
            category: "hiddenHtml",
            contextLocation: `ODS Sheet '${escapeForDisplay(sheetName)}'`,
            meta: {
              scope: "cells",
              maxCellsPerSheet: ODS_MAX_CELLS_PER_SHEET,
              sheetName: escapeForDisplay(sheetName),
            },
          });
          cappedHere = true;
          break;
        }
        const cellAttrs = cm[1] || "";
        const cellInner = cm[2] || "";
        const repeatM = NUMBER_COLS_REPEATED_RE.exec(cellAttrs);
        const repeat = repeatM ? Math.min(parseInt(repeatM[1], 10) || 1, 64) : 1;
        // Advance colIndex once per repeat group (we only emit the first
        // instance — repeated empty/typed cells are a layout primitive).
        colIndex += 1;
        const colLetters = colNumToLetters(colIndex);
        const ref = `${colLetters}${rowIndex}`;

        const fm = FORMULA_ATTR_RE.exec(cellAttrs);
        const formulaRaw = fm ? decodeXmlEntities(fm[1]) : "";
        const formulaBody = stripOdfFormulaPrefix(formulaRaw);
        const cellText = stripXmlTags(cellInner).trim();

        if (formulaBody) {
          // Emit on the formula text stream so detectFormulaInjection sweeps
          // it with sheet attribution.
          texts.push(`[ODS Sheet '${sheetName}'!${ref}] ${formulaBody}`);

          // DDE() link with shell-runner service name.
          const ddeMatch = /\bDDE\s*\(\s*["']([^"']+)["']/i.exec(formulaBody);
          if (ddeMatch && ODS_DDE_SHELL_RE.test(ddeMatch[1])) {
            extraFindings.push({
              element: `ODS Sheet '${escapeForDisplay(sheetName)}'!${ref}`,
              technique: "ods-external-dde-link",
              content: escapeForDisplay(formulaBody.slice(0, 200)),
              severity: "danger",
              category: "suspiciousPatterns",
              contextLocation: `ODS Sheet '${escapeForDisplay(sheetName)}'!${ref}`,
              meta: {
                sheetName: escapeForDisplay(sheetName),
                ref,
                ddeService: escapeForDisplay(ddeMatch[1].slice(0, 64)),
                source: "formula-dde",
              },
            });
          }
        }

        if (cellText) {
          // Emit cell text into the general text stream for unicode / md-exfil
          // / homoglyph sweeps.
          texts.push(`[ODS Sheet '${sheetName}'!${ref}] ${cellText}`);

          // Hidden / protected sheet smuggling an instruction-shaped cell.
          if ((isHidden || isProtected) && looksLikeInstruction(cellText)) {
            extraFindings.push({
              element: `ODS Sheet '${escapeForDisplay(sheetName)}'!${ref}`,
              technique: "ods-hidden-sheet-instruction",
              content: escapeForDisplay(cellText.slice(0, 200)),
              severity: "danger",
              category: "suspiciousPatterns",
              contextLocation: `ODS Sheet '${escapeForDisplay(sheetName)}'!${ref}`,
              meta: {
                sheetName: escapeForDisplay(sheetName),
                ref,
                isHidden,
                isProtected,
              },
            });
          }
        }

        cellCount++;
        if (repeat > 1) colIndex += repeat - 1;
      }
    }
  }
}

/**
 * Scan settings.xml for config-item bodies that reference an external command
 * or DDE-style remote target. Surfaces ods-external-dde-link with a
 * settings-side source tag.
 */
function scanSettingsForExternalCmd(settingsXml, extraFindings) {
  // <config:config-item config:name="…" config:type="string">BODY</config:config-item>
  const re = /<config:config-item\b([^/>]*)>([\s\S]*?)<\/config:config-item>/gi;
  let m;
  let hits = 0;
  while ((m = re.exec(settingsXml)) !== null && hits < 64) {
    const itemAttrs = m[1] || "";
    const body = decodeXmlEntities(m[2] || "");
    if (!body) continue;
    if (ODS_SETTINGS_EXTERNAL_CMD_RE.test(body)) {
      const name = attr(itemAttrs, "config:name") || "(unnamed)";
      extraFindings.push({
        element: `ODS settings.xml config-item '${escapeForDisplay(name)}'`,
        technique: "ods-external-dde-link",
        content: escapeForDisplay(body.slice(0, 200)),
        severity: "danger",
        category: "suspiciousPatterns",
        contextLocation: `settings.xml config-item '${escapeForDisplay(name)}'`,
        meta: {
          source: "settings-external-cmd",
          configName: escapeForDisplay(name.slice(0, 64)),
        },
      });
      hits++;
    }
  }
}
