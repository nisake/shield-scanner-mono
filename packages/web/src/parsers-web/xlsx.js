// XLSX parser (S10) - Web mirror of packages/mcp/server/parsers/xlsx.js.
//
// Depends on global: JSZip (CDN-loaded in index.template.html L25)
// Depends on core:
//   - escapeForDisplay / looksLikeInstruction (existing utils)
//   - parseRelationships / parseContentTypes / normalizeXlfn /
//     normalizeFormulaPrefix (S10 opc-helpers)
//
// R14 (library trap): regex-on-XML only — NO DOMParser, NO cheerio.
// R18 (env-abstract order contract): NO loadRule() at module-load.
//   detectFormulaInjection is NOT called here — analyze() folds it in when
//   fileType==='xlsx' is passed.
// R12 (no shadow-leak): raw cell content goes through escapeForDisplay before
//   any UI-bound field. Parser-emitted bracket prefix `[Sheet 'Name'!A1]` is
//   detector-controlled scaffolding (safe).
// R13 (5-key byCategory invariant): hiddenFindings carry `category` =
//   'suspiciousPatterns' | 'hiddenHtml' ONLY. The item-level `category`
//   ('formula-injection' / 'external-ref' / 'metadata-injection' /
//   'hidden-comment') is for routing/scoring only.
//
// Defensive caps (Web — per-part lowered to 5 MB vs MCP 8 MB to defend tab OOM):
//   XLSX_MAX_ARCHIVE_BYTES        = 15 MB (whole archive)
//   WEB_XLSX_MAX_INFLATED_PER_PART = 5 MB (per zip member after async('string'))
//   XLSX_MAX_SHEETS               = 50
//   XLSX_MAX_CELLS_PER_SHEET      = 50000
//   Web-only short-circuit: buffer.byteLength > 10 MB → oversize warning + bail.
//
// Image recursion reuses parseImage from image.js with the existing
// OFFICE_MEDIA_MAX_BYTES (5 MB) / OFFICE_MEDIA_MAX_COUNT (50) constants
// from docx.js — drift-safe.

import {
  escapeForDisplay,
  looksLikeInstruction,
  parseRelationships,
  parseContentTypes,
  normalizeXlfn,
  normalizeFormulaPrefix,
} from '@shield-scanner/core';
import { parseImage } from './image.js';
import { _extOf, _PDF_IMAGE_EXTS } from './pdf.js';

// --- Defensive caps ---------------------------------------------------------
const XLSX_MAX_ARCHIVE_BYTES = 15 * 1024 * 1024;
const WEB_XLSX_MAX_INFLATED_PER_PART = 5 * 1024 * 1024;
const XLSX_MAX_SHEETS = 50;
const XLSX_MAX_CELLS_PER_SHEET = 50000;
const WEB_XLSX_ARCHIVE_SHORT_CIRCUIT = 10 * 1024 * 1024; // tab-OOM defense
const _OFFICE_MEDIA_MAX_BYTES = 5 * 1024 * 1024;
const _OFFICE_MEDIA_MAX_COUNT = 50;
const CUSTOMXML_MAX_BYTES = 8 * 1024;

// Dangerous-function tokens for FI-03 definedName body scan / ddeService gate.
const DANGEROUS_FN_RE =
  /\b(?:HYPERLINK|WEBSERVICE|FILTERXML|IMPORTXML|IMPORTHTML|IMPORTDATA|IMPORTFEED|IMPORTRANGE|CALL|REGISTER|EXEC|RTD|DDE|DDEAUTO)\b|\bcmd\||powershell|mshta|wscript|cscript|rundll32|regsvr32/i;
const DDE_DANGEROUS_SERVICE_RE = /\b(?:cmd|powershell|mshta|wscript|cscript|rundll32|regsvr32)\b/i;
const AUTO_DEFINED_NAME_RE =
  /^_xlnm\.?(?:Auto_Open|Auto_Close|Auto_Activate|Auto_Deactivate)$|^Auto_Open$|^Workbook_Open$/i;

// v1.18.0 — deep-execution surface mirrors (byte-identical to MCP xlsx.js).
const POWER_QUERY_WEBCONTENTS_RE =
  /\b(?:Web\.Contents|Web\.BrowserContents|Csv\.Document\s*\(\s*Web\.Contents|Json\.Document\s*\(\s*Web\.Contents|Xml\.Tables\s*\(\s*Web\.Contents)\b/i;
const DATA_CONNECTION_SHELL_RE =
  /\b(?:cmd(?:\.exe)?|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)\b/i;
const CUSTOM_UI_CALLBACK_RE =
  /\b(onLoad|onAction|getEnabled|getVisible|getLabel|getImage|getContent)\s*=\s*"([^"]+)"/gi;
const _CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

// --- Helpers ----------------------------------------------------------------
function decodeXmlEntities(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function _attr(attrs, name) {
  if (!attrs) return '';
  const re = new RegExp(
    '\\b' + name + '\\s*=\\s*"([^"]*)"|\\b' + name + "\\s*=\\s*'([^']*)'",
    'i',
  );
  const m = re.exec(attrs);
  if (!m) return '';
  return decodeXmlEntities((m[1] != null ? m[1] : m[2]) || '');
}

// Async-read a zip member to string with a per-part inflation cap.
async function _readPartString(zip, path, cap) {
  const entry = zip.file(path);
  if (!entry) return null;
  let s;
  try {
    s = await entry.async('string');
  } catch {
    return null;
  }
  if (typeof s !== 'string') return null;
  if (s.length > cap) return s.slice(0, cap);
  return s;
}

// Convert column-letter prefix in an A1 ref to 0-based column index.
function _colFromA1(ref) {
  // ref like "AB12" — return 0-indexed column number.
  const m = /^([A-Za-z]+)\d+$/.exec(ref || '');
  if (!m) return -1;
  const letters = m[1].toUpperCase();
  let n = 0;
  for (let i = 0; i < letters.length; i++) {
    n = n * 26 + (letters.charCodeAt(i) - 64);
  }
  return n - 1;
}

// --- Main entry -------------------------------------------------------------
async function parseXlsx(buffer) {
  const texts = [];
  const hiddenFindings = [];

  // Short-circuit on oversize buffer to defend the Web tab from OOM.
  const byteLen = buffer.byteLength != null ? buffer.byteLength : buffer.length;
  if (byteLen > WEB_XLSX_ARCHIVE_SHORT_CIRCUIT) {
    hiddenFindings.push({
      element: 'XLSX archive',
      technique: 'xlsx-scan-limit',
      content: '(oversize — body not scanned)',
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'XLSX',
      meta: { scope: 'file', limitBytes: WEB_XLSX_ARCHIVE_SHORT_CIRCUIT },
    });
    return { text: '', hiddenFindings, fileType: 'xlsx' };
  }

  let zip;
  try {
    zip = await JSZip.loadAsync(buffer);
  } catch (err) {
    // Mirror docx/pptx soft-fail pattern — never throw out of the parser.
    const errMsg = escapeForDisplay(
      String(err && err.message ? err.message : err).slice(0, 64),
    );
    hiddenFindings.push({
      element: 'XLSX archive',
      technique: 'xlsx-corrupt-zip',
      content: escapeForDisplay(String(err && err.message ? err.message : err).slice(0, 200)),
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'XLSX',
      meta: { errorMessage: errMsg },
    });
    return { text: '', hiddenFindings, fileType: 'xlsx' };
  }

  // Approximate whole-archive cap defense — JSZip does not expose archive
  // size cheaply, so fall back to the buffer byte-length we already have.
  if (byteLen > XLSX_MAX_ARCHIVE_BYTES) {
    hiddenFindings.push({
      element: 'XLSX archive',
      technique: 'xlsx-scan-limit',
      content: '(oversize archive)',
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'XLSX',
      meta: { scope: 'archive', limitBytes: XLSX_MAX_ARCHIVE_BYTES },
    });
    // Don't bail — keep scanning what we can (defensive degrade).
  }

  // ---- 1. [Content_Types].xml → MV-04 extension/contentType mismatch ----
  let contentTypeOverrides = [];
  const ctEntry = zip.file('[Content_Types].xml');
  if (ctEntry) {
    let ctXml;
    try {
      ctXml = await ctEntry.async('string');
    } catch {
      ctXml = '';
    }
    if (ctXml && ctXml.length <= WEB_XLSX_MAX_INFLATED_PER_PART) {
      contentTypeOverrides = parseContentTypes(ctXml);
    }
  }

  const declaresMacroEnabled = contentTypeOverrides.some((o) =>
    /vnd\.ms-excel\.sheet\.macroEnabled/i.test(o.contentType || ''),
  );

  // ---- 2. MV-04: vbaProject / macrosheets presence ----
  const fileNames = Object.keys(zip.files);
  const hasVbaProject =
    zip.file('xl/vbaProject.bin') != null ||
    zip.file('xl/vbaProjectSignature.bin') != null;
  if (hasVbaProject) {
    const hasSig = zip.file('xl/vbaProjectSignature.bin') != null;
    hiddenFindings.push({
      element: 'XLSX OPC',
      technique: 'vba-macro-project',
      content: '(macro-bearing workbook)',
      severity: 'danger',
      category: 'hiddenHtml',
      contextLocation: 'xl/vbaProject.bin',
      meta: { hasSignature: hasSig },
    });
    // Sibling: extension mismatch
    if (declaresMacroEnabled) {
      hiddenFindings.push({
        element: 'XLSX OPC',
        technique: 'extension-content-type-mismatch',
        content: '(macroEnabled content-type on .xlsx extension)',
        severity: 'danger',
        category: 'hiddenHtml',
        contextLocation: '[Content_Types].xml',
      });
    }
  }
  const hasMacrosheets = fileNames.some((f) => /^xl\/macrosheets\//i.test(f));
  if (hasMacrosheets) {
    hiddenFindings.push({
      element: 'XLSX OPC',
      technique: 'xlm-macrosheet',
      content: '(legacy macro sheet)',
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'xl/macrosheets/',
    });
  }

  // ---- 3. workbook.xml — sheet map + definedNames ----
  // sheets : [{ name, sheetId, rId, state, file (resolved from rels) }]
  const sheets = [];
  // definedNames : [{ name, body }]
  const definedNames = [];

  const workbookXml = await _readPartString(
    zip,
    'xl/workbook.xml',
    WEB_XLSX_MAX_INFLATED_PER_PART,
  );
  if (workbookXml) {
    // Parse <sheets><sheet .../></sheets>
    const sheetTagRe = /<sheet\b([^>]*)\/?>/gi;
    let sm;
    while ((sm = sheetTagRe.exec(workbookXml)) !== null) {
      const attrs = sm[1] || '';
      const name = _attr(attrs, 'name');
      const sheetId = _attr(attrs, 'sheetId');
      const rId = _attr(attrs, 'r:id') || _attr(attrs, 'rid');
      const state = _attr(attrs, 'state');
      if (name) {
        sheets.push({ name, sheetId, rId, state, file: '' });
      }
    }

    // Parse <definedNames><definedName name="..."> body </definedName></definedNames>
    const dnRe = /<definedName\b([^>]*)>([\s\S]*?)<\/definedName>/gi;
    let dm;
    while ((dm = dnRe.exec(workbookXml)) !== null) {
      const name = _attr(dm[1] || '', 'name');
      const body = decodeXmlEntities((dm[2] || '').trim());
      if (name) definedNames.push({ name, body });
    }

    // SC-02: sheet-state findings.
    for (const sheet of sheets) {
      const state = (sheet.state || '').trim();
      if (!state) continue;
      const stateLower = state.toLowerCase();
      if (stateLower === 'visible') continue;
      // Pipe sheet name through the unicode/bidi pipeline by including it in
      // text (MD-11 wiring).
      texts.push(`[Sheet name] ${sheet.name}`);
      if (stateLower === 'hidden') {
        hiddenFindings.push({
          element: `Sheet '${sheet.name}'`,
          technique: 'hidden-sheet',
          content: escapeForDisplay(sheet.name.slice(0, 200)),
          severity: 'warning',
          category: 'hiddenHtml',
          contextLocation: `Sheet:'${sheet.name}'`,
        });
      } else if (stateLower === 'veryhidden') {
        hiddenFindings.push({
          element: `Sheet '${sheet.name}'`,
          technique: 'veryhidden-sheet',
          content: escapeForDisplay(sheet.name.slice(0, 200)),
          severity: 'danger',
          category: 'hiddenHtml',
          contextLocation: `Sheet:'${sheet.name}'`,
        });
      } else {
        hiddenFindings.push({
          element: `Sheet '${sheet.name}'`,
          technique: 'sheet-state-confusion',
          content: escapeForDisplay(sheet.name.slice(0, 200)),
          severity: 'warning',
          category: 'hiddenHtml',
          contextLocation: `Sheet:'${sheet.name}'`,
          meta: { stateValue: escapeForDisplay(String(state).slice(0, 64)) },
        });
      }
    }

    // FI-03: definedName auto-trigger + dangerous body
    for (const dn of definedNames) {
      if (!AUTO_DEFINED_NAME_RE.test(dn.name)) continue;
      // Cross-reference body sheet ref to detect hidden/veryHidden target.
      const refMatch = /^([^!]+)!/.exec(dn.body || '');
      let targetState = '';
      let targetName = '';
      if (refMatch) {
        targetName = refMatch[1].replace(/^'|'$/g, '');
        const tgt = sheets.find((s) => s.name === targetName);
        if (tgt) targetState = (tgt.state || '').toLowerCase();
      }
      const hasDangerousFn = DANGEROUS_FN_RE.test(dn.body || '');
      const targetHidden =
        targetState === 'hidden' || targetState === 'veryhidden';
      const severity = hasDangerousFn || targetHidden ? 'danger' : 'warning';
      const variant = targetHidden
        ? 'hiddenSheet'
        : hasDangerousFn
          ? 'dangerToken'
          : 'present';
      const meta = {
        variant,
        name: escapeForDisplay(dn.name.slice(0, 64)),
      };
      if (targetHidden) {
        meta.targetSheet = escapeForDisplay(String(targetName).slice(0, 64));
        meta.targetState = targetState;
      }
      hiddenFindings.push({
        element: 'XLSX workbook',
        technique: 'auto-run-defined-name',
        content: escapeForDisplay((dn.body || '').slice(0, 200)),
        severity,
        category: 'suspiciousPatterns',
        contextLocation: 'xl/workbook.xml definedName',
        meta,
      });
    }
  }

  // ---- 4. Resolve workbook rels to map sheets[].rId → sheets[].file ----
  const wbRelsXml = await _readPartString(
    zip,
    'xl/_rels/workbook.xml.rels',
    WEB_XLSX_MAX_INFLATED_PER_PART,
  );
  if (wbRelsXml) {
    const rels = parseRelationships(wbRelsXml);
    for (const sheet of sheets) {
      const rel = rels.find((r) => r.id === sheet.rId);
      if (rel && rel.target) {
        // Resolve relative target — typical: "worksheets/sheet1.xml"
        const t = rel.target.replace(/^\/+/, '');
        sheet.file = t.startsWith('xl/') ? t : 'xl/' + t;
      }
    }
  }

  // ---- 5. sharedStrings.xml ----
  const sharedStrings = [];
  const ssXml = await _readPartString(
    zip,
    'xl/sharedStrings.xml',
    WEB_XLSX_MAX_INFLATED_PER_PART,
  );
  if (ssXml) {
    // Each <si> may contain one or more <t> nodes; concat them.
    const siRe = /<si\b[^>]*>([\s\S]*?)<\/si>/gi;
    let sim;
    while ((sim = siRe.exec(ssXml)) !== null) {
      const inner = sim[1] || '';
      const tParts = inner.match(/<t[^>]*>([\s\S]*?)<\/t>/gi) || [];
      const joined = tParts
        .map((tt) => decodeXmlEntities(tt.replace(/<[^>]+>/g, '')))
        .join('');
      sharedStrings.push(joined);
    }
  }

  // ---- 6. Walk sheet*.xml — cells, formulas, hidden row/col ----
  let sheetCount = 0;
  for (const sheet of sheets) {
    if (sheetCount >= XLSX_MAX_SHEETS) {
      hiddenFindings.push({
        element: 'XLSX OPC',
        technique: 'xlsx-scan-limit',
        content: '(sheet cap reached)',
        severity: 'warning',
        category: 'hiddenHtml',
        contextLocation: 'XLSX',
        meta: { scope: 'sheets', limitCount: XLSX_MAX_SHEETS },
      });
      break;
    }
    if (!sheet.file) continue;
    const sheetXml = await _readPartString(
      zip,
      sheet.file,
      WEB_XLSX_MAX_INFLATED_PER_PART,
    );
    if (!sheetXml) continue;
    sheetCount++;

    // Walk <c r="A1" t="..."> ... </c> AND self-closing <c r="A1"/>
    const cellRe = /<c\b([^>]*)(?:\/>|>([\s\S]*?)<\/c>)/gi;
    let cm;
    let cellCount = 0;
    let cellCapWarned = false;
    while ((cm = cellRe.exec(sheetXml)) !== null) {
      if (cellCount >= XLSX_MAX_CELLS_PER_SHEET) {
        if (!cellCapWarned) {
          hiddenFindings.push({
            element: `Sheet '${sheet.name}'`,
            technique: 'xlsx-scan-limit',
            content: '(cell cap reached)',
            severity: 'warning',
            category: 'hiddenHtml',
            contextLocation: `Sheet:'${sheet.name}'`,
            meta: { scope: 'cells', limitCount: XLSX_MAX_CELLS_PER_SHEET },
          });
          cellCapWarned = true;
        }
        break;
      }
      cellCount++;
      const cAttrs = cm[1] || '';
      const cInner = cm[2] || '';
      const ref = _attr(cAttrs, 'r') || '';
      const cellType = _attr(cAttrs, 't') || '';
      if (!cInner) continue; // self-closing — no value

      // Extract formula (<f>...</f>) and value (<v>...</v>) / inline string.
      let cellText = '';
      const fMatch = /<f\b[^>]*>([\s\S]*?)<\/f>/i.exec(cInner);
      const vMatch = /<v\b[^>]*>([\s\S]*?)<\/v>/i.exec(cInner);
      const isMatch = /<is\b[^>]*>([\s\S]*?)<\/is>/i.exec(cInner);

      if (fMatch) {
        // Formula present — emit the formula text with leading '=' so the
        // FI-01/FI-02 detector engages on cells whose formula was hidden by
        // a cached <v> value (formula/cached-value desync).
        const formula = decodeXmlEntities((fMatch[1] || '').trim());
        if (formula) cellText = formula.charAt(0) === '=' ? formula : '=' + formula;
      } else if (cellType === 's' && vMatch) {
        // SharedString lookup
        const idx = parseInt(vMatch[1], 10);
        if (Number.isFinite(idx) && idx >= 0 && idx < sharedStrings.length) {
          cellText = sharedStrings[idx];
        }
      } else if ((cellType === 'inlineStr' || cellType === 'str') && isMatch) {
        const tParts = (isMatch[1] || '').match(/<t[^>]*>([\s\S]*?)<\/t>/gi) || [];
        cellText = tParts
          .map((tt) => decodeXmlEntities(tt.replace(/<[^>]+>/g, '')))
          .join('');
      } else if ((cellType === 'inlineStr' || cellType === 'str') && cInner) {
        const tParts = cInner.match(/<t[^>]*>([\s\S]*?)<\/t>/gi) || [];
        cellText = tParts
          .map((tt) => decodeXmlEntities(tt.replace(/<[^>]+>/g, '')))
          .join('');
      } else if (vMatch) {
        cellText = decodeXmlEntities(vMatch[1] || '');
      }

      if (cellText) {
        const prefix = `[Sheet '${sheet.name}'!${ref}] `;
        // One cell per line — detectFormulaInjection expects this shape.
        texts.push(prefix + cellText);
      }
    }
  }

  // ---- 7. docProps/core.xml + docProps/app.xml → MD-05 / MD-06 ----
  const coreXml = await _readPartString(
    zip,
    'docProps/core.xml',
    WEB_XLSX_MAX_INFLATED_PER_PART,
  );
  if (coreXml) {
    const coreFields = [
      ['dc:title', 'docProps/core dc:title'],
      ['dc:subject', 'docProps/core dc:subject'],
      ['dc:description', 'docProps/core dc:description'],
      ['cp:keywords', 'docProps/core cp:keywords'],
      ['cp:category', 'docProps/core cp:category'],
      ['dc:creator', 'docProps/core dc:creator'],
      ['cp:lastModifiedBy', 'docProps/core cp:lastModifiedBy'],
    ];
    for (const [tag, label] of coreFields) {
      const escTag = tag.replace(/:/g, '\\:');
      const re = new RegExp(`<${escTag}\\b[^>]*>([\\s\\S]*?)<\\/${escTag}>`, 'i');
      const m = re.exec(coreXml);
      if (!m) continue;
      const value = decodeXmlEntities((m[1] || '').trim());
      if (!value) continue;
      if (looksLikeInstruction(value)) {
        hiddenFindings.push({
          element: label,
          technique: 'docprops-prompt-injection',
          content: escapeForDisplay(value.slice(0, 200)),
          severity: 'warning',
          category: 'suspiciousPatterns',
          contextLocation: label,
          meta: { source: 'core', field: String(tag) },
        });
      }
    }
  }

  const appXml = await _readPartString(
    zip,
    'docProps/app.xml',
    WEB_XLSX_MAX_INFLATED_PER_PART,
  );
  if (appXml) {
    const appFields = [
      ['Manager', 'docProps/app Manager'],
      ['Company', 'docProps/app Company'],
      ['HeadingPairs', 'docProps/app HeadingPairs'],
      ['TitlesOfParts', 'docProps/app TitlesOfParts'],
    ];
    for (const [tag, label] of appFields) {
      const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i');
      const m = re.exec(appXml);
      if (!m) continue;
      const value = decodeXmlEntities((m[1] || '').replace(/<[^>]+>/g, '').trim());
      if (!value) continue;
      if (looksLikeInstruction(value)) {
        hiddenFindings.push({
          element: label,
          technique: 'docprops-prompt-injection',
          content: escapeForDisplay(value.slice(0, 200)),
          severity: 'warning',
          category: 'suspiciousPatterns',
          contextLocation: label,
          meta: { source: 'app', field: String(tag) },
        });
      }
    }

    // MD-06: HyperlinkBase
    const hbMatch = /<HyperlinkBase\b[^>]*>([\s\S]*?)<\/HyperlinkBase>/i.exec(appXml);
    if (hbMatch) {
      const hb = decodeXmlEntities((hbMatch[1] || '').trim());
      if (hb) {
        const isExternal =
          /^https?:\/\//i.test(hb) ||
          /^file:/i.test(hb) ||
          /^\\\\/.test(hb);
        if (isExternal) {
          hiddenFindings.push({
            element: 'docProps/app HyperlinkBase',
            technique: 'hyperlink-base-rewrite',
            content: escapeForDisplay(hb.slice(0, 200)),
            severity: 'danger',
            category: 'suspiciousPatterns',
            contextLocation: 'docProps/app HyperlinkBase',
          });
        }
      }
    }
  }

  // ---- 8. Comments + threadedComments + persons → MV-07 ----
  // Build persona map first so threadedComment author rId → displayName.
  const personMap = new Map();
  for (const fname of fileNames) {
    if (!/^xl\/persons\/person\d*\.xml$/i.test(fname)) continue;
    const pxml = await _readPartString(zip, fname, WEB_XLSX_MAX_INFLATED_PER_PART);
    if (!pxml) continue;
    const personRe = /<person\b([^>]*)\/?>/gi;
    let pm;
    while ((pm = personRe.exec(pxml)) !== null) {
      const attrs = pm[1] || '';
      const id = _attr(attrs, 'id') || _attr(attrs, 'userId');
      const name = _attr(attrs, 'displayName');
      if (id) personMap.set(id, name);
    }
  }

  for (const fname of fileNames) {
    if (!/^xl\/comments\d*\.xml$/i.test(fname)) continue;
    const cxml = await _readPartString(zip, fname, WEB_XLSX_MAX_INFLATED_PER_PART);
    if (!cxml) continue;
    const commentRe = /<comment\b([^>]*)>([\s\S]*?)<\/comment>/gi;
    let cm;
    while ((cm = commentRe.exec(cxml)) !== null) {
      const ref = _attr(cm[1] || '', 'ref');
      const inner = cm[2] || '';
      const tParts = inner.match(/<t[^>]*>([\s\S]*?)<\/t>/gi) || [];
      const text = tParts
        .map((tt) => decodeXmlEntities(tt.replace(/<[^>]+>/g, '')))
        .join(' ')
        .trim();
      if (!text) continue;
      if (looksLikeInstruction(text)) {
        hiddenFindings.push({
          element: `Comment ${ref}`,
          technique: 'instruction-shaped-comment',
          content: escapeForDisplay(text.slice(0, 200)),
          severity: 'warning',
          category: 'hiddenHtml',
          contextLocation: `comment:${ref}`,
          meta: { threaded: false },
        });
      }
    }
  }

  for (const fname of fileNames) {
    if (!/^xl\/threadedComments\/threadedComment\d*\.xml$/i.test(fname)) continue;
    const cxml = await _readPartString(zip, fname, WEB_XLSX_MAX_INFLATED_PER_PART);
    if (!cxml) continue;
    const tcRe = /<threadedComment\b([^>]*)>([\s\S]*?)<\/threadedComment>/gi;
    let tcm;
    while ((tcm = tcRe.exec(cxml)) !== null) {
      const attrs = tcm[1] || '';
      const ref = _attr(attrs, 'ref');
      const personId = _attr(attrs, 'personId');
      const inner = tcm[2] || '';
      const textMatch = /<text\b[^>]*>([\s\S]*?)<\/text>/i.exec(inner);
      const text = textMatch
        ? decodeXmlEntities((textMatch[1] || '').trim())
        : '';
      if (!text) continue;
      if (looksLikeInstruction(text)) {
        const persona = personMap.get(personId) || '';
        hiddenFindings.push({
          element: `ThreadedComment ${ref}`,
          technique: 'instruction-shaped-comment',
          content: escapeForDisplay(text.slice(0, 200)),
          severity: 'warning',
          category: 'hiddenHtml',
          contextLocation: persona
            ? `threadedComment:${ref} (author='${escapeForDisplay(persona.slice(0, 64))}')`
            : `threadedComment:${ref}`,
          meta: { threaded: true },
        });
      }
    }
  }

  // ---- 9. styles.xml → MD-08 numFmt ';;;' + white font ----
  const stylesXml = await _readPartString(
    zip,
    'xl/styles.xml',
    WEB_XLSX_MAX_INFLATED_PER_PART,
  );
  if (stylesXml) {
    const numFmtRe = /<numFmt\b([^>]*)\/?>/gi;
    let nf;
    while ((nf = numFmtRe.exec(stylesXml)) !== null) {
      const fmtCode = _attr(nf[1] || '', 'formatCode');
      if (!fmtCode) continue;
      const decoded = decodeXmlEntities(fmtCode);
      const isHideAll =
        decoded === ';;;' ||
        /^(?:[^;]*;){3,}[^;]*$/.test(decoded) === false
          ? decoded === ';;;'
          : false;
      const allSectionsEmpty = /^;{2,};?$/.test(decoded);
      const whiteBracket = /\[(?:White|#FFFFFF)\]/i.test(decoded);
      if (decoded === ';;;' || allSectionsEmpty || whiteBracket) {
        hiddenFindings.push({
          element: 'xl/styles.xml numFmt',
          technique: 'hidden-num-fmt',
          content: escapeForDisplay(decoded.slice(0, 200)),
          severity: 'warning',
          category: 'hiddenHtml',
          contextLocation: 'xl/styles.xml',
          meta: { formatCode: escapeForDisplay(String(decoded).slice(0, 64)) },
        });
      }
    }
    // White-on-white font (rgb="FFFFFFFF")
    if (/<font\b[\s\S]*?<color\s+rgb="FFFFFFFF"\s*\/>[\s\S]*?<\/font>/i.test(stylesXml)) {
      hiddenFindings.push({
        element: 'xl/styles.xml font',
        technique: 'White font color (#FFFFFFFF)',
        content: '(white-on-white font style)',
        severity: 'warning',
        category: 'hiddenHtml',
        contextLocation: 'xl/styles.xml',
      });
    }
  }

  // ---- 10. customXml/* → MV-09 ----
  const customXmlFiles = fileNames.filter((f) => /^customXml\/(item|itemProps)\d*\.xml$/i.test(f));
  let customXmlTotalBytes = 0;
  const customXmlTexts = [];
  for (const fname of customXmlFiles) {
    const cxml = await _readPartString(zip, fname, WEB_XLSX_MAX_INFLATED_PER_PART);
    if (!cxml) continue;
    customXmlTotalBytes += cxml.length;
    // Extract joined text content from every node.
    const stripped = cxml.replace(/<[^>]+>/g, ' ');
    const decoded = decodeXmlEntities(stripped).replace(/\s+/g, ' ').trim();
    if (decoded) customXmlTexts.push(decoded);
  }
  const customXmlJoined = customXmlTexts.join(' ');
  if (customXmlJoined && looksLikeInstruction(customXmlJoined)) {
    hiddenFindings.push({
      element: 'customXml/',
      technique: 'CustomXML prompt-injection payload',
      content: escapeForDisplay(customXmlJoined.slice(0, 200)),
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'customXml/',
    });
  }
  if (customXmlTotalBytes > CUSTOMXML_MAX_BYTES) {
    hiddenFindings.push({
      element: 'customXml/',
      technique: `Oversize CustomXML (> ${CUSTOMXML_MAX_BYTES} bytes)`,
      content: `(total ${customXmlTotalBytes} bytes)`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'customXml/',
    });
  }

  // ---- 11. Relationships walk → ER-03 external refs ----
  const relsFiles = fileNames.filter((f) => /^xl\/.*_rels\/.*\.rels$/i.test(f) || /^_rels\/\.rels$/i.test(f));
  const seenTargets = new Set();
  for (const fname of relsFiles) {
    const rxml = await _readPartString(zip, fname, WEB_XLSX_MAX_INFLATED_PER_PART);
    if (!rxml) continue;
    const rels = parseRelationships(rxml);
    for (const rel of rels) {
      if (rel.targetMode !== 'External') continue;
      const target = rel.target || '';
      if (!target || seenTargets.has(target)) continue;
      seenTargets.add(target);
      let severity = 'warning';
      let scheme = '';
      const isUnc = /^\\\\[^\\]+\\/.test(target) || /^file:\/\/\/?\\\\/.test(target);
      const isHttp = /^https?:\/\//i.test(target);
      const isJsOrData = /^(?:javascript|data):/i.test(target);
      if (isUnc) {
        severity = 'danger';
        scheme = 'unc';
      } else if (isJsOrData) {
        severity = 'danger';
        scheme = 'jsOrData';
      } else if (isHttp) {
        severity = 'warning';
        scheme = 'http';
      } else {
        // Skip other schemes (mailto:, etc.) — not in spec.
        continue;
      }
      hiddenFindings.push({
        element: 'XLSX Relationship',
        technique: 'external-relationship',
        content: escapeForDisplay(target.slice(0, 200)),
        severity,
        category: 'suspiciousPatterns',
        contextLocation: fname,
        meta: { scheme },
      });
    }
  }

  // ---- 12. externalLinks ddeLink / oleLink → FI-03 sibling ----
  // v1.18.0: oleLink mirror (was MCP-only) now bridged to web (v5 xlsx-bridge).
  const externalLinkFiles = fileNames.filter((f) =>
    /^xl\/externalLinks\/externalLink\d*\.xml$/i.test(f),
  );
  for (const fname of externalLinkFiles) {
    const elXml = await _readPartString(zip, fname, WEB_XLSX_MAX_INFLATED_PER_PART);
    if (!elXml) continue;
    const ddeRe = /<ddeLink\b([^>]*)>/gi;
    let dm;
    while ((dm = ddeRe.exec(elXml)) !== null) {
      const svc = _attr(dm[1] || '', 'ddeService');
      if (!svc) continue;
      const isBlocked = DDE_DANGEROUS_SERVICE_RE.test(svc);
      const severity = isBlocked ? 'danger' : 'warning';
      hiddenFindings.push({
        element: fname,
        technique: 'dde-link',
        content: escapeForDisplay(svc.slice(0, 200)),
        severity,
        category: 'suspiciousPatterns',
        contextLocation: fname,
        meta: {
          svc: escapeForDisplay(String(svc).slice(0, 64)),
          blocked: isBlocked,
        },
      });
    }
    // v1.18.0 oleLink mirror (was MCP-only).
    const oleRe = /<oleLink\b([^>]*)\/?>/gi;
    let oleM;
    while ((oleM = oleRe.exec(elXml)) !== null) {
      const progId = _attr(oleM[1] || '', 'progId');
      if (!progId) continue;
      hiddenFindings.push({
        element: 'OLE Link',
        technique: 'external-ole-link',
        content: escapeForDisplay(`progId="${progId}"`.slice(0, 200)),
        severity: 'warning',
        category: 'suspiciousPatterns',
        contextLocation: `${fname} > oleLink`,
        meta: { progId: escapeForDisplay(String(progId).slice(0, 64)) },
      });
    }
  }

  // ---- 13. xl/media/* image recursion ----
  const mediaFiles = fileNames.filter((f) => /^xl\/media\/[^/]+$/.test(f));
  let mediaProcessed = 0;
  for (const mediaPath of mediaFiles) {
    if (mediaProcessed >= _OFFICE_MEDIA_MAX_COUNT) break;
    const ext = _extOf(mediaPath.replace(/^xl\/media\//, ''));
    if (!_PDF_IMAGE_EXTS.has(ext)) continue;
    const entry = zip.file(mediaPath);
    if (!entry) continue;
    const mediaName = mediaPath.replace(/^xl\/media\//, '');
    let buf;
    try {
      buf = await entry.async('uint8array');
    } catch {
      continue;
    }
    if (buf.byteLength === 0) {
      hiddenFindings.push({
        element: 'XLSX Embedded Image',
        technique: 'empty-embedded-image',
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: 'warning',
        category: 'hiddenHtml',
        contextLocation: `XLSX media:${mediaName}`,
      });
      mediaProcessed++;
      continue;
    }
    if (buf.byteLength > _OFFICE_MEDIA_MAX_BYTES) {
      hiddenFindings.push({
        element: 'XLSX Embedded Image',
        technique: 'oversize-embedded-image',
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: 'warning',
        category: 'hiddenHtml',
        contextLocation: `XLSX media:${mediaName}`,
        meta: { maxBytes: _OFFICE_MEDIA_MAX_BYTES },
      });
      mediaProcessed++;
      continue;
    }
    let sub;
    try {
      sub = await parseImage(buf, ext);
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
    if (Array.isArray(sub.hiddenFindings)) {
      for (const f of sub.hiddenFindings) {
        const existing = typeof f.contextLocation === 'string' ? f.contextLocation : '';
        hiddenFindings.push({
          ...f,
          contextLocation: existing
            ? `XLSX media:${mediaName} > ${existing}`
            : `XLSX media:${mediaName}`,
        });
      }
    }
  }

  // ---- 14. xl/embeddings/oleObject*.bin → OL-10 ----
  // v1.18.0: oversize-embedded-object emit bridged from MCP (v5 xlsx-bridge).
  const embeddingFiles = fileNames.filter((f) => /^xl\/embeddings\/.+\.bin$/i.test(f));
  for (const epath of embeddingFiles) {
    const entry = zip.file(epath);
    if (!entry) continue;
    let buf;
    try {
      buf = await entry.async('uint8array');
    } catch {
      continue;
    }
    const name = epath.replace(/^xl\/embeddings\//, '');
    // Bridge: oversize check ahead of body sniff (MCP parity).
    if (buf.byteLength > _OFFICE_MEDIA_MAX_BYTES) {
      hiddenFindings.push({
        element: 'XLSX Embedded Object',
        technique: 'oversize-embedded-object',
        content: escapeForDisplay(epath.slice(0, 200)),
        severity: 'warning',
        category: 'hiddenHtml',
        contextLocation: epath,
        meta: { maxBytes: _OFFICE_MEDIA_MAX_BYTES },
      });
      continue;
    }
    // CFB / OLE2 magic: D0 CF 11 E0 A1 B1 1A E1
    const isCfb =
      buf.length >= 8 &&
      buf[0] === 0xd0 &&
      buf[1] === 0xcf &&
      buf[2] === 0x11 &&
      buf[3] === 0xe0 &&
      buf[4] === 0xa1 &&
      buf[5] === 0xb1 &&
      buf[6] === 0x1a &&
      buf[7] === 0xe1;
    const dangerousHint = /\.(?:exe|scr|bat|lnk|hta)\b/i.test(name);
    const severity = isCfb && dangerousHint ? 'danger' : 'warning';
    hiddenFindings.push({
      element: 'XLSX embedded OLE',
      technique:
        isCfb && dangerousHint
          ? 'CFB OLE object with dangerous extension hint'
          : 'Embedded OLE object present',
      content: escapeForDisplay(name.slice(0, 200)),
      severity,
      category: 'hiddenHtml',
      contextLocation: epath,
    });
  }

  // ---- 15. v1.18.0 deep-execution surface: Power Query / data connections /
  // ActiveX / customUI ribbon callbacks. Byte-identical mirror of MCP.
  await _scanPowerQueryWeb(zip, fileNames, hiddenFindings);
  await _scanDataConnectionsWeb(zip, fileNames, hiddenFindings);
  await _scanActiveXWeb(zip, fileNames, hiddenFindings);
  await _scanCustomUiWeb(zip, fileNames, hiddenFindings);

  return {
    text: texts.join('\n'),
    hiddenFindings,
    fileType: 'xlsx',
  };
}

// ---- v1.18.0 deep-execution scanners ----------------------------------------
// These mirror packages/mcp/server/parsers/xlsx.js scanPowerQuery /
// scanDataConnections / scanActiveX / scanCustomUi byte-identically so the
// parity-check.mjs MCP↔Web drift counter stays at 0.

async function _scanPowerQueryWeb(zip, fileNames, hiddenFindings) {
  const customFiles = fileNames.filter((f) =>
    /^customXml\/(?:item|itemProps)\d*\.xml$/i.test(f),
  );
  for (const cf of customFiles) {
    const xml = await _readPartString(zip, cf, WEB_XLSX_MAX_INFLATED_PER_PART);
    if (!xml) continue;
    if (!POWER_QUERY_WEBCONTENTS_RE.test(xml)) continue;
    const m = POWER_QUERY_WEBCONTENTS_RE.exec(xml);
    const fnName = m ? m[0] : 'Web.Contents';
    hiddenFindings.push({
      element: 'Power Query M',
      technique: 'xlsx-power-query-webcontents',
      content: escapeForDisplay(`${fnName} reference in ${cf}`.slice(0, 200)),
      severity: 'danger',
      category: 'suspiciousPatterns',
      contextLocation: `${cf} > Power Query`,
      meta: {
        connectionType: 'powerQuery',
        callbackName: escapeForDisplay(String(fnName).slice(0, 64)),
      },
    });
  }
}

async function _scanDataConnectionsWeb(zip, fileNames, hiddenFindings) {
  if (!fileNames.includes('xl/connections.xml')) return;
  const xml = await _readPartString(zip, 'xl/connections.xml', WEB_XLSX_MAX_INFLATED_PER_PART);
  if (!xml) return;
  const connRe = /<connection\b([^>]*)>([\s\S]*?)<\/connection>|<connection\b([^/>]*)\/>/gi;
  let cm;
  while ((cm = connRe.exec(xml)) !== null) {
    const attrs = cm[1] || cm[3] || '';
    const body = cm[2] || '';
    const haystack = `${attrs} ${body}`;
    if (!DATA_CONNECTION_SHELL_RE.test(haystack)) continue;
    const tokenMatch = DATA_CONNECTION_SHELL_RE.exec(haystack);
    const token = tokenMatch ? tokenMatch[0] : 'shell';
    const dbType =
      /\bdbCommand\b/i.test(haystack) || /OLEDB/i.test(haystack)
        ? 'OLEDB'
        : /ODBC/i.test(haystack)
          ? 'ODBC'
          : 'other';
    hiddenFindings.push({
      element: 'Data Connection',
      technique: 'xlsx-data-connection-shell',
      content: escapeForDisplay(
        `${dbType} connection carries shell-runner token`.slice(0, 200),
      ),
      severity: 'danger',
      category: 'suspiciousPatterns',
      contextLocation: 'xl/connections.xml > connection',
      meta: {
        connectionType: dbType,
        hasShellKeyword: true,
        callbackName: escapeForDisplay(String(token).slice(0, 64)),
      },
    });
  }
}

async function _scanActiveXWeb(zip, fileNames, hiddenFindings) {
  const activeXFiles = fileNames.filter((f) =>
    /^xl\/activeX\/activeX\d*\.bin$/i.test(f),
  );
  for (const af of activeXFiles) {
    const entry = zip.file(af);
    if (!entry) continue;
    let buf;
    try {
      buf = await entry.async('uint8array');
    } catch {
      continue;
    }
    let hasCfbMagic = false;
    if (buf.length >= 8) {
      hasCfbMagic = true;
      for (let i = 0; i < 8; i++) {
        if (buf[i] !== _CFB_MAGIC[i]) {
          hasCfbMagic = false;
          break;
        }
      }
    }
    hiddenFindings.push({
      element: 'ActiveX Control',
      technique: 'xlsx-activex-control',
      content: escapeForDisplay(af.slice(0, 200)),
      severity: 'warning',
      category: 'suspiciousPatterns',
      contextLocation: af,
      meta: {
        connectionType: hasCfbMagic ? 'cfb' : 'binary',
        hasShellKeyword: false,
      },
    });
  }
}

async function _scanCustomUiWeb(zip, fileNames, hiddenFindings) {
  const customUiFiles = fileNames.filter((f) =>
    /^customUI\/customUI(?:\d+)?\.xml$/i.test(f),
  );
  for (const uf of customUiFiles) {
    const xml = await _readPartString(zip, uf, WEB_XLSX_MAX_INFLATED_PER_PART);
    if (!xml) continue;
    const seen = new Set();
    let m;
    CUSTOM_UI_CALLBACK_RE.lastIndex = 0;
    while ((m = CUSTOM_UI_CALLBACK_RE.exec(xml)) !== null) {
      const attrName = m[1];
      const cbName = (m[2] || '').trim();
      if (!cbName) continue;
      const key = `${attrName}::${cbName}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hiddenFindings.push({
        element: 'CustomUI Callback',
        technique: 'xlsx-custom-ui-callback',
        content: escapeForDisplay(`${attrName}="${cbName}"`.slice(0, 200)),
        severity: 'warning',
        category: 'suspiciousPatterns',
        contextLocation: `${uf} > ${attrName}`,
        meta: {
          connectionType: 'customUI',
          callbackName: escapeForDisplay(String(cbName).slice(0, 64)),
          hasShellKeyword: false,
        },
      });
    }
  }
}

export { parseXlsx };
