// v1.20.0 Theme T2 — OpenDocument Spreadsheet (.ods) parser (Web mirror).
//
// Byte-for-byte mirror of packages/mcp/server/parsers/ods.js modulo the Web
// envelope (`hiddenFindings` instead of `extraFindings`, no fs surface). Same
// caps, same kebab ids, same R12/R13/R18 invariants:
//
//   - Output kebab ids (suspiciousPatterns fold):
//       ods-formula-injection
//       ods-external-dde-link
//       ods-hidden-sheet-instruction
//       ods-macro-bearing
//   - Warning kebab ids (hiddenHtml fold — envelope mirror of xlsx.js):
//       ods-scan-limit
//       ods-corrupt-zip
//   - Defensive caps: 15 MB archive / 8 MB per part / 50 sheets / 50000 cells.
//   - R12: sheet name / cell ref / config-item names flow through
//          escapeForDisplay before `content` / `contextLocation` surfacing.
//   - R13: every new id lands in `category: 'suspiciousPatterns'`
//          (warnings: `category: 'hiddenHtml'`).
//   - R18: only env-free `escapeForDisplay` / `looksLikeInstruction` +
//          `detectFormulaInjection` imports (the detector defers its own
//          rule-load to call time).

import {
  escapeForDisplay,
  looksLikeInstruction,
  detectFormulaInjection,
} from '@shield-scanner/core';

const ODS_MAX_ARCHIVE_BYTES = 15 * 1024 * 1024;
const ODS_MAX_INFLATED_PER_PART = 8 * 1024 * 1024;
const ODS_MAX_SHEETS = 50;
const ODS_MAX_CELLS_PER_SHEET = 50000;

const ODS_DDE_SHELL_RE =
  /\b(?:cmd(?:\.exe)?|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)\b/i;
const ODS_SETTINGS_EXTERNAL_CMD_RE =
  /(?:https?:\/\/|\\\\[^\s"<>]+\\[^\s"<>]+|cmd(?:\.exe)?|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)/i;
const ODS_SCRIPT_EVENT_LISTENER_RE =
  /<script:event-listener\b[^/>]*\bscript:language\s*=\s*["']ooo:script["'][^/>]*>/i;

// NOTE 1: `<table:table` overlaps with `<table:table-row>` / `<table:table-cell>`
// because `\b` does not treat `-` as a word boundary in JS regexen.
// NOTE 2: Attribute fragments can legally carry `/` inside attribute values
// (e.g. `table:formula="of:=cmd|'/c calc.exe'!A1"`), so the attr capture
// excludes `>` only — self-closing tags use the `\/?>` tail.
const TABLE_OPEN_RE = /<table:table(?=[\s/>])([^>]*?)\/?>/gi;
const TABLE_CLOSE_RE = /<\/table:table>/gi;
const ROW_OPEN_RE = /<table:table-row\b([^>]*?)>/gi;
const CELL_RE = /<table:table-cell\b([^>]*?)(?:\/>|>([\s\S]*?)<\/table:table-cell>)/gi;
const FORMULA_ATTR_RE = /\btable:formula\s*=\s*"([^"]*)"/i;
const NUMBER_COLS_REPEATED_RE = /\btable:number-columns-repeated\s*=\s*"(\d+)"/i;

function decodeXmlEntities(s) {
  if (typeof s !== 'string' || s.length === 0) return s;
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function attr(attrFragment, name) {
  if (!attrFragment) return '';
  const reD = new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, 'i');
  const md = reD.exec(attrFragment);
  if (md) return decodeXmlEntities(md[1]);
  const reS = new RegExp(`\\b${name}\\s*=\\s*'([^']*)'`, 'i');
  const ms = reS.exec(attrFragment);
  if (ms) return decodeXmlEntities(ms[1]);
  return '';
}

function colNumToLetters(n) {
  if (!Number.isFinite(n) || n <= 0) return '';
  let s = '';
  let v = n;
  while (v > 0) {
    const rem = (v - 1) % 26;
    s = String.fromCharCode(65 + rem) + s;
    v = Math.floor((v - 1) / 26);
  }
  return s;
}

function stripXmlTags(s) {
  if (typeof s !== 'string' || s.length === 0) return '';
  return decodeXmlEntities(s.replace(/<[^>]*>/g, ''));
}

function stripOdfFormulaPrefix(s) {
  if (typeof s !== 'string' || s.length === 0) return s;
  return s.replace(/^(?:of|oooc|msoxl):/i, '');
}

async function parseOds(buffer) {
  const texts = [];
  const hiddenFindings = [];

  const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

  if (u8.byteLength > ODS_MAX_ARCHIVE_BYTES) {
    hiddenFindings.push({
      element: 'ODS Archive',
      technique: 'ods-scan-limit',
      content: `(archive > ${ODS_MAX_ARCHIVE_BYTES} bytes; not scanned)`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'ODS Archive',
      meta: { scope: 'archive', maxBytes: ODS_MAX_ARCHIVE_BYTES, byteLen: u8.byteLength },
    });
    return { text: '', hiddenFindings, fileType: 'ods' };
  }

  // Web uses globalThis.JSZip (CDN-loaded in the browser, harness-installed
  // in node parity tests). Mirrors parsers-web/xlsx.js / archive.js.
  const JSZip = globalThis.JSZip;
  if (!JSZip) {
    hiddenFindings.push({
      element: 'ODS Archive',
      technique: 'ods-corrupt-zip',
      content: 'JSZip runtime missing',
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'ODS Archive',
      meta: { errorMessage: 'JSZip runtime missing' },
    });
    return { text: '', hiddenFindings, fileType: 'ods' };
  }

  let zip;
  try {
    zip = await JSZip.loadAsync(u8);
  } catch (err) {
    const errMsg = escapeForDisplay(
      (err && err.message ? err.message : 'JSZip parse error').slice(0, 64),
    );
    hiddenFindings.push({
      element: 'ODS Archive',
      technique: 'ods-corrupt-zip',
      content: escapeForDisplay(
        (err && err.message ? err.message : 'JSZip parse error').slice(0, 200),
      ),
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'ODS Archive',
      meta: { errorMessage: errMsg },
    });
    return { text: '', hiddenFindings, fileType: 'ods' };
  }

  const allMemberNames = Object.keys(zip.files);
  if (allMemberNames.length > 0) {
    texts.push('[ODS members] ' + allMemberNames.join(' '));
  }

  const hasBasicDir = allMemberNames.some((n) => /^Basic\/[^/]+/i.test(n));
  if (hasBasicDir) {
    hiddenFindings.push({
      element: 'ODS Archive',
      technique: 'ods-macro-bearing',
      content: 'Basic/ macro directory present',
      severity: 'danger',
      category: 'suspiciousPatterns',
      contextLocation: 'Basic/',
      meta: { source: 'basic-dir' },
    });
  }

  const contentEntry = zip.file('content.xml');
  let contentXml = '';
  if (contentEntry) {
    contentXml = await readPartString(contentEntry, hiddenFindings, 'content.xml');
  }

  if (contentXml && ODS_SCRIPT_EVENT_LISTENER_RE.test(contentXml) && !hasBasicDir) {
    hiddenFindings.push({
      element: 'ODS content.xml',
      technique: 'ods-macro-bearing',
      content: 'office:scripts event-listener (script:language="ooo:script")',
      severity: 'danger',
      category: 'suspiciousPatterns',
      contextLocation: 'content.xml office:scripts',
      meta: { source: 'office-scripts' },
    });
  }

  if (contentXml) {
    walkContent(contentXml, texts, hiddenFindings);
  }

  const settingsEntry = zip.file('settings.xml');
  if (settingsEntry) {
    const settingsXml = await readPartString(settingsEntry, hiddenFindings, 'settings.xml');
    if (settingsXml) scanSettingsForExternalCmd(settingsXml, hiddenFindings);
  }

  for (const metaName of ['meta.xml', 'META-INF/manifest.xml']) {
    const ent = zip.file(metaName);
    if (!ent) continue;
    const xml = await readPartString(ent, hiddenFindings, metaName);
    if (xml) texts.push(`[ODS ${metaName}]\n${stripXmlTags(xml)}`);
  }

  const formulaText = texts.filter((l) => l.startsWith('[ODS Sheet ')).join('\n');
  if (formulaText.length > 0) {
    try {
      // Pass fileType:'xlsx' — the shared detector handles `[ODS Sheet ...] `
      // bracket prefix identically to the XLSX `[Sheet ...] ` shape.
      const fi = detectFormulaInjection(formulaText, 'xlsx');
      if (Array.isArray(fi)) {
        for (const f of fi) {
          hiddenFindings.push({
            element: f.element || 'ODS formula',
            technique: 'ods-formula-injection',
            content: f.content || '',
            severity: f.severity || 'danger',
            category: 'suspiciousPatterns',
            contextLocation: f.contextLocation || 'ODS formula',
            meta: {
              ...(f.meta || {}),
              originalTechnique: f.technique || 'formula-injection',
            },
          });
        }
      }
    } catch {
      // detector failure must NOT abort parser — R18 envelope.
    }
  }

  return {
    text: texts.join('\n\n'),
    hiddenFindings,
    fileType: 'ods',
  };
}

async function readPartString(entry, hiddenFindings, partName) {
  try {
    const s = await entry.async('string');
    if (typeof s !== 'string') return '';
    if (s.length > ODS_MAX_INFLATED_PER_PART) {
      hiddenFindings.push({
        element: 'ODS part',
        technique: 'ods-scan-limit',
        content: `(${escapeForDisplay(partName)} > ${ODS_MAX_INFLATED_PER_PART} bytes; truncated)`,
        severity: 'warning',
        category: 'hiddenHtml',
        contextLocation: escapeForDisplay(partName),
        meta: {
          scope: 'part',
          partName: escapeForDisplay(partName),
          maxBytes: ODS_MAX_INFLATED_PER_PART,
        },
      });
      return s.slice(0, ODS_MAX_INFLATED_PER_PART);
    }
    return s;
  } catch (err) {
    const msg = err && err.message ? err.message : 'decompress error';
    hiddenFindings.push({
      element: 'ODS part',
      technique: 'ods-corrupt-zip',
      content: escapeForDisplay(msg.slice(0, 200)),
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: escapeForDisplay(partName),
      meta: { partName: escapeForDisplay(partName), errorMessage: escapeForDisplay(msg.slice(0, 64)) },
    });
    return '';
  }
}

function walkContent(xml, texts, hiddenFindings) {
  const tableOpens = [];
  let m;
  TABLE_OPEN_RE.lastIndex = 0;
  while ((m = TABLE_OPEN_RE.exec(xml)) !== null) {
    tableOpens.push({ start: m.index, end: m.index + m[0].length, attrs: m[1] || '' });
  }
  const tableCloses = [];
  TABLE_CLOSE_RE.lastIndex = 0;
  while ((m = TABLE_CLOSE_RE.exec(xml)) !== null) {
    tableCloses.push(m.index);
  }

  const sheetCount = Math.min(tableOpens.length, ODS_MAX_SHEETS);
  if (tableOpens.length > ODS_MAX_SHEETS) {
    hiddenFindings.push({
      element: 'ODS content.xml',
      technique: 'ods-scan-limit',
      content: `(sheet count ${tableOpens.length} > ${ODS_MAX_SHEETS}; trailing sheets skipped)`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'content.xml',
      meta: { scope: 'sheets', maxSheets: ODS_MAX_SHEETS, sheetCount: tableOpens.length },
    });
  }

  for (let s = 0; s < sheetCount; s++) {
    const open = tableOpens[s];
    const close = tableCloses[s] || xml.length;
    const sheetName = attr(open.attrs, 'table:name') || `Sheet${s + 1}`;
    const sheetDisplay = attr(open.attrs, 'table:display');
    const sheetProtected = attr(open.attrs, 'table:protected');
    const sheetBody = xml.slice(open.end, close);
    const isHidden = sheetDisplay === 'false';
    const isProtected = sheetProtected === 'true';

    let rowIndex = 0;
    let cellCount = 0;
    let cappedHere = false;
    ROW_OPEN_RE.lastIndex = 0;
    const rowSplits = [];
    let rowMatch;
    while ((rowMatch = ROW_OPEN_RE.exec(sheetBody)) !== null) {
      rowSplits.push(rowMatch.index + rowMatch[0].length);
    }
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
          hiddenFindings.push({
            element: `ODS Sheet '${escapeForDisplay(sheetName)}'`,
            technique: 'ods-scan-limit',
            content: `(cell count > ${ODS_MAX_CELLS_PER_SHEET}; trailing cells skipped)`,
            severity: 'warning',
            category: 'hiddenHtml',
            contextLocation: `ODS Sheet '${escapeForDisplay(sheetName)}'`,
            meta: {
              scope: 'cells',
              maxCellsPerSheet: ODS_MAX_CELLS_PER_SHEET,
              sheetName: escapeForDisplay(sheetName),
            },
          });
          cappedHere = true;
          break;
        }
        const cellAttrs = cm[1] || '';
        const cellInner = cm[2] || '';
        const repeatM = NUMBER_COLS_REPEATED_RE.exec(cellAttrs);
        const repeat = repeatM ? Math.min(parseInt(repeatM[1], 10) || 1, 64) : 1;
        colIndex += 1;
        const colLetters = colNumToLetters(colIndex);
        const ref = `${colLetters}${rowIndex}`;

        const fm = FORMULA_ATTR_RE.exec(cellAttrs);
        const formulaRaw = fm ? decodeXmlEntities(fm[1]) : '';
        const formulaBody = stripOdfFormulaPrefix(formulaRaw);
        const cellText = stripXmlTags(cellInner).trim();

        if (formulaBody) {
          texts.push(`[ODS Sheet '${sheetName}'!${ref}] ${formulaBody}`);
          const ddeMatch = /\bDDE\s*\(\s*["']([^"']+)["']/i.exec(formulaBody);
          if (ddeMatch && ODS_DDE_SHELL_RE.test(ddeMatch[1])) {
            hiddenFindings.push({
              element: `ODS Sheet '${escapeForDisplay(sheetName)}'!${ref}`,
              technique: 'ods-external-dde-link',
              content: escapeForDisplay(formulaBody.slice(0, 200)),
              severity: 'danger',
              category: 'suspiciousPatterns',
              contextLocation: `ODS Sheet '${escapeForDisplay(sheetName)}'!${ref}`,
              meta: {
                sheetName: escapeForDisplay(sheetName),
                ref,
                ddeService: escapeForDisplay(ddeMatch[1].slice(0, 64)),
                source: 'formula-dde',
              },
            });
          }
        }

        if (cellText) {
          texts.push(`[ODS Sheet '${sheetName}'!${ref}] ${cellText}`);
          if ((isHidden || isProtected) && looksLikeInstruction(cellText)) {
            hiddenFindings.push({
              element: `ODS Sheet '${escapeForDisplay(sheetName)}'!${ref}`,
              technique: 'ods-hidden-sheet-instruction',
              content: escapeForDisplay(cellText.slice(0, 200)),
              severity: 'danger',
              category: 'suspiciousPatterns',
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

function scanSettingsForExternalCmd(settingsXml, hiddenFindings) {
  const re = /<config:config-item\b([^/>]*)>([\s\S]*?)<\/config:config-item>/gi;
  let m;
  let hits = 0;
  while ((m = re.exec(settingsXml)) !== null && hits < 64) {
    const itemAttrs = m[1] || '';
    const body = decodeXmlEntities(m[2] || '');
    if (!body) continue;
    if (ODS_SETTINGS_EXTERNAL_CMD_RE.test(body)) {
      const name = attr(itemAttrs, 'config:name') || '(unnamed)';
      hiddenFindings.push({
        element: `ODS settings.xml config-item '${escapeForDisplay(name)}'`,
        technique: 'ods-external-dde-link',
        content: escapeForDisplay(body.slice(0, 200)),
        severity: 'danger',
        category: 'suspiciousPatterns',
        contextLocation: `settings.xml config-item '${escapeForDisplay(name)}'`,
        meta: {
          source: 'settings-external-cmd',
          configName: escapeForDisplay(name.slice(0, 64)),
        },
      });
      hits++;
    }
  }
}

export { parseOds };
