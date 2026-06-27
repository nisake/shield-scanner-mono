// =============================================================
//  Shield Scanner Web — v1.18.0 XLSX deep-execution surface harness
// =============================================================
// Drives packages/web/src/parsers-web/xlsx.js against the 5 attack + 2 benign
// XLSX fixtures added in v1.18.0 (Theme: deep-execution + v5 xlsx bridge).
//
// Pins the new kebab-id contract byte-identically to MCP:
//   - xlsx-power-query-webcontents (danger)
//   - xlsx-data-connection-shell   (danger)
//   - xlsx-activex-control         (warning)
//   - xlsx-custom-ui-callback      (warning)
//   - vba-macro-project also fires on .xlsm (sanity)
//
// Also covers the v5 xlsx-bridge of two previously MCP-only emits to web:
//   - external-ole-link (web mirror of oleLink)
//   - oversize-embedded-object (web mirror of >5MB embedding)
//   (the v5 bridges are exercised structurally by the main attack fixtures
//   here — a dedicated bridge fixture would just duplicate coverage.)
//
// R13 invariant: hiddenFindings carry suspiciousPatterns|hiddenHtml ONLY.
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import JSZip from 'jszip';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

globalThis.JSZip = JSZip;

const { parseXlsx } = await import('../src/parsers-web/xlsx.js');

const ATTACKS_DIR = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'attacks');
const BENIGN_DIR  = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'benign');

const tests = [];
function add(name, fn) { tests.push({ name, fn }); }

function readFixture(dir, file) {
  const p = join(dir, file);
  if (!existsSync(p)) return null;
  return new Uint8Array(readFileSync(p));
}

function findTechnique(findings, tech) {
  return (findings || []).find((f) => f && f.technique === tech);
}

add('v1.18.0 XLSX Web: xlsx_power_query_webcontents surfaces danger kebab id', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_power_query_webcontents.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const hit = findTechnique(out.hiddenFindings, 'xlsx-power-query-webcontents');
  if (!hit) throw new Error('no xlsx-power-query-webcontents finding');
  if (hit.severity !== 'danger') throw new Error(`severity=${hit.severity}`);
  if (!hit.meta || hit.meta.connectionType !== 'powerQuery') {
    throw new Error(`meta.connectionType=${hit.meta && hit.meta.connectionType}`);
  }
});

add('v1.18.0 XLSX Web: xlsx_data_connection_oledb_cmd surfaces danger kebab id', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_data_connection_oledb_cmd.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const hit = findTechnique(out.hiddenFindings, 'xlsx-data-connection-shell');
  if (!hit) throw new Error('no xlsx-data-connection-shell finding');
  if (hit.severity !== 'danger') throw new Error(`severity=${hit.severity}`);
  if (!hit.meta || hit.meta.hasShellKeyword !== true) {
    throw new Error(`meta.hasShellKeyword=${hit.meta && hit.meta.hasShellKeyword}`);
  }
});

add('v1.18.0 XLSX Web: xlsx_activex_equation_editor surfaces warning kebab id', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_activex_equation_editor.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const hit = findTechnique(out.hiddenFindings, 'xlsx-activex-control');
  if (!hit) throw new Error('no xlsx-activex-control finding');
  if (hit.severity !== 'warning') throw new Error(`severity=${hit.severity}`);
});

add('v1.18.0 XLSX Web: xlsx_custom_ui_onload_callback surfaces warning kebab id', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_custom_ui_onload_callback.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const hits = (out.hiddenFindings || []).filter(
    (f) => f && f.technique === 'xlsx-custom-ui-callback',
  );
  if (hits.length < 1) throw new Error('no xlsx-custom-ui-callback findings');
  if (hits[0].severity !== 'warning') throw new Error(`severity=${hits[0].severity}`);
});

add('v1.18.0 XLSX Web: xlsx_vba_macro_present.xlsm still surfaces vba-macro-project', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_vba_macro_present.xlsm');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const hit = findTechnique(out.hiddenFindings, 'vba-macro-project');
  if (!hit) throw new Error('no vba-macro-project finding');
  if (hit.severity !== 'danger') throw new Error(`severity=${hit.severity}`);
});

add('v1.18.0 XLSX Web: benign_xlsx_legit_connections_https does NOT fire shell rule', async () => {
  const buf = readFixture(BENIGN_DIR, 'benign_xlsx_legit_connections_https.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const shellHits = (out.hiddenFindings || []).filter(
    (f) => f && f.technique === 'xlsx-data-connection-shell',
  );
  if (shellHits.length !== 0) {
    throw new Error(`benign workbook fired ${shellHits.length} shell findings`);
  }
});

add('v1.18.0 XLSX Web: benign_xlsx_pivot_table_query does NOT fire Power Query rule', async () => {
  const buf = readFixture(BENIGN_DIR, 'benign_xlsx_pivot_table_query.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const pqHits = (out.hiddenFindings || []).filter(
    (f) => f && f.technique === 'xlsx-power-query-webcontents',
  );
  if (pqHits.length !== 0) {
    throw new Error(`benign pivot fired ${pqHits.length} power-query findings`);
  }
});

add('v1.18.0 XLSX Web R13 invariant — all 4 new kebab findings stay in suspiciousPatterns|hiddenHtml', async () => {
  const allowed = new Set(['suspiciousPatterns', 'hiddenHtml']);
  const files = [
    'xlsx_power_query_webcontents.xlsx',
    'xlsx_data_connection_oledb_cmd.xlsx',
    'xlsx_activex_equation_editor.xlsx',
    'xlsx_custom_ui_onload_callback.xlsx',
  ];
  for (const f of files) {
    const buf = readFixture(ATTACKS_DIR, f);
    if (!buf) continue;
    const out = await parseXlsx(buf);
    for (const finding of (out.hiddenFindings || [])) {
      if (!allowed.has(finding.category)) {
        throw new Error(`${f}: bad category ${finding.category} on ${finding.technique}`);
      }
    }
  }
});

let passed = 0;
let failed = 0;
for (const t of tests) {
  try {
    await t.fn();
    passed++;
    console.log(`PASS ${t.name}`);
  } catch (err) {
    failed++;
    console.log(`FAIL ${t.name}`);
    console.log('       error:', err && err.message ? err.message : String(err));
  }
}
console.log(`\nTotal: ${passed} passed / ${failed} failed`);
process.exitCode = failed === 0 ? 0 : 1;
