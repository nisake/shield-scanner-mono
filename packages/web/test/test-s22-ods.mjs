// =============================================================
//  Shield Scanner Web — v1.20.0 T2 OpenDocument Spreadsheet harness
// =============================================================
// Drives packages/web/src/parsers-web/ods.js end-to-end against the same
// .ods fixtures the MCP regression suite uses, plus 2 synthetic edge cases
// to pin the defensive caps (oversize / corrupt ZIP).
//
// Coverage:
//   - 3 ods attack fixtures — assert the Web parser surfaces the same
//     kebab id each kind of fixture targets:
//       ods_formula_injection.ods           → ods-formula-injection
//       ods_external_dde_link.ods           → ods-external-dde-link
//       ods_hidden_sheet_instruction.ods    → ods-hidden-sheet-instruction
//   - 1 benign fixture — must NOT emit any of the 4 ods kebab ids.
//   - 1 oversize buffer (>15 MB) — must emit ods-scan-limit warning.
//   - 1 corrupt ZIP — must emit ods-corrupt-zip warning without throwing.
//
// R12 / R13 / R18: invariants matched against MCP — categories all fold into
// suspiciousPatterns / hiddenHtml, severities mirror MCP, env-abstract pure
// helpers only (no rule-load at module-load).
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import JSZip from 'jszip';

// Install JSZip onto globalThis so parsers-web/ods.js (which reads
// globalThis.JSZip mirroring the browser CDN bootstrap) resolves the same
// way it does in the browser. Mirrors test-s10-xlsx.mjs / test-s13-archive.mjs.
globalThis.JSZip = JSZip;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { parseOds } = await import('../src/parsers-web/ods.js');

const ATTACKS_DIR = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'attacks');
const BENIGN_DIR  = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'benign');

const tests = [];
function add(name, fn) { tests.push({ name, fn }); }

function readFixture(dir, file) {
  const p = join(dir, file);
  if (!existsSync(p)) return null;
  return new Uint8Array(readFileSync(p));
}

function techniques(out) {
  return (out.hiddenFindings || []).map((f) => f && f.technique).filter(Boolean);
}

// --- Attack 1: formula injection ---
add('ODS-01 attack: ods_formula_injection emits ods-formula-injection', async () => {
  const buf = readFixture(ATTACKS_DIR, 'ods_formula_injection.ods');
  if (!buf) throw new Error('fixture missing');
  const out = await parseOds(buf);
  if (out.fileType !== 'ods') throw new Error(`fileType=${out.fileType}`);
  const techs = techniques(out);
  if (!techs.includes('ods-formula-injection')) {
    throw new Error(`missing ods-formula-injection. techs=${JSON.stringify(techs)}`);
  }
  const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'ods-formula-injection');
  if (hits.length < 1) throw new Error(`expected >=1 hit. got=${hits.length}`);
  if (hits[0].category !== 'suspiciousPatterns') {
    throw new Error(`expected category=suspiciousPatterns. got=${hits[0].category}`);
  }
});

// --- Attack 2: external DDE link ---
add('ODS-02 attack: ods_external_dde_link emits ods-external-dde-link', async () => {
  const buf = readFixture(ATTACKS_DIR, 'ods_external_dde_link.ods');
  if (!buf) throw new Error('fixture missing');
  const out = await parseOds(buf);
  const techs = techniques(out);
  if (!techs.includes('ods-external-dde-link')) {
    throw new Error(`missing ods-external-dde-link. techs=${JSON.stringify(techs)}`);
  }
  const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'ods-external-dde-link');
  if (hits.length < 1) throw new Error(`expected >=1 hit. got=${hits.length}`);
  if (!hits.some((f) => f.severity === 'danger')) {
    throw new Error('expected at least one danger-severity DDE link hit');
  }
  if (typeof hits[0].meta.source !== 'string') {
    throw new Error(`expected meta.source string. got=${JSON.stringify(hits[0].meta)}`);
  }
});

// --- Attack 3: hidden sheet instruction ---
add('ODS-03 attack: ods_hidden_sheet_instruction emits ods-hidden-sheet-instruction', async () => {
  const buf = readFixture(ATTACKS_DIR, 'ods_hidden_sheet_instruction.ods');
  if (!buf) throw new Error('fixture missing');
  const out = await parseOds(buf);
  const techs = techniques(out);
  if (!techs.includes('ods-hidden-sheet-instruction')) {
    throw new Error(`missing ods-hidden-sheet-instruction. techs=${JSON.stringify(techs)}`);
  }
  const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'ods-hidden-sheet-instruction');
  if (hits.length < 1) throw new Error(`expected >=1 hit. got=${hits.length}`);
  if (hits[0].severity !== 'danger') throw new Error(`expected severity=danger. got=${hits[0].severity}`);
  if (hits[0].meta.isHidden !== true) {
    throw new Error(`expected meta.isHidden=true. got=${JSON.stringify(hits[0].meta)}`);
  }
});

// --- Benign: plain spreadsheet (FP guard) ---
add('ODS-04 benign: benign_ods_basic emits none of the 4 ods kebab ids', async () => {
  const buf = readFixture(BENIGN_DIR, 'benign_ods_basic.ods');
  if (!buf) throw new Error('fixture missing');
  const out = await parseOds(buf);
  const techs = techniques(out);
  for (const k of [
    'ods-formula-injection',
    'ods-external-dde-link',
    'ods-hidden-sheet-instruction',
    'ods-macro-bearing',
  ]) {
    if (techs.includes(k)) throw new Error(`unexpected ${k}. techs=${JSON.stringify(techs)}`);
  }
});

// --- Edge 1: oversize buffer (>15MB) ---
add('ODS-05 oversize buffer (>15MB) emits ods-scan-limit warning', async () => {
  const big = new Uint8Array(16 * 1024 * 1024);
  for (let i = 0; i < big.length; i++) big[i] = 0x20;
  const out = await parseOds(big);
  if (out.fileType !== 'ods') throw new Error(`fileType=${out.fileType}`);
  if (out.text !== '') throw new Error('expected empty text on oversize short-circuit');
  const hit = (out.hiddenFindings || []).find((f) => f.technique === 'ods-scan-limit');
  if (!hit) {
    throw new Error(`no ods-scan-limit warning. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
  if (hit.severity !== 'warning') throw new Error(`expected severity=warning. got=${hit.severity}`);
});

// --- Edge 2: corrupt ZIP — no throw, emits ods-corrupt-zip ---
add('ODS-06 corrupt ZIP emits ods-corrupt-zip warning without throwing', async () => {
  const bad = new TextEncoder().encode('definitely not a zip archive');
  const out = await parseOds(bad);
  if (out.fileType !== 'ods') throw new Error(`fileType=${out.fileType}`);
  if (out.text !== '') throw new Error('expected empty text on corrupt ZIP');
  const hit = (out.hiddenFindings || []).find((f) => f.technique === 'ods-corrupt-zip');
  if (!hit) {
    throw new Error(`no ods-corrupt-zip warning. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
  if (hit.severity !== 'warning') throw new Error(`expected severity=warning. got=${hit.severity}`);
});

// ---- Runner ----

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
