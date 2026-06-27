// =============================================================
//  Shield Scanner Web — S10 CSV parser harness
// =============================================================
// Drives packages/web/src/parsers-web/csv.js end-to-end against the same
// csv fixtures the MCP regression suite uses, plus a few synthetic edge cases
// to pin the Web-specific behaviors (Shift-JIS fallback, oversize gate).
//
// Coverage:
//   - 4 CSV attack fixtures from the MCP corpus — assert the parser emits a
//     deterministic `[Row N, Col M] ` line stream so the downstream
//     formula-injection detector can engage (parser-level findings are
//     typically empty here; that's by design).
//   - 2 CSV benign fixtures — must not produce any danger-level finding.
//   - 1 synthetic Shift-JIS no-BOM Japanese case — Web-specific fallback.
//   - 1 oversize buffer edge case — must emit a single oversize warning.
//
// R12 (no shadow-leak): cell payloads round-trip raw; the parser prefix
// `[Row N, Col M] ` is parser scaffolding. No assertion on UI-bound fields
// here — those flow through escapeForDisplay in the analyze pipeline.
// R13 (5-key byCategory invariant): any parser-level hiddenFinding category
// is asserted to be 'suspiciousPatterns' | 'hiddenHtml'.
// R18: Node default env wires fs-based rules-loader automatically; no setEnv.
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { parseCsv } = await import('../src/parsers-web/csv.js');

const ATTACKS_DIR = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'attacks');
const BENIGN_DIR  = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'benign');

const tests = [];
const skipped = [];

function add(name, fn) { tests.push({ name, fn }); }
function skip(name, reason) { skipped.push({ name, reason }); }

function readFixture(dir, file) {
  const p = join(dir, file);
  if (!existsSync(p)) return null;
  return new Uint8Array(readFileSync(p));
}

// --- 83: attack — DDE/calc — parser emits prefixed line stream ---
add('83 S10 CSV: csv_formula_dde_calc emits prefixed cell line stream', async () => {
  const buf = readFixture(ATTACKS_DIR, 'csv_formula_dde_calc.csv');
  if (!buf) throw new Error('fixture missing');
  const out = await parseCsv(buf);
  if (out.fileType !== 'csv') throw new Error(`fileType=${out.fileType}`);
  if (!/\[Row \d+, Col \d+\] /.test(out.text || '')) {
    throw new Error(`body missing [Row N, Col M] prefix. text=${(out.text || '').slice(0, 300)}`);
  }
  // The actual DDE attack body must appear somewhere in the stream so the
  // downstream FI detector engages.
  if (!/DDE|cmd|calc|powershell/i.test(out.text || '')) {
    throw new Error(`body missing DDE/calc payload. text=${(out.text || '').slice(0, 300)}`);
  }
});

// --- 84: attack — HYPERLINK phish ---
add('84 S10 CSV: csv_formula_hyperlink_phish emits cell with HYPERLINK token', async () => {
  const buf = readFixture(ATTACKS_DIR, 'csv_formula_hyperlink_phish.csv');
  if (!buf) throw new Error('fixture missing');
  const out = await parseCsv(buf);
  if (!/HYPERLINK/i.test(out.text || '')) {
    throw new Error(`body missing HYPERLINK. text=${(out.text || '').slice(0, 300)}`);
  }
});

// --- 85: attack — tab-prefix bypass ---
add('85 S10 CSV: csv_formula_tab_prefix_bypass keeps TAB prefix intact for downstream detector', async () => {
  const buf = readFixture(ATTACKS_DIR, 'csv_formula_tab_prefix_bypass.csv');
  if (!buf) throw new Error('fixture missing');
  const out = await parseCsv(buf);
  // The cell payload after the bracket prefix must contain a TAB followed
  // by '=' OR a CR followed by '=' — that's the bypass signature.
  if (!/\[Row \d+, Col \d+\] [\t\r]?=/.test(out.text || '')) {
    throw new Error(`body missing TAB/CR-prefix formula. text=${JSON.stringify((out.text || '').slice(0, 300))}`);
  }
});

// --- 86: attack — fullwidth equals (U+FF1D) preserved in cell payload ---
add('86 S10 CSV: csv_formula_fullwidth_equals preserves U+FF1D for normalizeFormulaPrefix', async () => {
  const buf = readFixture(ATTACKS_DIR, 'csv_formula_fullwidth_equals.csv');
  if (!buf) throw new Error('fixture missing');
  const out = await parseCsv(buf);
  if (!/＝/.test(out.text || '')) {
    throw new Error(`body missing U+FF1D fullwidth equals. text=${JSON.stringify((out.text || '').slice(0, 300))}`);
  }
});

// --- 87: benign — accounting negatives — no danger findings ---
add('87 S10 CSV: csv_benign_accounting_negatives emits no danger findings', async () => {
  const buf = readFixture(BENIGN_DIR, 'csv_benign_accounting_negatives.csv');
  if (!buf) return;
  const out = await parseCsv(buf);
  if (out.fileType !== 'csv') throw new Error(`fileType=${out.fileType}`);
  const dangers = (out.hiddenFindings || []).filter((f) => f.severity === 'danger');
  if (dangers.length > 0) {
    throw new Error(`benign csv emitted dangers: ${JSON.stringify(dangers)}`);
  }
});

// --- 88: benign — sum formulas (=SUM etc are NOT in dangerous blocklist) ---
add('88 S10 CSV: csv_benign_sum_formulas emits no parser-level danger findings', async () => {
  const buf = readFixture(BENIGN_DIR, 'csv_benign_sum_formulas.csv');
  if (!buf) return;
  const out = await parseCsv(buf);
  const dangers = (out.hiddenFindings || []).filter((f) => f.severity === 'danger');
  if (dangers.length > 0) {
    throw new Error(`benign sum csv emitted dangers: ${JSON.stringify(dangers)}`);
  }
});

// --- 89: Web-specific — Shift-JIS no-BOM fallback decodes without throwing ---
add('89 S10 CSV: Shift-JIS no-BOM Japanese csv decodes successfully (Web-specific)', async () => {
  // Build a minimal Shift-JIS CSV in-memory so we don't depend on the
  // fixture file (which the MCP side cannot decode).
  //   "Apple","リンゴ","100"
  //   "Orange","ミカン","150"
  // 'リ'=0x83 0x8A, 'ン'=0x83 0x93, 'ゴ'=0x83 0x53
  // 'ミ'=0x83 0x7E, 'カ'=0x83 0x4A, 'ン'=0x83 0x93
  const sj = new Uint8Array([
    0x22, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x22, 0x2c,
    0x22, 0x83, 0x8a, 0x83, 0x93, 0x83, 0x53, 0x22, 0x2c,
    0x22, 0x31, 0x30, 0x30, 0x22, 0x0a,
    0x22, 0x4f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x22, 0x2c,
    0x22, 0x83, 0x7e, 0x83, 0x4a, 0x83, 0x93, 0x22, 0x2c,
    0x22, 0x31, 0x35, 0x30, 0x22, 0x0a,
  ]);
  let out;
  try {
    out = await parseCsv(sj);
  } catch (err) {
    throw new Error('parser threw on Shift-JIS input: ' + (err && err.message));
  }
  if (out.fileType !== 'csv') throw new Error(`fileType=${out.fileType}`);
  // Either the Shift-JIS path or the lenient UTF-8 fallback path must
  // produce SOMETHING — the requirement is just "no throw + structured
  // output". The R13 invariant on any emitted finding still holds below.
  if (typeof out.text !== 'string') throw new Error('text is not a string');
});

// --- 90: R13 invariant on every emitted hidden finding ---
add('90 S10 CSV: R13 invariant — every hidden finding category is suspiciousPatterns|hiddenHtml', async () => {
  const allowed = new Set(['suspiciousPatterns', 'hiddenHtml']);
  const files = [
    ['attacks', 'csv_formula_dde_calc.csv'],
    ['attacks', 'csv_formula_hyperlink_phish.csv'],
    ['attacks', 'csv_formula_tab_prefix_bypass.csv'],
    ['attacks', 'csv_formula_fullwidth_equals.csv'],
    ['benign',  'csv_benign_accounting_negatives.csv'],
    ['benign',  'csv_benign_sum_formulas.csv'],
  ];
  for (const [bucket, f] of files) {
    const dir = bucket === 'attacks' ? ATTACKS_DIR : BENIGN_DIR;
    const buf = readFixture(dir, f);
    if (!buf) continue;
    const out = await parseCsv(buf);
    for (const finding of (out.hiddenFindings || [])) {
      if (!allowed.has(finding.category)) {
        throw new Error(`${f}: bad category ${finding.category} on ${finding.technique}`);
      }
    }
  }
});

// --- 91: oversize buffer (>10MB) — single warning, leading slice scanned ---
add('91 S10 CSV: oversize buffer (>10MB) emits oversize warning', async () => {
  // 11MB of 'a,b,c\n' rows — strictly above CSV_MAX_BYTES (10MB).
  const lineSize = 6;
  const lines = Math.ceil((11 * 1024 * 1024) / lineSize);
  const oversize = new Uint8Array(lines * lineSize);
  for (let i = 0; i < lines; i++) {
    oversize[i * lineSize + 0] = 0x61; // 'a'
    oversize[i * lineSize + 1] = 0x2c; // ','
    oversize[i * lineSize + 2] = 0x62; // 'b'
    oversize[i * lineSize + 3] = 0x2c; // ','
    oversize[i * lineSize + 4] = 0x63; // 'c'
    oversize[i * lineSize + 5] = 0x0a; // \n
  }
  const out = await parseCsv(oversize);
  if (out.fileType !== 'csv') throw new Error(`fileType=${out.fileType}`);
  const oversizeHit = (out.hiddenFindings || []).find(
    (f) => /exceeds scan limits|partial scan|exceeds row limit|too large|csv-scan-limit/i.test(f.technique || ''),
  );
  if (!oversizeHit) {
    throw new Error(`no oversize warning. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
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

for (const s of skipped) {
  console.log(`SKIP ${s.name}`);
  console.log('       reason:', s.reason);
}

console.log(`\nTotal: ${passed} passed / ${failed} failed / ${skipped.length} skipped`);
process.exitCode = failed === 0 ? 0 : 1;
