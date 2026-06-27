// =============================================================
//  Shield Scanner Web — v1.19.0 B3 Jupyter Notebook parser harness
// =============================================================
// Drives packages/web/src/parsers-web/ipynb.js end-to-end against the same
// .ipynb fixtures the MCP regression suite uses, plus 2 synthetic edge cases
// to pin the defensive caps (oversize / corrupt-JSON).
//
// Coverage:
//   - 4 ipynb attack fixtures — assert the Web parser surfaces the same
//     kebab id each kind of fixture targets:
//       ipynb_output_html_injection      → ipynb-output-html-injection
//       ipynb_hide_input_instruction     → ipynb-hidden-cell-instruction
//       ipynb_metadata_tag_smuggle       → ipynb-metadata-tag-smuggle
//       ipynb_untrusted_signature        → ipynb-untrusted-signature
//   - 2 benign fixtures — must NOT emit any of the 4 kebab ids (signed
//     notebook, benign tag values).
//   - 1 oversize buffer (>10 MB) — must emit ipynb-scan-limit warning.
//   - 1 corrupt JSON — must emit ipynb-corrupt-json warning without throwing.
//
// R12 / R13 / R18: invariants matched against MCP — categories all fold into
// suspiciousPatterns, severities mirror MCP, R18 env-abstract pure helpers
// only (no rule-load at module-load).
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { parseIpynb } = await import('../src/parsers-web/ipynb.js');

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

// --- Attack 1: output HTML / JS injection ---
add('IPYNB-01 attack: ipynb_output_html_injection emits ipynb-output-html-injection', async () => {
  const buf = readFixture(ATTACKS_DIR, 'ipynb_output_html_injection.ipynb');
  if (!buf) throw new Error('fixture missing');
  const out = await parseIpynb(buf);
  if (out.fileType !== 'ipynb') throw new Error(`fileType=${out.fileType}`);
  const techs = techniques(out);
  if (!techs.includes('ipynb-output-html-injection')) {
    throw new Error(`missing ipynb-output-html-injection. techs=${JSON.stringify(techs)}`);
  }
  const htmlHits = (out.hiddenFindings || []).filter((f) => f.technique === 'ipynb-output-html-injection');
  if (htmlHits.length < 2) {
    throw new Error(`expected >=2 hits (text/html + application/javascript). got=${htmlHits.length}`);
  }
  if (htmlHits[0].category !== 'suspiciousPatterns') {
    throw new Error(`expected category=suspiciousPatterns. got=${htmlHits[0].category}`);
  }
  if (htmlHits[0].severity !== 'danger') {
    throw new Error(`expected severity=danger. got=${htmlHits[0].severity}`);
  }
});

// --- Attack 2: hide_input + instruction-shaped source ---
add('IPYNB-02 attack: ipynb_hide_input_instruction emits ipynb-hidden-cell-instruction', async () => {
  const buf = readFixture(ATTACKS_DIR, 'ipynb_hide_input_instruction.ipynb');
  if (!buf) throw new Error('fixture missing');
  const out = await parseIpynb(buf);
  const techs = techniques(out);
  if (!techs.includes('ipynb-hidden-cell-instruction')) {
    throw new Error(`missing ipynb-hidden-cell-instruction. techs=${JSON.stringify(techs)}`);
  }
  const hit = (out.hiddenFindings || []).find((f) => f.technique === 'ipynb-hidden-cell-instruction');
  if (hit.category !== 'suspiciousPatterns') {
    throw new Error(`expected category=suspiciousPatterns. got=${hit.category}`);
  }
  if (hit.severity !== 'danger') {
    throw new Error(`expected severity=danger. got=${hit.severity}`);
  }
  if (!Array.isArray(hit.meta.hideSignals) || hit.meta.hideSignals.length === 0) {
    throw new Error(`expected meta.hideSignals array. got=${JSON.stringify(hit.meta)}`);
  }
});

// --- Attack 3: metadata.tags smuggling ---
add('IPYNB-03 attack: ipynb_metadata_tag_smuggle emits ipynb-metadata-tag-smuggle', async () => {
  const buf = readFixture(ATTACKS_DIR, 'ipynb_metadata_tag_smuggle.ipynb');
  if (!buf) throw new Error('fixture missing');
  const out = await parseIpynb(buf);
  const techs = techniques(out);
  if (!techs.includes('ipynb-metadata-tag-smuggle')) {
    throw new Error(`missing ipynb-metadata-tag-smuggle. techs=${JSON.stringify(techs)}`);
  }
  const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'ipynb-metadata-tag-smuggle');
  if (hits.length < 2) {
    throw new Error(`expected >=2 tag hits. got=${hits.length}`);
  }
  if (!hits.some((h) => h.severity === 'danger')) {
    throw new Error('expected at least one danger-severity tag hit');
  }
});

// --- Attack 4: untrusted signature ---
add('IPYNB-04 attack: ipynb_untrusted_signature emits ipynb-untrusted-signature', async () => {
  const buf = readFixture(ATTACKS_DIR, 'ipynb_untrusted_signature.ipynb');
  if (!buf) throw new Error('fixture missing');
  const out = await parseIpynb(buf);
  const techs = techniques(out);
  if (!techs.includes('ipynb-untrusted-signature')) {
    throw new Error(`missing ipynb-untrusted-signature. techs=${JSON.stringify(techs)}`);
  }
  const hit = (out.hiddenFindings || []).find((f) => f.technique === 'ipynb-untrusted-signature');
  if (hit.severity !== 'warning') {
    throw new Error(`expected severity=warning. got=${hit.severity}`);
  }
  if (hit.meta.nbformat !== 4) {
    throw new Error(`expected meta.nbformat=4. got=${hit.meta.nbformat}`);
  }
});

// --- Benign 1: signed data-analysis notebook (FP guard) ---
add('IPYNB-05 benign: benign_ipynb_data_analysis emits none of the 4 ipynb kebab ids', async () => {
  const buf = readFixture(BENIGN_DIR, 'benign_ipynb_data_analysis.ipynb');
  if (!buf) throw new Error('fixture missing');
  const out = await parseIpynb(buf);
  const techs = techniques(out);
  for (const k of [
    'ipynb-output-html-injection',
    'ipynb-hidden-cell-instruction',
    'ipynb-metadata-tag-smuggle',
    'ipynb-untrusted-signature',
  ]) {
    if (techs.includes(k)) throw new Error(`unexpected ${k}. techs=${JSON.stringify(techs)}`);
  }
});

// --- Benign 2: markdown-only signed notebook (FP guard) ---
add('IPYNB-06 benign: benign_ipynb_markdown_only emits no ipynb-* findings', async () => {
  const buf = readFixture(BENIGN_DIR, 'benign_ipynb_markdown_only.ipynb');
  if (!buf) throw new Error('fixture missing');
  const out = await parseIpynb(buf);
  const techs = techniques(out);
  for (const t of techs) {
    if (t.startsWith('ipynb-')) {
      throw new Error(`unexpected ${t}. techs=${JSON.stringify(techs)}`);
    }
  }
});

// --- Edge 1: oversize buffer (>10MB) ---
add('IPYNB-07 oversize buffer (>10MB) emits ipynb-scan-limit warning', async () => {
  // 11 MB of spaces. Buffer never reaches JSON.parse — the parser short-circuits
  // before decode, so the content is irrelevant.
  const big = new Uint8Array(11 * 1024 * 1024);
  for (let i = 0; i < big.length; i++) big[i] = 0x20;
  const out = await parseIpynb(big);
  if (out.fileType !== 'ipynb') throw new Error(`fileType=${out.fileType}`);
  if (out.text !== '') throw new Error('expected empty text on oversize short-circuit');
  const hit = (out.hiddenFindings || []).find((f) => f.technique === 'ipynb-scan-limit');
  if (!hit) {
    throw new Error(`no ipynb-scan-limit warning. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
  if (hit.severity !== 'warning') throw new Error(`expected severity=warning. got=${hit.severity}`);
});

// --- Edge 2: corrupt JSON — no throw, emits ipynb-corrupt-json ---
add('IPYNB-08 corrupt JSON emits ipynb-corrupt-json warning without throwing', async () => {
  const bad = new TextEncoder().encode('{not really json');
  const out = await parseIpynb(bad);
  if (out.fileType !== 'ipynb') throw new Error(`fileType=${out.fileType}`);
  if (out.text !== '') throw new Error('expected empty text on corrupt JSON');
  const hit = (out.hiddenFindings || []).find((f) => f.technique === 'ipynb-corrupt-json');
  if (!hit) {
    throw new Error(`no ipynb-corrupt-json warning. findings=${JSON.stringify(out.hiddenFindings)}`);
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
