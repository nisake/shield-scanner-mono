// =============================================================
//  Shield Scanner Web — v1.19.0 B2 RTF parser harness
// =============================================================
// Drives packages/web/src/parsers-web/rtf.js end-to-end against the
// rtf_*.rtf fixtures the MCP regression suite uses. Direct node-test
// harness — no browser tab required.
//
// Coverage (7 cases): 5 attack + 2 benign:
//   - rtf-ole-object         (rtf_objdata_ole.rtf)
//   - rtf-field-hyperlink    (rtf_field_hyperlink_exfil.rtf)
//   - rtf-hidden-text-v      (rtf_hidden_v_instruction.rtf)
//   - rtf-microscopic-font   (rtf_microscopic_fs6.rtf)
//   - rtf-binary-block       (rtf_bin_payload.rtf)
//   - benign — plain letter, RTF with hex-encoded image
//
// R12 (no shadow-leak): only detector-controlled meta keys surface.
//   Hidden body / decoded payload must never leak in JSON.stringify(out).
// R13 (5-key byCategory): hiddenFindings carry category='suspiciousPatterns'
//   ONLY for the 6 v1.19.0 RTF kebabs.
// R22-R23: byte-identical with MCP (kebab id, severity, meta key shape).
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { parseRtf } = await import('../src/parsers-web/rtf.js');

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

function pickKebab(out, technique) {
  return (out.hiddenFindings || []).filter((f) => f.technique === technique);
}

const V19_RTF_KEBABS = new Set([
  'rtf-ole-object',
  'rtf-field-hyperlink',
  'rtf-hidden-text-v',
  'rtf-microscopic-font',
  'rtf-binary-block',
  'rtf-unknown-destination',
]);

function v19Findings(out) {
  return (out.hiddenFindings || []).filter((f) => V19_RTF_KEBABS.has(f.technique));
}

// --- B2-01: rtf-ole-object danger -------------------------------------------
add('B2-01 RTF: rtf_objdata_ole.rtf surfaces rtf-ole-object (danger)', async () => {
  const buf = readFixture(ATTACKS_DIR, 'rtf_objdata_ole.rtf');
  if (!buf) { skip('B2-01', 'fixture missing'); return; }
  const out = await parseRtf(buf);
  if (out.fileType !== 'rtf') throw new Error(`fileType=${out.fileType}`);
  const hits = pickKebab(out, 'rtf-ole-object');
  if (hits.length < 1) throw new Error(`no rtf-ole-object finding. findings=${JSON.stringify(out.hiddenFindings)}`);
  if (hits[0].severity !== 'danger') throw new Error(`severity=${hits[0].severity}`);
  if (hits[0].category !== 'suspiciousPatterns') throw new Error(`category=${hits[0].category}`);
  const withClass = hits.filter((h) => h.meta && typeof h.meta.objclass === 'string' && h.meta.objclass.length > 0);
  if (withClass.length < 1) throw new Error(`no rtf-ole-object with non-empty meta.objclass`);
});

// --- B2-02: rtf-field-hyperlink warning, scheme+host only -------------------
add('B2-02 RTF: rtf_field_hyperlink_exfil.rtf surfaces rtf-field-hyperlink (warning, sanitized URL)', async () => {
  const buf = readFixture(ATTACKS_DIR, 'rtf_field_hyperlink_exfil.rtf');
  if (!buf) { skip('B2-02', 'fixture missing'); return; }
  const out = await parseRtf(buf);
  const hits = pickKebab(out, 'rtf-field-hyperlink');
  if (hits.length !== 1) throw new Error(`expected 1 hit, got ${hits.length}`);
  const f = hits[0];
  if (f.severity !== 'warning') throw new Error(`severity=${f.severity}`);
  if (!/^http:\/\/attacker\.example\.com\/?$/.test(f.meta.url || '')) {
    throw new Error(`meta.url leaks path/query: ${f.meta.url}`);
  }
  if (/exfil|token|ABC/.test(f.meta.url || '')) {
    throw new Error(`meta.url leaks sensitive token: ${f.meta.url}`);
  }
});

// --- B2-03: rtf-hidden-text-v warning, body never echoed --------------------
add('B2-03 RTF: rtf_hidden_v_instruction.rtf surfaces rtf-hidden-text-v (warning, body redacted)', async () => {
  const buf = readFixture(ATTACKS_DIR, 'rtf_hidden_v_instruction.rtf');
  if (!buf) { skip('B2-03', 'fixture missing'); return; }
  const out = await parseRtf(buf);
  const hits = pickKebab(out, 'rtf-hidden-text-v');
  if (hits.length < 1) throw new Error(`no rtf-hidden-text-v finding`);
  if (typeof hits[0].meta.charCount !== 'number' || hits[0].meta.charCount <= 0) {
    throw new Error(`meta.charCount invalid: ${hits[0].meta.charCount}`);
  }
  // R12: hidden body must NOT appear in the surface.
  const joined = JSON.stringify(out.hiddenFindings);
  if (/ignore_all_previous_instructions/.test(joined)) {
    throw new Error(`R12 violation — hidden body leaked: ${joined}`);
  }
});

// --- B2-04: rtf-microscopic-font warning, fontSize=3 ------------------------
add('B2-04 RTF: rtf_microscopic_fs6.rtf surfaces rtf-microscopic-font (warning, fontSize=3)', async () => {
  const buf = readFixture(ATTACKS_DIR, 'rtf_microscopic_fs6.rtf');
  if (!buf) { skip('B2-04', 'fixture missing'); return; }
  const out = await parseRtf(buf);
  const hits = pickKebab(out, 'rtf-microscopic-font');
  if (hits.length < 1) throw new Error(`no rtf-microscopic-font finding`);
  if (hits[0].meta.fontSize !== 3) throw new Error(`fontSize=${hits[0].meta.fontSize}`);
  // R12: \fs6-tagged body must NOT leak.
  const joined = JSON.stringify(out.hiddenFindings);
  if (/hidden_payload_for_llm_at_3pt/.test(joined)) {
    throw new Error(`R12 violation — hidden body leaked: ${joined}`);
  }
});

// --- B2-05: rtf-binary-block warning, byteCount=64 --------------------------
add('B2-05 RTF: rtf_bin_payload.rtf surfaces rtf-binary-block (warning, byteCount=64)', async () => {
  const buf = readFixture(ATTACKS_DIR, 'rtf_bin_payload.rtf');
  if (!buf) { skip('B2-05', 'fixture missing'); return; }
  const out = await parseRtf(buf);
  const hits = pickKebab(out, 'rtf-binary-block');
  if (hits.length < 1) throw new Error(`no rtf-binary-block finding`);
  if (hits[0].meta.byteCount !== 64) throw new Error(`byteCount=${hits[0].meta.byteCount}`);
});

// --- B2-06: benign plain letter — 0 RTF findings ----------------------------
add('B2-06 RTF: benign_rtf_plain_letter.rtf emits zero v1.19.0 RTF findings', async () => {
  const buf = readFixture(BENIGN_DIR, 'benign_rtf_plain_letter.rtf');
  if (!buf) { skip('B2-06', 'fixture missing'); return; }
  const out = await parseRtf(buf);
  const hits = v19Findings(out);
  if (hits.length > 0) {
    throw new Error(`benign letter emitted ${hits.length} RTF findings: ${JSON.stringify(hits)}`);
  }
});

// --- B2-07: benign RTF with hex-encoded image — 0 RTF findings --------------
add('B2-07 RTF: benign_rtf_with_image.rtf emits zero v1.19.0 RTF findings', async () => {
  const buf = readFixture(BENIGN_DIR, 'benign_rtf_with_image.rtf');
  if (!buf) { skip('B2-07', 'fixture missing'); return; }
  const out = await parseRtf(buf);
  const hits = v19Findings(out);
  if (hits.length > 0) {
    throw new Error(`benign image RTF emitted ${hits.length} RTF findings: ${JSON.stringify(hits)}`);
  }
});

// --- B2-08: R13 5-key invariant — every RTF finding is suspiciousPatterns ---
add('B2-08 RTF: R13 invariant — every RTF kebab folds to suspiciousPatterns', async () => {
  const files = [
    'rtf_objdata_ole.rtf',
    'rtf_field_hyperlink_exfil.rtf',
    'rtf_hidden_v_instruction.rtf',
    'rtf_microscopic_fs6.rtf',
    'rtf_bin_payload.rtf',
  ];
  for (const f of files) {
    const buf = readFixture(ATTACKS_DIR, f);
    if (!buf) continue;
    const out = await parseRtf(buf);
    for (const finding of v19Findings(out)) {
      if (finding.category !== 'suspiciousPatterns') {
        throw new Error(`${f}: bad category ${finding.category} on ${finding.technique}`);
      }
    }
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
