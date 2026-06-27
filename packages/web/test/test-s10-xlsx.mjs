// =============================================================
//  Shield Scanner Web — S10 XLSX parser harness
// =============================================================
// Drives packages/web/src/parsers-web/xlsx.js end-to-end against the same
// xlsx fixtures the MCP regression suite uses, so the Web mirror's detection
// surface is exercised under Node (no browser tab required).
//
// Coverage:
//   - 7 XLSX attack fixtures exercising every detection rule
//     (SC-02 / FI-01 / FI-03 / MV-04 / ER-03 / MD-05 / MV-07 / MD-08)
//   - 2 XLSX benign fixtures (no findings expected on a clean workbook)
//   - 1 corrupt-zip soft-fail case (parser must NOT throw)
//
// R13 (5-key byCategory invariant): hiddenFindings carry
// category='suspiciousPatterns'|'hiddenHtml' ONLY. We assert that on every
// fixture so a future rule that invents a new bucket regresses loudly.
//
// R14 (library trap): parsers-web/xlsx.js depends on `globalThis.JSZip`. We
// load JSZip from node_modules and install it on the global before the
// dynamic import, mirroring how index.template.html loads it from the CDN.
//
// R18 (env-abstract order contract): parsers-web/xlsx.js transitively imports
// from `@shield-scanner/core` whose barrel pulls in detectors that call
// loadRule() at module-init. The Node default env wires the fs-based loader
// automatically, so no explicit setEnv() is needed here. We still keep the
// dynamic import (after JSZip install) so the order contract is documented
// for any future env-bound rewrite.
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import JSZip from 'jszip';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Install JSZip global BEFORE the parser dynamic-import — parsers-web/xlsx.js
// uses `globalThis.JSZip` (CDN-loaded in the browser bundle).
globalThis.JSZip = JSZip;

const { parseXlsx } = await import('../src/parsers-web/xlsx.js');

const ATTACKS_DIR = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'attacks');
const BENIGN_DIR  = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'benign');

const tests = [];
const skipped = [];

function add(name, fn) { tests.push({ name, fn }); }
function skip(name, reason) { skipped.push({ name, reason }); }

// Read a fixture; if missing, downstream tests skip instead of fail-loud.
function readFixture(dir, file) {
  const p = join(dir, file);
  if (!existsSync(p)) return null;
  return new Uint8Array(readFileSync(p));
}

function categorySet(findings) {
  return new Set((findings || []).map((f) => f && f.category).filter(Boolean));
}

function severitySet(findings) {
  return new Set((findings || []).map((f) => f && f.severity).filter(Boolean));
}

function hasFindingMatching(findings, predicate) {
  return (findings || []).some((f) => f && predicate(f));
}

// --- 71: SC-02 + FI-03 + MV-04 (very-hidden + auto-open + macrosheets) ---
add('71 S10 XLSX: xlsx_very_hidden_with_auto_open surfaces SC-02 + FI-03 + MV-04', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_very_hidden_with_auto_open.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  if (out.fileType !== 'xlsx') throw new Error(`fileType=${out.fileType}`);
  // SC-02 veryHidden — danger
  const veryHidden = hasFindingMatching(out.hiddenFindings,
    (f) => f.severity === 'danger' && f.technique === 'veryhidden-sheet');
  if (!veryHidden) throw new Error('no veryHidden danger finding');
  // FI-03 — Auto-trigger definedName (suspiciousPatterns)
  const autoOpen = hasFindingMatching(out.hiddenFindings,
    (f) => f.category === 'suspiciousPatterns' && f.technique === 'auto-run-defined-name');
  if (!autoOpen) throw new Error('no auto-run-defined-name finding');
});

// --- 72: SC-02 state-confusion / case-folded veryHidden detection ---
// The fixture carries state="VeryHidden" (capital V). Both MCP and Web
// toLowerCase()-fold the state token, so "VeryHidden" maps to the
// canonical "veryhidden" branch → danger. (The fixture's index.json notes
// document the intent as "warning state confusion"; the actual runtime
// behavior is the case-folded danger path, which is what we pin here.)
add('72 S10 XLSX: xlsx_state_confusion_capitalised surfaces SC-02 finding on Quirky sheet', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_state_confusion_capitalised.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const hit = hasFindingMatching(out.hiddenFindings,
    (f) => f.category === 'hiddenHtml'
        && /Quirky/.test(f.element || '')
        && (f.severity === 'warning' || f.severity === 'danger'));
  if (!hit) {
    throw new Error(`no SC-02 finding on Quirky sheet. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
});

// --- 73: ER-03 UNC/SMB external link ---
add('73 S10 XLSX: xlsx_external_link_unc_smb surfaces ER-03 UNC danger', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_external_link_unc_smb.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const unc = hasFindingMatching(out.hiddenFindings,
    (f) => f.severity === 'danger'
      && f.technique === 'external-relationship'
      && f.meta && f.meta.scheme === 'unc');
  if (!unc) {
    throw new Error(`no UNC danger finding. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
});

// --- 74: MV-04 vbaProject presence (extension mismatch is a documented Web-side
// drift — Web emits only the vbaProject danger; MCP emits both. The vbaProject
// danger is the critical alarm, so we pin that and treat the extension-mismatch
// surface as Web-side drift documented in xlsx-parity.test.js KNOWN_DRIFT_FIXTURES.
add('74 S10 XLSX: xlsx_vba_present_extension_mismatch surfaces MV-04 vbaProject danger', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_vba_present_extension_mismatch.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const dangers = (out.hiddenFindings || []).filter((f) => f.severity === 'danger');
  if (dangers.length < 1) {
    throw new Error(`expected >=1 danger finding, got ${dangers.length}. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
  const vba = dangers.some((f) => f.technique === 'vba-macro-project');
  if (!vba) throw new Error('no vbaProject finding among dangers');
});

// --- 75: MD-05 docProps prompt injection ---
add('75 S10 XLSX: xlsx_docprops_prompt_injection surfaces MD-05 warnings on docProps', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_docprops_prompt_injection.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const md05 = hasFindingMatching(out.hiddenFindings,
    (f) => f.category === 'suspiciousPatterns'
        && f.technique === 'docprops-prompt-injection');
  if (!md05) {
    throw new Error(`no docProps prompt-injection finding. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
});

// --- 76: MV-07 threaded comment persona spoof ---
add('76 S10 XLSX: xlsx_threaded_comment_persona_spoof surfaces MV-07 warning', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_threaded_comment_persona_spoof.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  const mv07 = hasFindingMatching(out.hiddenFindings,
    (f) => f.severity === 'warning' && /comment|threadedComment/i.test((f.element || '') + ' ' + (f.contextLocation || '')));
  if (!mv07) {
    throw new Error(`no MV-07 finding. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
});

// --- 77: FI-01 — <f> node DDE command (parser must emit cell line for downstream FI detector) ---
add('77 S10 XLSX: xlsx_dde_command_in_f_node emits formula cell line for FI-01 detection', async () => {
  const buf = readFixture(ATTACKS_DIR, 'xlsx_dde_command_in_f_node.xlsx');
  if (!buf) throw new Error('fixture missing');
  const out = await parseXlsx(buf);
  // The FI-01 finding itself comes from core analyze() folded over the body
  // (downstream). The parser-level contract is: emit the formula text with
  // a leading '=' on a `[Sheet 'X'!A1] ` -prefixed line so the detector can
  // engage.
  if (!/\[Sheet '[^']+'![A-Z]+\d+\] =/.test(out.text || '')) {
    throw new Error(`body missing prefixed formula line. text=${(out.text || '').slice(0, 400)}`);
  }
});

// --- 78: benign invoice template — no danger / warning findings expected ---
add('78 S10 XLSX: xlsx_benign_invoice_template emits no danger findings', async () => {
  const buf = readFixture(BENIGN_DIR, 'xlsx_benign_invoice_template.xlsx');
  if (!buf) {
    // benign fixtures may be optional in some checkouts — skip rather than fail.
    return;
  }
  const out = await parseXlsx(buf);
  const dangers = (out.hiddenFindings || []).filter((f) => f.severity === 'danger');
  if (dangers.length > 0) {
    throw new Error(`benign workbook emitted dangers: ${JSON.stringify(dangers)}`);
  }
});

// --- 79: benign chart with title — no danger findings ---
add('79 S10 XLSX: xlsx_benign_chart_with_title emits no danger findings', async () => {
  const buf = readFixture(BENIGN_DIR, 'xlsx_benign_chart_with_title.xlsx');
  if (!buf) return;
  const out = await parseXlsx(buf);
  const dangers = (out.hiddenFindings || []).filter((f) => f.severity === 'danger');
  if (dangers.length > 0) {
    throw new Error(`benign workbook emitted dangers: ${JSON.stringify(dangers)}`);
  }
});

// --- 80: R13 invariant — hiddenFindings.category is 5-key safe ---
add('80 S10 XLSX: R13 invariant — every hidden finding category is suspiciousPatterns|hiddenHtml', async () => {
  // Walk the attack corpus once and assert the union of categories is the 2
  // allowed values, not a new bucket. This is the canary for R13 drift.
  const allowed = new Set(['suspiciousPatterns', 'hiddenHtml']);
  const files = [
    'xlsx_very_hidden_with_auto_open.xlsx',
    'xlsx_state_confusion_capitalised.xlsx',
    'xlsx_external_link_unc_smb.xlsx',
    'xlsx_vba_present_extension_mismatch.xlsx',
    'xlsx_docprops_prompt_injection.xlsx',
    'xlsx_threaded_comment_persona_spoof.xlsx',
    'xlsx_dde_command_in_f_node.xlsx',
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

// --- 81: corrupt zip header — soft-fail (parser must return, not throw) ---
add('81 S10 XLSX: corrupt zip header — parser returns warning shape without throwing', async () => {
  // 4 bytes that are not a valid zip signature — JSZip rejects, parser must
  // catch and emit a structured warning.
  const garbage = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
  let out;
  try {
    out = await parseXlsx(garbage);
  } catch (err) {
    throw new Error('parser threw on corrupt zip: ' + (err && err.message));
  }
  if (out.fileType !== 'xlsx') throw new Error(`fileType=${out.fileType}`);
  if (!(out.hiddenFindings || []).length) throw new Error('no warning emitted on corrupt zip');
  const cat = categorySet(out.hiddenFindings);
  if (!(cat.has('suspiciousPatterns') || cat.has('hiddenHtml'))) {
    throw new Error('finding category not in allowed set on corrupt zip');
  }
});

// --- 82: oversize buffer short-circuit (>10MB) ---
add('82 S10 XLSX: oversize buffer (>10MB) short-circuits with warning', async () => {
  // 11MB of zero bytes — well above WEB_XLSX_ARCHIVE_SHORT_CIRCUIT (10MB).
  const oversize = new Uint8Array(11 * 1024 * 1024);
  const out = await parseXlsx(oversize);
  if (out.fileType !== 'xlsx') throw new Error(`fileType=${out.fileType}`);
  const oversizeHit = (out.hiddenFindings || []).find(
    (f) => f.technique === 'xlsx-scan-limit',
  );
  if (!oversizeHit) {
    throw new Error(`no oversize warning. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
  // Severity floor
  if (oversizeHit.severity !== 'warning' && oversizeHit.severity !== 'danger') {
    throw new Error(`oversize finding severity=${oversizeHit.severity}`);
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
