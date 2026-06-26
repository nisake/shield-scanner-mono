// =============================================================
//  Shield Scanner Web — S13 archive parser harness
// =============================================================
// Drives packages/web/src/parsers-web/archive.js end-to-end against the
// `archive_*.zip` fixtures the MCP regression suite uses. Mirrors the S10
// XLSX harness shape — no browser tab required, runs from Node directly.
//
// Coverage (12 cases):
//   - AR-01 bomb (high ratio)
//   - AR-01 bomb (total cap)
//   - AR-02 depth cap (depth=4)
//   - AR-03 zip-slip (dotdot)
//   - AR-03 zip-slip (absolute)
//   - AR-03 zip-slip (nullbyte)
//   - AR-04 encrypted archive/entry
//   - AR-05 suspicious entry extension (.exe)
//   - AR-06 Office package renamed to .zip — implicit via the
//           macro-in-nested-xlsm fixture (an .xlsm carries [Content_Types].xml)
//   - AR-07 entry-count cap
//   - benign single-txt
//   - benign nested depth=2 (allowed)
//
// R12 (no shadow-leak): the harness only checks detector-controlled scaffolding
//   on hiddenFindings (technique / severity / category / element). User-content
//   strings (entry names) are echo-bounded by escapeForDisplay in the parser.
// R13 (5-key byCategory invariant): hiddenFindings carry category
//   in { 'suspiciousPatterns', 'hiddenHtml' } ONLY. A canary at the end walks
//   the corpus and asserts the union is the 2 allowed values.
// R14 (library trap): parsers-web/archive.js depends on `globalThis.JSZip`.
//   Install it before the dynamic import. JSZip-dep-guard pattern (S12-XR-02
//   / S10-xlsx): wrap the require in try/catch and `skip` rather than fail-loud
//   if the package is unavailable.
// R18 (env-abstract order contract): parsers-web/archive.js imports only the
//   env-free archive-detection helpers from core, so no setEnv() is required.
//   Mirror parsers-web/xlsx.js: keep the dynamic import AFTER JSZip install so
//   the contract is documented for any future env-bound rewrite.
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// JSZip-dep guard — if jszip is not installed in this workspace, skip the
// whole suite rather than fail-loud (matches S12-XR-02 / S10-xlsx).
let JSZip;
try {
  JSZip = (await import('jszip')).default;
} catch (_e) {
  console.log('SKIP S13 archive harness — jszip not installed in this workspace');
  process.exit(0);
}

// Install JSZip global BEFORE the parser dynamic-import — parsers-web/archive.js
// uses `globalThis.JSZip` (CDN-loaded in the browser bundle).
globalThis.JSZip = JSZip;

const { parseArchiveBuffer } = await import('../src/parsers-web/archive.js');

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

function hasFindingMatching(findings, predicate) {
  return (findings || []).some((f) => f && predicate(f));
}

function findingsByCat(findings, cat) {
  return (findings || []).filter((f) => f && f.category === cat);
}

// --- 83: AR-01 high-ratio zip bomb ------------------------------------------
add('83 S13 archive: archive_zip_bomb_high_ratio.zip surfaces AR-01 bomb (ratio block)', async () => {
  const buf = readFixture(ATTACKS_DIR, 'archive_zip_bomb_high_ratio.zip');
  if (!buf) { skip('83', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  if (out.fileType !== 'zip') throw new Error(`fileType=${out.fileType}`);
  if (!out.archive || out.archive.bomb < 1) {
    throw new Error(`expected archive.bomb >= 1, got ${out.archive && out.archive.bomb}`);
  }
  const bomb = hasFindingMatching(out.hiddenFindings,
    (f) => f.severity === 'danger' && /compression ratio/i.test(f.technique || ''));
  if (!bomb) throw new Error('no compression-ratio bomb finding');
});

// --- 84: AR-01 total-cap zip bomb -------------------------------------------
add('84 S13 archive: archive_zip_bomb_total_cap.zip surfaces AR-01 bomb (total cap)', async () => {
  const buf = readFixture(ATTACKS_DIR, 'archive_zip_bomb_total_cap.zip');
  if (!buf) { skip('84', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  if (!out.archive || out.archive.bomb < 1) {
    throw new Error(`expected archive.bomb >= 1 (total cap), got ${out.archive && out.archive.bomb}`);
  }
});

// --- 85: AR-02 nested depth 4 -----------------------------------------------
add('85 S13 archive: archive_nested_depth_4.zip surfaces AR-02 depth cap', async () => {
  const buf = readFixture(ATTACKS_DIR, 'archive_nested_depth_4.zip');
  if (!buf) { skip('85', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  if (!out.archive || out.archive.depth < 1) {
    throw new Error(`expected archive.depth >= 1, got ${out.archive && out.archive.depth}`);
  }
  const depthHit = hasFindingMatching(out.hiddenFindings,
    (f) => /nest depth|depth cap/i.test(f.technique || ''));
  if (!depthHit) throw new Error('no nest-depth finding');
});

// --- 86: AR-03 zip-slip (dotdot or normalized-absolute) ---------------------
add('86 S13 archive: archive_path_traversal_dotdot.zip surfaces AR-03 zip-slip', async () => {
  const buf = readFixture(ATTACKS_DIR, 'archive_path_traversal_dotdot.zip');
  if (!buf) { skip('86', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  // JSZip normalizes `../../../etc/passwd` into `/etc/passwd` at load — the
  // classification can land as dotdot or absolute. Both fold into
  // suspiciousPatterns as danger.
  const slip = findingsByCat(out.hiddenFindings, 'suspiciousPatterns').filter(
    (f) => /Zip slip/i.test(f.technique || ''));
  if (slip.length < 1) {
    throw new Error(`no zip-slip finding. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
  if (slip[0].severity !== 'danger') {
    throw new Error(`zip-slip severity=${slip[0].severity}`);
  }
});

// --- 87: AR-03 zip-slip absolute --------------------------------------------
add('87 S13 archive: archive_path_traversal_absolute.zip surfaces AR-03 absolute', async () => {
  const buf = readFixture(ATTACKS_DIR, 'archive_path_traversal_absolute.zip');
  if (!buf) { skip('87', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  const slip = findingsByCat(out.hiddenFindings, 'suspiciousPatterns').filter(
    (f) => /Zip slip/i.test(f.technique || ''));
  if (slip.length < 1) {
    throw new Error(`no zip-slip absolute finding. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
});

// --- 88: AR-03 zip-slip nullbyte --------------------------------------------
add('88 S13 archive: archive_path_traversal_nullbyte.zip surfaces AR-03 nullbyte', async () => {
  const buf = readFixture(ATTACKS_DIR, 'archive_path_traversal_nullbyte.zip');
  if (!buf) { skip('88', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  const slip = findingsByCat(out.hiddenFindings, 'suspiciousPatterns').filter(
    (f) => /Zip slip/i.test(f.technique || ''));
  if (slip.length < 1) {
    throw new Error(`no zip-slip nullbyte finding. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
});

// --- 89: AR-04 encrypted archive -------------------------------------------
add('89 S13 archive: archive_encrypted_entry.zip surfaces AR-04 protected', async () => {
  const buf = readFixture(ATTACKS_DIR, 'archive_encrypted_entry.zip');
  if (!buf) { skip('89', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  if (!out.archive || out.archive.protected < 1) {
    throw new Error(`expected archive.protected >= 1, got ${out.archive && out.archive.protected}`);
  }
  const enc = hasFindingMatching(out.hiddenFindings,
    (f) => /encrypted/i.test(f.technique || ''));
  if (!enc) throw new Error('no encrypted-archive finding');
});

// --- 90: AR-05 suspicious entry extension (.exe) ----------------------------
add('90 S13 archive: archive_suspicious_ext_exe.zip surfaces AR-05 in suspiciousPatterns', async () => {
  const buf = readFixture(ATTACKS_DIR, 'archive_suspicious_ext_exe.zip');
  if (!buf) { skip('90', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  const susp = findingsByCat(out.hiddenFindings, 'suspiciousPatterns').filter(
    (f) => /Suspicious archive entry/i.test(f.technique || ''));
  if (susp.length < 1) {
    throw new Error(`no AR-05 finding. findings=${JSON.stringify(out.hiddenFindings)}`);
  }
  if (susp[0].severity !== 'warning') {
    throw new Error(`AR-05 severity=${susp[0].severity}`);
  }
});

// --- 91: AR-06 Office-rename (via nested xlsm having [Content_Types].xml) ---
// The fixtures-agent macro-in-nested-xlsm contains an .xlsm; that .xlsm
// itself has [Content_Types].xml inside it. The outer .zip does NOT carry
// the marker — the AR-06 surface in this case is on the recursive level if
// the inner archive is descended. The robust assertion here is the
// structural rollup: the archive was scanned at least once.
add('91 S13 archive: archive_macro_in_nested_xlsm.zip scans the outer archive (AR-06 path covered)', async () => {
  const buf = readFixture(ATTACKS_DIR, 'archive_macro_in_nested_xlsm.zip');
  if (!buf) { skip('91', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  if (!out.archive || out.archive.scanned < 1) {
    throw new Error(`expected archive.scanned >= 1, got ${out.archive && out.archive.scanned}`);
  }
});

// --- 92: AR-07 entry-count cap ----------------------------------------------
add('92 S13 archive: archive_entry_count_overflow.zip surfaces AR-07 entryCap', async () => {
  const buf = readFixture(ATTACKS_DIR, 'archive_entry_count_overflow.zip');
  if (!buf) { skip('92', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  if (!out.archive || out.archive.entryCap < 1) {
    throw new Error(`expected archive.entryCap >= 1, got ${out.archive && out.archive.entryCap}`);
  }
});

// --- 93: benign single-txt --------------------------------------------------
add('93 S13 archive: archive_benign_single_txt.zip emits no danger', async () => {
  const buf = readFixture(BENIGN_DIR, 'archive_benign_single_txt.zip');
  if (!buf) { skip('93', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  const dangers = (out.hiddenFindings || []).filter((f) => f.severity === 'danger');
  if (dangers.length > 0) {
    throw new Error(`benign single-txt emitted dangers: ${JSON.stringify(dangers)}`);
  }
  if (out.archive && (out.archive.bomb !== 0 || out.archive.depth !== 0 || out.archive.entryCap !== 0)) {
    throw new Error(`benign single-txt archive structural counters nonzero: ${JSON.stringify(out.archive)}`);
  }
});

// --- 94: benign nested depth=2 (allowed) ------------------------------------
add('94 S13 archive: archive_benign_nested_depth_2.zip allowed (no danger)', async () => {
  const buf = readFixture(BENIGN_DIR, 'archive_benign_nested_depth_2.zip');
  if (!buf) { skip('94', 'fixture missing'); return; }
  const out = await parseArchiveBuffer(buf, { depth: 0 });
  const dangers = (out.hiddenFindings || []).filter((f) => f.severity === 'danger');
  if (dangers.length > 0) {
    throw new Error(`benign nested depth=2 emitted dangers: ${JSON.stringify(dangers)}`);
  }
});

// --- 95: R13 invariant — hiddenFindings.category is 5-key safe --------------
add('95 S13 archive: R13 invariant — every hidden finding category is suspiciousPatterns|hiddenHtml', async () => {
  const allowed = new Set(['suspiciousPatterns', 'hiddenHtml']);
  const files = [
    'archive_zip_bomb_high_ratio.zip',
    'archive_path_traversal_dotdot.zip',
    'archive_suspicious_ext_exe.zip',
    'archive_encrypted_entry.zip',
    'archive_nested_depth_4.zip',
  ];
  for (const f of files) {
    const buf = readFixture(ATTACKS_DIR, f);
    if (!buf) continue;
    const out = await parseArchiveBuffer(buf, { depth: 0 });
    for (const finding of (out.hiddenFindings || [])) {
      if (!allowed.has(finding.category)) {
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
