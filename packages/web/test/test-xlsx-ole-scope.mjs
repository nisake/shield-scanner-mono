// =============================================================
//  Shield Scanner Web — v1.20.0 T8-XLSX-OLE harness
// =============================================================
// Standalone node-test harness for packages/web/src/parsers-web/xlsx-ole-scope.js.
// Mirrors the MCP regression test in packages/mcp/test/regression/
// xlsx-ole-scope.test.js. Confirms the web helper is byte-identical with the
// MCP helper for the three v1.20.0 kebab ids:
//
//   - xlsx-ole-oversize       (warning, hiddenHtml)
//   - xlsx-ole-encrypted      (warning, hiddenHtml)
//   - xlsx-ole-macro-bearing  (danger,  suspiciousPatterns)
//
// Not yet wired into packages/web/test (the package.json test script). Add to
// that pipeline in the v1.20.x parser wire-in phase.
// =============================================================

import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { scanXlsxOleScope, XLSX_OLE_OVERSIZE_THRESHOLD, XLSX_OLE_SCOPE_KEBABS } =
  await import('../src/parsers-web/xlsx-ole-scope.js');

const CFB_MAGIC = Uint8Array.from([
  0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1,
]);

function utf16le(s) {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    out[i * 2] = s.charCodeAt(i) & 0xff;
    out[i * 2 + 1] = (s.charCodeAt(i) >> 8) & 0xff;
  }
  return out;
}

function concatBuffers(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function makeOversizeBlob() {
  const buf = new Uint8Array(XLSX_OLE_OVERSIZE_THRESHOLD + 1);
  buf.set(CFB_MAGIC, 0);
  return buf;
}

function makeEncryptedBlob() {
  return concatBuffers([
    CFB_MAGIC,
    new Uint8Array(2048),
    utf16le('EncryptedPackage'),
    new Uint8Array(1024),
  ]);
}

function makeMacroBearingBlob() {
  return concatBuffers([
    CFB_MAGIC,
    new Uint8Array(1024),
    utf16le('_VBA_PROJECT'),
    new Uint8Array(512),
  ]);
}

let passed = 0;
let failed = 0;
const failures = [];

function check(name, cond, detail) {
  if (cond) {
    passed++;
    console.log(`  ok  - ${name}`);
  } else {
    failed++;
    failures.push({ name, detail });
    console.log(`  FAIL - ${name}` + (detail ? `\n        ${detail}` : ''));
  }
}

console.log('xlsx-ole-scope (web) — v1.20.0 T8-XLSX-OLE');

// Kebab id set
check(
  'exports the documented kebab id set',
  Array.from(XLSX_OLE_SCOPE_KEBABS).sort().join(',') ===
    'xlsx-ole-encrypted,xlsx-ole-macro-bearing,xlsx-ole-oversize',
);

// Oversize
{
  const f = scanXlsxOleScope(makeOversizeBlob(), {
    memberName: 'xl/embeddings/oleObject1.bin',
  });
  check('xlsx-ole-oversize: exactly one finding', f.length === 1);
  if (f.length === 1) {
    const h = f[0];
    check('xlsx-ole-oversize: technique', h.technique === 'xlsx-ole-oversize');
    check('xlsx-ole-oversize: severity warning', h.severity === 'warning');
    check('xlsx-ole-oversize: category hiddenHtml', h.category === 'hiddenHtml');
    check(
      'xlsx-ole-oversize: meta.maxBytes pinned',
      h.meta && h.meta.maxBytes === XLSX_OLE_OVERSIZE_THRESHOLD,
    );
    check(
      'xlsx-ole-oversize: meta.sizeBytes over threshold',
      h.meta && h.meta.sizeBytes > XLSX_OLE_OVERSIZE_THRESHOLD,
    );
  }
}

// Encrypted
{
  const f = scanXlsxOleScope(makeEncryptedBlob(), {
    memberName: 'xl/embeddings/oleObject1.bin',
  });
  const hit = f.find((x) => x.technique === 'xlsx-ole-encrypted');
  check('xlsx-ole-encrypted: finding present', !!hit);
  if (hit) {
    check('xlsx-ole-encrypted: severity warning', hit.severity === 'warning');
    check(
      'xlsx-ole-encrypted: category hiddenHtml',
      hit.category === 'hiddenHtml',
    );
    check(
      'xlsx-ole-encrypted: meta.streamName',
      hit.meta && hit.meta.streamName === 'EncryptedPackage',
    );
  }
  check(
    'xlsx-ole-encrypted: no macro-bearing finding',
    !f.find((x) => x.technique === 'xlsx-ole-macro-bearing'),
  );
}

// Macro-bearing
{
  const f = scanXlsxOleScope(makeMacroBearingBlob(), {
    memberName: 'xl/embeddings/oleObject1.bin',
  });
  const hit = f.find((x) => x.technique === 'xlsx-ole-macro-bearing');
  check('xlsx-ole-macro-bearing: finding present', !!hit);
  if (hit) {
    check('xlsx-ole-macro-bearing: severity danger', hit.severity === 'danger');
    check(
      'xlsx-ole-macro-bearing: category suspiciousPatterns',
      hit.category === 'suspiciousPatterns',
    );
    check(
      'xlsx-ole-macro-bearing: meta.streamName',
      hit.meta && hit.meta.streamName === '_VBA_PROJECT',
    );
    check(
      'xlsx-ole-macro-bearing: meta.hasVbaProject true',
      hit.meta && hit.meta.hasVbaProject === true,
    );
  }
  check(
    'xlsx-ole-macro-bearing: no encrypted finding',
    !f.find((x) => x.technique === 'xlsx-ole-encrypted'),
  );
}

// Benign / null shapes
check(
  'benign CFB blob produces zero findings',
  scanXlsxOleScope(concatBuffers([CFB_MAGIC, new Uint8Array(512)])).length === 0,
);
check('null input returns []', scanXlsxOleScope(null).length === 0);
check('undefined input returns []', scanXlsxOleScope(undefined).length === 0);
check(
  'non-CFB header returns []',
  scanXlsxOleScope(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0])).length === 0,
);

// Oversize short-circuit
{
  const f = scanXlsxOleScope(makeOversizeBlob());
  check(
    'oversize short-circuits before stream-name scan',
    f.length === 1 && f[0].technique === 'xlsx-ole-oversize',
  );
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('\nFAILURES:');
  for (const f of failures) console.log(`  - ${f.name}` + (f.detail ? `\n    ${f.detail}` : ''));
  process.exit(1);
}
