// =============================================================
//  Shield Scanner Web — v1.20.0 T6 PDF /EmbeddedFile /Subtype raw helper
// =============================================================
// Pins the Web mirror of the MCP regression `pdf-embedded-html-revival.test.js`.
// The Web stub at packages/web/src/parsers-web/pdf-attachment-subtype.js is
// kept in lock-step with the MCP helper at
// packages/mcp/server/parsers/pdf-attachment-subtype.js. This standalone
// harness verifies that the Web build's exports behave identically for the
// load-bearing cases:
//
//   - real on-disk fixture (hex-encoded /text#2Fhtml decodes to text/html)
//   - benign /text#2Fplain stays text/plain (NOT html)
//   - absent /EmbeddedFile → empty list
//   - boundary check — /SubtypeQuirk does not spoof a hit
//   - lookahead does not leak past endobj
//
// R23: this test does NOT touch the production parsers-web/pdf.js. The
// helper is unwired in v1.20.0 (deferred wire-in), so dist bytes are
// unchanged.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(
  __dirname,
  '..',
  '..',
  'mcp',
  'test',
  'fixtures',
  'attacks',
  'pdf_embedded_html_subtype.pdf',
);

const mod = await import('../src/parsers-web/pdf-attachment-subtype.js');
const { extractEmbeddedFileSubtypes, hasEmbeddedHtmlSubtype } = mod;

let failures = 0;
function check(name, cond, detail) {
  if (cond) {
    console.log(`OK   ${name}`);
  } else {
    failures++;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

// 1) real on-disk fixture
{
  const buf = readFileSync(FIXTURE);
  const subs = extractEmbeddedFileSubtypes(buf);
  check(
    'real fixture: exactly one subtype hit',
    subs.length === 1,
    `got ${subs.length}`,
  );
  check(
    'real fixture: subtype === "text/html"',
    subs[0] && subs[0].subtype === 'text/html',
    `got ${JSON.stringify(subs[0])}`,
  );
  check(
    'real fixture: hasEmbeddedHtmlSubtype === true',
    hasEmbeddedHtmlSubtype(buf) === true,
  );
}

// helper: build a latin1 Buffer (Web env uses Uint8Array under the hood,
// Buffer is a Uint8Array subclass so the helper accepts both).
function synthBuf(s) {
  return Buffer.from(s, 'latin1');
}

// 2) benign /text#2Fplain
{
  const buf = synthBuf(
    '1 0 obj\n<< /Type /EmbeddedFile /Subtype /text#2Fplain >>\nendobj\n',
  );
  const subs = extractEmbeddedFileSubtypes(buf);
  check(
    'benign plain: returns text/plain, not html',
    subs.length === 1 && subs[0].subtype === 'text/plain',
    JSON.stringify(subs),
  );
  check(
    'benign plain: hasEmbeddedHtmlSubtype === false',
    hasEmbeddedHtmlSubtype(buf) === false,
  );
}

// 3) absent /EmbeddedFile
{
  const buf = synthBuf('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n');
  check(
    'no embedded file: empty list',
    extractEmbeddedFileSubtypes(buf).length === 0,
  );
  check(
    'no embedded file: hasEmbeddedHtmlSubtype false',
    hasEmbeddedHtmlSubtype(buf) === false,
  );
}

// 4) boundary check: /SubtypeQuirk must NOT spoof a hit
{
  const buf = synthBuf(
    '1 0 obj\n<< /Type /EmbeddedFile /SubtypeQuirk /text#2Fhtml >>\nendobj\n',
  );
  const subs = extractEmbeddedFileSubtypes(buf);
  check(
    'boundary: /SubtypeQuirk does not spoof a hit',
    subs.length === 0,
    JSON.stringify(subs),
  );
}

// 5) lookahead stops at endobj — sibling /Subtype does not leak
{
  const buf = synthBuf(
    '1 0 obj\n<< /Type /EmbeddedFile /Length 0 >>\nstream\n\nendstream\nendobj\n' +
      '2 0 obj\n<< /Type /Annot /Subtype /text#2Fhtml >>\nendobj\n',
  );
  const subs = extractEmbeddedFileSubtypes(buf);
  check(
    'lookahead: sibling /Subtype does not leak past endobj',
    subs.length === 0,
    JSON.stringify(subs),
  );
}

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log('\nAll v1.20.0 T6 Web helper checks passed.');
