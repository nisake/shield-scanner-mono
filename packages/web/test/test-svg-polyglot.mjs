// =============================================================
//  Shield Scanner Web — v1.19.0 B1 Polyglot-SVG harness
// =============================================================
// Drives packages/web/src/parsers-web/svg.js (+ html.js wrapper) against the
// shared mcp/test/fixtures/{attacks,benign}/svg_*.svg corpus. Mirrors the
// MCP svg-polyglot regression file — same 6 kebab ids, same R12/R13
// invariants — so the parity-check.mjs SVG_FIXTURES section can pin
// MCP↔Web drift = 0.
//
// R12 / R13 invariants:
//   - kebab technique ids are fixed literals; dynamic scalars ride
//     meta.{attribute,href} only.
//   - hiddenFindings carry category === 'suspiciousPatterns' so the
//     app.js extras-splice path (DOCX/PPTX media recurse) folds them into
//     the 5-bucket schema.
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { loadSvgFixtureSync } from '../../../tools/svg-fixture-loader.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { parseSvg, detectSvgInjection } = await import('../src/parsers-web/svg.js');
const { parseHtml } = await import('../src/parsers-web/html.js');
const { dispatchBuffer, recognizeMime, recognizeExt } = await import(
  '../src/parsers-web/index.js'
);

const ATTACKS_DIR = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'attacks');
const BENIGN_DIR = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'benign');

const tests = [];
const skipped = [];
function add(name, fn) { tests.push({ name, fn }); }
function skip(name, reason) { skipped.push({ name, reason }); }

// v1.20.0 T7-SVG-B64: attack fixtures live as ".svg.b64" so Claude Desktop's
// file preview cannot inline-render them (the live <script>/onload= payloads
// would otherwise execute). Benign fixtures (no script surface) stay as .svg.
// The loader transparently decodes .b64 and falls through for .svg, so
// readFixture's signature is unchanged for callers.
function readFixture(dir, file) {
  // Prefer .svg.b64 sibling in the attacks dir; fall back to plain .svg for
  // benign fixtures and any not-yet-migrated entry.
  if (dir === ATTACKS_DIR) {
    const b64 = join(dir, `${file}.b64`);
    if (existsSync(b64)) {
      return new Uint8Array(loadSvgFixtureSync(b64));
    }
  }
  const p = join(dir, file);
  if (!existsSync(p)) return null;
  return new Uint8Array(readFileSync(p));
}

function findingsByTech(out, tech) {
  return (out.hiddenFindings || []).filter((f) => f.technique === tech);
}

// --- 01: script-tag attack -------------------------------------------------
add('01 SVG polyglot: svg_script_tag.svg emits svg-script-element (danger)', async () => {
  const buf = readFixture(ATTACKS_DIR, 'svg_script_tag.svg');
  if (!buf) { skip('01', 'fixture missing'); return; }
  const out = await parseSvg(buf);
  if (out.fileType !== 'html') throw new Error(`fileType=${out.fileType}`);
  const hits = findingsByTech(out, 'svg-script-element');
  if (hits.length < 1) throw new Error('no svg-script-element finding');
  if (hits[0].severity !== 'danger') throw new Error(`severity=${hits[0].severity}`);
  if (hits[0].category !== 'suspiciousPatterns') {
    throw new Error(`category=${hits[0].category}`);
  }
});

// --- 02: event-handler attack ---------------------------------------------
add('02 SVG polyglot: svg_onerror_handler.svg surfaces svg-event-handler with meta.attribute', async () => {
  const buf = readFixture(ATTACKS_DIR, 'svg_onerror_handler.svg');
  if (!buf) { skip('02', 'fixture missing'); return; }
  const out = await parseSvg(buf);
  const hits = findingsByTech(out, 'svg-event-handler');
  if (hits.length < 2) throw new Error(`expected >=2 handlers, got ${hits.length}`);
  const attrs = new Set(hits.map((h) => h.meta && h.meta.attribute));
  if (!attrs.has('onload')) throw new Error(`onload not detected; got ${[...attrs].join(',')}`);
  if (!(attrs.has('onerror') || attrs.has('onclick'))) {
    throw new Error(`onerror/onclick not detected; got ${[...attrs].join(',')}`);
  }
  for (const h of hits) {
    if (h.severity !== 'danger') throw new Error(`severity=${h.severity}`);
    if (typeof h.meta.attribute !== 'string') throw new Error('meta.attribute missing');
  }
});

// --- 03: javascript: href attack ------------------------------------------
add('03 SVG polyglot: svg_javascript_href.svg surfaces svg-javascript-href', async () => {
  const buf = readFixture(ATTACKS_DIR, 'svg_javascript_href.svg');
  if (!buf) { skip('03', 'fixture missing'); return; }
  const out = await parseSvg(buf);
  const hits = findingsByTech(out, 'svg-javascript-href');
  if (hits.length < 2) throw new Error(`expected >=2 js-href, got ${hits.length}`);
  for (const h of hits) {
    if (h.severity !== 'danger') throw new Error(`severity=${h.severity}`);
  }
});

// --- 04: foreignObject attack ---------------------------------------------
add('04 SVG polyglot: svg_foreignobject_prompt.svg surfaces svg-foreignobject-html', async () => {
  const buf = readFixture(ATTACKS_DIR, 'svg_foreignobject_prompt.svg');
  if (!buf) { skip('04', 'fixture missing'); return; }
  const out = await parseSvg(buf);
  const hits = findingsByTech(out, 'svg-foreignobject-html');
  if (hits.length < 1) throw new Error('no svg-foreignobject-html finding');
  if (hits[0].severity !== 'warning') throw new Error(`severity=${hits[0].severity}`);
});

// --- 05: CDATA attack ------------------------------------------------------
add('05 SVG polyglot: svg_cdata_instruction.svg surfaces svg-cdata-section', async () => {
  const buf = readFixture(ATTACKS_DIR, 'svg_cdata_instruction.svg');
  if (!buf) { skip('05', 'fixture missing'); return; }
  const out = await parseSvg(buf);
  const hits = findingsByTech(out, 'svg-cdata-section');
  if (hits.length < 2) throw new Error(`expected >=2 CDATA, got ${hits.length}`);
  for (const h of hits) {
    if (h.severity !== 'warning') throw new Error(`severity=${h.severity}`);
  }
});

// --- 06: external use attack ----------------------------------------------
add('06 SVG polyglot: svg_use_external_ref.svg surfaces svg-use-external-ref; #local stays silent', async () => {
  const buf = readFixture(ATTACKS_DIR, 'svg_use_external_ref.svg');
  if (!buf) { skip('06', 'fixture missing'); return; }
  const out = await parseSvg(buf);
  const hits = findingsByTech(out, 'svg-use-external-ref');
  if (hits.length !== 2) throw new Error(`expected exactly 2 external use, got ${hits.length}`);
  for (const h of hits) {
    if (h.severity !== 'warning') throw new Error(`severity=${h.severity}`);
    if (!h.meta || typeof h.meta.href !== 'string') throw new Error('meta.href missing');
    if (h.meta.href.startsWith('#')) throw new Error('local fragment leaked into findings');
  }
});

// --- 07: benign logo - no SVG-polyglot findings ---------------------------
add('07 SVG polyglot: benign_svg_logo.svg emits no svg-* findings', async () => {
  const buf = readFixture(BENIGN_DIR, 'benign_svg_logo.svg');
  if (!buf) { skip('07', 'fixture missing'); return; }
  const out = await parseSvg(buf);
  const svgHits = (out.hiddenFindings || []).filter((f) =>
    String(f.technique || '').startsWith('svg-'),
  );
  if (svgHits.length > 0) {
    throw new Error(`benign logo emitted svg-* findings: ${JSON.stringify(svgHits)}`);
  }
});

// --- 08: benign inline-style - local <use> + https <a href> silent --------
add('08 SVG polyglot: benign_svg_inline_style.svg local use + https a href stay silent', async () => {
  const buf = readFixture(BENIGN_DIR, 'benign_svg_inline_style.svg');
  if (!buf) { skip('08', 'fixture missing'); return; }
  const out = await parseSvg(buf);
  const svgHits = (out.hiddenFindings || []).filter((f) =>
    String(f.technique || '').startsWith('svg-'),
  );
  if (svgHits.length > 0) {
    throw new Error(`benign inline-style emitted svg-* findings: ${JSON.stringify(svgHits)}`);
  }
});

// --- 09: html.js inline-SVG wrapper ---------------------------------------
add('09 SVG polyglot: parseHtml wrapper surfaces svg-event-handler from inline <svg onload>', async () => {
  const html = `<!doctype html><body><svg xmlns="http://www.w3.org/2000/svg" onload="evil()"></svg></body>`;
  const out = await parseHtml(html);
  const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'svg-event-handler');
  if (hits.length !== 1) throw new Error(`expected exactly 1 inline onload, got ${hits.length}`);
  if (hits[0].meta.attribute !== 'onload') throw new Error(`attr=${hits[0].meta.attribute}`);
});

// --- 10: parsers-web/index.js dispatch helper -----------------------------
add('10 SVG polyglot: dispatchBuffer routes image/svg+xml MIME + .svg ext to parseSvg', async () => {
  const buf = readFixture(ATTACKS_DIR, 'svg_script_tag.svg');
  if (!buf) { skip('10', 'fixture missing'); return; }
  if (recognizeMime('image/svg+xml') !== 'svg') {
    throw new Error('recognizeMime(image/svg+xml) failed');
  }
  if (recognizeExt('foo.SVG') !== 'svg') {
    throw new Error('recognizeExt is not case-insensitive');
  }
  const byMime = await dispatchBuffer(buf, { mime: 'image/svg+xml' });
  if (!byMime || byMime.fileType !== 'html') {
    throw new Error(`dispatch by mime failed: ${JSON.stringify(byMime)}`);
  }
  if (!byMime.hiddenFindings.some((f) => f.technique === 'svg-script-element')) {
    throw new Error('dispatch by mime missed svg-script-element');
  }
  const byExt = await dispatchBuffer(buf, { ext: 'svg' });
  if (!byExt || byExt.fileType !== 'html') {
    throw new Error('dispatch by ext failed');
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
