// =============================================================
// Shield Scanner Web — S12-XR-02 (Office media: DOCX/PPTX embedded images)
// =============================================================
// Standalone test runner for the S12-XR-02 follow-up. Verifies that:
//   - parseDocx scans `word/media/*` entries with the correct single-segment
//     regex and the 5 MB / 50-count zip-bomb caps, prefix-joining the
//     contextLocation as `DOCX media:<name> > <inner>`
//   - parsePptx mirrors the above for `ppt/media/*` / `PPTX media:<name>`
//   - end-to-end: a synthesized DOCX / PPTX with a COM-injected JPEG under
//     the media folder surfaces a hiddenFinding whose contextLocation starts
//     with the wrapper prefix
//
// Pinned by 6 static-source needles + 2 optional functional integration
// tests. The functional tests SKIP gracefully if `jszip` is not installed
// (root node_modules has it transitively but workspace install drift is
// possible).
//
// R18: setEnv(createWebEnv()) is called up front even though the tests
//   themselves don't invoke analyze() — this keeps the order contract
//   honest in case parser imports later grow an env dependency.
// R12: assertions include a JSON.stringify(finding) raw-string scan to
//   guarantee the attack literal 'INJECTION' is NOT echoed back inside any
//   finding produced by parseDocx / parsePptx for the synthesized JPEG.
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { setEnv } from '@shield-scanner/core/env';
import { createNodeEnv } from '@shield-scanner/core/env/node';

// R18 ORDER CONTRACT: setEnv(...) MUST run before any detector module is
// imported transitively. parseImage (called from parseDocx/parsePptx for
// each `*/media/*` entry) pulls in invisible-unicode.js, which calls
// loadRule('invisible-chars.json') at module-load time via the active env.
//
// Spec asks for createWebEnv() — but createDomHtmlParser() throws on Node
// because DOMParser is undefined here. createNodeEnv() (rules-loader +
// cheerio) is the existing test-harness adapter used by sibling tests
// (test-s16-reveal / test-s21-bulk-scan) — it provides the same
// rulesLoader contract that detector modules need, without requiring
// jsdom. The Web build itself still ships createWebEnv() at build time;
// this swap is harness-only.
setEnv(createNodeEnv());

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DOCX_SRC_PATH = resolve(__dirname, '..', 'src', 'parsers-web', 'docx.js');
const PPTX_SRC_PATH = resolve(__dirname, '..', 'src', 'parsers-web', 'pptx.js');
// Shared canonical fixture (also referenced by test-s12-image.mjs). The
// loader gracefully falls back to a synthesized JPEG when the fixture is
// absent, so missing-file does not fail the harness.
const ARCHIVE_JPEG_FIXTURE = resolve(
  __dirname,
  '..',
  '..',
  'mcp',
  'test',
  'fixtures',
  'image-attacks',
  '01-jpeg-com-injection.jpg'
);

// --- Synthetic JPEG fallback: SOI + COM('INJECTION') + EOI. parseImage's
// COM-segment scanner only needs FFD8 / FFFE LL LL <payload> / FFD9 to
// surface a hiddenFinding for the embedded literal.
function buildSyntheticInjectionJpeg() {
  const payload = Buffer.from('INJECTION', 'ascii');
  // length field counts the length bytes themselves but NOT the marker
  const len = payload.length + 2; // 2 bytes for the length field
  const out = Buffer.alloc(2 + 2 + 2 + payload.length + 2);
  let i = 0;
  out[i++] = 0xff; out[i++] = 0xd8;          // SOI
  out[i++] = 0xff; out[i++] = 0xfe;          // COM marker
  out[i++] = (len >> 8) & 0xff; out[i++] = len & 0xff;
  payload.copy(out, i); i += payload.length;
  out[i++] = 0xff; out[i++] = 0xd9;          // EOI
  return new Uint8Array(out);
}

function loadInjectionJpegBytes() {
  if (existsSync(ARCHIVE_JPEG_FIXTURE)) {
    try {
      const buf = readFileSync(ARCHIVE_JPEG_FIXTURE);
      return new Uint8Array(buf);
    } catch {
      // fall through to synthetic
    }
  }
  return buildSyntheticInjectionJpeg();
}

// --- Lazy JSZip + dynamic parser imports. Returns null on failure so the
// functional tests can SKIP cleanly without poisoning the runner.
async function tryLoadJSZip() {
  try {
    const mod = await import('jszip');
    return mod.default || mod;
  } catch {
    return null;
  }
}

// --- Test result accumulator ----------------------------------------------
let passed = 0;
let failed = 0;
let skipped = 0;
const failures = [];

function record(name, ok, err) {
  if (ok === 'skip') {
    skipped++;
    console.log(`SKIP ${name}${err ? ` (${err})` : ''}`);
    return;
  }
  if (ok) {
    passed++;
    console.log(`PASS ${name}`);
  } else {
    failed++;
    console.log(`FAIL ${name}`);
    if (err) {
      console.log(`     ${err}`);
      failures.push({ name, err: String(err) });
    }
  }
}

// --- Static-source tests --------------------------------------------------
// All six read source files as plain text; no parser execution, no env use.
let docxSrc = null;
let pptxSrc = null;
try { docxSrc = readFileSync(DOCX_SRC_PATH, 'utf8'); } catch (e) { docxSrc = null; }
try { pptxSrc = readFileSync(PPTX_SRC_PATH, 'utf8'); } catch (e) { pptxSrc = null; }

function staticAssert(name, src, needle) {
  if (src == null) {
    record(name, false, `source file not readable`);
    return;
  }
  const ok = src.includes(needle);
  record(name, ok, ok ? null : `needle not found: ${JSON.stringify(needle)}`);
}

staticAssert(
  "S12-XR-02 (static-source) parseDocx scans word/media/* entries (needle: /^word\\/media\\/[^/]+$/)",
  docxSrc,
  '/^word\\/media\\/[^/]+$/'
);

staticAssert(
  'S12-XR-02 (static-source) parseDocx uses 5MB per-image cap (needle: _OFFICE_MEDIA_MAX_BYTES = 5 * 1024 * 1024)',
  docxSrc,
  '_OFFICE_MEDIA_MAX_BYTES = 5 * 1024 * 1024'
);

staticAssert(
  'S12-XR-02 (static-source) parseDocx uses 50-media count cap (needle: _OFFICE_MEDIA_MAX_COUNT = 50)',
  docxSrc,
  '_OFFICE_MEDIA_MAX_COUNT = 50'
);

staticAssert(
  "S12-XR-02 (static-source) parseDocx prefix-joins contextLocation as 'DOCX media:<name> > <existing>'",
  docxSrc,
  '`DOCX media:${mediaName} > ${existing}`'
);

staticAssert(
  "S12-XR-02 (static-source) parsePptx scans ppt/media/* entries (needle: /^ppt\\/media\\/[^/]+$/)",
  pptxSrc,
  '/^ppt\\/media\\/[^/]+$/'
);

staticAssert(
  "S12-XR-02 (static-source) parsePptx prefix-joins contextLocation as 'PPTX media:<name> > <existing>'",
  pptxSrc,
  '`PPTX media:${mediaName} > ${existing}`'
);

// --- v1.13.0 Theme docx-microscopic static-source needles ----------------
// Pin the kebab-case technique id in the Web parser and guard against a
// revert to the legacy format-string label (R12 invariant).
staticAssert(
  "v1.13.0 (static-source) parseDocx emits kebab technique 'microscopic-font-size'",
  docxSrc,
  "technique: 'microscopic-font-size'"
);

function staticAssertAbsent(name, src, needle) {
  if (src == null) {
    record(name, false, 'source file not readable');
    return;
  }
  const ok = !src.includes(needle);
  record(name, ok, ok ? null : `legacy needle present: ${JSON.stringify(needle)}`);
}

staticAssertAbsent(
  "v1.13.0 (static-source) parseDocx no longer emits legacy format-string 'Microscopic font size (${'",
  docxSrc,
  'Microscopic font size (${'
);

// --- Functional integration tests -----------------------------------------
// These exercise the actual parsers via JSZip-built synthetic archives. If
// JSZip isn't available we SKIP both with a PASS-noop log (devDependency
// install is a separate phase). mock cleanup is done in finally blocks so
// global state never leaks between tests.

async function runDocxFunctional() {
  const name =
    "S12-XR-02 (functional) parseDocx integration: synthesized docx with word/media/inject.jpg containing COM-segment 'INJECTION' surfaces hiddenFinding with contextLocation starting 'DOCX media:inject.jpg'";
  const JSZip = await tryLoadJSZip();
  if (!JSZip) {
    record(name, 'skip', 'jszip not installed');
    return { skipped: true };
  }
  const hadGlobal = 'JSZip' in globalThis;
  const prevGlobal = globalThis.JSZip;
  globalThis.JSZip = JSZip;
  try {
    const { parseDocx } = await import('../src/parsers-web/docx.js');
    const jpegBytes = loadInjectionJpegBytes();
    const zip = new JSZip();
    zip.file(
      'word/document.xml',
      '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>hi</w:t></w:r></w:p></w:body></w:document>'
    );
    zip.file('word/media/inject.jpg', jpegBytes);
    const buf = await zip.generateAsync({ type: 'uint8array' });
    const out = await parseDocx(buf);
    const ctxOk = Array.isArray(out.hiddenFindings) && out.hiddenFindings.some(
      (f) => typeof f.contextLocation === 'string' && f.contextLocation.startsWith('DOCX media:inject.jpg')
    );
    const textOk = typeof out.text === 'string' && out.text.includes('[DOCX media:inject.jpg]');
    // R12: ensure no raw attack literal leaks into the finding payload.
    // contextLocation legitimately echoes the media filename ('inject.jpg')
    // but must NOT contain 'INJECTION' (the embedded COM payload).
    const r12Ok = (out.hiddenFindings || []).every((f) => !JSON.stringify(f).includes('INJECTION'));
    const ok = ctxOk && textOk && r12Ok;
    record(
      name,
      ok,
      ok ? null : `ctxOk=${ctxOk} textOk=${textOk} r12Ok=${r12Ok} hiddenFindings=${JSON.stringify((out.hiddenFindings || []).map(f => f.contextLocation))}`
    );
    return {};
  } catch (e) {
    record(name, false, e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : String(e));
    return {};
  } finally {
    if (hadGlobal) globalThis.JSZip = prevGlobal;
    else delete globalThis.JSZip;
  }
}

async function runPptxFunctional() {
  const name =
    "S12-XR-02 (functional) parsePptx integration: synthesized pptx with ppt/media/inject.jpg surfaces 'PPTX media:inject.jpg' prefix";
  const JSZip = await tryLoadJSZip();
  if (!JSZip) {
    record(name, 'skip', 'jszip not installed');
    return { skipped: true };
  }
  const hadGlobal = 'JSZip' in globalThis;
  const prevGlobal = globalThis.JSZip;
  globalThis.JSZip = JSZip;
  try {
    const { parsePptx } = await import('../src/parsers-web/pptx.js');
    const jpegBytes = loadInjectionJpegBytes();
    const zip = new JSZip();
    zip.file(
      'ppt/slides/slide1.xml',
      '<?xml version="1.0"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>hi</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>'
    );
    zip.file('ppt/media/inject.jpg', jpegBytes);
    const buf = await zip.generateAsync({ type: 'uint8array' });
    const out = await parsePptx(buf);
    const ctxOk = Array.isArray(out.hiddenFindings) && out.hiddenFindings.some(
      (f) => typeof f.contextLocation === 'string' && f.contextLocation.startsWith('PPTX media:inject.jpg')
    );
    const textOk = typeof out.text === 'string' && out.text.includes('[PPTX media:inject.jpg]');
    const r12Ok = (out.hiddenFindings || []).every((f) => !JSON.stringify(f).includes('INJECTION'));
    const ok = ctxOk && textOk && r12Ok;
    record(
      name,
      ok,
      ok ? null : `ctxOk=${ctxOk} textOk=${textOk} r12Ok=${r12Ok} hiddenFindings=${JSON.stringify((out.hiddenFindings || []).map(f => f.contextLocation))}`
    );
    return {};
  } catch (e) {
    record(name, false, e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : String(e));
    return {};
  } finally {
    if (hadGlobal) globalThis.JSZip = prevGlobal;
    else delete globalThis.JSZip;
  }
}

// --- v1.13.0 Theme docx-microscopic functional integration ----------------
// Synthesize a DOCX with a w:sz val="2" (1pt) run and assert the Web
// parseDocx surfaces a hiddenFinding with the kebab technique id +
// numeric meta.fontSize. Mirrors the MCP regression in
// packages/mcp/test/regression/docx-microscopic.test.js, exercising the
// Web parser to guard parser-mirror drift.
async function runDocxMicroscopicFunctional() {
  const name =
    "v1.13.0 (functional) parseDocx microscopic-font-size: w:sz val='2' surfaces hiddenFinding with technique='microscopic-font-size' + meta.fontSize===1";
  const JSZip = await tryLoadJSZip();
  if (!JSZip) {
    record(name, 'skip', 'jszip not installed');
    return { skipped: true };
  }
  const hadGlobal = 'JSZip' in globalThis;
  const prevGlobal = globalThis.JSZip;
  globalThis.JSZip = JSZip;
  try {
    const { parseDocx } = await import('../src/parsers-web/docx.js');
    const zip = new JSZip();
    zip.file(
      'word/document.xml',
      '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' +
      '<w:p><w:r><w:rPr><w:sz w:val="2"/></w:rPr><w:t>hidden one point payload</w:t></w:r></w:p>' +
      '</w:body></w:document>'
    );
    const buf = await zip.generateAsync({ type: 'uint8array' });
    const out = await parseDocx(buf);
    const micros = (out.hiddenFindings || []).filter(
      (f) => f.technique === 'microscopic-font-size'
    );
    const surfaceOk = micros.length === 1;
    const metaOk = surfaceOk && micros[0].meta && micros[0].meta.fontSize === 1
      && typeof micros[0].meta.fontSize === 'number';
    const severityOk = surfaceOk && micros[0].severity === 'danger';
    // R12 functional pin: no legacy format-string label leaks through.
    const r12Ok = (out.hiddenFindings || []).every(
      (f) => typeof f.technique !== 'string' ||
             !/^Microscopic font size \(/.test(f.technique)
    );
    const ok = surfaceOk && metaOk && severityOk && r12Ok;
    record(
      name,
      ok,
      ok ? null : `surfaceOk=${surfaceOk} metaOk=${metaOk} severityOk=${severityOk} r12Ok=${r12Ok} hiddenFindings=${JSON.stringify(out.hiddenFindings)}`
    );
    return {};
  } catch (e) {
    record(name, false, e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : String(e));
    return {};
  } finally {
    if (hadGlobal) globalThis.JSZip = prevGlobal;
    else delete globalThis.JSZip;
  }
}

await runDocxFunctional();
await runPptxFunctional();
await runDocxMicroscopicFunctional();

console.log(`\nTotal: ${passed} passed / ${failed} failed / ${skipped} skipped`);
process.exitCode = failed === 0 ? 0 : 1;
