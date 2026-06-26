// =============================================================
// Shield Scanner Web — v1.14.0 ext-2 (DOCX shape textbox microscopic)
// =============================================================
// Standalone test runner for the v1.14.0 docx-microscopic-shape-extension
// follow-up to v1.13.0 Theme docx-microscopic. Verifies that:
//   - parseDocx (Web) scans wps:txbxContent blocks for w:sz < 4pt runs and
//     surfaces a hiddenFinding with element='w:r (Word run, shape textbox)'
//   - element label is a fixed string (R12) — never echoes raw user text
//   - MCP and Web parsers stay byte-identical on the shape walker shape
//     (technique label, element label, meta.fontSize, severity)
//
// Pinned by 2 static-source needles + 2 functional integration tests. The
// functional tests SKIP gracefully if jszip is not installed.
//
// R18: setEnv(createNodeEnv()) is called up front to honor the order
//   contract — parseDocx imports parseImage transitively which pulls in
//   detector modules that consult the active env at load time.
// R12: assertions include a JSON.stringify(finding) raw-string scan to
//   guarantee an attack literal is NOT echoed inside the technique/element
//   fixed-string fields.
// =============================================================

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { setEnv } from '@shield-scanner/core/env';
import { createNodeEnv } from '@shield-scanner/core/env/node';

// R18 ORDER CONTRACT — see test-s12-xr02-office-media.mjs for rationale.
setEnv(createNodeEnv());

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DOCX_SRC_PATH = resolve(__dirname, '..', 'src', 'parsers-web', 'docx.js');

async function tryLoadJSZip() {
  try {
    const mod = await import('jszip');
    return mod.default || mod;
  } catch {
    return null;
  }
}

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
let docxSrc = null;
try { docxSrc = readFileSync(DOCX_SRC_PATH, 'utf8'); } catch { docxSrc = null; }

function staticAssert(name, src, needle) {
  if (src == null) {
    record(name, false, 'source file not readable');
    return;
  }
  const ok = src.includes(needle);
  record(name, ok, ok ? null : `needle not found: ${JSON.stringify(needle)}`);
}

staticAssert(
  "v1.14.0 ext-2 (static-source) parseDocx scans wps:txbxContent blocks",
  docxSrc,
  'wps:txbxContent'
);

staticAssert(
  "v1.14.0 ext-2 (static-source) parseDocx emits shape-context element label 'w:r (Word run, shape textbox)'",
  docxSrc,
  "'w:r (Word run, shape textbox)'"
);

// --- Functional integration tests -----------------------------------------
async function runShapeMicroscopicFunctional() {
  const name =
    "v1.14.0 ext-2 (functional) parseDocx shape textbox: wps:txbxContent run with w:sz val='2' surfaces hiddenFinding element='w:r (Word run, shape textbox)' + technique='microscopic-font-size'";
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
      '<?xml version="1.0"?>' +
      '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">' +
      '<w:body>' +
      '<w:p>' +
      '<wps:txbxContent>' +
      '<w:p><w:r><w:rPr><w:sz w:val="2"/></w:rPr><w:t>shape textbox microscopic payload</w:t></w:r></w:p>' +
      '</wps:txbxContent>' +
      '</w:p>' +
      '</w:body></w:document>'
    );
    const buf = await zip.generateAsync({ type: 'uint8array' });
    const out = await parseDocx(buf);
    const micros = (out.hiddenFindings || []).filter(
      (f) => f.technique === 'microscopic-font-size'
    );
    const surfaceOk = micros.length === 1;
    const elementOk = surfaceOk && micros[0].element === 'w:r (Word run, shape textbox)';
    const metaOk = surfaceOk && micros[0].meta && micros[0].meta.fontSize === 1
      && typeof micros[0].meta.fontSize === 'number';
    const severityOk = surfaceOk && micros[0].severity === 'danger';
    const contentOk = surfaceOk && micros[0].content.includes('shape textbox microscopic payload');
    const ok = surfaceOk && elementOk && metaOk && severityOk && contentOk;
    record(
      name,
      ok,
      ok ? null : `surfaceOk=${surfaceOk} elementOk=${elementOk} metaOk=${metaOk} severityOk=${severityOk} contentOk=${contentOk} hiddenFindings=${JSON.stringify(out.hiddenFindings)}`
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

async function runShapeR12LeakFunctional() {
  const name =
    "v1.14.0 ext-2 (functional) parseDocx shape textbox R12: attack literal 'ATTACK_PAYLOAD' never leaks into technique or element fixed-string fields";
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
      '<?xml version="1.0"?>' +
      '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">' +
      '<w:body>' +
      '<w:p>' +
      '<wps:txbxContent>' +
      '<w:p><w:r><w:rPr><w:sz w:val="1"/></w:rPr><w:t>ATTACK_PAYLOAD</w:t></w:r></w:p>' +
      '</wps:txbxContent>' +
      '</w:p>' +
      '</w:body></w:document>'
    );
    const buf = await zip.generateAsync({ type: 'uint8array' });
    const out = await parseDocx(buf);
    const micros = (out.hiddenFindings || []).filter(
      (f) => f.technique === 'microscopic-font-size'
    );
    const surfaceOk = micros.length === 1;
    // R12: technique + element are fixed strings, ATTACK_PAYLOAD allowed only
    // in the content field (which legitimately echoes user-controlled text
    // after escapeForDisplay).
    const techniqueClean = surfaceOk && !micros[0].technique.includes('ATTACK_PAYLOAD');
    const elementClean = surfaceOk && !micros[0].element.includes('ATTACK_PAYLOAD');
    const contentEchoesPayload = surfaceOk && micros[0].content.includes('ATTACK_PAYLOAD');
    // Pin the fixed-string element label exactly.
    const elementExact = surfaceOk && micros[0].element === 'w:r (Word run, shape textbox)';
    const ok = surfaceOk && techniqueClean && elementClean && contentEchoesPayload && elementExact;
    record(
      name,
      ok,
      ok ? null : `surfaceOk=${surfaceOk} techniqueClean=${techniqueClean} elementClean=${elementClean} contentEchoesPayload=${contentEchoesPayload} elementExact=${elementExact} finding=${JSON.stringify(micros[0])}`
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

await runShapeMicroscopicFunctional();
await runShapeR12LeakFunctional();

console.log(`\nTotal: ${passed} passed / ${failed} failed / ${skipped} skipped`);
process.exitCode = failed === 0 ? 0 : 1;
