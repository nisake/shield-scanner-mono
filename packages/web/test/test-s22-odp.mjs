// =============================================================
//  Shield Scanner Web — v1.20.0 T3-ODP OpenDocument Presentation harness
// =============================================================
// Drives packages/web/src/parsers-web/odp.js end-to-end against the same
// .odp fixtures the MCP regression suite uses.
//
// Coverage:
//   - 3 odp attack fixtures — assert the Web parser surfaces the same kebab
//     id each fixture targets:
//       odp_notes_prompt_injection.odp        → odp-notes-prompt-injection
//       odp_slide_transition_macro.odp        → odp-slide-transition-macro
//       odp_embedded_object_external.odp      → odp-embedded-object-external
//   - 1 benign fixture — must NOT emit any of the 4 odp kebab ids.
//
// R12 / R13: invariants matched against MCP — categories fold into
// suspiciousPatterns; meta carries detector-controlled scalars only.
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// JSZip is normally a CDN global on Web. For Node harness, pull it from
// node_modules and stash on globalThis before importing the parser.
const { createRequire } = await import('node:module');
const require = createRequire(import.meta.url);
const JSZip = require('jszip');
globalThis.JSZip = JSZip;

const { parseOdp } = await import('../src/parsers-web/odp.js');

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

// --- Attack 1: notes prompt injection ---
add('ODP-01 attack: odp_notes_prompt_injection emits odp-notes-prompt-injection', async () => {
  const buf = readFixture(ATTACKS_DIR, 'odp_notes_prompt_injection.odp');
  if (!buf) throw new Error('fixture missing');
  const out = await parseOdp(buf);
  const techs = techniques(out);
  if (!techs.includes('odp-notes-prompt-injection')) {
    throw new Error(`missing odp-notes-prompt-injection. techs=${JSON.stringify(techs)}`);
  }
  const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'odp-notes-prompt-injection');
  if (hits.length < 1) throw new Error(`expected >=1 hit. got=${hits.length}`);
  if (hits[0].category !== 'suspiciousPatterns') {
    throw new Error(`expected category=suspiciousPatterns. got=${hits[0].category}`);
  }
  if (hits[0].severity !== 'danger') {
    throw new Error(`expected severity=danger. got=${hits[0].severity}`);
  }
});

// --- Attack 2: slide transition macro ---
add('ODP-02 attack: odp_slide_transition_macro emits odp-slide-transition-macro', async () => {
  const buf = readFixture(ATTACKS_DIR, 'odp_slide_transition_macro.odp');
  if (!buf) throw new Error('fixture missing');
  const out = await parseOdp(buf);
  const techs = techniques(out);
  if (!techs.includes('odp-slide-transition-macro')) {
    throw new Error(`missing odp-slide-transition-macro. techs=${JSON.stringify(techs)}`);
  }
  const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'odp-slide-transition-macro');
  if (hits.length < 2) throw new Error(`expected >=2 hits (event-listener + sound). got=${hits.length}`);
});

// --- Attack 3: embedded external object ---
add('ODP-03 attack: odp_embedded_object_external emits odp-embedded-object-external', async () => {
  const buf = readFixture(ATTACKS_DIR, 'odp_embedded_object_external.odp');
  if (!buf) throw new Error('fixture missing');
  const out = await parseOdp(buf);
  const techs = techniques(out);
  if (!techs.includes('odp-embedded-object-external')) {
    throw new Error(`missing odp-embedded-object-external. techs=${JSON.stringify(techs)}`);
  }
  const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'odp-embedded-object-external');
  if (hits.length < 2) throw new Error(`expected >=2 hits. got=${hits.length}`);
});

// --- Benign FP guard ---
add('ODP-04 benign: benign_odp_basic stays clean (no odp-* kebab ids)', async () => {
  const buf = readFixture(BENIGN_DIR, 'benign_odp_basic.odp');
  if (!buf) throw new Error('fixture missing');
  const out = await parseOdp(buf);
  const techs = techniques(out);
  const bad = techs.filter(t =>
    t === 'odp-notes-prompt-injection' ||
    t === 'odp-slide-transition-macro' ||
    t === 'odp-embedded-object-external' ||
    t === 'odp-master-slide-instruction'
  );
  if (bad.length > 0) throw new Error(`expected clean benign. unexpected=${JSON.stringify(bad)}`);
});

// --- Runner ---
let pass = 0, fail = 0;
const failed = [];
for (const { name, fn } of tests) {
  try {
    await fn();
    pass++;
    console.log(`  PASS  ${name}`);
  } catch (err) {
    fail++;
    failed.push({ name, err: err.message });
    console.error(`  FAIL  ${name}\n        ${err.message}`);
  }
}
console.log(`\n${pass}/${tests.length} passed`);
if (fail > 0) {
  process.exit(1);
}
