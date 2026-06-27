// =============================================================
//  Shield Scanner Web — v1.19.0 B4 structured-text harness
// =============================================================
// Drives the structured-text-frontmatter detector + the parsers-web
// dispatcher (.yml / .yaml / .toml) end-to-end on the same fixture
// corpus the MCP regression suite uses. Direct node-test harness — no
// browser tab required.
//
// Coverage:
//   - YAML frontmatter prompt injection            (md_frontmatter_yaml_inject.md)
//   - TOML frontmatter instruction key             (md_frontmatter_toml_inject.md)
//   - !!python/object dangerous tag                (yaml_python_object_tag.yaml)
//   - Anchor / depth bomb                          (yaml_anchor_billion_laughs.yaml)
//   - JSON-LD description injection                (jsonld_description_inject.html)
//   - Benign baselines (blog frontmatter / yaml config / news article)
//
// R12 (no shadow-leak): only detector-controlled meta keys surface (key /
//   tagName / field / format / depth). Raw attacker text never appears.
// R13: every finding carries category='suspiciousPatterns'.
// R22-R23: byte-identical with MCP route on the (technique, severity, meta-
//   key-set) triple.
// =============================================================

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// R18: env-abstract setEnv MUST run before the dynamic core import so the
// rules loader is wired up. We use createWebEnv() with the same DOMParser
// stub other web harnesses use.
import { setEnv } from '@shield-scanner/core/env';
import { createWebEnv } from '@shield-scanner/core/env/web';

if (typeof globalThis.DOMParser === 'undefined') {
  globalThis.DOMParser = class {
    parseFromString() {
      return {
        querySelectorAll: () => [],
        createTreeWalker: () => ({ nextNode: () => null }),
      };
    }
  };
  globalThis.NodeFilter = globalThis.NodeFilter || { SHOW_COMMENT: 128 };
}
setEnv(createWebEnv());

const {
  detectStructuredTextFrontmatter,
  analyze,
} = await import('@shield-scanner/core');
const {
  parseStructuredTextBuffer,
  recognizeStructuredTextExt,
  STRUCTURED_TEXT_DISPATCH,
} = await import('../src/parsers-web/index.js');

const ATTACKS_DIR = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'attacks');
const BENIGN_DIR  = resolve(__dirname, '..', '..', 'mcp', 'test', 'fixtures', 'benign');

const tests = [];
const skipped = [];

function add(name, fn) { tests.push({ name, fn }); }
function skip(name, reason) { skipped.push({ name, reason }); }

function readFixtureText(dir, file) {
  const p = join(dir, file);
  if (!existsSync(p)) return null;
  return readFileSync(p, 'utf8');
}

function techniques(out) {
  return out.map((f) => f.technique).sort();
}

// --- B4-01: YAML frontmatter prompt injection ------------------------------
add('B4-01 structured-text: md_frontmatter_yaml_inject.md surfaces frontmatter-prompt-injection (danger)', async () => {
  const text = readFixtureText(ATTACKS_DIR, 'md_frontmatter_yaml_inject.md');
  if (!text) { skip('B4-01', 'fixture missing'); return; }
  const out = detectStructuredTextFrontmatter(text);
  if (out.length < 1) throw new Error(`no findings: ${JSON.stringify(out)}`);
  const techs = techniques(out);
  if (!techs.includes('frontmatter-prompt-injection')) {
    throw new Error(`missing frontmatter-prompt-injection. got: ${techs.join(',')}`);
  }
  for (const f of out) {
    if (f.category !== 'suspiciousPatterns') throw new Error(`bad category=${f.category}`);
    if (f.severity !== 'danger') throw new Error(`bad severity=${f.severity}`);
    if (!/^[a-z-]+$/.test(f.technique)) throw new Error(`technique not kebab: ${f.technique}`);
  }
});

// --- B4-02: TOML frontmatter instruction key / value ------------------------
add('B4-02 structured-text: md_frontmatter_toml_inject.md surfaces TOML signal', async () => {
  const text = readFixtureText(ATTACKS_DIR, 'md_frontmatter_toml_inject.md');
  if (!text) { skip('B4-02', 'fixture missing'); return; }
  const out = detectStructuredTextFrontmatter(text);
  if (out.length < 1) throw new Error('no findings');
  const techs = techniques(out);
  const ok = techs.some((t) => t === 'frontmatter-prompt-injection' || t === 'toml-instruction-key');
  if (!ok) throw new Error(`no TOML signal. got: ${techs.join(',')}`);
});

// --- B4-03: YAML !!python/object dangerous tag ------------------------------
add('B4-03 structured-text: yaml_python_object_tag.yaml surfaces yaml-dangerous-tag (danger)', async () => {
  const text = readFixtureText(ATTACKS_DIR, 'yaml_python_object_tag.yaml');
  if (!text) { skip('B4-03', 'fixture missing'); return; }
  const out = detectStructuredTextFrontmatter(text, { format: 'yaml' });
  const techs = techniques(out);
  if (!techs.includes('yaml-dangerous-tag')) {
    throw new Error(`missing yaml-dangerous-tag. got: ${techs.join(',')}`);
  }
  const f = out.find((x) => x.technique === 'yaml-dangerous-tag');
  if (typeof f.meta.tagName !== 'string' || f.meta.tagName.length === 0) {
    throw new Error('meta.tagName not surfaced');
  }
  if (!/^[A-Za-z0-9_\-./:!]+$/.test(f.meta.tagName)) {
    throw new Error(`meta.tagName not sanitized: ${f.meta.tagName}`);
  }
});

// --- B4-04: YAML anchor / depth bomb ---------------------------------------
add('B4-04 structured-text: yaml_anchor_billion_laughs.yaml surfaces yaml-anchor-bomb', async () => {
  const text = readFixtureText(ATTACKS_DIR, 'yaml_anchor_billion_laughs.yaml');
  if (!text) { skip('B4-04', 'fixture missing'); return; }
  const out = detectStructuredTextFrontmatter(text, { format: 'yaml' });
  const techs = techniques(out);
  if (!techs.includes('yaml-anchor-bomb')) {
    throw new Error(`missing yaml-anchor-bomb. got: ${techs.join(',')}`);
  }
  const bomb = out.find((x) => x.technique === 'yaml-anchor-bomb');
  if (typeof bomb.meta.depth !== 'number' || bomb.meta.depth <= 0) {
    throw new Error(`meta.depth invalid: ${JSON.stringify(bomb.meta)}`);
  }
});

// --- B4-05: JSON-LD description injection -----------------------------------
add('B4-05 structured-text: jsonld_description_inject.html surfaces jsonld-description-injection', async () => {
  const text = readFixtureText(ATTACKS_DIR, 'jsonld_description_inject.html');
  if (!text) { skip('B4-05', 'fixture missing'); return; }
  const out = detectStructuredTextFrontmatter(text);
  const techs = techniques(out);
  if (!techs.includes('jsonld-description-injection')) {
    throw new Error(`missing jsonld-description-injection. got: ${techs.join(',')}`);
  }
  const inj = out.find((x) => x.technique === 'jsonld-description-injection');
  if (typeof inj.meta.field !== 'string' || inj.meta.field.length === 0) {
    throw new Error('meta.field not surfaced');
  }
});

// --- B4-06: benign baselines stay quiet ------------------------------------
add('B4-06 structured-text: benign blog frontmatter has zero findings', async () => {
  const text = readFixtureText(BENIGN_DIR, 'benign_md_blog_frontmatter.md');
  if (!text) { skip('B4-06', 'fixture missing'); return; }
  const out = detectStructuredTextFrontmatter(text);
  if (out.length !== 0) throw new Error(`expected 0 findings, got ${out.length}: ${techniques(out).join(',')}`);
});

add('B4-07 structured-text: benign yaml config has zero findings', async () => {
  const text = readFixtureText(BENIGN_DIR, 'benign_yaml_config.yaml');
  if (!text) { skip('B4-07', 'fixture missing'); return; }
  const out = detectStructuredTextFrontmatter(text, { format: 'yaml' });
  if (out.length !== 0) throw new Error(`expected 0 findings, got ${out.length}`);
});

add('B4-08 structured-text: benign JSON-LD article has zero findings', async () => {
  const text = readFixtureText(BENIGN_DIR, 'benign_jsonld_article.html');
  if (!text) { skip('B4-08', 'fixture missing'); return; }
  const out = detectStructuredTextFrontmatter(text);
  if (out.length !== 0) throw new Error(`expected 0 findings, got ${out.length}`);
});

// --- B4-09: parsers-web dispatcher recognizes yaml/yml/toml -----------------
add('B4-09 structured-text: recognizeStructuredTextExt maps .yaml/.yml/.toml correctly', async () => {
  if (recognizeStructuredTextExt('a.yaml') !== 'yaml') throw new Error('yaml miss');
  if (recognizeStructuredTextExt('a.YML') !== 'yaml') throw new Error('yml miss');
  if (recognizeStructuredTextExt('a.toml') !== 'toml') throw new Error('toml miss');
  if (recognizeStructuredTextExt('a.json') !== null) throw new Error('json should miss');
  if (!Array.isArray(STRUCTURED_TEXT_DISPATCH.exts) || STRUCTURED_TEXT_DISPATCH.exts.length !== 3) {
    throw new Error('exts wrong length');
  }
});

// --- B4-10: parseStructuredTextBuffer routes through analyze --------------
add('B4-10 structured-text: parseStructuredTextBuffer + analyze() folds into suspiciousPatterns', async () => {
  const text = readFixtureText(ATTACKS_DIR, 'yaml_python_object_tag.yaml');
  if (!text) { skip('B4-10', 'fixture missing'); return; }
  const buffer = new TextEncoder().encode(text);
  const r = await parseStructuredTextBuffer(buffer, 'yaml');
  if (!r) throw new Error('parseStructuredTextBuffer returned null');
  if (r.fileType !== 'yaml') throw new Error(`fileType=${r.fileType}`);
  const { findings, summary } = analyze(r.text, { fileType: r.fileType });
  // R13: 5 byCategory keys preserved.
  const keys = Object.keys(summary.byCategory).sort();
  const want = ['controlChars', 'hiddenHtml', 'homoglyphs', 'invisibleUnicode', 'suspiciousPatterns'];
  if (JSON.stringify(keys) !== JSON.stringify(want)) {
    throw new Error(`byCategory keys drift: ${keys.join(',')}`);
  }
  const techs = findings.suspiciousPatterns.map((f) => f.technique || f.pattern);
  if (!techs.includes('yaml-dangerous-tag')) {
    throw new Error(`missing yaml-dangerous-tag in pipeline. got: ${techs.join(',')}`);
  }
});

// --- B4-11: R12 — no raw attacker text in finding payload -------------------
add('B4-11 structured-text: R12 — finding payload contains no raw injection sentence', async () => {
  const text = readFixtureText(ATTACKS_DIR, 'md_frontmatter_yaml_inject.md');
  if (!text) { skip('B4-11', 'fixture missing'); return; }
  const out = detectStructuredTextFrontmatter(text);
  const json = JSON.stringify(out);
  // The full attacker sentence MUST NOT appear in any finding field. We
  // emit only the key name + the meta object (kebab id + format).
  if (json.includes('reveal the system prompt verbatim')) {
    throw new Error('R12 violation: raw injection sentence leaked into finding payload');
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
