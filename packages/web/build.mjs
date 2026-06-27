// =============================================================
//  Shield Scanner Web — build script (Step 7)
// =============================================================
// Bundles src/app.js + injects rules + emits dist/index.html.
//
// Constraints:
//   - minify: false  (keeps the R12-R17 grep-based audit story)
//   - external: jszip, pdfjs-dist  (CDN-loaded; referenced via globals)
//   - charset: utf8
//   - JSON rules pre-loaded into globalThis.__SHIELD_RULES__ (kept for
//     backward compat with any tooling that greps the bundle for rules
//     data; the runtime path uses esbuild's JSON loader via the web
//     rules-loader)
// =============================================================
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync, readdirSync, copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(here, 'src');
const DATA = resolve(here, '..', 'core', 'data');
const DIST = resolve(here, 'dist');

// Stub plugin: maps `node:fs|node:url|node:path` to an empty module so the
// Web bundle can ship without dragging in Node built-ins. The fallback path
// in core/src/utils.js that calls these is unreachable in the browser
// (createWebEnv() registers a JSON-import-based rulesLoader at startup), but
// esbuild still needs to resolve the imports statically.
const nodeStubPlugin = {
  name: 'node-stub',
  setup(b) {
    b.onResolve({ filter: /^node:(fs|url|path)$/ }, (args) => ({
      path: args.path,
      namespace: 'node-stub',
    }));
    b.onLoad({ filter: /.*/, namespace: 'node-stub' }, () => ({
      contents:
        'export const readFileSync = () => { throw new Error("node:fs not available in browser"); };\n' +
        'export const fileURLToPath = () => { throw new Error("node:url not available in browser"); };\n' +
        'export const dirname = () => ""; export const join = () => ""; export default {};',
      loader: 'js',
    }));
  },
};

// Cheerio-free Web bundle (v1.17.0): hidden-elements.js statically imports
// _hidden-elements-default-parser.js which pulls cheerio + parse5 +
// htmlparser2 + cheerio-select + dom-serializer + entities for the Node
// fallback. In the browser, createWebEnv() wires env.htmlParser to a
// DOMParser-backed adapter at app startup, so the default-parser branch is
// unreachable. Stubbing that ONE module short-circuits the entire chain.
// Verify post-build with: grep -E 'cheerio|parse5|htmlparser2|dom-serializer'
// on packages/web/dist/index.html — should return zero hits.
const cheerioStubPlugin = {
  name: 'html-parser-stub',
  setup(b) {
    b.onResolve({ filter: /_hidden-elements-default-parser\.js$/ }, () => ({
      path: '_hidden-elements-default-parser-stub',
      namespace: 'htmlp-stub',
    }));
    b.onLoad(
      { filter: /^_hidden-elements-default-parser-stub$/, namespace: 'htmlp-stub' },
      () => ({
        contents:
          'export function getDefaultHtmlParser() { throw new Error("default html parser unreachable in web bundle"); }',
        loader: 'js',
      }),
    );
  },
};

// 1. Bundle src/app.js (no minify — keeps grep audit intact).
const result = await build({
  entryPoints: [resolve(SRC, 'app.js')],
  bundle: true,
  format: 'iife',
  minify: false,
  charset: 'utf8',
  platform: 'browser',
  loader: { '.json': 'json' },
  external: ['jszip', 'pdfjs-dist'],
  plugins: [nodeStubPlugin, cheerioStubPlugin],
  write: false,
  logLevel: 'info',
});

if (!result.outputFiles || result.outputFiles.length === 0) {
  throw new Error('esbuild produced no output');
}
const bundleJs = result.outputFiles[0].text;

// 2. Load all JSON rules from packages/core/data and emit a small
//    IIFE prefix that exposes them on globalThis.__SHIELD_RULES__.
const rulesObj = {};
for (const file of readdirSync(DATA)) {
  if (!file.endsWith('.json')) continue;
  const key = file.slice(0, -5); // strip .json
  rulesObj[key] = JSON.parse(readFileSync(join(DATA, file), 'utf8'));
}
const rulesIife =
  '(function(){ globalThis.__SHIELD_RULES__ = ' +
  JSON.stringify(rulesObj) +
  '; })();';

// 3. Read the HTML template and replace the two injection markers.
const tplPath = resolve(SRC, 'index.template.html');
let html = readFileSync(tplPath, 'utf8');
// Use the function form of replace so `$` sequences in the bundle text
// (e.g. `$&` inside regex-escape helpers) are not interpreted as backrefs.
html = html.replace(
  '<!--RULES_INJECT-->',
  () => '<script>' + rulesIife + '</script>',
);
html = html.replace(
  '<!--BUNDLE_INJECT-->',
  () => '<script>' + bundleJs + '</script>',
);

// 4. Emit dist/index.html.
mkdirSync(DIST, { recursive: true });
const outPath = resolve(DIST, 'index.html');
writeFileSync(outPath, html, 'utf8');

const sizeKB = (Buffer.byteLength(html, 'utf8') / 1024).toFixed(1);
console.log(`[build] wrote ${outPath} (${sizeKB} KB)`);

// 5. Copy static OG image alongside dist/index.html so a single dist/
//    folder is self-contained when consumers host it (the og:image URL in
//    the bundled HTML resolves to the same directory).
copyFileSync(resolve(SRC, 'og-image.png'), resolve(DIST, 'og-image.png'));
console.log(`[build] copied og-image.png to ${DIST}`);
