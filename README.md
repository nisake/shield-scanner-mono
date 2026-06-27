# Shield Scanner

[![bench-detector](https://github.com/your-github-handle/shield-scanner-mono/actions/workflows/bench-detector.yml/badge.svg)](https://github.com/your-github-handle/shield-scanner-mono/actions/workflows/bench-detector.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](#requirements)
[![dist](https://img.shields.io/badge/web%20bundle-461.30%20KiB%20%2F%20900%20KiB%20cap-blue.svg)](#performance--budgets)
[![tests](https://img.shields.io/badge/tests-1726%20passing-success.svg)](#tests)

Shield Scanner is a prompt-injection / hidden-instruction / obfuscated-payload scanner for the
content you are about to feed into an LLM. It catches invisible Unicode, homoglyph host swaps,
PDF / Office metadata smuggling, JSON-encoded instructions, Markdown image / link exfiltration,
SVG / RTF / Notebook (.ipynb) payloads, archive nesting, OpenDocument (.odt/.ods/.odp) injection,
encoded-payload (base64 / hex / URL-encoded / HTML entity) instruction smuggling, MCP tool
descriptor poisoning, and more — across plain text, web pages, email, PDFs, Office files,
archives, and notebooks.

The same rules ship as **two distributions** built from a single monorepo:

- A **Claude Desktop MCP server** (`@shield-scanner/mcp`) that exposes seven scan / sanitize tools.
- A **single-file Web app** (`@shield-scanner/web`) — one `dist/index.html` (461.30 KiB) you can
  upload to any static host.

Both call into the same `@shield-scanner/core` rules and detectors, and `tools/parity-check.mjs`
asserts byte-identical findings between the two on every PR (drift budget: **0**).

---

## Table of contents

- [Highlights](#highlights)
- [Supported inputs](#supported-inputs)
- [Detection coverage](#detection-coverage)
- [Requirements](#requirements)
- [Install](#install)
- [Run the MCP server (Claude Desktop)](#run-the-mcp-server-claude-desktop)
- [Build & run the Web app](#build--run-the-web-app)
- [Library / CLI usage](#library--cli-usage)
- [Repository layout](#repository-layout)
- [Tests](#tests)
- [Continuous integration](#continuous-integration)
- [Performance & budgets](#performance--budgets)
- [Internationalization](#internationalization)
- [Contributing](#contributing)
- [Security policy](#security-policy)
- [License](#license)
- [Credits](#credits)
- [Migration notes](#migration-notes)

---

## Highlights

- **Two distributions, one rule set.** MCP server + single-file Web app, byte-identical findings
  guaranteed by `tools/parity-check.mjs` (drift budget 0).
- **R12 / R13 guardrails.** Detector-controlled kebab IDs, fixed bucket fold, no leakage of
  decoded user-controlled text into `technique` / `matched` / `pattern` fields.
- **Wide format coverage.** Markdown, HTML, plain text, PDF (incl. struct tree H1-H6 / actions),
  DOCX / PPTX / XLSX (incl. Power Query, ActiveX, Follina templates), OpenDocument (.odt / .ods /
  .odp), EML (incl. IDN homograph headers), SVG, RTF, Jupyter `.ipynb`, structured-text
  front-matter (YAML / TOML / JSON-LD), and ZIP archives (with nested-archive walk).
- **Three sanitize modes.** `strip` (default, removes), `mask` (replace with visible glyphs),
  `placeholder` (replace with fixed category label — R12-safe, never echoes raw input).
- **MCP descriptor scanning.** Detects CVE-2025-54136-class rug pulls, shadow-tool collisions,
  and invisible-Unicode smuggling in tool `description` fields (OWASP MCP03).
- **Encoded-payload decoder.** Walks base64 / hex / URL-encoded / HTML-entity / Punycode layers
  with hard caps (`Object.freeze`), and surfaces decoded-side instruction matches without ever
  leaking the decoded buffer into findings.
- **Performance hardened.** Streaming chunked scan for 5 MB+ inputs, regex precompilation,
  per-detector CI benchmark with a regression gate.
- **Bilingual UI.** Japanese + English (`i18n.js`), default Japanese on the Web app.

---

## Supported inputs

| Category | Formats | Notes |
| --- | --- | --- |
| Plain text / markup | `txt`, `md`, `csv`, `tsv`, `json`, `html`, `xml` | Raw text path; also drives URL fetch + email body |
| PDF | `pdf` | pdf.js parse: text, struct tree (H1-H6 / Figure / Table / List / Sect / BlockQuote / Quote / Span), Action dictionary, JavaScript, attachments, OpenAction, outline |
| Office Open XML | `docx`, `pptx`, `xlsx` | OPC parts walk: hidden text, microscopic / white-font shapes, Follina templates, customXml, Power Query, Data Connection, ActiveX, OLE CFB |
| OpenDocument | `odt`, `ods`, `odp` | Notes / slide transitions / macros / embedded external objects |
| Email | `eml` | mailparser: headers, body, HTML parts; From / Reply-To / Sender mismatch, DMARC / SPF / DKIM failure, IDN homograph, RFC2047 encoded-word invisible-Unicode |
| Notebook | `ipynb` | Cells, outputs, signature trust, metadata-tag smuggle, output HTML injection |
| Vector graphics | `svg` | `<script>`, event handlers, `javascript:` href, `<foreignObject>`, CDATA, external `<use>` |
| Rich text | `rtf` | Unknown destinations, `\bin` binary blocks, `\object` OLE (CVE-2017-11882), `\v` hidden text, `\fs2` microscopic font, `\field HYPERLINK` |
| Structured text front-matter | `yaml`, `toml`, JSON-LD, Markdown front-matter | YAML dangerous tags / anchor bombs, JSON-LD description injection, TOML instruction keys, front-matter prompt injection |
| Archive | `zip` (+ Office / OpenDocument containers) | Multi-archive walk with depth + entry-count caps; nested archives, sanitized member listing |
| URLs | `http(s)` | Fetch + scan as HTML |
| MCP descriptors | `mcp.json` / tools-list JSON | Injection in `description`, rug-pull (SHA-256 canonical sorted-key JSON), shadow-tool collision, invisible Unicode in `description` |

---

## Detection coverage

A non-exhaustive snapshot of the rule families. The complete list lives in
`packages/core/data/*.json` and the per-detector source under `packages/core/src/`.

- **Invisible / control characters** — zero-width, BiDi, variation selectors, combining-character
  pile-ups (`invisible-chars.json`, `invisible-unicode.js`, `combining-chars.js`,
  `control-chars.js`, `variation-selectors.js`).
- **Homoglyphs** — Cherokee / Armenian / Cyrillic / Greek mappings with sanity-check filter
  (`homoglyphs.json`, `homoglyphs.js`).
- **Suspicious instruction patterns** — fixed corpus of override / role-swap / system-prompt
  patterns (`suspicious-patterns.json`).
- **Hidden HTML elements** — `display:none`, `visibility:hidden`, `aria-hidden`, off-screen
  positioning, microscopic font sizes, white-on-white text (`hidden-elements.js`).
- **Markdown exfiltration** — image / link host classification with a six-tier matrix
  (Tier 6 = `trusted-allowlist`), entity / percent / two-pass decode, IPv6 hosts, allowed-host
  allowlist downgrade (`markdown-exfil.js`, `exfil-patterns.json`).
- **Formula injection** — CSV / XLSX leading `=`, `+`, `-`, `@`, DDE links
  (`formula-injection.json`, `formula-injection.js`).
- **Math-bypass instruction smuggling** (`math-bypass.js`).
- **Encoded-payload decode** — base64 / hex / URL-encoded / HTML-entity / multi-layer with
  R12-safe placeholder (`encoded-decoder.js`).
- **Structured-text front-matter** — YAML / TOML / JSON-LD / Markdown front-matter
  (`structured-text-frontmatter.js`).
- **PDF struct tree walk** — 21 roles incl. H1-H6, Figure / Table / List / Sect / BlockQuote /
  Quote / Span; struct-tree image Alt / ActualText extraction (`pdf-struct.js`).
- **Archive walk** — depth-bound nested archive scan with entry-count caps
  (`archive-detection.json`, `archive-detection.js`).
- **MCP descriptor poisoning** — injection / rug-pull / shadow-tool / hidden-instruction
  (CVE-2025-54136 / OWASP MCP03).

---

## Requirements

- **Node.js >= 18.0.0** (LTS recommended).
- **npm 9+** for workspaces support.
- Platform: Windows, macOS, Linux (matches `packages/mcp/manifest.json` `compatibility.platforms`).

---

## Install

```sh
git clone https://github.com/your-github-handle/shield-scanner-mono.git
cd shield-scanner-mono
npm install
```

`npm install` runs at the workspace root and pulls dependencies for all three packages (`core`,
`mcp`, `web`).

---

## Run the MCP server (Claude Desktop)

### 1. Start the server (manual smoke test)

```sh
npm run start --workspace @shield-scanner/mcp
# or, equivalently:
node packages/mcp/server/index.js
```

The server speaks MCP over stdio. For day-to-day use let Claude Desktop launch it for you via
the config below — Claude Desktop will spawn / respawn it on demand.

### 2. Register in Claude Desktop

Edit Claude Desktop's `claude_desktop_config.json`:

- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Add a `shield-scanner` entry under `mcpServers`, pointing `args` at the absolute path to
`packages/mcp/server/index.js` on your machine:

```json
{
  "mcpServers": {
    "shield-scanner": {
      "command": "node",
      "args": [
        "<YOUR_PATH>/shield-scanner-mono/packages/mcp/server/index.js"
      ]
    }
  }
}
```

Restart Claude Desktop after editing the config.

### 3. Tools exposed

| Tool | Purpose |
| --- | --- |
| `scan_text` | Scan raw text for prompt-injection threats (invisible Unicode, control chars, suspicious patterns, homoglyphs, …) |
| `scan_file` | Scan a file path. Supported: `txt`, `md`, `csv`, `tsv`, `json`, `html`, `xml`, `svg`, `rtf`, `ipynb`, `pdf`, `docx`, `pptx`, `xlsx`, `odt`, `ods`, `odp`, `eml`, archive containers |
| `scan_url` | Fetch a URL and scan its HTML before the model reads it |
| `scan_email` | Scan an `.eml` file or raw email text (headers / body / HTML parts independently) |
| `sanitize_text` | Return a cleaned copy of the text. Accepts `mode: 'strip' \| 'mask' \| 'placeholder'` (default `strip`) |
| `sanitize_file` | Write a sanitized copy of a file next to the original |
| `scan_mcp_descriptor` | Scan another MCP server's tool descriptor (mcp.json / tools-list response) for poisoning, rug-pull, and shadow-tool collision |

---

## Build & run the Web app

The Web app is the same rule set, packaged into a single `index.html` you can upload to any
static host (Netlify, Cloudflare Pages, S3 + CloudFront, GitHub Pages, …) or open from disk.

```sh
npm run build --workspace @shield-scanner/web
# → packages/web/dist/index.html  (single self-contained HTML)
```

Open it locally:

```sh
# macOS
open packages/web/dist/index.html

# Linux
xdg-open packages/web/dist/index.html

# Windows (PowerShell)
start packages/web/dist/index.html
```

The build keeps **`minify: false`** so the R12-R23 grep audits (parity-check, dist-budget) can
walk the bundle deterministically. Two heavy dependencies — **JSZip** and **pdf.js** — are
loaded via CDN `<script>` tags at runtime, so they do not count against the dist budget.

Build output:

- Single file, ~461 KiB (cap 900 KiB; budget enforced by `tools/dist-budget.mjs`).
- No `cheerio` shipped to the Web bundle (verified by `grep -c cheerio packages/web/dist/index.html` == 0).
- Rules JSON injected into `globalThis.__SHIELD_RULES__` at build time.

---

## Library / CLI usage

`@shield-scanner/core` is a plain ES module — you can import it directly into any Node 18+
project without going through the MCP server or Web bundle.

### `analyze(content, options)`

```js
import { analyze } from '@shield-scanner/core';

const { findings, summary } = analyze('Please ignore all previous instructions​.', {
  fileType: 'text',           // 'text' | 'html' | 'pdf' | 'docx' | 'pptx' | 'xlsx' | 'eml' | 'svg' | 'rtf' | 'ipynb' | 'odt' | 'ods' | 'odp' | ...
  categories: undefined,      // optional: restrict to a subset of detector categories
  profile: 'standard',        // optional: 'standard' | 'streaming' | 'mcp-descriptor'
});

console.log(summary.byCategory);
// { suspiciousPatterns: 1, hiddenHtml: 0, markdownExfil: 0, mcpRisk: 0, prompt: 1 }

for (const f of findings) {
  console.log(`[${f.severity}] ${f.kebabId}  ${f.technique}`);
}
```

### `sanitize(content, options)`

```js
import { sanitize } from '@shield-scanner/core';

const { cleaned, removedCounts } = sanitize(suspiciousMarkdown, {
  fileType: 'text',
  mode: 'strip',              // 'strip' (default — backwards-compatible) | 'mask' | 'placeholder'
});

console.log(cleaned);          // sanitized output
console.log(removedCounts);    // { invisibleUnicode: 3, suspiciousPatterns: 1, ... }
```

`mode: 'placeholder'` replaces detected content with fixed category labels (e.g.
`[invisible unicode]`) and is the safest choice when the sanitized text will be re-displayed —
it never echoes raw user-controlled bytes back into the output.

### Programmatic MCP descriptor scan

```js
import { analyzeMcpDescriptor } from '@shield-scanner/core';
// or call `scan_mcp_descriptor` from the MCP server.
```

---

## Repository layout

```
shield-scanner-mono/
├── packages/
│   ├── core/                       # Shared rules + detectors + sanitizer
│   │   ├── data/                   # 6 JSON rule files
│   │   ├── src/                    # 24 source modules (detector, sanitizer, env shims, …)
│   │   └── test/                   # vitest specs
│   ├── mcp/                        # Claude Desktop MCP server (Node)
│   │   ├── manifest.json
│   │   ├── server/
│   │   │   ├── index.js            # MCP stdio entry point
│   │   │   ├── tools/              # 7 tool implementations
│   │   │   └── parsers/            # 20 file-type parsers
│   │   └── test/
│   │       ├── regression/         # vitest regression suite
│   │       └── fixtures/           # attack + benign corpora, with generators
│   └── web/                        # Single-HTML web distribution (esbuild)
│       ├── build.mjs
│       ├── src/                    # app.js, parsers-web/, ui/, ui-guards/, i18n.js, components/
│       ├── test/                   # node-based harness scripts (one per parser theme)
│       └── dist/index.html         # build artifact (461.30 KiB)
├── tools/
│   ├── parity-check.mjs            # MCP ⇔ Web byte-identical findings check (drift budget 0)
│   ├── dist-budget.mjs             # 900 KiB hard cap on dist/index.html
│   ├── bench-detector.mjs          # per-detector micro-benchmark harness
│   ├── bench-ci-summary.mjs        # Markdown summary for PR artifact
│   ├── bench-regression-gate.mjs   # CI gate vs. cached baseline
│   ├── bench-threshold.json        # per-detector caps + regression knobs
│   ├── gen-bench-fixtures.mjs      # 1/10/50 MB + 10k-line synthetic inputs
│   └── …                           # fixture generators (PDF / DOCX / SVG)
├── .github/workflows/
│   └── bench-detector.yml          # benchmark CI workflow
├── .gitattributes
├── .gitignore
├── .npmrc
├── BENCH.md                        # detailed benchmark / CI documentation
├── LICENSE                         # MIT
├── package.json                    # npm workspaces root
└── README.md
```

---

## Tests

```sh
# Run every workspace's test suite.
npm test --workspaces

# Run the parity check (MCP ⇔ Web byte-identical findings).
npm run parity

# Run tests + dist-budget gate (~ what CI does on every PR).
npm run check
```

Current totals (v1.20.0 working tree):

| Suite | Count |
| --- | ---: |
| `@shield-scanner/core` vitest | 427 |
| `@shield-scanner/mcp` vitest | 992 |
| `@shield-scanner/web` harness | 307 |
| **Total** | **1726 passing / 0 failing** |
| Parity drift | **0** |

---

## Continuous integration

`.github/workflows/bench-detector.yml` runs on every PR + push to `main`:

1. Runs `tools/bench-detector.mjs --iters=3` against a deterministic fixture corpus
   (`SOURCE_DATE_EPOCH` is pinned so `bench-latest.json` is byte-reproducible).
2. Generates a Markdown summary via `tools/bench-ci-summary.mjs`.
3. Runs `tools/bench-regression-gate.mjs` against the cached previous-main baseline. First runs
   and PRs from forks where the cache is empty soft-pass by design.
4. Uploads `bench-latest.json` + `bench-summary.md` as a 30-day artifact.
5. On pushes to `main`, refreshes the baseline cache so the next PR diffs against fresh numbers.

See [BENCH.md](./BENCH.md) for benchmark internals, threshold tuning, and how to re-pin caps
when a perf-touching PR lands.

Additional non-CI gates the repo enforces locally and in `npm run check`:

- **`tools/parity-check.mjs`** — runs every fixture through both the MCP parser stack and the
  Web parser stack; if a single finding differs the gate fails (drift budget 0).
- **`tools/dist-budget.mjs`** — hard caps `packages/web/dist/index.html` at 900 KiB.

---

## Performance & budgets

- **Web bundle**: 461.30 KiB (cap **900 KiB**, headroom ~438 KiB).
- **Streaming threshold**: inputs above **5 MB** stream through invisible-unicode / control-chars /
  homoglyph detectors in **1 MB chunks with a 2 KB overlap**; dedup keys on
  `(detectorId, absoluteStart, matchLen)` for cross-chunk boundaries.
- **Regex precompilation**: `suspicious-patterns.json` strip patterns compile once at module
  load (2-3x speedup on large transcripts).
- **Bench corpus**: deterministic 1 MB / 10 MB / 50 MB plain-text + 10 000-line markdown
  fixtures, regenerated by `tools/gen-bench-fixtures.mjs`.
- **Regression knobs**: see `tools/bench-threshold.json`. `regressionPct` (default 50) is
  deliberately loose because `performance.now()` on Windows swings 50-100% between consecutive
  single-iter runs.

---

## Internationalization

UI strings, finding labels, and category descriptions are bilingual (Japanese / English) and
live in:

- `packages/web/src/i18n.js` — short labels (default Japanese, English fallback).
- `packages/web/src/i18n-descriptions.js` — longer per-kebab descriptions.

Adding a language: extend both files with the new locale key (`ja` / `en` / …) and the Web app
will pick it up via the language selector in the UI header. The MCP server returns the
finding's stable `kebabId` and `category` — host applications are free to map those to their own
localized strings.

---

## Contributing

PRs welcome! A few guardrails this repo takes seriously:

1. **MCP ⇔ Web drift budget: 0.** Any change that touches detectors, rules, or parsers must
   keep `npm run parity` green. If you add a new parser, mirror it on both sides
   (`packages/mcp/server/parsers/<x>.js` and `packages/web/src/parsers-web/<x>.js`).
2. **R12 / R13 guardrails.** Findings expose detector-controlled kebab IDs and a fixed
   five-bucket `byCategory` fold (`suspiciousPatterns`, `hiddenHtml`, `markdownExfil`,
   `mcpRisk`, `prompt`). New finding categories should fold into one of these — please open an
   issue first if you think a new bucket is warranted.
3. **Web bundle stays single-file.** Build with `npm run build --workspace @shield-scanner/web`
   and confirm `dist/index.html` is under the 900 KiB cap (`npm run check` enforces this).
4. **Tests + parity + benchmark.** Run `npm run check` before pushing. For perf-touching
   changes, run `npm run bench` and re-pin `tools/bench-threshold.json` in the same commit.
5. **`minify: false`** on the Web build is intentional — please don't flip it.

A short [CONTRIBUTING.md](./CONTRIBUTING.md) walks through the typical workflow.

---

## Security policy

Please **do not** open a public GitHub issue for a security vulnerability. Instead, use
**GitHub Security Advisories** ("Report a vulnerability" on the repository's Security tab).
See [SECURITY.md](./SECURITY.md) for the full policy, supported versions, and disclosure
timeline.

---

## License

[MIT](./LICENSE) © 2026 Shield Scanner contributors.

---

## Credits

Shield Scanner contributors. The Web app and MCP server reuse:

- [pdf.js](https://github.com/mozilla/pdf.js) — PDF parsing (CDN-loaded in Web build).
- [JSZip](https://stuk.github.io/jszip/) — ZIP / OPC container walk (CDN-loaded in Web build).
- [mailparser](https://nodemailer.com/extras/mailparser/) — EML parsing (MCP server only).
- [cheerio](https://cheerio.js.org/) — HTML walk (MCP server only; intentionally **excluded**
  from the Web bundle).
- [pdf-lib](https://pdf-lib.js.org/) — deterministic PDF fixture generation (devDependency).
- [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk) — MCP
  server protocol.
- [vitest](https://vitest.dev/) + [esbuild](https://esbuild.github.io/) — test runner and Web
  bundler.

---

## Migration notes

### From v1.5.x → v1.6.0+ (`analyze` / `sanitize` signatures)

In v1.6.0 the `analyze` and `sanitize` functions moved to an **options-object** second argument.
Calls written against v1.5.x or earlier will throw at runtime — please update them.

```js
// v1.5.x (no longer works):
analyze(content, 'text');
sanitize(content, findings);

// v1.6.0+:
analyze(content, { fileType: 'text' });
sanitize(content, { fileType: 'text' });
```

### v1.20.0 new sanitize modes (backwards-compatible)

`sanitize(content, { mode })` now accepts `'strip' | 'mask' | 'placeholder'`. The default
remains `'strip'` and is **byte-identical** to calling `sanitize` without a `mode` key, so
existing callers need no changes. `'placeholder'` is the safest mode when the sanitized output
will be re-displayed — it never echoes raw user-controlled bytes back.
