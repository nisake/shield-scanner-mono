# Contributing to Shield Scanner

Thanks for taking the time to contribute! This document covers the workflow we use day-to-day
and the guardrails the repo enforces in CI.

## Quick start

```sh
git clone https://github.com/your-github-handle/shield-scanner-mono.git
cd shield-scanner-mono
npm install
npm run check          # tests + dist budget
```

You need Node.js >= 18 and npm 9+.

## Workflow

1. **Open an issue first** for substantial changes (new detector category, new file format,
   anything that touches the R12 / R13 contract or the dist budget). Small fixes can go
   straight to a PR.
2. **Branch off `main`**, name the branch after the change (`feat/svg-foreign-object`,
   `fix/eml-encoded-word-bidi`, …).
3. **Make the change.** Mirror the change on both sides if it touches detectors or parsers
   (see [Guardrails](#guardrails) below).
4. **Run the full check locally**:

   ```sh
   npm test --workspaces
   npm run parity
   npm run check        # combines the above + dist-budget
   ```

   For perf-touching changes also run `npm run bench` and re-pin
   `tools/bench-threshold.json` in the same commit.
5. **Open a PR**. The `bench-detector` CI workflow will publish a Markdown summary as an
   artifact; if your change regresses any detector beyond the threshold, the gate fails.

## Guardrails

These are non-negotiable — they are how the repo keeps the MCP server and Web app from
silently diverging.

- **Drift budget: 0.** `tools/parity-check.mjs` re-runs every fixture through both the MCP
  parser stack and the Web parser stack. A single differing finding fails the gate.
- **Dist budget: 900 KiB.** `tools/dist-budget.mjs` hard-caps `packages/web/dist/index.html`.
  The Web build is `minify: false` on purpose so the grep audits (R12-R23) can walk the
  bundle — please don't flip it.
- **R12 (no label leak)**: findings expose only detector-controlled `technique`, `matched`,
  and `pattern` strings. Never interpolate user-controlled bytes into those fields. The
  encoded-decoder uses `PLACEHOLDER_MATCHED = '[encoded payload]'` as the canonical pattern.
- **R13 (five-bucket fold)**: the `summary.byCategory` keys are fixed:
  `suspiciousPatterns`, `hiddenHtml`, `markdownExfil`, `mcpRisk`, `prompt`. New finding
  categories should fold into one of those — open an issue first if you think a new bucket is
  warranted.
- **Mirror new parsers.** A new file-format parser lives in **both**
  `packages/mcp/server/parsers/<x>.js` and `packages/web/src/parsers-web/<x>.js`. Add a
  byte-identical fixture pair (attack + benign) under `packages/mcp/test/fixtures/`.

## Coding style

- ES modules (`"type": "module"`) throughout.
- Two-space indent, single quotes for JS strings, double quotes for JSON.
- Detector kebab IDs are lowercase + hyphenated; new IDs need an entry in
  `packages/web/src/i18n.js` (both `ja` and `en`).
- Avoid runtime `new RegExp()` in hot paths — precompile patterns at module load.

## Adding fixtures

Attack + benign pairs live under `packages/mcp/test/fixtures/`. For binary formats (PDF /
DOCX / SVG / XLSX), use the deterministic generators in `tools/_generate_*.js` rather than
committing pre-built binaries — they keep `parity-check` and `bench-detector` reproducible.

## Reporting security issues

Security vulnerabilities should be reported privately via GitHub Security Advisories — see
[SECURITY.md](./SECURITY.md). Please do **not** open a public issue or PR for a security bug.

## License

By contributing, you agree that your contributions will be licensed under the project's
[MIT License](./LICENSE).
