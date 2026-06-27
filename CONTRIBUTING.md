# Contributing to Shield Scanner

This is a small personal project. Issues and PRs are welcome, but please
keep the guardrails below in mind — they exist to keep the MCP server and
Web app byte-identical and the bundle small.

## Quick start

```sh
git clone https://github.com/nisake/shield-scanner-mono.git
cd shield-scanner-mono
npm install
npm run check          # tests + parity + dist budget
```

Node.js >= 18 required.

## Guardrails

- **Drift budget: 0.** Web and MCP must produce byte-identical findings
  (`tools/parity-check.mjs`).
- **Dist budget: 900 KiB.** Hard cap on `packages/web/dist/index.html`
  (`tools/dist-budget.mjs`).
- **Mirror parsers.** New format parsers go in **both**
  `packages/mcp/server/parsers/` **and** `packages/web/src/parsers-web/`.
- **i18n.** New detector kebab IDs need both `ja` and `en` entries in
  `packages/web/src/i18n.js`.

## License

By contributing, you agree your contributions are licensed under [MIT](./LICENSE).
