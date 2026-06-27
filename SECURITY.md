# Security policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in Shield Scanner, please report it
privately through **GitHub Security Advisories**:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the form — include reproduction steps, affected version(s), and the impact you
   observed.

Please do **not** open a public GitHub issue, discussion, or pull request for a security
vulnerability. Public disclosure before a fix is available puts every user at risk.

## What to expect

- **Acknowledgement**: within 5 business days of your report.
- **Initial assessment**: within 10 business days — we will tell you whether we are treating
  the report as a vulnerability, need more information, or believe it is out of scope.
- **Fix + advisory**: timeline depends on severity. Critical and high-severity issues are
  prioritized; we aim to publish a fix and a GitHub Security Advisory within 30 days for those.
- **Credit**: with your permission, we credit reporters in the advisory.

## Supported versions

Shield Scanner uses a rolling-release model. Security fixes land on `main` and are published
in the next tagged release. The latest tagged release on `main` is the only supported version.

## Scope

In scope:

- The `@shield-scanner/core`, `@shield-scanner/mcp`, and `@shield-scanner/web` packages.
- The build outputs in `packages/web/dist/`.
- The bundled rule files in `packages/core/data/`.
- The MCP tool surface exposed by `packages/mcp/server/`.

Out of scope (please report to the upstream project):

- Vulnerabilities in third-party dependencies (`pdf.js`, `JSZip`, `mailparser`, `cheerio`,
  `pdf-lib`, `@modelcontextprotocol/sdk`, …). If a Shield Scanner-specific configuration of a
  dependency creates a vulnerability, that is in scope.
- Issues in Claude Desktop itself or the MCP protocol.

## False-positive / detection-quality reports

Detection misses or false positives are bug reports, not security vulnerabilities. Please
open a regular GitHub issue with a minimal fixture so we can add it to the regression suite.

## Safe-harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and service
  disruption.
- Report vulnerabilities promptly via the channel above.
- Give us a reasonable opportunity to fix the issue before public disclosure.

Thank you for helping keep Shield Scanner and its users safe.
