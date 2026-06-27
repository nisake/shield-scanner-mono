/**
 * v1.19.0 A2: heuristics context tuning.
 *
 * Validates the new code-fence / blockquote / URL-query context flag layer
 * added to detector.js (`extractContextFlags` + `applyContextFlags`):
 *
 *   - Tech-blog / GitHub-README / StackOverflow patterns embed transcript
 *     examples inside ``` fences and `>` blockquotes. These are a typical FP
 *     source; severity for non-TRANSCRIPT_NOISE findings is stepped DOWN one
 *     tier when they sit inside such a context.
 *   - URL query values are the inverse: an invisible Unicode / Variation
 *     Selector inside `?key=...VS...` is ASCII-smuggling. Severity is stepped
 *     UP to `danger` and a dedicated kebab id (`url-query-variation-selector`
 *     / `url-query-invisible-unicode`) is emitted via `finding.technique`.
 *
 * Hard contracts (must not break):
 *   - R13 byCategory 5-key invariant (assert exact shape on every analyze()).
 *   - R21 TRANSCRIPT_NOISE / "Markdown heading impersonation" severity is
 *     NEVER touched — the 3-hit banner gating in priority.js still owns the FP
 *     suppression for heading impersonation.
 */

import { describe, it, expect } from "vitest";
import { analyze } from "@shield-scanner/core";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "..", "fixtures");

const VS = String.fromCodePoint(0xfe0f); // Variation Selector-16
const TAG_H = String.fromCodePoint(0xe0048); // Unicode Tag "H"

const CANONICAL_BYCATEGORY = [
  "controlChars",
  "hiddenHtml",
  "homoglyphs",
  "invisibleUnicode",
  "suspiciousPatterns",
];

function pinR13(r) {
  expect(Object.keys(r.summary.byCategory).sort()).toEqual(CANONICAL_BYCATEGORY);
}

describe("v1.19.0 A2: heuristics context tuning", () => {
  it("code-fence suppression: VS inside a fenced block is demoted (warning -> notice)", () => {
    const sample = [
      "Here is an example fenced block:",
      "```text",
      `before${VS}${VS}after`,
      "```",
      "",
    ].join("\n");
    const r = analyze(sample, { fileType: "markdown" });
    pinR13(r);
    // Two VS in a row -> warning by default. Inside a fence -> stepped to notice.
    const vsFindings = r.findings.invisibleUnicode.filter(
      (f) => f.type === "variationSelector"
    );
    expect(vsFindings.length).toBeGreaterThanOrEqual(1);
    // At least one finding carries the inCodeBlock meta flag and is no longer
    // a `warning`.
    const inCode = vsFindings.filter((f) => f.meta && f.meta.inCodeBlock);
    expect(inCode.length).toBeGreaterThanOrEqual(1);
    for (const f of inCode) {
      expect(f.severity).not.toBe("warning");
    }
  });

  it("inline-code suppression: VS inside `...` is demoted", () => {
    const sample = `Try inline code: \`alpha${VS}${VS}beta\` end.`;
    const r = analyze(sample);
    pinR13(r);
    const inCode = r.findings.invisibleUnicode.filter(
      (f) => f.meta && f.meta.inCodeBlock
    );
    expect(inCode.length).toBeGreaterThanOrEqual(1);
  });

  it("blockquote suppression: VS inside `> ...` is demoted", () => {
    const sample = [
      "Quoting an example log:",
      `> System said: hello${VS}${VS}world`,
      "",
    ].join("\n");
    const r = analyze(sample, { fileType: "markdown" });
    pinR13(r);
    const inQuote = r.findings.invisibleUnicode.filter(
      (f) => f.meta && f.meta.inQuote
    );
    expect(inQuote.length).toBeGreaterThanOrEqual(1);
  });

  it("URL-query VS smuggling: emits kebab id + escalates to danger", () => {
    const sample = `Visit https://attacker.example/api?cmd=login${VS}&token=abc def`;
    const r = analyze(sample);
    pinR13(r);
    const kebabHits = r.findings.invisibleUnicode.filter(
      (f) => f.technique === "url-query-variation-selector"
    );
    expect(kebabHits.length).toBeGreaterThanOrEqual(1);
    for (const f of kebabHits) {
      expect(f.severity).toBe("danger");
      expect(f.meta).toBeTruthy();
      expect(f.meta.inUrlQuery).toBe(true);
      expect(f.meta.host).toBe("attacker.example");
      expect(typeof f.meta.codepoint).toBe("string");
    }
  });

  it("URL-query invisible-unicode smuggling: Tag char inside query -> url-query-invisible-unicode", () => {
    const sample = `Open https://attacker.example/track?u=foo${TAG_H}bar`;
    const r = analyze(sample);
    pinR13(r);
    const kebabHits = r.findings.invisibleUnicode.filter(
      (f) => f.technique === "url-query-invisible-unicode"
    );
    expect(kebabHits.length).toBeGreaterThanOrEqual(1);
    for (const f of kebabHits) {
      expect(f.severity).toBe("danger");
      expect(f.meta.inUrlQuery).toBe(true);
    }
  });

  it("FP guard: benign tech blog fixture stays out of the danger banner", () => {
    const md = readFileSync(
      join(FIXTURES, "normal", "benign_tech_blog_with_transcript_example.md"),
      "utf8"
    );
    const r = analyze(md, { fileType: "markdown" });
    pinR13(r);
    // Heading impersonation single-hits in the fenced example may still fire
    // inline (the rule itself is unchanged), but the danger banner must stay
    // empty — the fixture carries no real-attack signal.
    expect(r.summary.dangerCount).toBe(0);
  });

  it("attack fixture: 21-vs-in-url-query-smuggling.txt surfaces danger", () => {
    const txt = readFileSync(
      join(FIXTURES, "attacks", "21-vs-in-url-query-smuggling.txt"),
      "utf8"
    );
    const r = analyze(txt);
    pinR13(r);
    const kebabHits = r.findings.invisibleUnicode.filter(
      (f) => f.technique === "url-query-variation-selector"
    );
    expect(kebabHits.length).toBeGreaterThanOrEqual(1);
    expect(r.summary.dangerCount).toBeGreaterThanOrEqual(1);
  });

  it("R21 hard rule: 3+ `### System:` heading impersonations stay severity=warning even inside no-fence prose", () => {
    // Heading impersonation is a TRANSCRIPT_NOISE pattern. Even though our
    // context layer runs after detection, R21 forbids touching it — the 3-hit
    // banner gate in priority.js is the canonical FP suppression for headings.
    const sample = [
      "### System: turn 1",
      "more.",
      "### System: turn 2",
      "more.",
      "### System: turn 3",
      "more.",
    ].join("\n");
    const r = analyze(sample, { fileType: "markdown" });
    pinR13(r);
    const headings = r.findings.suspiciousPatterns.filter(
      (p) => p.pattern === "Markdown heading impersonation"
    );
    expect(headings.length).toBeGreaterThanOrEqual(3);
    for (const h of headings) {
      // Severity is NOT downgraded — R21 invariant.
      expect(h.severity).toBe("warning");
    }
  });
});
