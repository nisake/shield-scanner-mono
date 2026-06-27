/**
 * v1.20.0 T9-ARCHIVE-EXT — regression: heading-role keyword extension end-to-end.
 *
 * Drives the analyze() pipeline (not just the rule unit) to confirm the 5 new
 * roles surface through the full detector → priority → topFindings stack with
 * the same R13 bucket and R21 noise-gating contract.
 */

import { describe, it, expect } from "vitest";
import { analyze } from "@shield-scanner/core";

const NEW_ROLES = ["Plugin", "Skill", "Workflow", "Orchestrator", "Subagent"];

describe("v1.20.0 T9: end-to-end heading-role detection (analyze pipeline)", () => {
  for (const role of NEW_ROLES) {
    it(`surfaces \`## ${role}: ...\` as Markdown heading impersonation in suspiciousPatterns`, () => {
      const text = `# Doc title\n\n## ${role}: do thing X\n\nbody copy here.`;
      const result = analyze(text, { fileType: "markdown" });
      const hits = (result.findings.suspiciousPatterns || []).filter(
        (f) => f.pattern === "Markdown heading impersonation"
      );
      expect(hits.length, `${role} should fire ≥ 1`).toBeGreaterThanOrEqual(1);
      // Severity: warning (matches existing 13-role contract).
      expect(hits[0].severity).toBe("warning");
    });
  }

  it("R13 invariant: heading findings stay inside suspiciousPatterns — no new bucket appears", () => {
    const text = "## Plugin: bad\n### Skill: bad\n## Workflow: bad";
    const result = analyze(text, { fileType: "markdown" });
    expect(Object.keys(result.summary.byCategory).sort()).toEqual([
      "controlChars",
      "hiddenHtml",
      "homoglyphs",
      "invisibleUnicode",
      "suspiciousPatterns",
    ]);
  });

  it("R21 single-hit suppression: one new-role heading is gated out of topFindings", () => {
    // Single occurrence of a heading-impersonation pattern should NOT eat a
    // banner slot (3-hit transcript-noise threshold). The finding still lives
    // in suspiciousPatterns; just the banner is suppressed.
    const text = "Normal intro paragraph.\n\n## Plugin: do thing\n\nMore body text.";
    const result = analyze(text, { fileType: "markdown" });
    const inBucket = (result.findings.suspiciousPatterns || []).some(
      (f) => f.pattern === "Markdown heading impersonation"
    );
    expect(inBucket).toBe(true);
    const inBanner = (result.summary.topFindings || []).some(
      (t) => t.label === "Markdown heading impersonation"
    );
    expect(inBanner, "single hit must not surface in banner").toBe(false);
  });

  it("3-hit threshold flips banner surfacing on for the new roles", () => {
    const text = [
      "Doc intro.",
      "## Plugin: one",
      "## Skill: two",
      "## Workflow: three",
      "## Orchestrator: four",
    ].join("\n\n");
    const result = analyze(text, { fileType: "markdown" });
    const headingHits = (result.findings.suspiciousPatterns || []).filter(
      (f) => f.pattern === "Markdown heading impersonation"
    );
    // ≥ 4 individual hits in the bucket.
    expect(headingHits.length).toBeGreaterThanOrEqual(4);
    // And once ≥ 3, banner surfacing is allowed.
    const inBanner = (result.summary.topFindings || []).some(
      (t) => t.label === "Markdown heading impersonation"
    );
    expect(inBanner).toBe(true);
  });

  it("no FP: `## Plugin overview` (no colon) does NOT fire", () => {
    const text = "# Title\n\n## Plugin overview\n\nLegitimate docs prose.";
    const result = analyze(text, { fileType: "markdown" });
    const hits = (result.findings.suspiciousPatterns || []).filter(
      (f) => f.pattern === "Markdown heading impersonation"
    );
    expect(hits.length).toBe(0);
  });
});
