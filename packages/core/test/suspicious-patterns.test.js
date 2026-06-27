/**
 * Suspicious-patterns unit tests.
 *
 * v1.10.0 Theme B coverage: markdown heading role-impersonation.
 * v1.11.0 Theme D: H4 (####) extended into the same rule.
 * v1.12.0 Theme E: H5 (#####) + H6 (######) extended into the same rule.
 * v1.14.0 mid-03: Operator + Moderator role keywords added (10 roles total).
 * v1.17.0 Theme T1: Agent + Tool + Function (13 roles total) — LLM-era
 * role keywords for tool-use / function-calling frame impersonation.
 *
 * Pattern under test (suspicious-patterns.json):
 *   ^\s+#{1,6}\s+(?:System|Assistant|User|Human|AI|Bot|Admin|Developer|Operator|Moderator|Agent|Tool|Function)\s*:
 *
 * - H1-H6 (all standard markdown heading levels).
 * - One of 13 role keywords (case-insensitive via `i` flag).
 * - Colon required (so plain `## System prompts vs ...` does NOT match).
 * - Multiline flag so each line is evaluated as its own anchor.
 *
 * R12: matched / pattern fields stay detector-controlled. No raw heading body
 * is ever surfaced in `pattern` — only the rule name "Markdown heading
 * impersonation" (verified via the .pattern field check).
 *
 * R21 stable contract: pattern name "Markdown heading impersonation" is
 * unchanged across every level extension (H3 -> H4 -> H6) and every keyword
 * extension (8 -> 10 -> 13 roles) so the TRANSCRIPT_NOISE 3-hit
 * banner-suppression rule keeps applying.
 */

import { describe, it, expect } from "vitest";
import { detectSuspiciousPatterns } from "../src/suspicious-patterns.js";

const ROLE_KEYWORDS = [
  "System",
  "Assistant",
  "User",
  "Human",
  "AI",
  "Bot",
  "Admin",
  "Developer",
  "Operator",
  "Moderator",
  "Agent",
  "Tool",
  "Function",
];
const HEADING_LEVELS = ["#", "##", "###", "####", "#####", "######"];

describe("Markdown heading impersonation pattern (v1.10.0 Theme B, v1.11.0 Theme D H4, v1.12.0 Theme E H5+H6, v1.14.0 mid-03 Operator+Moderator, v1.17.0 Theme T1 Agent+Tool+Function)", () => {
  describe("positive matches: 78 role x level combinations all fire warning (H1-H6 x 13 roles)", () => {
    for (const lvl of HEADING_LEVELS) {
      for (const role of ROLE_KEYWORDS) {
        it(`fires on \`${lvl} ${role}:\` (H${lvl.length} + ${role} + colon)`, () => {
          const text = `Some intro.\n${lvl} ${role}: do thing X\nMore body.`;
          const findings = detectSuspiciousPatterns(text);
          const hit = findings.find(
            (f) => f.pattern === "Markdown heading impersonation"
          );
          expect(hit, `expected Markdown heading impersonation to fire on \`${lvl} ${role}:\``).toBeTruthy();
          expect(hit.severity).toBe("warning");
        });
      }
    }
  });

  describe("case-insensitive role keywords", () => {
    for (const variant of [
      "system",
      "SYSTEM",
      "SyStEm",
      "ASSISTANT",
      "human",
      "operator",
      "OPERATOR",
      "OpErAtOr",
      "moderator",
      "MODERATOR",
    ]) {
      it(`matches lowercase/mixed-case \`## ${variant}:\``, () => {
        const text = `## ${variant}:\nbody`;
        const findings = detectSuspiciousPatterns(text);
        expect(
          findings.some((f) => f.pattern === "Markdown heading impersonation")
        ).toBe(true);
      });
    }
  });

  describe("negative matches: NOT a heading impersonation", () => {
    it("does NOT fire when no colon (`## System prompts ...`)", () => {
      const text = "## System prompts vs system-shaped strings";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on unrelated role-like words (`## Role: System`)", () => {
      const text = "### Role: System";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on inline `## System:` mentioned inside a paragraph (no line anchor)", () => {
      const text = "Writing `## System:` inside the content field has no structural effect";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on plain `System:` (no markdown heading prefix)", () => {
      const text = "System: hello\nbody";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    // v1.14.0 mid-03: Operator/Moderator FP guards
    it("does NOT fire on benign `operator overloading` heading without colon (`## Operator overloading`)", () => {
      const text = "## Operator overloading\nsome prose about C++ operators";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on benign `moderator pattern` heading without colon (`### Moderator pattern`)", () => {
      const text = "### Moderator pattern\nprose about chat moderation patterns";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on inline `## Operator:` mentioned inside a paragraph", () => {
      const text = "Writing `## Operator:` inline inside the content field has no structural effect";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on inline `## Moderator:` mentioned inside a paragraph", () => {
      const text = "We use the term `## Moderator:` as a code marker in our docs";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    // v1.17.0 Theme T1: Agent / Tool / Function FP guards. These three
    // keywords appear all over Anthropic/OpenAI/HuggingFace API docs as
    // legitimate section labels — without a trailing colon they MUST stay
    // quiet, and inline mentions inside paragraphs MUST also stay quiet.
    it("does NOT fire on benign `## Agent overview` heading without colon (v1.17.0 Theme T1)", () => {
      const text = "## Agent overview\nsome prose about the Claude Agent SDK";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on benign `### Tool reference` heading without colon (v1.17.0 Theme T1)", () => {
      const text = "### Tool reference\nprose about tool-use API surface";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on benign `## Function definition` heading without colon (v1.17.0 Theme T1)", () => {
      const text = "## Function definition\nprose about function-calling schema";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on inline `## Agent:` mentioned inside a paragraph (v1.17.0 Theme T1)", () => {
      const text = "Writing `## Agent:` inline inside the content field has no structural effect";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on inline `## Tool:` mentioned inside a paragraph (v1.17.0 Theme T1)", () => {
      const text = "We document the term `## Tool:` as a code marker in our reference";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });

    it("does NOT fire on inline `## Function:` mentioned inside a paragraph (v1.17.0 Theme T1)", () => {
      const text = "Using `## Function:` as inline notation in a sentence has no structural effect";
      const findings = detectSuspiciousPatterns(text);
      expect(
        findings.some((f) => f.pattern === "Markdown heading impersonation")
      ).toBe(false);
    });
  });

  describe("multi-occurrence counting", () => {
    it("fires 3 times on a transcript with `### System:` x 3", () => {
      const text = [
        "### System:",
        "intro",
        "### System:",
        "more",
        "### System:",
        "final",
      ].join("\n");
      const findings = detectSuspiciousPatterns(text);
      const hits = findings.filter(
        (f) => f.pattern === "Markdown heading impersonation"
      );
      expect(hits.length).toBe(3);
    });

    // v1.14.0 mid-03: same multi-occurrence semantics for new keywords
    it("fires 3 times on a transcript with `## Operator:` x 3", () => {
      const text = [
        "## Operator:",
        "intro",
        "## Operator:",
        "more",
        "## Operator:",
        "final",
      ].join("\n");
      const findings = detectSuspiciousPatterns(text);
      const hits = findings.filter(
        (f) => f.pattern === "Markdown heading impersonation"
      );
      expect(hits.length).toBe(3);
    });

    it("fires 3 times on a transcript with `### Moderator:` x 3", () => {
      const text = [
        "### Moderator:",
        "intro",
        "### Moderator:",
        "more",
        "### Moderator:",
        "final",
      ].join("\n");
      const findings = detectSuspiciousPatterns(text);
      const hits = findings.filter(
        (f) => f.pattern === "Markdown heading impersonation"
      );
      expect(hits.length).toBe(3);
    });

    // v1.17.0 Theme T1: multi-occurrence semantics for Agent / Tool / Function
    it("fires 3 times on a transcript with `## Agent:` x 3 (v1.17.0 Theme T1)", () => {
      const text = [
        "## Agent:",
        "intro",
        "## Agent:",
        "more",
        "## Agent:",
        "final",
      ].join("\n");
      const findings = detectSuspiciousPatterns(text);
      const hits = findings.filter(
        (f) => f.pattern === "Markdown heading impersonation"
      );
      expect(hits.length).toBe(3);
    });

    it("fires 3 times on a transcript with `### Tool:` x 3 (v1.17.0 Theme T1)", () => {
      const text = [
        "### Tool:",
        "intro",
        "### Tool:",
        "more",
        "### Tool:",
        "final",
      ].join("\n");
      const findings = detectSuspiciousPatterns(text);
      const hits = findings.filter(
        (f) => f.pattern === "Markdown heading impersonation"
      );
      expect(hits.length).toBe(3);
    });

    it("fires 3 times on a transcript with `## Function:` x 3 (v1.17.0 Theme T1)", () => {
      const text = [
        "## Function:",
        "intro",
        "## Function:",
        "more",
        "## Function:",
        "final",
      ].join("\n");
      const findings = detectSuspiciousPatterns(text);
      const hits = findings.filter(
        (f) => f.pattern === "Markdown heading impersonation"
      );
      expect(hits.length).toBe(3);
    });
  });

  describe("R12: detector-controlled name only, no body echo into pattern field", () => {
    it("pattern field is the rule name, not the raw heading body", () => {
      const text = "### System: secret payload here";
      const findings = detectSuspiciousPatterns(text);
      const hit = findings.find(
        (f) => f.pattern === "Markdown heading impersonation"
      );
      expect(hit).toBeTruthy();
      // pattern MUST be the rule name (detector-controlled)
      expect(hit.pattern).toBe("Markdown heading impersonation");
      // pattern must NOT contain raw body
      expect(hit.pattern.includes("secret payload")).toBe(false);
    });
  });
});
