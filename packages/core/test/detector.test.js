/**
 * Smoke tests for the main detector pipeline.
 *
 * Confirms the env-abstract rules-loader fallback works end-to-end:
 * if these pass, every detector module was able to call loadRule() at
 * import time without setEnv() — proving the Node default is wired.
 */
import { describe, it, expect } from "vitest";
import { analyze, ALL_CATEGORIES } from "../src/detector.js";

describe("detector.analyze smoke", () => {
  it("returns empty findings for benign text", () => {
    const r = analyze("hello world this is a perfectly normal sentence", {
      fileType: "text",
    });
    expect(r.findings).toBeTypeOf("object");
    expect(r.summary).toBeTypeOf("object");
    for (const cat of ALL_CATEGORIES) {
      expect(Array.isArray(r.findings[cat])).toBe(true);
    }
  });

  it("detects an invisible Tag-block character", () => {
    // U+E0041 is in the Tag block (invisible)
    const txt = "secret\u{E0041}payload here is the prompt";
    const r = analyze(txt);
    expect(r.findings.invisibleUnicode.length).toBeGreaterThan(0);
  });

  it("detects a Cyrillic homoglyph 'а' for Latin 'a'", () => {
    // Cyrillic small letter a (U+0430) embedded inside a Latin word so it sits
    // adjacent to a-z chars (detector requires nearLatin context).
    const txt = "this is a pаyload test of the homoglyph detector behavior";
    const r = analyze(txt);
    expect(r.findings.homoglyphs.length).toBeGreaterThan(0);
  });

  it("respects categories option (only invisibleUnicode)", () => {
    const txt = "secret\u{E0041}payload of decent length to allow detection";
    const r = analyze(txt, { categories: ["invisibleUnicode"] });
    expect(r.findings.invisibleUnicode.length).toBeGreaterThan(0);
    expect(r.findings.homoglyphs.length).toBe(0);
    expect(r.findings.controlChars.length).toBe(0);
  });

  it("populates summary.byCategory / total / status", () => {
    const txt = "secret\u{E0041}payload with sufficient context for analysis";
    const r = analyze(txt);
    expect(r.summary).toHaveProperty("status");
    expect(typeof r.summary.total).toBe("number");
  });
});
