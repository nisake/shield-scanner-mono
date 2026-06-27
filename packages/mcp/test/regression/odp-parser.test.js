/**
 * v1.20.0 T3-ODP regression: OpenDocument Presentation (.odp) parser corpus.
 *
 * Walks the 3 attack + 1 benign fixtures and pins:
 *   - Each attack lights up its dedicated kebab id (odp-notes-prompt-injection
 *     / odp-slide-transition-macro / odp-embedded-object-external /
 *     odp-master-slide-instruction) under category 'suspiciousPatterns'.
 *   - The R13 5-key byCategory invariant survives every fixture.
 *   - Benign fixture stays clean (no danger findings).
 *
 * R12 invariant note: scriptHref / objectHref / masterName flow through
 * escapeForDisplay before reaching `meta`, never as part of the kebab id.
 */

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scanFile } from "../../server/tools/scan-file.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ATTACKS = join(__dirname, "..", "fixtures", "attacks");
const BENIGN = join(__dirname, "..", "fixtures", "benign");

const CANONICAL = [
  "controlChars",
  "hiddenHtml",
  "homoglyphs",
  "invisibleUnicode",
  "suspiciousPatterns",
];

function pinByCategory(result) {
  expect(result.summary).toBeDefined();
  expect(result.summary.byCategory).toBeDefined();
  expect(Object.keys(result.summary.byCategory).sort()).toEqual(CANONICAL);
}

function techniqueIds(findings) {
  return (findings || [])
    .map((f) => (f && typeof f.technique === "string" ? f.technique : ""))
    .filter(Boolean);
}

describe("T3-ODP odp parser: attack corpus", () => {
  it("odp_notes_prompt_injection.odp — speaker note instruction lights up", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "odp_notes_prompt_injection.odp"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).toContain("odp-notes-prompt-injection");
    const hits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "odp-notes-prompt-injection",
    );
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits[0].severity).toBe("danger");
    expect(typeof hits[0].meta.slideIndex).toBe("number");
  });

  it("odp_slide_transition_macro.odp — script-href transition lights up", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "odp_slide_transition_macro.odp"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).toContain("odp-slide-transition-macro");
    const hits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "odp-slide-transition-macro",
    );
    // Two findings: the event-listener and the sound href
    expect(hits.length).toBeGreaterThanOrEqual(2);
    expect(hits[0].severity).toBe("danger");
    expect(typeof hits[0].meta.scriptHref).toBe("string");
  });

  it("odp_embedded_object_external.odp — external draw:object href lights up", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "odp_embedded_object_external.odp"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).toContain("odp-embedded-object-external");
    const hits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "odp-embedded-object-external",
    );
    // content.xml has 2 draw:object refs + settings.xml carries 1 more = 3
    expect(hits.length).toBeGreaterThanOrEqual(2);
    expect(hits[0].severity).toBe("warning");
    expect(typeof hits[0].meta.objectHref).toBe("string");
  });
});

describe("T3-ODP odp parser: benign corpus (FP guard)", () => {
  it("benign_odp_basic.odp — plain ODP with harmless notes stays clean", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "benign_odp_basic.odp"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).not.toContain("odp-notes-prompt-injection");
    expect(ids).not.toContain("odp-slide-transition-macro");
    expect(ids).not.toContain("odp-embedded-object-external");
    expect(ids).not.toContain("odp-master-slide-instruction");
    expect(r.summary.dangerCount).toBe(0);
  });
});
