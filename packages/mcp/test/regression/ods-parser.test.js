/**
 * v1.20.0 T2 regression: OpenDocument Spreadsheet (.ods) parser corpus.
 *
 * Walks the 3 attack + 1 benign .ods fixture and pins:
 *   - Each attack lights up its dedicated kebab id (ods-formula-injection /
 *     ods-external-dde-link / ods-hidden-sheet-instruction) under category
 *     'suspiciousPatterns'.
 *   - The R13 5-key byCategory invariant survives every fixture.
 *   - Benign fixture stays clean (no danger findings, no ods-* kebab ids
 *     other than the expected zero).
 *
 * R12 invariant note: sheet name / ref / formula body only appear via
 * `escapeForDisplay`-passed `meta.sheetName` / `meta.ref` / `content`,
 * never as part of the kebab id itself.
 */

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scanFile } from "../../server/tools/scan-file.js";
import { parseOdsBuffer } from "../../server/parsers/ods.js";

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

describe("T2 ods parser: attack corpus", () => {
  it("ods_formula_injection.ods — formula injection lights up", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "ods_formula_injection.ods"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).toContain("ods-formula-injection");
    const hits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "ods-formula-injection",
    );
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits.some((f) => f.severity === "danger")).toBe(true);
  });

  it("ods_external_dde_link.ods — DDE link / settings external cmd lights up", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "ods_external_dde_link.ods"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).toContain("ods-external-dde-link");
    const hits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "ods-external-dde-link",
    );
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits.some((f) => f.severity === "danger")).toBe(true);
    // R12: source tag lives in meta, not in the kebab id.
    expect(hits[0].meta).toBeDefined();
    expect(typeof hits[0].meta.source).toBe("string");
  });

  it("ods_hidden_sheet_instruction.ods — hidden sheet instruction lights up", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "ods_hidden_sheet_instruction.ods"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).toContain("ods-hidden-sheet-instruction");
    const hits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "ods-hidden-sheet-instruction",
    );
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits[0].severity).toBe("danger");
    expect(hits[0].meta.isHidden).toBe(true);
  });
});

describe("T2 ods parser: benign corpus (FP guard)", () => {
  it("benign_ods_basic.ods — plain spreadsheet stays clean", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "benign_ods_basic.ods"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).not.toContain("ods-formula-injection");
    expect(ids).not.toContain("ods-external-dde-link");
    expect(ids).not.toContain("ods-hidden-sheet-instruction");
    expect(ids).not.toContain("ods-macro-bearing");
    expect(r.summary.dangerCount).toBe(0);
  });
});

describe("T2 ods parser: defensive guards (unit)", () => {
  it("oversize buffer (>15MB) yields ods-scan-limit warning and empty text", async () => {
    const big = new Uint8Array(16 * 1024 * 1024);
    for (let i = 0; i < big.length; i++) big[i] = 0x20;
    const out = await parseOdsBuffer(big);
    expect(out.fileType).toBe("ods");
    expect(out.text).toBe("");
    const hit = out.extraFindings.find((f) => f.technique === "ods-scan-limit");
    expect(hit).toBeDefined();
    expect(hit.severity).toBe("warning");
  });

  it("corrupt ZIP yields ods-corrupt-zip warning, no throw", async () => {
    const bad = new TextEncoder().encode("definitely not a zip archive");
    const out = await parseOdsBuffer(bad);
    expect(out.fileType).toBe("ods");
    expect(out.text).toBe("");
    const hit = out.extraFindings.find((f) => f.technique === "ods-corrupt-zip");
    expect(hit).toBeDefined();
    expect(hit.severity).toBe("warning");
  });
});
