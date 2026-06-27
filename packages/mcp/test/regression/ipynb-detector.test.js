/**
 * v1.19.0 B3 regression: Jupyter Notebook (.ipynb) parser corpus.
 *
 * Walks the 4 attack + 2 benign fixtures and pins:
 *   - Each attack lights up its dedicated kebab id (ipynb-output-html-injection
 *     / ipynb-hidden-cell-instruction / ipynb-metadata-tag-smuggle /
 *     ipynb-untrusted-signature) under category 'suspiciousPatterns'.
 *   - The R13 5-key byCategory invariant survives every fixture.
 *   - Benign fixtures stay clean (no danger findings, signed notebooks do
 *     NOT trip the untrusted-signature warning).
 *
 * R12 invariant note: tag / source text only appears under `meta.tag` /
 * `meta.cellType` and inside `content` (which the parser passes through
 * escapeForDisplay), never as part of the kebab id itself.
 */

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scanFile } from "../../server/tools/scan-file.js";
import { parseIpynbBuffer } from "../../server/parsers/ipynb.js";

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

describe("B3 ipynb parser: attack corpus", () => {
  it("ipynb_output_html_injection.ipynb — output cell HTML / JS lights up", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "ipynb_output_html_injection.ipynb"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).toContain("ipynb-output-html-injection");
    // Both the text/html output and the application/javascript output should
    // surface; the parser emits one finding per MIME type per output cell.
    const htmlHits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "ipynb-output-html-injection",
    );
    expect(htmlHits.length).toBeGreaterThanOrEqual(2);
    // Severity stack: at least one danger.
    expect(htmlHits.some((f) => f.severity === "danger")).toBe(true);
    // R12: cell index / mime live in `meta`, not in the kebab id.
    expect(htmlHits[0].meta).toBeDefined();
    expect(typeof htmlHits[0].meta.cellIndex).toBe("number");
    expect(typeof htmlHits[0].meta.mime).toBe("string");
  });

  it("ipynb_hide_input_instruction.ipynb — hidden-source instruction lights up", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "ipynb_hide_input_instruction.ipynb"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).toContain("ipynb-hidden-cell-instruction");
    const hits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "ipynb-hidden-cell-instruction",
    );
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits[0].severity).toBe("danger");
    expect(Array.isArray(hits[0].meta.hideSignals)).toBe(true);
    expect(hits[0].meta.hideSignals.length).toBeGreaterThan(0);
  });

  it("ipynb_metadata_tag_smuggle.ipynb — instruction-shaped tag lights up", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "ipynb_metadata_tag_smuggle.ipynb"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).toContain("ipynb-metadata-tag-smuggle");
    const hits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "ipynb-metadata-tag-smuggle",
    );
    expect(hits.length).toBeGreaterThanOrEqual(2);
    // At least one is danger (instruction-shaped tag), at least one warning
    // (hide-* tag without instruction content) is fine.
    expect(hits.some((f) => f.severity === "danger")).toBe(true);
  });

  it("ipynb_untrusted_signature.ipynb — missing signature lights up", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "ipynb_untrusted_signature.ipynb"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).toContain("ipynb-untrusted-signature");
    const hits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "ipynb-untrusted-signature",
    );
    expect(hits.length).toBe(1);
    expect(hits[0].severity).toBe("warning");
    expect(hits[0].meta.nbformat).toBe(4);
  });
});

describe("B3 ipynb parser: benign corpus (FP guard)", () => {
  it("benign_ipynb_data_analysis.ipynb — signed notebook with benign tags stays clean", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "benign_ipynb_data_analysis.ipynb"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const ids = techniqueIds(r.findings.suspiciousPatterns);
    expect(ids).not.toContain("ipynb-output-html-injection");
    expect(ids).not.toContain("ipynb-hidden-cell-instruction");
    expect(ids).not.toContain("ipynb-metadata-tag-smuggle");
    expect(ids).not.toContain("ipynb-untrusted-signature");
    expect(r.summary.dangerCount).toBe(0);
  });

  it("benign_ipynb_markdown_only.ipynb — markdown-only signed notebook stays clean", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "benign_ipynb_markdown_only.ipynb"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    expect(r.summary.dangerCount).toBe(0);
    expect(r.summary.warningCount).toBe(0);
  });
});

describe("B3 ipynb parser: defensive guards (unit)", () => {
  it("oversize buffer (>10MB) yields ipynb-scan-limit warning and empty text", async () => {
    const big = new Uint8Array(11 * 1024 * 1024);
    for (let i = 0; i < big.length; i++) big[i] = 0x20; // spaces — JSON-invalid
    const out = await parseIpynbBuffer(big);
    expect(out.fileType).toBe("ipynb");
    expect(out.text).toBe("");
    const hit = out.extraFindings.find((f) => f.technique === "ipynb-scan-limit");
    expect(hit).toBeDefined();
    expect(hit.severity).toBe("warning");
  });

  it("corrupt JSON yields ipynb-corrupt-json warning, no throw", async () => {
    const bad = new TextEncoder().encode("{not really json");
    const out = await parseIpynbBuffer(bad);
    expect(out.fileType).toBe("ipynb");
    expect(out.text).toBe("");
    const hit = out.extraFindings.find((f) => f.technique === "ipynb-corrupt-json");
    expect(hit).toBeDefined();
    expect(hit.severity).toBe("warning");
  });

  it("non-object root JSON (e.g. array) returns empty text, no findings, no throw", async () => {
    const arr = new TextEncoder().encode("[1, 2, 3]");
    const out = await parseIpynbBuffer(arr);
    expect(out.fileType).toBe("ipynb");
    expect(out.text).toBe("");
    expect(out.extraFindings.length).toBe(0);
  });
});
