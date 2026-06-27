/**
 * v1.19.0 B2 — RTF detector regression.
 *
 * Six new kebab signals (all fold to category:'suspiciousPatterns'):
 *   - rtf-ole-object            (danger — \objdata / \objclass)
 *   - rtf-field-hyperlink       (warning — \field { HYPERLINK ... })
 *   - rtf-hidden-text-v         (warning — \v hidden text run)
 *   - rtf-microscopic-font      (warning — \fs <= 8 i.e. <= 4pt)
 *   - rtf-binary-block          (warning — \binN, N >= 8)
 *   - rtf-unknown-destination   (warning — \* unknown destination)
 *
 * Guardrails verified by these tests:
 *   - R12: meta carries only detector-controlled values (objclass, url scheme
 *          + host, byteCount, fontSize, charCount, destination). Raw RTF
 *          body text never appears in `content` / `meta`.
 *   - R13: every finding carries category:'suspiciousPatterns' so the global
 *         5-key byCategory contract stays intact.
 *   - FP guard: 2 benign fixtures (plain letter, RTF with hex-encoded image)
 *         emit ZERO v1.19.0 RTF findings.
 */

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { parseRtfBuffer } from "../../server/parsers/rtf.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ATTACK_DIR = resolve(__dirname, "../fixtures/attacks");
const BENIGN_DIR = resolve(__dirname, "../fixtures/benign");

const V19_RTF_KEBABS = new Set([
  "rtf-ole-object",
  "rtf-field-hyperlink",
  "rtf-hidden-text-v",
  "rtf-microscopic-font",
  "rtf-binary-block",
  "rtf-unknown-destination",
]);

async function loadFixture(dir, name) {
  const buf = await readFile(resolve(dir, name));
  return parseRtfBuffer(buf);
}

function pickKebab(out, technique) {
  return (out.extraFindings || []).filter((f) => f.technique === technique);
}

function v19Findings(out) {
  return (out.extraFindings || []).filter((f) => V19_RTF_KEBABS.has(f.technique));
}

describe("v1.19.0 B2 RTF detector — positive cases", () => {
  it("rtf_objdata_ole.rtf emits rtf-ole-object (danger)", async () => {
    const out = await loadFixture(ATTACK_DIR, "rtf_objdata_ole.rtf");
    const hits = pickKebab(out, "rtf-ole-object");
    expect(hits.length).toBeGreaterThanOrEqual(1);
    const f = hits[0];
    expect(f.severity).toBe("danger");
    expect(f.category).toBe("suspiciousPatterns");
    expect(f.element).toBe("RTF OLE object");
    // R12: meta carries an objclass (may be null for bare \objdata, or the
    // class name when \objclass {Name} precedes it).
    expect(f.meta).toBeDefined();
    expect("objclass" in f.meta).toBe(true);
    // At least one OLE finding should carry the actual class name.
    const withClass = hits.filter((h) => h.meta && typeof h.meta.objclass === "string" && h.meta.objclass.length > 0);
    expect(withClass.length).toBeGreaterThanOrEqual(1);
  });

  it("rtf_field_hyperlink_exfil.rtf emits rtf-field-hyperlink (warning)", async () => {
    const out = await loadFixture(ATTACK_DIR, "rtf_field_hyperlink_exfil.rtf");
    const hits = pickKebab(out, "rtf-field-hyperlink");
    expect(hits.length).toBe(1);
    const f = hits[0];
    expect(f.severity).toBe("warning");
    expect(f.category).toBe("suspiciousPatterns");
    expect(f.element).toBe("RTF \\field hyperlink");
    // R12: url is sanitized to scheme+host (no path / query).
    expect(typeof f.meta.url).toBe("string");
    expect(f.meta.url).toMatch(/^http:\/\/attacker\.example\.com\/?$/);
    // The path /exfil?token=ABC must NOT leak through.
    expect(f.meta.url).not.toMatch(/exfil/);
    expect(f.meta.url).not.toMatch(/token/);
  });

  it("rtf_hidden_v_instruction.rtf emits rtf-hidden-text-v (warning)", async () => {
    const out = await loadFixture(ATTACK_DIR, "rtf_hidden_v_instruction.rtf");
    const hits = pickKebab(out, "rtf-hidden-text-v");
    expect(hits.length).toBeGreaterThanOrEqual(1);
    const f = hits[0];
    expect(f.severity).toBe("warning");
    expect(f.category).toBe("suspiciousPatterns");
    expect(typeof f.meta.charCount).toBe("number");
    expect(f.meta.charCount).toBeGreaterThan(0);
    // R12: hidden body itself must NOT appear in content or meta.
    expect(JSON.stringify(f)).not.toMatch(/ignore_all_previous_instructions/);
  });

  it("rtf_microscopic_fs6.rtf emits rtf-microscopic-font (warning) with fontSize=3", async () => {
    const out = await loadFixture(ATTACK_DIR, "rtf_microscopic_fs6.rtf");
    const hits = pickKebab(out, "rtf-microscopic-font");
    expect(hits.length).toBeGreaterThanOrEqual(1);
    const f = hits[0];
    expect(f.severity).toBe("warning");
    expect(f.category).toBe("suspiciousPatterns");
    expect(f.meta.fontSize).toBe(3); // \fs6 -> 3pt
  });

  it("rtf_bin_payload.rtf emits rtf-binary-block (warning) with byteCount=64", async () => {
    const out = await loadFixture(ATTACK_DIR, "rtf_bin_payload.rtf");
    const hits = pickKebab(out, "rtf-binary-block");
    expect(hits.length).toBeGreaterThanOrEqual(1);
    const f = hits[0];
    expect(f.severity).toBe("warning");
    expect(f.category).toBe("suspiciousPatterns");
    expect(f.meta.byteCount).toBe(64);
  });
});

describe("v1.19.0 B2 RTF detector — R13 5-key invariant", () => {
  it("every RTF finding folds into suspiciousPatterns", async () => {
    const files = [
      ["attacks", "rtf_objdata_ole.rtf"],
      ["attacks", "rtf_field_hyperlink_exfil.rtf"],
      ["attacks", "rtf_hidden_v_instruction.rtf"],
      ["attacks", "rtf_microscopic_fs6.rtf"],
      ["attacks", "rtf_bin_payload.rtf"],
    ];
    for (const [dir, name] of files) {
      const out = await loadFixture(dir === "attacks" ? ATTACK_DIR : BENIGN_DIR, name);
      for (const f of v19Findings(out)) {
        expect(f.category).toBe("suspiciousPatterns");
      }
    }
  });
});

describe("v1.19.0 B2 RTF detector — false-positive guard (benign fixtures)", () => {
  it("benign_rtf_plain_letter.rtf emits zero RTF findings", async () => {
    const out = await loadFixture(BENIGN_DIR, "benign_rtf_plain_letter.rtf");
    const hits = v19Findings(out);
    expect(hits).toEqual([]);
  });

  it("benign_rtf_with_image.rtf emits zero RTF findings", async () => {
    const out = await loadFixture(BENIGN_DIR, "benign_rtf_with_image.rtf");
    const hits = v19Findings(out);
    // The hex-encoded \pict block has no \binN, no \objdata, no \field
    // HYPERLINK, no \v hidden text, no \fs<=8. Known destinations (fonttbl,
    // pict) keep \* unknown-destination quiet.
    expect(hits).toEqual([]);
  });
});

describe("v1.19.0 B2 RTF detector — R12 raw-text leak guard", () => {
  it("no extraFinding surfaces the hidden \\v body literally", async () => {
    const out = await loadFixture(ATTACK_DIR, "rtf_hidden_v_instruction.rtf");
    const joined = JSON.stringify(out.extraFindings || []);
    expect(joined).not.toMatch(/ignore_all_previous_instructions/);
  });

  it("no extraFinding surfaces the \\fs body literally", async () => {
    const out = await loadFixture(ATTACK_DIR, "rtf_microscopic_fs6.rtf");
    const joined = JSON.stringify(out.extraFindings || []);
    expect(joined).not.toMatch(/hidden_payload_for_llm_at_3pt/);
  });

  it("rtf-field-hyperlink meta.url scrubs path and query", async () => {
    const out = await loadFixture(ATTACK_DIR, "rtf_field_hyperlink_exfil.rtf");
    const hits = pickKebab(out, "rtf-field-hyperlink");
    expect(hits.length).toBe(1);
    expect(hits[0].meta.url).not.toMatch(/ABC/);
  });
});

describe("v1.19.0 B2 RTF parser — fileType + shape contract", () => {
  it("returns {text:'', fileType:'rtf', extraFindings:[...]} shape", async () => {
    const out = await loadFixture(ATTACK_DIR, "rtf_objdata_ole.rtf");
    expect(out.text).toBe("");
    expect(out.fileType).toBe("rtf");
    expect(Array.isArray(out.extraFindings)).toBe(true);
  });
});
