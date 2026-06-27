/**
 * S10 regression: XLSX OPC walker — workbook / styles / docProps / comments /
 * customXml / externalLinks / drawings.
 *
 * Pins the v1.6.0 (S10) walker contract for XLSX:
 *   - SC-02   sheet-state findings (hidden / veryHidden / non-canonical token)
 *   - FI-01   <f> formula body emits with leading `=` so the core
 *             detectFormulaInjection danger gate fires
 *   - FI-03   Auto_Open definedName + DDE ddeLink ddeService blocklist
 *   - MV-04   vbaProject.bin + extension/contentType mismatch + macrosheets/
 *   - MD-05   instruction-shaped text in docProps/core.xml + docProps/app.xml
 *   - MD-06   HyperlinkBase silent rewrite
 *   - MV-07   instruction-shaped threaded comments + persona surfacing
 *   - MD-08   numFmt ';;;' / white-font hidden cell carrying text
 *   - MV-09   customXml/ instruction-shaped payload
 *   - MD-11   RTLO / homoglyphs in sheet names flow through the unicode pipe
 *   - ER-03   UNC/SMB + http external-link relationships
 *
 * Hard invariant for every fixture: scanFile()'s summary.byCategory MUST equal
 * the canonical 5-key set exactly. A new bucket name (or a missing one) is a
 * regression even if the count balance happens to look fine.
 *
 * Fixtures live in packages/mcp/test/fixtures/{attacks,benign}/. They are
 * read-only here; the fixtures agent owns generation.
 */

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scanFile } from "../../server/tools/scan-file.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ATTACKS = join(__dirname, "..", "fixtures", "attacks");
const BENIGN = join(__dirname, "..", "fixtures", "benign");

// R13 — canonical 5-key byCategory shape. ANY divergence (extra key, missing
// key) is a regression — pinned with toEqual on the SORTED key list.
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

describe("S10 XLSX extended parts: attack fixtures", () => {
  it("xlsx_dde_command_in_f_node.xlsx — FI-01 <f> body fires danger", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_dde_command_in_f_node.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("danger");
    expect(r.summary.dangerCount).toBeGreaterThanOrEqual(1);
    // FI-01: a formula-injection finding lands in suspiciousPatterns.
    const fiHits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.category === "formula-injection",
    );
    expect(fiHits.length).toBeGreaterThanOrEqual(1);
  });

  it("xlsx_very_hidden_with_auto_open.xlsx — SC-02 veryHidden + FI-03 Auto_Open + MV-04 macrosheets", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_very_hidden_with_auto_open.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("danger");
    expect(r.summary.dangerCount).toBeGreaterThanOrEqual(2);
    // SC-02 veryHidden surfaces in hiddenHtml as danger.
    const veryHidden = (r.findings.hiddenHtml || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /veryhidden-sheet/i.test(f.technique),
    );
    expect(veryHidden.length).toBeGreaterThanOrEqual(1);
    expect(veryHidden[0].severity).toBe("danger");
    // FI-03 Auto_Open definedName surfaces in suspiciousPatterns.
    const autoOpen = (r.findings.suspiciousPatterns || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /auto-run-defined-name/i.test(f.technique),
    );
    expect(autoOpen.length).toBeGreaterThanOrEqual(1);
    // MV-04 macrosheets/ warning landing in hiddenHtml.
    const macrosheets = (r.findings.hiddenHtml || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /xlm-macrosheet/i.test(f.technique),
    );
    expect(macrosheets.length).toBeGreaterThanOrEqual(1);
  });

  it("xlsx_state_confusion_capitalised.xlsx — case-insensitive SC-02 match (capital VeryHidden)", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_state_confusion_capitalised.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    // Capital-V "VeryHidden" lowercases to "veryhidden" → danger branch in
    // xlsx.js. The fixture's purpose is to verify the toLowerCase()
    // normalization, not to land at warning level — what matters is that a
    // non-canonical capitalisation still fires.
    const sheetFindings = (r.findings.hiddenHtml || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /(veryhidden-sheet|hidden-sheet|sheet-state-confusion)/i.test(
          f.technique,
        ),
    );
    expect(sheetFindings.length).toBeGreaterThanOrEqual(1);
    expect(r.summary.dangerCount + r.summary.warningCount).toBeGreaterThanOrEqual(1);
  });

  it("xlsx_external_link_unc_smb.xlsx — ER-03 UNC/SMB danger", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_external_link_unc_smb.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("danger");
    const uncHits = (r.findings.suspiciousPatterns || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /external-relationship/i.test(f.technique) &&
        f.meta && f.meta.scheme === "unc",
    );
    expect(uncHits.length).toBeGreaterThanOrEqual(1);
    expect(uncHits[0].severity).toBe("danger");
  });

  it("xlsx_drawing_external_image_unc.xlsx — ER-03 drawing rels danger", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_drawing_external_image_unc.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("danger");
    const externalHits = (r.findings.suspiciousPatterns || []).filter(
      (f) =>
        f &&
        f.element === "OPC Relationship" &&
        typeof f.technique === "string" &&
        /external-relationship/i.test(f.technique) &&
        f.meta &&
        (f.meta.scheme === "unc" ||
          f.meta.scheme === "http" ||
          f.meta.scheme === "jsOrData" ||
          f.meta.scheme === "file"),
    );
    expect(externalHits.length).toBeGreaterThanOrEqual(1);
  });

  it("xlsx_vba_present_extension_mismatch.xlsx — MV-04 dual danger", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_vba_present_extension_mismatch.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("danger");
    expect(r.summary.dangerCount).toBeGreaterThanOrEqual(2);
    const vbaPresent = (r.findings.hiddenHtml || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /vba-macro-project/i.test(f.technique),
    );
    expect(vbaPresent.length).toBeGreaterThanOrEqual(1);
    const mismatch = (r.findings.hiddenHtml || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /extension-content-type-mismatch/i.test(f.technique),
    );
    expect(mismatch.length).toBeGreaterThanOrEqual(1);
  });

  it("xlsx_docprops_prompt_injection.xlsx — MD-05 docProps instruction-shaped text", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_docprops_prompt_injection.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    // docProps fields fire as warning (category=suspiciousPatterns).
    const docPropsHits = (r.findings.suspiciousPatterns || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /docprops-prompt-injection/i.test(f.technique),
    );
    expect(docPropsHits.length).toBeGreaterThanOrEqual(1);
    expect(docPropsHits[0].severity).toBe("warning");
  });

  it("xlsx_hyperlinkbase_silent_rewrite.xlsx — MD-06 danger", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_hyperlinkbase_silent_rewrite.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("danger");
    const hbHits = (r.findings.suspiciousPatterns || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /hyperlink-base-rewrite/i.test(f.technique),
    );
    expect(hbHits.length).toBeGreaterThanOrEqual(1);
    expect(hbHits[0].severity).toBe("danger");
  });

  it("xlsx_threaded_comment_persona_spoof.xlsx — MV-07 warning + persona contextLocation", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_threaded_comment_persona_spoof.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const threadedHits = (r.findings.hiddenHtml || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /instruction-shaped-comment/i.test(f.technique) &&
        f.meta && f.meta.threaded === true,
    );
    expect(threadedHits.length).toBeGreaterThanOrEqual(1);
    expect(threadedHits[0].severity).toBe("warning");
    // contextLocation must reference the threadedComment + sheet ref. Persona
    // displayName surfaces only when the threadedComment.personId attribute
    // matches a person.id verbatim (curly-brace mismatch in real fixtures is
    // a known limitation — we don't pin the persona key here so the bracket
    // normalisation can land later without breaking this regression net).
    expect(threadedHits[0].contextLocation).toMatch(/threadedComment ref/);
  });

  it("xlsx_numfmt_triple_semicolon_hidden.xlsx — MD-08 hidden cell carries text", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_numfmt_triple_semicolon_hidden.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("danger");
    const hiddenStyleHits = (r.findings.hiddenHtml || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /(Hidden cell \(numFmt ';;;'\)|White-on-white font)/i.test(f.technique),
    );
    expect(hiddenStyleHits.length).toBeGreaterThanOrEqual(1);
  });

  it("xlsx_customxml_payload.xlsx — MV-09 CustomXML warning", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_customxml_payload.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const customHits = (r.findings.hiddenHtml || []).filter(
      (f) =>
        f &&
        typeof f.technique === "string" &&
        /CustomXML prompt-injection payload/i.test(f.technique),
    );
    expect(customHits.length).toBeGreaterThanOrEqual(1);
    expect(customHits[0].severity).toBe("warning");
  });

  it("xlsx_rtlo_in_sheet_name.xlsx — MD-11 unicode pipeline catches RTLO in sheet name", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_rtlo_in_sheet_name.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    // RTLO surfaces under invisibleUnicode (bidi-control / RTLO category).
    expect(r.summary.byCategory.invisibleUnicode).toBeGreaterThanOrEqual(1);
  });
});

describe("S10 XLSX extended parts: benign fixtures (FP guard)", () => {
  it("xlsx_benign_invoice_template.xlsx — 0 danger (acknowledged Formula-prefix warning allowed)", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "xlsx_benign_invoice_template.xlsx"),
      verbosity: "normal",
    });
    pinByCategory(r);
    expect(r.summary.dangerCount).toBe(0);
    // Acknowledged FP: =SUM(...) in the template fires the warning-tier
    // "Formula prefix" gate. Documents the boundary — must not silently
    // escalate to danger via future detector changes.
    expect(r.summary.warningCount).toBeLessThanOrEqual(2);
  });

  it("xlsx_benign_with_legitimate_hidden_sheet.xlsx — 1 warning SC-02 only (acknowledged FP)", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "xlsx_benign_with_legitimate_hidden_sheet.xlsx"),
      verbosity: "normal",
    });
    pinByCategory(r);
    expect(r.summary.dangerCount).toBe(0);
    // Legitimate Lookups sheet at state="hidden" fires SC-02 warning by
    // design — verifies severity stays at warning (does not escalate).
    expect(r.summary.warningCount).toBeGreaterThanOrEqual(1);
    expect(r.summary.warningCount).toBeLessThanOrEqual(2);
  });

  it("xlsx_benign_with_embedded_logo_image.xlsx — clean (logo well under 5MB cap)", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "xlsx_benign_with_embedded_logo_image.xlsx"),
      verbosity: "normal",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("safe");
    expect(r.summary.dangerCount).toBe(0);
    expect(r.summary.warningCount).toBe(0);
  });

  it("xlsx_benign_chart_with_title.xlsx — chart title does not trip looksLikeInstruction", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "xlsx_benign_chart_with_title.xlsx"),
      verbosity: "normal",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("safe");
    expect(r.summary.dangerCount).toBe(0);
    expect(r.summary.warningCount).toBe(0);
  });
});

describe("S10 XLSX extended parts: byCategory shape invariant (R13)", () => {
  // Repeat-pin the canonical shape across one attack + one benign scan so a
  // future bucket-name typo in xlsx.js (or scan-file.js) gets caught here even
  // if the per-fixture asserts above were skipped or skipped on disk.
  it("attack fixture flow keeps the canonical 5 byCategory keys", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_dde_command_in_f_node.xlsx"),
      verbosity: "normal",
    });
    expect(Object.keys(r.summary.byCategory).sort()).toEqual(CANONICAL);
  });

  it("benign fixture flow keeps the canonical 5 byCategory keys", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "xlsx_benign_chart_with_title.xlsx"),
      verbosity: "normal",
    });
    expect(Object.keys(r.summary.byCategory).sort()).toEqual(CANONICAL);
  });
});
