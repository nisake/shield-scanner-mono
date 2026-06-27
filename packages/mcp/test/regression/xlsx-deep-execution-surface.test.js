/**
 * v1.18.0 — XLSX deep-execution surface regression.
 *
 * Pins the new kebab-id contract added in v1.18.0:
 *   - xlsx-power-query-webcontents : Power Query M expressions in
 *     customXml/item*.xml that fetch over HTTP (Web.Contents /
 *     Csv.Document(Web.Contents(...))). Severity = danger.
 *   - xlsx-data-connection-shell   : xl/connections.xml OLEDB / ODBC connection
 *     string carrying shell-runner tokens (cmd / powershell / mshta / wscript
 *     / cscript / rundll32 / regsvr32). Severity = danger.
 *   - xlsx-activex-control         : xl/activeX/activeX*.bin presence (Equation
 *     Editor CVE family). Severity = warning.
 *   - xlsx-custom-ui-callback      : customUI/customUI*.xml ribbon callback
 *     attributes (onLoad / onAction etc.) naming VBA entrypoints. Severity =
 *     warning.
 *
 * Also re-confirms vba-macro-project still fires on a workbook saved with
 * a .xlsm extension (sanity check for the v1.18.0 deep-execution refactor).
 *
 * R13 invariant: every fixture's byCategory must equal the canonical 5-key set.
 */

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFile } from "node:fs/promises";
import { scanFile } from "../../server/tools/scan-file.js";
import { parseXlsxBuffer } from "../../server/parsers/xlsx.js";

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

describe("v1.18.0 XLSX deep-execution surface: attack fixtures", () => {
  it("xlsx_power_query_webcontents.xlsx surfaces xlsx-power-query-webcontents (danger)", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_power_query_webcontents.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const hit = (r.findings.suspiciousPatterns || []).find(
      (f) => f && f.technique === "xlsx-power-query-webcontents",
    );
    expect(hit, "no xlsx-power-query-webcontents finding").toBeDefined();
    expect(hit.severity).toBe("danger");
    expect(hit.meta && hit.meta.connectionType).toBe("powerQuery");
    expect(r.summary.dangerCount).toBeGreaterThanOrEqual(1);
  });

  it("xlsx_data_connection_oledb_cmd.xlsx surfaces xlsx-data-connection-shell (danger)", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_data_connection_oledb_cmd.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const hit = (r.findings.suspiciousPatterns || []).find(
      (f) => f && f.technique === "xlsx-data-connection-shell",
    );
    expect(hit, "no xlsx-data-connection-shell finding").toBeDefined();
    expect(hit.severity).toBe("danger");
    expect(hit.meta && hit.meta.hasShellKeyword).toBe(true);
  });

  it("xlsx_activex_equation_editor.xlsx surfaces xlsx-activex-control (warning)", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_activex_equation_editor.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const hit = (r.findings.suspiciousPatterns || []).find(
      (f) => f && f.technique === "xlsx-activex-control",
    );
    expect(hit, "no xlsx-activex-control finding").toBeDefined();
    expect(hit.severity).toBe("warning");
  });

  it("xlsx_custom_ui_onload_callback.xlsx surfaces xlsx-custom-ui-callback (warning)", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "xlsx_custom_ui_onload_callback.xlsx"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    const hits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "xlsx-custom-ui-callback",
    );
    expect(hits.length).toBeGreaterThanOrEqual(1);
    // We expect onLoad + onAction → at least 2 unique callbacks.
    expect(hits.some((h) => h.meta && /StartupHook|RunAttack/.test(h.meta.callbackName || ""))).toBe(true);
    expect(hits[0].severity).toBe("warning");
  });

  it("xlsx_vba_macro_present.xlsm — vba-macro-project still fires when parsed directly", async () => {
    // .xlsm is not in SUPPORTED_EXTENSIONS for scan-file (parseFile gate);
    // we call parseXlsxBuffer directly to verify the deep-execution refactor
    // didn't accidentally suppress vbaProject.bin on macro-bearing workbooks.
    const buf = await readFile(join(ATTACKS, "xlsx_vba_macro_present.xlsm"));
    const result = await parseXlsxBuffer(buf, { fileNameHint: "xlsx_vba_macro_present.xlsm" });
    expect(result.fileType).toBe("xlsx");
    const vba = (result.extraFindings || []).find(
      (f) => f && f.technique === "vba-macro-project",
    );
    expect(vba, "no vba-macro-project finding on .xlsm").toBeDefined();
    expect(vba.severity).toBe("danger");
  });
});

describe("v1.18.0 XLSX deep-execution surface: benign fixtures (FP guard)", () => {
  it("benign_xlsx_legit_connections_https.xlsx — does NOT fire xlsx-data-connection-shell", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "benign_xlsx_legit_connections_https.xlsx"),
      verbosity: "normal",
    });
    pinByCategory(r);
    const shellHits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "xlsx-data-connection-shell",
    );
    expect(shellHits.length).toBe(0);
    expect(r.summary.dangerCount).toBe(0);
  });

  it("benign_xlsx_pivot_table_query.xlsx — does NOT fire xlsx-power-query-webcontents", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "benign_xlsx_pivot_table_query.xlsx"),
      verbosity: "normal",
    });
    pinByCategory(r);
    const pqHits = (r.findings.suspiciousPatterns || []).filter(
      (f) => f && f.technique === "xlsx-power-query-webcontents",
    );
    expect(pqHits.length).toBe(0);
    expect(r.summary.dangerCount).toBe(0);
  });
});
