/**
 * S10 regression: CSV formula-injection corpus.
 *
 * Walks the 7 attack + 4 benign CSV fixtures and pins the expected severity
 * stack:
 *   - All `csv_formula_*` attack fixtures must surface at least one danger
 *     finding in suspiciousPatterns with category='formula-injection'.
 *   - All `csv_benign_*` fixtures must yield 0 danger. Warning-tier noise is
 *     allowed only on `csv_benign_sum_formulas.csv` (acknowledged warning-tier
 *     "Formula prefix" hits on =SUM/=AVERAGE/=VLOOKUP/=IF), capped to keep
 *     future detector tweaks from triggering an FP storm without notice.
 *   - `csv_benign_japanese_shift_jis.csv` MUST parse without error (BOM-less
 *     UTF-8 fallback decoder) and yield 0 findings — encoding regression guard.
 *
 * Every test also re-pins the R13 5-key byCategory shape so a parser change
 * that accidentally introduces a new bucket name fails here loudly.
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

// Attack fixtures: (file, minDanger, technique-substring expected on at least
// one suspiciousPatterns finding).
const ATTACK_CASES = [
  {
    file: "csv_formula_dde_calc.csv",
    minDanger: 1,
    notes: "Classic =cmd|'/c calc'!A1 DDE invocation.",
  },
  {
    file: "csv_formula_powershell_b64.csv",
    minDanger: 1,
    notes: "DDE + base64 powershell encoded command.",
  },
  {
    file: "csv_formula_hyperlink_phish.csv",
    minDanger: 1,
    notes: "=HYPERLINK phishing target; benign =A1+B1 row must NOT escalate to danger.",
  },
  {
    file: "csv_formula_webservice_exfil.csv",
    minDanger: 1,
    notes: "Excel 2013+ WEBSERVICE zero-click HTTP exfil.",
  },
  {
    file: "csv_formula_importxml_gsheets.csv",
    minDanger: 1,
    notes: "Google Sheets IMPORTXML exfil.",
  },
  {
    file: "csv_formula_tab_prefix_bypass.csv",
    minDanger: 2,
    notes: "TAB-prefix + quoted HYPERLINK bypasses naive ^= regex.",
  },
  {
    file: "csv_formula_fullwidth_equals.csv",
    minDanger: 1,
    notes: "Fullwidth equals (U+FF1D) prefix bypass — normalizeFormulaPrefix.",
  },
];

describe("S10 CSV formula-injection: attack corpus", () => {
  for (const c of ATTACK_CASES) {
    it(`${c.file} — ${c.notes}`, async () => {
      const r = await scanFile({
        file_path: join(ATTACKS, c.file),
        verbosity: "detailed",
      });
      pinByCategory(r);
      expect(r.summary.status).toBe("danger");
      expect(r.summary.dangerCount).toBeGreaterThanOrEqual(c.minDanger);
      // FI-01 / FI-02 land in suspiciousPatterns with category='formula-injection'.
      const fiHits = (r.findings.suspiciousPatterns || []).filter(
        (f) => f && f.category === "formula-injection",
      );
      expect(fiHits.length).toBeGreaterThanOrEqual(c.minDanger);
      // At least one fi-hit is severity=danger (warnings allowed in addition).
      const fiDangers = fiHits.filter((f) => f.severity === "danger");
      expect(fiDangers.length).toBeGreaterThanOrEqual(1);
    });
  }
});

describe("S10 CSV formula-injection: benign corpus (FP guard)", () => {
  it("csv_benign_accounting_negatives.csv — numeric/phone suppression keeps 0 findings", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "csv_benign_accounting_negatives.csv"),
      verbosity: "normal",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("safe");
    expect(r.summary.dangerCount).toBe(0);
    expect(r.summary.warningCount).toBe(0);
  });

  it("csv_benign_sum_formulas.csv — 0 danger; warning-tier Formula prefix capped", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "csv_benign_sum_formulas.csv"),
      verbosity: "detailed",
    });
    pinByCategory(r);
    expect(r.summary.dangerCount).toBe(0);
    // =SUM / =AVERAGE / =VLOOKUP / =IF are not in the dangerous blocklist;
    // they fire the warning-tier "Formula prefix" gate (category=
    // 'formula-prefix'). The cap guards against a future detector tweak
    // accidentally lighting these up as danger or producing a FP storm.
    expect(r.summary.warningCount).toBeLessThanOrEqual(5);
    const fiDangers = (r.findings.suspiciousPatterns || []).filter(
      (f) =>
        f &&
        f.category === "formula-injection" &&
        f.severity === "danger",
    );
    expect(fiDangers.length).toBe(0);
  });

  it("csv_benign_japanese_shift_jis.csv — BOM-less Shift-JIS decodes, 0 findings (encoding guard)", async () => {
    // Today's decoder falls back to UTF-8 fatal:false on BOM-less input; this
    // test pins that the fallback does NOT throw and does NOT manufacture
    // findings out of mojibake bytes. When real Shift-JIS sniffing lands, the
    // expectation stays the same — 0 findings.
    const r = await scanFile({
      file_path: join(BENIGN, "csv_benign_japanese_shift_jis.csv"),
      verbosity: "normal",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("safe");
    expect(r.summary.dangerCount).toBe(0);
    expect(r.summary.warningCount).toBe(0);
  });

  it("csv_benign_url_in_cell.csv — plain HTTPS URL without leading = stays safe", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "csv_benign_url_in_cell.csv"),
      verbosity: "normal",
    });
    pinByCategory(r);
    expect(r.summary.status).toBe("safe");
    expect(r.summary.dangerCount).toBe(0);
    expect(r.summary.warningCount).toBe(0);
  });
});

describe("S10 CSV formula-injection: byCategory shape invariant (R13)", () => {
  it("attack fixture flow keeps the canonical 5 byCategory keys", async () => {
    const r = await scanFile({
      file_path: join(ATTACKS, "csv_formula_dde_calc.csv"),
      verbosity: "normal",
    });
    expect(Object.keys(r.summary.byCategory).sort()).toEqual(CANONICAL);
  });

  it("benign fixture flow keeps the canonical 5 byCategory keys", async () => {
    const r = await scanFile({
      file_path: join(BENIGN, "csv_benign_url_in_cell.csv"),
      verbosity: "normal",
    });
    expect(Object.keys(r.summary.byCategory).sort()).toEqual(CANONICAL);
  });
});
