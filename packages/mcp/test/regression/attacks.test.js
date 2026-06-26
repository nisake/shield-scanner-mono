/**
 * Attack corpus regression tests.
 *
 * For every fixture in test/fixtures/attacks/ with currentlyDetected=true:
 *   - the scanner MUST surface at least 1 finding in the expected category
 *   - overall status must be "danger" or "warning" (never "safe")
 *
 * For fixtures with currentlyDetected=false (M1/M2/future targets):
 *   - we DOCUMENT the current miss with a passing test. When detection lands,
 *     flip currentlyDetected in the fixture metadata to true and the strict
 *     branch will start guarding the new capability.
 *
 * This file is the safety net for "did we break a detector?".
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { analyze } from "@shield-scanner/core";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ATTACKS_DIR = join(__dirname, "..", "fixtures", "attacks");

// Lightweight fileType inference shared with false-positives.test.js: HTML
// tags win, Markdown image syntax escalates "text" to "markdown" so the
// hiddenHtml-gated detectors (incl. S4) actually run on .md-style payloads.
function inferFileType(text) {
  if (/<[a-z][\s\S]*>/i.test(text)) return "html";
  if (/!\[[^\]]*\]\(/.test(text)) return "markdown";
  return "text";
}

const index = JSON.parse(readFileSync(join(ATTACKS_DIR, "index.json"), "utf8"));
const indexByFile = new Map(index.map((e) => [e.file, e]));

// Sanity: every .txt file on disk must have an index entry
const txtFiles = readdirSync(ATTACKS_DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

describe("attack corpus: index integrity", () => {
  it("every .txt file has an index.json entry", () => {
    for (const f of txtFiles) {
      expect(indexByFile.has(f), `missing index entry for ${f}`).toBe(true);
    }
  });

  it("has at least 5 attack patterns (project minimum)", () => {
    expect(txtFiles.length).toBeGreaterThanOrEqual(5);
  });
});

describe("attack corpus: currently-detected fixtures must trigger detector", () => {
  const detectedFixtures = txtFiles.filter(
    (f) => indexByFile.get(f)?.currentlyDetected === true
  );

  it("has at least 5 currently-detected fixtures (so the safety net is meaningful)", () => {
    expect(detectedFixtures.length).toBeGreaterThanOrEqual(5);
  });

  for (const file of detectedFixtures) {
    const meta = indexByFile.get(file);
    it(`${file} — ${meta.notes}`, () => {
      const text = readFileSync(join(ATTACKS_DIR, file), "utf8");
      const fileType = inferFileType(text);
      const r = analyze(text, { fileType });

      // Overall: must not be 'safe'
      expect(r.summary.status, `expected non-safe status for ${file}`).not.toBe(
        "safe"
      );
      expect(r.summary.total).toBeGreaterThanOrEqual(1);

      // At least one expected category fired
      const firedAny = meta.expectCategories.some(
        (cat) => r.summary.byCategory[cat] > 0
      );
      expect(
        firedAny,
        `expected at least one of [${meta.expectCategories.join(
          ", "
        )}] to fire, got ${JSON.stringify(r.summary.byCategory)}`
      ).toBe(true);
    });
  }
});

describe("attack corpus: future-target fixtures document expected gaps", () => {
  const gapFixtures = txtFiles.filter(
    (f) => indexByFile.get(f)?.currentlyDetected === false
  );

  for (const file of gapFixtures) {
    const meta = indexByFile.get(file);
    it(`${file} — currently MISSED (${meta.notes})`, () => {
      const text = readFileSync(join(ATTACKS_DIR, file), "utf8");
      const fileType = inferFileType(text);
      const r = analyze(text, { fileType });

      // Right now we expect the EXPECTED categories NOT to fire.
      // When detection lands, this test will fail loudly — that's the signal
      // to flip currentlyDetected:true in index.json (regenerate via
      // node test/fixtures/_generate.js).
      const firedAny = meta.expectCategories.some(
        (cat) => r.summary.byCategory[cat] > 0
      );
      expect(
        firedAny,
        `${file} now triggers ${JSON.stringify(
          r.summary.byCategory
        )}. If this is intentional new coverage, edit _generate.js to set currentlyDetected:true and rerun the generator.`
      ).toBe(false);
    });
  }
});
