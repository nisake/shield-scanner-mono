/**
 * False-positive regression tests.
 *
 * Scans the normal/ corpus and pins TODAY's danger/warning counts as the
 * baseline. If a future detector tweak starts flagging legitimate Japanese,
 * legitimate emoji, or product codes as dangerous, this file fails.
 *
 * Policy:
 *   - dangerCount on any normal fixture MUST stay 0. Hard wall.
 *   - warningCount: pinned to the current baseline. If new warnings appear,
 *     either the change is wanted (update BASELINE_WARNINGS in the same
 *     commit, with a justification) or it's a regression (fix the detector).
 *
 * Risk #2 guardrail: VS / IVS detection MUST NOT introduce FPs on
 * legitimate Japanese (02-japanese-ivs.txt) or emoji (04-emoji.txt).
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { analyze } from "@shield-scanner/core";

const __dirname = dirname(fileURLToPath(import.meta.url));
const NORMAL_DIR = join(__dirname, "..", "fixtures", "normal");

// Baseline pinned from observed behavior on 2026-06-25.
// Update DELIBERATELY (with reason) when intentionally tuning detectors.
const BASELINE_WARNINGS = {
  "01-japanese-prose.txt": 0,
  "02-japanese-ivs.txt": 0, // U+E0100 is Plane 14, NOT PUA; currently not flagged
  "03-english-prose.txt": 0,
  "04-emoji.txt": 0,
  "05-product-codes.txt": 0,
  // S4: legitimate Markdown image URLs. Firebase `token=`, S3 `X-Amz-*`,
  // Discord CDN `hm=/ex=/is=`, Mermaid base64 paths — every one of these
  // would land in the "looks suspicious" zone for a substring matcher, but
  // our strict key list keeps the count at 0.
  "06-md-images.txt": 0,
  // v1.9.0 md-exfil FP safety-net expansion. The next agent will relax the
  // weak-key threshold (weak>=2 -> weak>=1) for md-image-exfil. These three
  // benign corpora prove the safety net BEFORE the relax: real-world
  // analytics / signed-CDN / safe-host-with-noisy-keys URLs must stay quiet
  // under the current weak>=2 detector and continue to stay quiet once the
  // threshold tightens.
  "benign_analytics_utm.txt": 0,
  "benign_cdn_signed.txt": 0,
  "benign_image_hosts_weak_key.txt": 0,
  // v1.10.0 Theme B: Markdown heading impersonation pattern fires warning on
  // legitimate `## System:` / `### Developer:` section headings in API-doc /
  // RLHF blog prose. Two hits stays UNDER the 3-hit TRANSCRIPT_NOISE threshold
  // (priority.js), so topFindings stays empty — the warning shows up in the
  // detail list but never lands on the banner. dangerCount remains 0.
  "benign_markdown_heading_blog.txt": 2,
};

// Lightweight fileType inference: HTML wins on raw tags, markdown on image
// syntax, otherwise plain text. Matches the contract used by attacks.test.js
// so the same fixture exercises the same detector path here.
function inferFileType(text) {
  if (/<[a-z][\s\S]*>/i.test(text)) return "html";
  if (/!\[[^\]]*\]\(/.test(text)) return "markdown";
  return "text";
}

const txtFiles = readdirSync(NORMAL_DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

describe("false positives: hard wall — no danger on normal corpus", () => {
  for (const file of txtFiles) {
    it(`${file} produces 0 danger findings`, () => {
      const text = readFileSync(join(NORMAL_DIR, file), "utf8");
      const fileType = inferFileType(text);
      const r = analyze(text, { fileType });
      expect(
        r.summary.dangerCount,
        `${file} flagged as danger: ${JSON.stringify(r.summary.byCategory)}`
      ).toBe(0);
    });
  }
});

describe("false positives: warning counts pinned to baseline", () => {
  for (const file of txtFiles) {
    const baseline = BASELINE_WARNINGS[file];
    it(`${file} warning count = ${baseline} (baseline)`, () => {
      expect(
        baseline,
        `no baseline entry for ${file}; add to BASELINE_WARNINGS in false-positives.test.js`
      ).toBeTypeOf("number");

      const text = readFileSync(join(NORMAL_DIR, file), "utf8");
      const fileType = inferFileType(text);
      const r = analyze(text, { fileType });

      expect(
        r.summary.warningCount,
        `${file} warnings drifted: expected ${baseline}, got ${
          r.summary.warningCount
        } — ${JSON.stringify(r.summary.byCategory)}`
      ).toBe(baseline);
    });
  }
});

// S18: topFindings hard wall. The banner is the most prominent surface in the
// LLM JSON and the Web UI, so a single false positive here is doubly costly.
// Every file in the normal corpus must produce ZERO entries on the banner.
describe("false positives: topFindings hard wall on normal corpus", () => {
  for (const file of txtFiles) {
    it(`${file} produces summary.topFindings === []`, () => {
      const text = readFileSync(join(NORMAL_DIR, file), "utf8");
      const fileType = inferFileType(text);
      const r = analyze(text, { fileType });
      expect(
        r.summary.topFindings,
        `${file} surfaced ${JSON.stringify(r.summary.topFindings)} on the banner`,
      ).toEqual([]);
    });
  }
});

describe("false positives: aggregate sanity", () => {
  it("total warnings across the normal corpus stay <= the baseline sum", () => {
    const baselineTotal = Object.values(BASELINE_WARNINGS).reduce(
      (a, b) => a + b,
      0
    );
    let observed = 0;
    for (const file of txtFiles) {
      const text = readFileSync(join(NORMAL_DIR, file), "utf8");
      const fileType = inferFileType(text);
      observed += analyze(text, { fileType }).summary.warningCount;
    }
    expect(
      observed,
      `normal-corpus FP warnings rose from ${baselineTotal} to ${observed}. Review the detector change.`
    ).toBeLessThanOrEqual(baselineTotal);
  });
});
