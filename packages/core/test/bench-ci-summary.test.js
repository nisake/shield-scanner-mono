/**
 * bench-ci-summary + bench-regression-gate unit tests.
 *
 * v1.20.0 T5-BENCH-CI: cover the pure functions extracted from the two new
 * CI helpers so the GitHub Actions workflow has a unit-tested safety net.
 *
 * These tests intentionally do NOT execute the CLI scripts themselves —
 * importing them would run main() and call process.exit(). Both modules
 * gate the main() call behind `import.meta.url === file://process.argv[1]`,
 * and they export buildMarkdown / diffRegressions for direct exercise.
 *
 * No fixtures, no fs, no network — pure object inputs.
 */

import { describe, it, expect } from "vitest";
import { buildMarkdown } from "../../../tools/bench-ci-summary.mjs";
import { diffRegressions } from "../../../tools/bench-regression-gate.mjs";

const MIN_BENCH = {
  schemaVersion: 1,
  generatorVersion: "v1.20.0",
  sourceDateEpoch: 1700000000,
  iters: 3,
  rows: [
    {
      label: "synthetic/plain-50mb.txt",
      bytes: 52428800,
      fileType: "text",
      totalMedianMs: 1234.5,
      totalMaxMs: 1300.0,
      detectors: [
        { name: "invisibleUnicode", medianMs: 50.0, maxMs: 60.0, calls: 3 },
        { name: "suspiciousPatterns", medianMs: 200.0, maxMs: 220.0, calls: 3 },
        { name: "mathBypass", medianMs: 0.5, maxMs: 0.7, calls: 3 },
      ],
    },
    {
      label: "attacks/01-zwsp-injection.txt",
      bytes: 67,
      fileType: "text",
      totalMedianMs: 7.0,
      totalMaxMs: 8.0,
      detectors: [
        { name: "invisibleUnicode", medianMs: 0.6, maxMs: 0.7, calls: 3 },
      ],
    },
  ],
  thresholdFailures: [],
  regressionFailures: [],
};

describe("buildMarkdown (bench-ci-summary)", () => {
  it("includes the header line with generator metadata", () => {
    const md = buildMarkdown(MIN_BENCH);
    expect(md).toContain("# Detector benchmark summary");
    expect(md).toContain("`v1.20.0`");
    expect(md).toContain("iters: `3`");
    expect(md).toContain("sourceDateEpoch: `1700000000`");
    expect(md).toContain("rows: `2`");
  });

  it("renders the worst-case row table sorted by medianMs desc", () => {
    const md = buildMarkdown(MIN_BENCH);
    expect(md).toContain("## Worst-case row (`synthetic/plain-50mb.txt`)");
    expect(md).toContain("| detector | medianMs | maxMs | calls |");
    // suspiciousPatterns (200ms) must appear before invisibleUnicode (50ms)
    // and mathBypass (0.5ms) in the rendered output.
    const susIdx = md.indexOf("`suspiciousPatterns`");
    const invIdx = md.indexOf("`invisibleUnicode`");
    const mathIdx = md.indexOf("`mathBypass`");
    expect(susIdx).toBeGreaterThan(-1);
    expect(invIdx).toBeGreaterThan(susIdx);
    expect(mathIdx).toBeGreaterThan(invIdx);
  });

  it("renders the per-input totals table covering every row", () => {
    const md = buildMarkdown(MIN_BENCH);
    expect(md).toContain("## Per-input totals");
    expect(md).toContain("| `synthetic/plain-50mb.txt` | 52428800 | 1234.5 | 1300 |");
    expect(md).toContain("| `attacks/01-zwsp-injection.txt` | 67 | 7 | 8 |");
  });

  it("renders empty failure sections as _none._", () => {
    const md = buildMarkdown(MIN_BENCH);
    expect(md).toContain("## Threshold failures (0)");
    expect(md).toContain("## Regression failures (0)");
    // Two _none._ markers — one per failure section.
    const noneCount = (md.match(/_none\._/g) || []).length;
    expect(noneCount).toBe(2);
  });

  it("lists threshold + regression failure messages when present", () => {
    const bench = {
      ...MIN_BENCH,
      thresholdFailures: ["detector \"foo\" on plain-50mb: medianMs=99 > cap=10"],
      regressionFailures: ["synthetic/plain-50mb.txt :: bar regressed +42.0%"],
    };
    const md = buildMarkdown(bench);
    expect(md).toContain("## Threshold failures (1)");
    expect(md).toContain("- detector \"foo\"");
    expect(md).toContain("## Regression failures (1)");
    expect(md).toContain("- synthetic/plain-50mb.txt :: bar");
  });

  it("handles a missing worst-case row gracefully", () => {
    const bench = {
      ...MIN_BENCH,
      rows: MIN_BENCH.rows.filter((r) => r.label !== "synthetic/plain-50mb.txt"),
    };
    const md = buildMarkdown(bench);
    expect(md).toContain("_no `synthetic/plain-50mb.txt` row in bench report._");
  });
});

describe("diffRegressions (bench-regression-gate)", () => {
  const baseline = MIN_BENCH;

  it("reports no regressions when current matches baseline", () => {
    const { regressions } = diffRegressions(baseline, baseline, { pct: 10, min: 1 });
    expect(regressions).toEqual([]);
  });

  it("flags a detector that regressed beyond the pct gate", () => {
    const current = JSON.parse(JSON.stringify(baseline));
    // suspiciousPatterns: 200ms -> 250ms = +25%, well over the 10% gate.
    current.rows[0].detectors[1].medianMs = 250.0;
    const { regressions } = diffRegressions(current, baseline, { pct: 10, min: 1 });
    expect(regressions.length).toBe(1);
    expect(regressions[0]).toContain("suspiciousPatterns");
    expect(regressions[0]).toContain("200");
    expect(regressions[0]).toContain("250");
  });

  it("ignores a regression on a sub-min-baseline detector", () => {
    const current = JSON.parse(JSON.stringify(baseline));
    // mathBypass baseline is 0.5ms which is < min=1ms — must be ignored
    // even at +200% movement, because perf.now() noise dominates.
    current.rows[0].detectors[2].medianMs = 1.5;
    const { regressions } = diffRegressions(current, baseline, { pct: 10, min: 1 });
    expect(regressions).toEqual([]);
  });

  it("ignores an improvement (negative delta)", () => {
    const current = JSON.parse(JSON.stringify(baseline));
    current.rows[0].detectors[1].medianMs = 100.0; // 50% faster
    const { regressions } = diffRegressions(current, baseline, { pct: 10, min: 1 });
    expect(regressions).toEqual([]);
  });

  it("returns no regressions when worst-case row is missing on either side", () => {
    const bench = {
      ...baseline,
      rows: baseline.rows.filter((r) => r.label !== "synthetic/plain-50mb.txt"),
    };
    const { regressions } = diffRegressions(bench, baseline, { pct: 10, min: 1 });
    expect(regressions).toEqual([]);
    const r2 = diffRegressions(baseline, bench, { pct: 10, min: 1 });
    expect(r2.regressions).toEqual([]);
  });

  it("returns no regressions when a detector is new in current (no baseline pair)", () => {
    const current = JSON.parse(JSON.stringify(baseline));
    current.rows[0].detectors.push({
      name: "brandNewDetector",
      medianMs: 999.0,
      maxMs: 1000.0,
      calls: 3,
    });
    const { regressions } = diffRegressions(current, baseline, { pct: 10, min: 1 });
    expect(regressions).toEqual([]);
  });

  it("respects a custom pct gate", () => {
    const current = JSON.parse(JSON.stringify(baseline));
    current.rows[0].detectors[1].medianMs = 220.0; // +10% exactly
    // With pct=15, +10% is below the gate.
    expect(diffRegressions(current, baseline, { pct: 15, min: 1 }).regressions).toEqual([]);
    // With pct=5, +10% trips it.
    expect(diffRegressions(current, baseline, { pct: 5, min: 1 }).regressions.length).toBe(1);
  });
});
