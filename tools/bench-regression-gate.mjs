#!/usr/bin/env node
/**
 * bench-regression-gate.mjs — v1.20.0 T5-BENCH-CI
 *
 * Standalone regression gate that compares two bench reports:
 *   - current: tools/bench-latest.json (the run that just completed)
 *   - baseline: a previous bench-latest.json (default: PR base / cached CI
 *     artifact, supplied via --baseline=path/to/file.json)
 *
 * Differs from the regression check baked into bench-detector.mjs in three
 * ways:
 *   1. It does NOT require the bench harness to re-run. The CI workflow can
 *      restore a baseline artifact from the previous main-branch run and
 *      diff against the freshly produced bench-latest.json.
 *   2. The regression threshold percent + minimum baseline ms are read from
 *      tools/bench-threshold.json (single source of truth) — when this file
 *      is later wired into bench-detector.mjs (next bump), both layers stay
 *      in sync without copy-paste.
 *   3. Default regressionPct is 10% (the brief's tighter CI gate) when not
 *      set in bench-threshold.json. The harness still defaults to 50% for
 *      its internal check (Windows perf.now() noise floor). When iters=5+
 *      becomes the default the harness number can be tightened to match.
 *
 *   Usage
 *   ─────
 *     node tools/bench-regression-gate.mjs --baseline=path/to/baseline.json
 *     node tools/bench-regression-gate.mjs --current=tools/bench-latest.json
 *                                          --baseline=baseline.json
 *                                          --pct=10 --min-baseline-ms=1
 *
 *   Exit codes
 *   ──────────
 *     0 — no regression detected (or baseline missing — soft-pass first CI run)
 *     1 — at least one detector regressed beyond the configured threshold
 *     2 — input file unreadable / malformed
 *
 *   Forbidden: editing bench-detector.mjs, editing bench-latest.json,
 *   editing dist-budget.mjs, editing parity-check.mjs. This script is
 *   strictly additive (tools/ only, no dist impact, no R12/R13 impact).
 */

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const DEFAULT_CURRENT = resolve(__dirname, "bench-latest.json");
const DEFAULT_THRESHOLD = resolve(__dirname, "bench-threshold.json");
const WORST_LABEL = "synthetic/plain-50mb.txt";

const ARGS = (() => {
  const out = {
    current: DEFAULT_CURRENT,
    baseline: null,
    pct: null,
    minBaselineMs: null,
    quiet: false,
  };
  for (const a of process.argv.slice(2)) {
    if (a.startsWith("--current=")) out.current = resolve(ROOT, a.slice("--current=".length));
    else if (a.startsWith("--baseline=")) out.baseline = resolve(ROOT, a.slice("--baseline=".length));
    else if (a.startsWith("--pct=")) {
      const n = Number(a.slice("--pct=".length));
      if (Number.isFinite(n) && n > 0) out.pct = n;
    } else if (a.startsWith("--min-baseline-ms=")) {
      const n = Number(a.slice("--min-baseline-ms=".length));
      if (Number.isFinite(n) && n >= 0) out.minBaselineMs = n;
    } else if (a === "--quiet") out.quiet = true;
  }
  return out;
})();

function loadJson(path, label) {
  if (!existsSync(path)) {
    console.error(`[bench-regression-gate] FAIL: ${label} not found: ${path}`);
    process.exit(2);
  }
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    console.error(`[bench-regression-gate] FAIL: could not parse ${label} ${path}: ${err.message}`);
    process.exit(2);
  }
}

function resolveSettings() {
  let pct = ARGS.pct;
  let min = ARGS.minBaselineMs;
  if (existsSync(DEFAULT_THRESHOLD)) {
    try {
      const t = JSON.parse(readFileSync(DEFAULT_THRESHOLD, "utf8"));
      if (pct == null && Number.isFinite(t.regressionPctCi)) pct = t.regressionPctCi;
      if (min == null && Number.isFinite(t.minBaselineMsCi)) min = t.minBaselineMsCi;
    } catch {
      // fall through to defaults
    }
  }
  if (pct == null) pct = 10;
  if (min == null) min = 1;
  return { pct, min };
}

/**
 * Pure function — exported for unit tests.
 * Returns { regressions: string[] } describing every detector that crossed
 * the regression threshold on the worst-case row.
 */
export function diffRegressions(current, baseline, settings) {
  const out = { regressions: [] };
  if (!current || !Array.isArray(current.rows)) return out;
  if (!baseline || !Array.isArray(baseline.rows)) return out;
  const curRow = current.rows.find((r) => r.label === WORST_LABEL);
  const prevRow = baseline.rows.find((r) => r.label === WORST_LABEL);
  if (!curRow || !prevRow) return out;
  for (const cur of curRow.detectors || []) {
    const prev = (prevRow.detectors || []).find((d) => d.name === cur.name);
    if (!prev) continue;
    if (prev.medianMs < settings.min) continue;
    const delta = cur.medianMs - prev.medianMs;
    const deltaPct = (delta / prev.medianMs) * 100;
    if (deltaPct > settings.pct) {
      out.regressions.push(
        `${cur.name}: ${prev.medianMs}ms -> ${cur.medianMs}ms ` +
          `(+${deltaPct.toFixed(1)}%, gate ${settings.pct}% / baseline >= ${settings.min}ms)`
      );
    }
  }
  return out;
}

function main() {
  const settings = resolveSettings();
  const current = loadJson(ARGS.current, "current");
  if (!ARGS.baseline) {
    if (!ARGS.quiet) {
      console.log("[bench-regression-gate] no --baseline supplied; treating as first-run soft-pass.");
    }
    process.exit(0);
  }
  if (!existsSync(ARGS.baseline)) {
    if (!ARGS.quiet) {
      console.log(
        `[bench-regression-gate] baseline ${ARGS.baseline} not present; soft-pass (first CI run with this gate).`
      );
    }
    process.exit(0);
  }
  const baseline = loadJson(ARGS.baseline, "baseline");
  const { regressions } = diffRegressions(current, baseline, settings);
  if (regressions.length === 0) {
    if (!ARGS.quiet) {
      console.log(
        `[bench-regression-gate] OK: 0 regressions on ${WORST_LABEL} ` +
          `(gate ${settings.pct}% / baseline >= ${settings.min}ms).`
      );
    }
    process.exit(0);
  }
  console.error(`[bench-regression-gate] FAIL: ${regressions.length} regression(s) on ${WORST_LABEL}:`);
  for (const r of regressions) console.error(`  - ${r}`);
  process.exit(1);
}

const invokedDirectly =
  import.meta.url === `file://${process.argv[1]}` ||
  import.meta.url === new URL(`file:${process.argv[1]}`).href;
if (invokedDirectly) main();
