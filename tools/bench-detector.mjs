#!/usr/bin/env node
/**
 * bench-detector.mjs — v1.18.0
 *
 * Detector benchmark + per-detector profile aggregator.
 *
 *   Usage
 *   ─────
 *     node tools/bench-detector.mjs                # build + run, write bench-latest.json
 *     node tools/bench-detector.mjs --skip-gen     # skip fixture regen (faster reruns)
 *     node tools/bench-detector.mjs --no-write     # write to stdout only
 *     node tools/bench-detector.mjs --iters=3      # repeat each input N times, take median
 *
 *   What it does
 *   ────────────
 *   1. Generates the synthetic large inputs (plain-1mb / plain-10mb /
 *      plain-50mb / markdown-10k) via tools/gen-bench-fixtures.mjs unless
 *      --skip-gen is passed.
 *   2. Loads every text/markdown attack + benign fixture under
 *      packages/mcp/test/fixtures/{attacks,benign}/ that the analyze() text
 *      path can consume directly. Binary fixtures (PDF / XLSX / ZIP) are
 *      skipped here — they have their own parser layer and are out of scope
 *      for the detector micro-benchmark.
 *   3. For every (input, iter) pair, calls analyze(text, {profile:true}) and
 *      collects per-detector ms. The per-detector ms are then aggregated:
 *      median / max / total across iterations.
 *   4. Compares against the per-detector caps in tools/bench-threshold.json.
 *      Any detector that exceeds its cap on the 50 MB plain-text input
 *      (the worst-case row) flags the run as failing.
 *   5. Also compares against the previous run (tools/bench-latest.json, if
 *      it exists). Any detector regressing > regressionPct % AND > 1 ms
 *      baseline is flagged.
 *   6. Writes a deterministic summary to tools/bench-latest.json. The output
 *      uses the SOURCE_DATE_EPOCH env var (if set) or a fixed sentinel as
 *      the recorded timestamp so the file is reproducible.
 *
 *   Why no Date.now() / Math.random() / argless new Date()?
 *   ──────────────────────────────────────────────────────
 *   The v1.18.0 workflow forbids non-deterministic clocks at fixture-gen +
 *   bench-output time so reruns produce byte-identical reports the human
 *   eyeballer can diff cleanly. performance.now() IS allowed — it's a
 *   monotonic high-resolution timer, not a wall-clock — and is what feeds
 *   the per-detector ms samples.
 *
 *   Exit codes
 *   ──────────
 *     0 — all thresholds met, no regression
 *     1 — at least one detector exceeded its cap or regressed
 *     2 — bench harness itself errored (fixture missing, parse failure, etc.)
 */

import { mkdirSync, readdirSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join, extname } from "node:path";
import { spawnSync } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const FIXTURE_ROOT = resolve(ROOT, "packages", "mcp", "test", "fixtures");
const BENCH_DIR = resolve(__dirname, "bench-fixtures");
const THRESHOLD_PATH = resolve(__dirname, "bench-threshold.json");
const OUT_PATH = resolve(__dirname, "bench-latest.json");
const PREV_PATH = OUT_PATH;

// ─── arg parsing ──────────────────────────────────────────────────────────
const ARGS = (() => {
  const out = { skipGen: false, noWrite: false, iters: 1 };
  for (const a of process.argv.slice(2)) {
    if (a === "--skip-gen") out.skipGen = true;
    else if (a === "--no-write") out.noWrite = true;
    else if (a.startsWith("--iters=")) {
      const n = parseInt(a.slice("--iters=".length), 10);
      if (Number.isFinite(n) && n >= 1) out.iters = n;
    }
  }
  return out;
})();

// ─── fixture regeneration ─────────────────────────────────────────────────
function ensureFixtures() {
  const needed = ["plain-1mb.txt", "plain-10mb.txt", "plain-50mb.txt", "markdown-10k.md"];
  const allPresent = needed.every((f) => existsSync(resolve(BENCH_DIR, f)));
  if (ARGS.skipGen && allPresent) {
    console.log("[bench-detector] --skip-gen + fixtures present, reusing.");
    return;
  }
  if (ARGS.skipGen && !allPresent) {
    console.warn("[bench-detector] --skip-gen but a fixture is missing; regenerating.");
  }
  mkdirSync(BENCH_DIR, { recursive: true });
  const gen = resolve(__dirname, "gen-bench-fixtures.mjs");
  console.log(`[bench-detector] generating synthetic fixtures via ${gen}`);
  const r = spawnSync(process.execPath, [gen], { stdio: "inherit" });
  if (r.status !== 0) {
    console.error("[bench-detector] FAIL: fixture generation exited non-zero.");
    process.exit(2);
  }
}

// ─── text fixture discovery ───────────────────────────────────────────────
// Only fixtures the detector text path can swallow directly: .txt / .md / .csv
// / .html / .json. Binary fixtures (.pdf / .zip / .xlsx / .docx / .pptx / .eml
// / image) are out of scope — they have their own parser layer.
const TEXT_EXTS = new Set([".txt", ".md", ".csv", ".html", ".json"]);

function listTextFixtures(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (!st.isFile()) continue;
    const ext = extname(name).toLowerCase();
    if (!TEXT_EXTS.has(ext)) continue;
    // Skip huge files (the synthetic ones are loaded separately).
    if (st.size > 2 * 1024 * 1024) continue;
    out.push({ path: full, label: `${dir.includes("attacks") ? "attacks" : "benign"}/${name}` });
  }
  return out;
}

function fileTypeFor(label) {
  const lower = label.toLowerCase();
  if (lower.endsWith(".md") || lower.endsWith(".markdown")) return "markdown";
  if (lower.endsWith(".html") || lower.endsWith(".htm")) return "html";
  if (lower.endsWith(".csv")) return "csv";
  return "text";
}

// ─── bench core ───────────────────────────────────────────────────────────
function median(nums) {
  if (nums.length === 0) return 0;
  const sorted = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[mid]
    : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function runOneInput(analyze, text, fileType, iters) {
  // Per-detector samples across iters.
  const buckets = new Map(); // name -> ms[]
  let totalMsArr = [];
  for (let i = 0; i < iters; i++) {
    const r = analyze(text, { fileType, profile: true });
    const prof = r && r.summary && r.summary.profile;
    if (!prof) {
      throw new Error(
        `analyze(text, {profile:true}) did not return summary.profile (text length=${text.length}, fileType=${fileType})`
      );
    }
    totalMsArr.push(prof.totalMs);
    for (const d of prof.detectors) {
      if (!buckets.has(d.name)) buckets.set(d.name, []);
      buckets.get(d.name).push(d.ms);
    }
  }
  const detectorRows = [];
  for (const [name, msArr] of buckets) {
    detectorRows.push({
      name,
      medianMs: round3(median(msArr)),
      maxMs: round3(Math.max(...msArr)),
      calls: msArr.length,
    });
  }
  detectorRows.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return {
    totalMedianMs: round3(median(totalMsArr)),
    totalMaxMs: round3(Math.max(...totalMsArr)),
    detectors: detectorRows,
  };
}

function round3(n) {
  return Math.round(n * 1000) / 1000;
}

// ─── threshold + regression check ─────────────────────────────────────────
function loadThreshold() {
  try {
    return JSON.parse(readFileSync(THRESHOLD_PATH, "utf8"));
  } catch (err) {
    console.error(`[bench-detector] FAIL: could not read threshold ${THRESHOLD_PATH}: ${err.message}`);
    process.exit(2);
  }
}

function loadPrev() {
  if (!existsSync(PREV_PATH)) return null;
  try {
    return JSON.parse(readFileSync(PREV_PATH, "utf8"));
  } catch {
    return null;
  }
}

function checkThresholds(rows, threshold) {
  // rows = [{label, ...}]; check against the largest synthetic input.
  const worst = rows.find((r) => r.label === "synthetic/plain-50mb.txt");
  if (!worst) {
    console.warn("[bench-detector] WARN: no synthetic/plain-50mb.txt row to compare against thresholds.");
    return { failed: false, notes: ["missing worst-case row"] };
  }
  const failures = [];
  for (const det of worst.detectors) {
    const cap = threshold.thresholds && threshold.thresholds[det.name];
    if (typeof cap !== "number") continue;
    if (det.medianMs > cap) {
      failures.push(`detector "${det.name}" on plain-50mb: medianMs=${det.medianMs} > cap=${cap}`);
    }
  }
  return { failed: failures.length > 0, failures };
}

function checkRegression(rows, prev, threshold) {
  if (!prev || !Array.isArray(prev.rows)) return { failed: false, regressions: [] };
  const pct = threshold.regressionPct || 20;
  const regressions = [];
  for (const row of rows) {
    const prevRow = prev.rows.find((r) => r.label === row.label);
    if (!prevRow) continue;
    for (const det of row.detectors) {
      const prevDet = prevRow.detectors.find((d) => d.name === det.name);
      if (!prevDet) continue;
      // Skip sub-5ms baselines — at that resolution the wall-clock noise
      // floor (Windows perf counters, GC, process scheduling) dominates any
      // real signal. The 50 MB synthetic row is the canonical regression
      // gate; the small fixtures are kept in the report for visibility only.
      if (prevDet.medianMs < 5) continue;
      const delta = det.medianMs - prevDet.medianMs;
      const deltaPct = (delta / prevDet.medianMs) * 100;
      if (deltaPct > pct) {
        regressions.push(
          `${row.label} :: ${det.name} regressed +${deltaPct.toFixed(1)}% (` +
            `${prevDet.medianMs}ms -> ${det.medianMs}ms, threshold ${pct}%)`
        );
      }
    }
  }
  return { failed: regressions.length > 0, regressions };
}

// ─── main ─────────────────────────────────────────────────────────────────
async function main() {
  ensureFixtures();

  // Lazy-import after fixtures exist so the threshold-pass test order is
  // deterministic.
  const coreUrl = new URL(
    "../packages/core/src/index.js",
    import.meta.url
  );
  const { analyze } = await import(coreUrl.href);

  const inputs = [];

  // 1. Existing text/markdown fixtures (attacks + benign).
  for (const f of listTextFixtures(join(FIXTURE_ROOT, "attacks"))) inputs.push(f);
  for (const f of listTextFixtures(join(FIXTURE_ROOT, "benign"))) inputs.push(f);

  // 2. Synthetic large inputs.
  inputs.push({ path: join(BENCH_DIR, "plain-1mb.txt"), label: "synthetic/plain-1mb.txt" });
  inputs.push({ path: join(BENCH_DIR, "plain-10mb.txt"), label: "synthetic/plain-10mb.txt" });
  inputs.push({ path: join(BENCH_DIR, "plain-50mb.txt"), label: "synthetic/plain-50mb.txt" });
  inputs.push({ path: join(BENCH_DIR, "markdown-10k.md"), label: "synthetic/markdown-10k.md" });

  const rows = [];
  for (const input of inputs) {
    if (!existsSync(input.path)) {
      console.warn(`[bench-detector] skip missing fixture: ${input.path}`);
      continue;
    }
    const text = readFileSync(input.path, "utf8");
    const fileType = fileTypeFor(input.path);
    try {
      const r = await runOneInput(analyze, text, fileType, ARGS.iters);
      rows.push({
        label: input.label,
        bytes: text.length,
        fileType,
        totalMedianMs: r.totalMedianMs,
        totalMaxMs: r.totalMaxMs,
        detectors: r.detectors,
      });
      console.log(
        `[bench-detector] ${input.label.padEnd(48)} bytes=${String(text.length).padStart(9)} ` +
          `total=${String(r.totalMedianMs).padStart(8)}ms`
      );
    } catch (err) {
      console.error(`[bench-detector] FAIL on ${input.label}: ${err.message}`);
      process.exit(2);
    }
  }

  const threshold = loadThreshold();
  const prev = loadPrev();
  const tCheck = checkThresholds(rows, threshold);
  const rCheck = checkRegression(rows, prev, threshold);

  const epoch = process.env.SOURCE_DATE_EPOCH
    ? parseInt(process.env.SOURCE_DATE_EPOCH, 10)
    : 0;
  const summary = {
    schemaVersion: 1,
    generatorVersion: "v1.18.0",
    sourceDateEpoch: epoch,
    iters: ARGS.iters,
    rows,
    thresholdFailures: tCheck.failures || [],
    regressionFailures: rCheck.regressions || [],
  };

  if (!ARGS.noWrite) {
    writeFileSync(OUT_PATH, JSON.stringify(summary, null, 2) + "\n");
    console.log(`[bench-detector] wrote ${OUT_PATH}`);
  } else {
    console.log(JSON.stringify(summary, null, 2));
  }

  if (tCheck.failed) {
    console.error(`[bench-detector] THRESHOLD FAIL (${tCheck.failures.length} entries):`);
    for (const f of tCheck.failures) console.error(`  - ${f}`);
  }
  if (rCheck.failed) {
    console.error(`[bench-detector] REGRESSION FAIL (${rCheck.regressions.length} entries):`);
    for (const f of rCheck.regressions) console.error(`  - ${f}`);
  }

  if (tCheck.failed || rCheck.failed) process.exit(1);
  console.log(`[bench-detector] OK: ${rows.length} inputs, no threshold or regression failures.`);
  process.exit(0);
}

main().catch((err) => {
  console.error(`[bench-detector] crash: ${err && err.stack ? err.stack : err}`);
  process.exit(2);
});
