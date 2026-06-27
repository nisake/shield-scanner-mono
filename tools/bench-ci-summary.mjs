#!/usr/bin/env node
/**
 * bench-ci-summary.mjs — v1.20.0 T5-BENCH-CI
 *
 * Reads tools/bench-latest.json (produced by tools/bench-detector.mjs) and
 * emits a compact GitHub-Flavored Markdown report intended for:
 *   - PR comment artifacts (uploaded by the bench-detector CI workflow)
 *   - Local "what changed?" inspection (`node tools/bench-ci-summary.mjs`)
 *
 *   Usage
 *   ─────
 *     node tools/bench-ci-summary.mjs                       # stdout
 *     node tools/bench-ci-summary.mjs --out=bench-summary.md
 *     node tools/bench-ci-summary.mjs --in=tools/bench-latest.json
 *
 *   Output shape
 *   ────────────
 *   - Header line with generatorVersion / iters / row count.
 *   - "Worst-case row" table: per-detector medianMs on
 *     synthetic/plain-50mb.txt (the canonical regression-gate row).
 *   - "Per-input totals" table: every row's totalMedianMs / totalMaxMs.
 *   - "Threshold failures" + "Regression failures" sections (empty when
 *     bench-latest.json reports none).
 *
 *   This script is read-only with respect to tools/bench-latest.json — it
 *   never mutates the bench report. Forbidden: editing bench-detector.mjs,
 *   editing bench-latest.json, editing dist-budget.mjs, editing
 *   parity-check.mjs (R23 fingerprint stays untouched).
 *
 *   Exit codes
 *   ──────────
 *     0 — summary written successfully
 *     2 — could not read input JSON / could not write output file
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const DEFAULT_IN = resolve(__dirname, "bench-latest.json");

const ARGS = (() => {
  const out = { in: DEFAULT_IN, out: null };
  for (const a of process.argv.slice(2)) {
    if (a.startsWith("--in=")) out.in = resolve(ROOT, a.slice("--in=".length));
    else if (a.startsWith("--out=")) out.out = resolve(ROOT, a.slice("--out=".length));
  }
  return out;
})();

function loadBench(path) {
  if (!existsSync(path)) {
    console.error(`[bench-ci-summary] FAIL: input not found: ${path}`);
    process.exit(2);
  }
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    console.error(`[bench-ci-summary] FAIL: could not parse ${path}: ${err.message}`);
    process.exit(2);
  }
}

const WORST_LABEL = "synthetic/plain-50mb.txt";

function buildMarkdown(bench) {
  const lines = [];
  lines.push("# Detector benchmark summary");
  lines.push("");
  lines.push(
    `- generatorVersion: \`${bench.generatorVersion || "?"}\`` +
      `  · iters: \`${bench.iters ?? "?"}\`` +
      `  · sourceDateEpoch: \`${bench.sourceDateEpoch ?? 0}\`` +
      `  · rows: \`${Array.isArray(bench.rows) ? bench.rows.length : 0}\``
  );
  lines.push("");

  const worst = Array.isArray(bench.rows)
    ? bench.rows.find((r) => r.label === WORST_LABEL)
    : null;

  lines.push(`## Worst-case row (\`${WORST_LABEL}\`)`);
  lines.push("");
  if (!worst) {
    lines.push(`_no \`${WORST_LABEL}\` row in bench report._`);
  } else {
    lines.push(
      `bytes: \`${worst.bytes}\` · totalMedianMs: \`${worst.totalMedianMs}\`` +
        ` · totalMaxMs: \`${worst.totalMaxMs}\``
    );
    lines.push("");
    lines.push("| detector | medianMs | maxMs | calls |");
    lines.push("| --- | ---: | ---: | ---: |");
    const dets = [...(worst.detectors || [])].sort((a, b) => b.medianMs - a.medianMs);
    for (const d of dets) {
      lines.push(`| \`${d.name}\` | ${d.medianMs} | ${d.maxMs} | ${d.calls} |`);
    }
  }
  lines.push("");

  lines.push("## Per-input totals");
  lines.push("");
  lines.push("| label | bytes | totalMedianMs | totalMaxMs |");
  lines.push("| --- | ---: | ---: | ---: |");
  for (const row of bench.rows || []) {
    lines.push(
      `| \`${row.label}\` | ${row.bytes} | ${row.totalMedianMs} | ${row.totalMaxMs} |`
    );
  }
  lines.push("");

  const tFails = Array.isArray(bench.thresholdFailures) ? bench.thresholdFailures : [];
  lines.push(`## Threshold failures (${tFails.length})`);
  lines.push("");
  if (tFails.length === 0) {
    lines.push("_none._");
  } else {
    for (const f of tFails) lines.push(`- ${f}`);
  }
  lines.push("");

  const rFails = Array.isArray(bench.regressionFailures) ? bench.regressionFailures : [];
  lines.push(`## Regression failures (${rFails.length})`);
  lines.push("");
  if (rFails.length === 0) {
    lines.push("_none._");
  } else {
    for (const f of rFails) lines.push(`- ${f}`);
  }
  lines.push("");

  return lines.join("\n");
}

function main() {
  const bench = loadBench(ARGS.in);
  const md = buildMarkdown(bench);
  if (ARGS.out) {
    try {
      writeFileSync(ARGS.out, md);
      console.log(`[bench-ci-summary] wrote ${ARGS.out} (${md.length} chars)`);
    } catch (err) {
      console.error(`[bench-ci-summary] FAIL: could not write ${ARGS.out}: ${err.message}`);
      process.exit(2);
    }
  } else {
    process.stdout.write(md);
  }
  process.exit(0);
}

// Export the markdown builder so unit tests can exercise it without I/O.
export { buildMarkdown };

// Only execute main() when run as a CLI, not when imported by tests.
const invokedDirectly =
  import.meta.url === `file://${process.argv[1]}` ||
  import.meta.url === new URL(`file:${process.argv[1]}`).href;
if (invokedDirectly) main();
