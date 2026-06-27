# Detector benchmark — local + CI

Shield Scanner ships a per-detector micro-benchmark that times every detector
in `packages/core/src/index.js` against a fixed corpus of attack + benign
fixtures plus four synthetic large inputs (1 MB / 10 MB / 50 MB plain text +
10 000-line markdown). v1.20.0 adds a CI workflow that runs the same harness
on every PR + push to `main`, posts a Markdown summary artifact, and gates
regressions against a cached baseline.

## Files

| Path | Role |
| --- | --- |
| `tools/bench-detector.mjs` | the harness — runs analyze() with `profile:true` and writes `tools/bench-latest.json` |
| `tools/gen-bench-fixtures.mjs` | generates the synthetic 1/10/50 MB + 10k-line markdown inputs |
| `tools/bench-fixtures/` | generated synthetic fixtures (gitignored at the directory level) |
| `tools/bench-latest.json` | most recent run report — used as the previous-run baseline for in-harness regression check |
| `tools/bench-threshold.json` | per-detector caps + regression knobs (both harness + CI) |
| `tools/bench-ci-summary.mjs` | reads bench-latest.json, emits Markdown summary for PR comment artifact |
| `tools/bench-regression-gate.mjs` | standalone gate that diffs current vs. cached baseline bench-latest.json |
| `.github/workflows/bench-detector.yml` | CI workflow tying the three scripts together |

## Local usage

```sh
# Full run: regenerate synthetic fixtures, run all detectors, write
# tools/bench-latest.json. ~1-2 minutes on a stock dev box.
npm run bench

# Skip the synthetic fixture regen (faster reruns, ~30s).
node tools/bench-detector.mjs --skip-gen

# Run 5 iterations and take the median per detector — recommended when
# you want a tighter signal for a perf-touching PR.
node tools/bench-detector.mjs --iters=5

# Print the Markdown summary that CI uploads to PRs.
npm run bench:ci

# Diff the just-produced bench-latest.json against a saved baseline.
npm run bench:gate -- --baseline=path/to/old-bench-latest.json
```

## Reading `bench-latest.json`

Each row is one input fixture. The `synthetic/plain-50mb.txt` row is the
canonical worst-case row — both `bench-detector.mjs` (threshold check) and
`bench-regression-gate.mjs` (CI gate) compare against it. Smaller fixtures
are kept in the report for visibility only.

The `sourceDateEpoch` field comes from the `SOURCE_DATE_EPOCH` env var so
the file is byte-reproducible across CI runs that share the same code. The
field does NOT affect detector timing — `performance.now()` is monotonic and
unrelated to wall-clock.

## CI workflow

`.github/workflows/bench-detector.yml` runs on PRs + pushes to `main`:

1. `node tools/bench-detector.mjs --iters=3` — write `tools/bench-latest.json`.
2. `node tools/bench-ci-summary.mjs --out=tools/bench-summary.md` — Markdown.
3. `node tools/bench-regression-gate.mjs --baseline=tools/bench-baseline.json`
   — diff against the cached baseline (the previous main-branch run). First
   runs + PRs from forks where the cache is empty soft-pass.
4. Upload `bench-latest.json` + `bench-summary.md` as a 30-day artifact.
5. On pushes to `main`, refresh the baseline cache so the next PR diffs
   against fresh numbers.

## Threshold tuning

Per-detector caps in `bench-threshold.json` are initial-pin = peak observed
medianMs on `synthetic/plain-50mb.txt`, padded ~2x because
`performance.now()` on Windows swings 50-100% between consecutive
single-iter runs. Re-pin numbers in the same commit as any intentional perf
change.

The two regression knobs:

- `regressionPct` (default 50) — used by `bench-detector.mjs` for its
  internal previous-run check, deliberately loose because the harness often
  runs on a noisy dev box with `iters=1`.
- `regressionPctCi` (default 10) + `minBaselineMsCi` (default 1) — used by
  `bench-regression-gate.mjs`. The tighter 10% gate is safe on a clean
  GitHub Actions runner with `iters=3` and a cached baseline. Tighten both
  together when `iters=5` becomes the default.

## What this layer does NOT touch

- Distribution bundle (`packages/web/dist/`) — bench scripts live in
  `tools/` only, no dist impact.
- Parser pipeline — bench feeds analyze() directly via the text path; no
  parser layer changes.
- R1-R23 guardrails — bench is read-only with respect to detectors,
  patterns, and fingerprints.
