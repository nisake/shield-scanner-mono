#!/usr/bin/env node
/**
 * gen-bench-fixtures.mjs — v1.18.0
 *
 * Builds synthetic large-input fixtures for the detector benchmark. The
 * generated files live under `tools/bench-fixtures/` and are .gitignored
 * (see bench-fixtures/.gitignore) so they never enter the public dist
 * pipeline or PII-scan surface.
 *
 * Determinism: this script must NOT use Math.random() or argless `new Date()`
 * — the v1.18.0 workflow forbids non-deterministic clocks at fixture
 * generation time so reruns produce byte-identical fixtures and the bench
 * regression check stays meaningful. We use a tiny xorshift32 PRNG seeded
 * from CLI arg / SOURCE_DATE_EPOCH so the same seed always yields the same
 * bytes.
 *
 * Usage:
 *   node tools/gen-bench-fixtures.mjs               # seed = 1
 *   node tools/gen-bench-fixtures.mjs --seed=42     # seed = 42
 *
 * Generates:
 *   tools/bench-fixtures/plain-1mb.txt    (~1 MB ASCII paragraphs)
 *   tools/bench-fixtures/plain-10mb.txt   (~10 MB ASCII paragraphs)
 *   tools/bench-fixtures/plain-50mb.txt   (~50 MB ASCII paragraphs)
 *   tools/bench-fixtures/markdown-10k.md  (10000 markdown headings/lists)
 *
 * These fixtures are intentionally benign — no injection payloads, no
 * homoglyphs, no Bidi controls — so the bench measures the detectors' cost
 * on realistic-shape input without inflating finding counts. The benchmark
 * separately exercises the 28 existing attack/benign fixtures for hot-path
 * coverage on real payloads.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(__dirname, "bench-fixtures");

// ─── deterministic PRNG ────────────────────────────────────────────────────
// xorshift32, returns uint32. Seed must be non-zero.
function makeRng(seed) {
  let state = (seed | 0) || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function parseSeed(argv) {
  for (const arg of argv) {
    if (arg.startsWith("--seed=")) {
      const n = parseInt(arg.slice("--seed=".length), 10);
      if (!Number.isNaN(n) && n !== 0) return n;
    }
  }
  if (process.env.SOURCE_DATE_EPOCH) {
    const n = parseInt(process.env.SOURCE_DATE_EPOCH, 10);
    if (!Number.isNaN(n) && n !== 0) return n;
  }
  return 1;
}

// ─── paragraph corpus ─────────────────────────────────────────────────────
// Benign English sentences. No homoglyphs, no Bidi, no Unicode tags. Picked
// for length variety so detectors see both short and long matches.
const SENTENCES = [
  "The quick brown fox jumps over the lazy dog while a small bird watches from above.",
  "She arranged the books in alphabetical order and dusted the shelves with great care.",
  "Compression ratio benchmarks rarely tell the whole story without a deeper look at allocation patterns.",
  "When the weather turned cold the gardener pulled the last tomatoes off the vine and brought them inside.",
  "He paused at the corner store to buy a newspaper and a small carton of fresh milk.",
  "Detector throughput scales mostly with input length and rarely with the number of distinct patterns.",
  "The river was calm and the boats drifted slowly with the morning tide along the green riverbank.",
  "Memory pressure can hide as latency when an allocator must walk a long free list before settling.",
  "She walked along the beach picking up smooth stones and tossing them into the gentle waves.",
  "Each line of telemetry tells a small story but only the whole stream reveals the underlying shape.",
  "A long afternoon nap left the cat thoroughly refreshed and ready for the evening hunt.",
  "Parsing nested structures should always bound depth so a hostile input cannot exhaust the stack.",
];

function buildParagraph(rng) {
  // 3 to 6 sentences per paragraph, drawn from the corpus.
  const n = 3 + (rng() % 4);
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push(SENTENCES[rng() % SENTENCES.length]);
  }
  return out.join(" ");
}

function buildPlainText(targetBytes, seed) {
  const rng = makeRng(seed);
  const chunks = [];
  let size = 0;
  while (size < targetBytes) {
    const para = buildParagraph(rng);
    chunks.push(para);
    chunks.push("\n\n");
    // +2 for the trailing blank line.
    size += para.length + 2;
  }
  return chunks.join("");
}

function buildMarkdown(lineCount, seed) {
  const rng = makeRng(seed);
  const lines = [];
  for (let i = 0; i < lineCount; i++) {
    const kind = rng() % 6;
    const para = SENTENCES[rng() % SENTENCES.length];
    if (kind === 0) {
      lines.push(`# ${para}`);
    } else if (kind === 1) {
      lines.push(`## ${para}`);
    } else if (kind === 2) {
      lines.push(`### ${para}`);
    } else if (kind === 3) {
      lines.push(`- ${para}`);
    } else if (kind === 4) {
      lines.push(`> ${para}`);
    } else {
      lines.push(para);
    }
  }
  return lines.join("\n") + "\n";
}

// ─── main ─────────────────────────────────────────────────────────────────
function main() {
  const seed = parseSeed(process.argv.slice(2));
  mkdirSync(OUT_DIR, { recursive: true });

  const targets = [
    { name: "plain-1mb.txt", bytes: 1 * 1024 * 1024 },
    { name: "plain-10mb.txt", bytes: 10 * 1024 * 1024 },
    { name: "plain-50mb.txt", bytes: 50 * 1024 * 1024 },
  ];
  for (const { name, bytes } of targets) {
    const path = resolve(OUT_DIR, name);
    const data = buildPlainText(bytes, seed);
    writeFileSync(path, data);
    console.log(`[gen-bench-fixtures] wrote ${name} (${data.length} bytes, seed=${seed})`);
  }

  {
    const path = resolve(OUT_DIR, "markdown-10k.md");
    const data = buildMarkdown(10000, seed);
    writeFileSync(path, data);
    console.log(`[gen-bench-fixtures] wrote markdown-10k.md (${data.length} bytes, 10000 lines, seed=${seed})`);
  }
}

main();
