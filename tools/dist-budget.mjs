#!/usr/bin/env node
// =============================================================
//  Shield Scanner — dist-budget assertion (v1.17.1)
// =============================================================
// Post-build CI gate. Asserts two invariants on packages/web/dist/index.html:
//
//   1. Forbidden-string grep is empty. The cheerio + parse5 + htmlparser2 +
//      dom-serializer + cheerio-select chain was stubbed out by
//      cheerioStubPlugin in v1.16.1 (dist 297 KiB). v1.17.0 parallel theme
//      work re-introduced the chain via the build pipeline and dist
//      ballooned to 891 KiB before recovery. This script makes that
//      re-introduction a hard CI fail.
//
//   2. Total dist size <= 900 KiB. Hard ceiling so an unrelated regression
//      cannot silently consume budget.
//
// Exit codes:
//   0 — all assertions pass (logs remaining budget)
//   1 — at least one assertion failed (logs hit counts + sample context)
// =============================================================
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const DIST = resolve(here, '..', 'packages', 'web', 'dist', 'index.html');

const FORBIDDEN = [
  'cheerio',
  'parse5',
  'htmlparser2',
  'dom-serializer',
  'cheerio-select',
];

const MAX_BYTES = 900 * 1024;

function readDist() {
  try {
    return readFileSync(DIST, 'utf8');
  } catch (err) {
    console.error(`[dist-budget] FAIL: could not read ${DIST}`);
    console.error(`[dist-budget]   ${err.message}`);
    process.exit(1);
  }
}

function statDist() {
  try {
    return statSync(DIST).size;
  } catch (err) {
    console.error(`[dist-budget] FAIL: could not stat ${DIST}`);
    console.error(`[dist-budget]   ${err.message}`);
    process.exit(1);
  }
}

function findHits(haystack, needle) {
  const hits = [];
  let from = 0;
  while (from < haystack.length) {
    const idx = haystack.indexOf(needle, from);
    if (idx < 0) break;
    hits.push(idx);
    from = idx + needle.length;
  }
  return hits;
}

function contextLines(haystack, indices, max = 3) {
  const out = [];
  for (const idx of indices.slice(0, max)) {
    // Find the line containing this hit.
    const lineStart = haystack.lastIndexOf('\n', idx - 1) + 1;
    const lineEnd = haystack.indexOf('\n', idx);
    const line = haystack.slice(
      lineStart,
      lineEnd < 0 ? haystack.length : lineEnd,
    );
    // Trim long lines so a minified blob does not dump megabytes.
    const trimmed = line.length > 200
      ? line.slice(0, 200) + ' ...[truncated]'
      : line;
    out.push(trimmed);
  }
  return out;
}

const html = readDist();
const size = statDist();

let failed = false;

// Assertion 1: forbidden strings.
for (const needle of FORBIDDEN) {
  const hits = findHits(html, needle);
  if (hits.length > 0) {
    failed = true;
    console.error(
      `[dist-budget] FAIL: forbidden string "${needle}" found ${hits.length} time(s) in dist/index.html`,
    );
    const samples = contextLines(html, hits, 3);
    samples.forEach((line, i) => {
      console.error(`[dist-budget]   sample ${i + 1}: ${line}`);
    });
  }
}

// Assertion 2: size ceiling.
if (size > MAX_BYTES) {
  failed = true;
  console.error(
    `[dist-budget] FAIL: dist size ${size} bytes (${(size / 1024).toFixed(2)} KiB) exceeds budget ${MAX_BYTES} bytes (${(MAX_BYTES / 1024).toFixed(0)} KiB)`,
  );
}

if (failed) {
  console.error(
    '[dist-budget] One or more assertions failed. cheerio re-injection or unrelated bloat suspected.',
  );
  process.exit(1);
}

const remaining = MAX_BYTES - size;
console.log(
  `[dist-budget] OK: dist ${size} bytes (${(size / 1024).toFixed(2)} KiB), budget ${MAX_BYTES} bytes, remaining ${remaining} bytes (${(remaining / 1024).toFixed(2)} KiB).`,
);
process.exit(0);
