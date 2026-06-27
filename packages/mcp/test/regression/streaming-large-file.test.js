/**
 * v1.18.0 regression: large-file streaming chunk-scan contract.
 *
 * Detectors that walk content linearly (invisible-unicode / control-chars /
 * homoglyphs) auto-chunk inputs > 5MB into 1MB windows with a 2KB overlap.
 * This test pins:
 *
 *   1. shouldStream() gate — 4MB input stays on the single-pass path, 6MB
 *      input takes the chunked path.
 *   2. Boundary integrity — a finding whose absolute position sits exactly
 *      on the 1MB chunk boundary is detected EXACTLY ONCE (no duplicate from
 *      the overlap, no drop from the chunk seam).
 *   3. Absolute-position normalization — the surviving finding carries the
 *      true offset within the original 6MB string, not a chunk-local index.
 *   4. summary.streamed + summary.chunkCount sibling keys appear only on the
 *      streamed path; non-streamed analyze() output retains the v1.17.x shape.
 *
 * R12 contract is honoured throughout — we never assert on raw user text in
 * the response; only on (position, length, char codepoint label, severity).
 *
 * Fixtures are synthesized at test runtime via Buffer / String.fromCharCode
 * (no committed binary blobs) because a 6MB file in the repo would bloat the
 * package and defeat the streaming-perf rationale.
 */

import { describe, it, expect } from "vitest";
import {
  analyze,
  detectInvisibleUnicode,
  detectControlChars,
  detectHomoglyphs,
} from "@shield-scanner/core";

// `shouldStream` is a v1.18.0-internal helper. Each individual detector
// module exports its own copy (so the gating decision and the constants live
// next to the chunked walker that uses them). Tests import directly from the
// module source files — public re-export is intentionally not added at the
// core barrel to avoid bloating the analyze() surface area for unrelated
// callers.
import * as invisibleMod from "../../../core/src/invisible-unicode.js";
import * as controlMod from "../../../core/src/control-chars.js";
import * as homoglyphsMod from "../../../core/src/homoglyphs.js";

const ZWSP = "​"; // U+200B Zero Width Space (invisible-unicode, warning)
const BEL = "\x07"; // U+0007 Bell (control-char, warning)
const CYR_A = "а"; // Cyrillic 'а' (homoglyph for Latin 'a')

const CHUNK_SIZE = 1024 * 1024;
const STREAM_THRESHOLD = 5 * 1024 * 1024;

/**
 * Build a content string of approximately `targetLen` UTF-16 units, with
 * exactly one ZWSP inserted at absolute offset `boundaryPos`. The rest is
 * harmless ASCII (lowercase 'x') so no other invisible-unicode / control /
 * homoglyph signal fires.
 */
function buildBoundaryFixture(targetLen, boundaryPos, marker) {
  if (boundaryPos < 0 || boundaryPos >= targetLen) {
    throw new Error("boundaryPos out of range");
  }
  // Build with two ASCII halves + the marker in the middle so we can keep
  // memory pressure minimal compared to a per-char loop. The boundary span
  // is exactly 1 UTF-16 unit so position+1 = position of the next char.
  const left = "x".repeat(boundaryPos);
  const right = "x".repeat(targetLen - boundaryPos - 1);
  return left + marker + right;
}

describe("v1.18.0: shouldStream() gate", () => {
  it("returns false for 4MB input (below 5MB threshold)", () => {
    const small = "x".repeat(4 * 1024 * 1024);
    expect(invisibleMod.shouldStream(small)).toBe(false);
    expect(controlMod.shouldStream(small)).toBe(false);
    expect(homoglyphsMod.shouldStream(small)).toBe(false);
  });

  it("returns true for 6MB input (above 5MB threshold)", () => {
    const big = "x".repeat(6 * 1024 * 1024);
    expect(invisibleMod.shouldStream(big)).toBe(true);
    expect(controlMod.shouldStream(big)).toBe(true);
    expect(homoglyphsMod.shouldStream(big)).toBe(true);
  });

  it("returns false at exactly 5MB (strictly greater than threshold)", () => {
    const exact = "x".repeat(STREAM_THRESHOLD);
    expect(invisibleMod.shouldStream(exact)).toBe(false);
  });
});

describe("v1.18.0: invisible-unicode streaming boundary integrity", () => {
  it("detects a ZWSP placed exactly at the 1MB chunk boundary, only once", () => {
    // 6MB total, ZWSP at offset = CHUNK_SIZE (the first chunk seam).
    const totalLen = 6 * 1024 * 1024;
    const boundaryPos = CHUNK_SIZE;
    const content = buildBoundaryFixture(totalLen, boundaryPos, ZWSP);

    const findings = detectInvisibleUnicode(content);
    // Filter to ZWSP only — the rest of the content is 'x', no other
    // invisible-unicode signals should fire.
    const zwsps = findings.filter((f) => f.char === "U+200B");

    expect(zwsps.length).toBe(1);
    expect(zwsps[0].position).toBe(boundaryPos);
    expect(zwsps[0].severity).toBe("warning");
  });

  it("detects a ZWSP just after the boundary (inside overlap region) exactly once", () => {
    // Place the marker 100 bytes past the first chunk seam — well inside the
    // 2KB overlap tail of chunk-0 AND inside chunk-1's prefix.
    const totalLen = 6 * 1024 * 1024;
    const boundaryPos = CHUNK_SIZE + 100;
    const content = buildBoundaryFixture(totalLen, boundaryPos, ZWSP);

    const findings = detectInvisibleUnicode(content);
    const zwsps = findings.filter((f) => f.char === "U+200B");

    expect(zwsps.length).toBe(1);
    expect(zwsps[0].position).toBe(boundaryPos);
  });

  it("non-streaming 4MB ZWSP fixture matches streaming-shape findings", () => {
    // Same single-ZWSP fixture below the threshold — must return the same
    // shape as the streaming path so the only observable difference is the
    // (absent) summary.streamed flag at the analyze() level.
    const totalLen = 4 * 1024 * 1024;
    const boundaryPos = 2 * 1024 * 1024;
    const content = buildBoundaryFixture(totalLen, boundaryPos, ZWSP);

    const findings = detectInvisibleUnicode(content);
    const zwsps = findings.filter((f) => f.char === "U+200B");

    expect(zwsps.length).toBe(1);
    expect(zwsps[0].position).toBe(boundaryPos);
    expect(zwsps[0].severity).toBe("warning");
  });
});

describe("v1.18.0: control-chars streaming boundary integrity", () => {
  it("detects a BEL placed exactly at the 1MB chunk boundary, only once", () => {
    const totalLen = 6 * 1024 * 1024;
    const boundaryPos = CHUNK_SIZE;
    const content = buildBoundaryFixture(totalLen, boundaryPos, BEL);

    const findings = detectControlChars(content);
    expect(findings.length).toBe(1);
    expect(findings[0].position).toBe(boundaryPos);
    expect(findings[0].char).toBe("U+0007");
  });

  it("4MB BEL fixture stays on single-pass path with correct offset", () => {
    const totalLen = 4 * 1024 * 1024;
    const boundaryPos = 1_500_000;
    const content = buildBoundaryFixture(totalLen, boundaryPos, BEL);

    const findings = detectControlChars(content);
    expect(findings.length).toBe(1);
    expect(findings[0].position).toBe(boundaryPos);
  });
});

describe("v1.18.0: homoglyphs streaming boundary integrity", () => {
  it("detects Cyrillic 'а' between two Latin letters at the chunk boundary", () => {
    // Homoglyphs only fires when adjacent to Latin — 'x' is Latin so the
    // nearLatin check is satisfied automatically by the surrounding fill.
    const totalLen = 6 * 1024 * 1024;
    const boundaryPos = CHUNK_SIZE;
    const content = buildBoundaryFixture(totalLen, boundaryPos, CYR_A);

    const findings = detectHomoglyphs(content);
    expect(findings.length).toBe(1);
    expect(findings[0].position).toBe(boundaryPos);
  });

  it("4MB Cyrillic-а fixture stays on single-pass path", () => {
    const totalLen = 4 * 1024 * 1024;
    const boundaryPos = 1024 * 1024 * 2 + 5;
    const content = buildBoundaryFixture(totalLen, boundaryPos, CYR_A);

    const findings = detectHomoglyphs(content);
    expect(findings.length).toBe(1);
    expect(findings[0].position).toBe(boundaryPos);
  });
});

describe("v1.18.0: analyze() summary.streamed + chunkCount siblings", () => {
  it("4MB analyze() output has NO `streamed` / `chunkCount` keys", () => {
    const content = buildBoundaryFixture(4 * 1024 * 1024, 1_000_000, ZWSP);
    const r = analyze(content);
    expect("streamed" in r.summary).toBe(false);
    expect("chunkCount" in r.summary).toBe(false);
    // byCategory shape is still pinned to the 5-key invariant (R13).
    expect(Object.keys(r.summary.byCategory).sort()).toEqual([
      "controlChars",
      "hiddenHtml",
      "homoglyphs",
      "invisibleUnicode",
      "suspiciousPatterns",
    ]);
  });

  it("6MB analyze() output sets streamed:true and chunkCount=6", () => {
    const content = buildBoundaryFixture(6 * 1024 * 1024, CHUNK_SIZE, ZWSP);
    const r = analyze(content);
    expect(r.summary.streamed).toBe(true);
    expect(r.summary.chunkCount).toBe(6);
    // R13 invariant still holds — streaming flags are siblings, not buckets.
    expect(Object.keys(r.summary.byCategory).sort()).toEqual([
      "controlChars",
      "hiddenHtml",
      "homoglyphs",
      "invisibleUnicode",
      "suspiciousPatterns",
    ]);
    // The boundary ZWSP is detected exactly once and lives in
    // invisibleUnicode (warning).
    const ius = r.findings.invisibleUnicode.filter(
      (f) => f.char === "U+200B",
    );
    expect(ius.length).toBe(1);
    expect(ius[0].position).toBe(CHUNK_SIZE);
  });
});
