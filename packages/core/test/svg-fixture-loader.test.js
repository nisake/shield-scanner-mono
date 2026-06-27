// =============================================================
// v1.20.0 T7-SVG-B64 — svg-fixture-loader unit tests (core)
// =============================================================
// The loader lives in tools/svg-fixture-loader.mjs; this test pins its
// contract from the *core* workspace (where parser-independent helpers
// live). The MCP regression mirror only verifies that the 6 polyglot
// fixtures round-trip — here we verify the loader's behaviour in
// isolation: extension routing, whitespace tolerance, error paths.
//
// R12 reminder: this test deals only with bytes-in / bytes-out. No
// finding objects, no kebab ids — the loader does not touch parser code.
// =============================================================

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  loadSvgFixture,
  loadSvgFixtureSync,
} from "../../../tools/svg-fixture-loader.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const ATTACKS = join(
  REPO_ROOT,
  "packages",
  "mcp",
  "test",
  "fixtures",
  "attacks",
);

describe("svg-fixture-loader: extension routing", () => {
  it("decodes a real .svg.b64 attack fixture to the original SVG bytes", async () => {
    const buf = await loadSvgFixture(join(ATTACKS, "svg_script_tag.svg.b64"));
    expect(Buffer.isBuffer(buf)).toBe(true);
    const text = buf.toString("utf8");
    expect(text.startsWith("<?xml")).toBe(true);
    expect(text).toContain("<script>");
    // The payload itself must be present byte-for-byte.
    expect(text).toContain("attacker.example");
  });

  it("passes plain .svg files through untouched (backward-compat)", async () => {
    // We synthesise a tmp .svg so this test does not depend on the
    // attack-fixture .svg files existing on disk (they may be removed
    // by tools/migrate-svg-fixtures.mjs in future).
    const dir = await mkdtemp(join(tmpdir(), "svg-loader-"));
    try {
      const p = join(dir, "plain.svg");
      const body = '<svg xmlns="http://www.w3.org/2000/svg"/>';
      await writeFile(p, body, "utf8");
      const buf = await loadSvgFixture(p);
      expect(buf.toString("utf8")).toBe(body);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("is case-insensitive on the .svg.b64 suffix", async () => {
    const dir = await mkdtemp(join(tmpdir(), "svg-loader-"));
    try {
      const p = join(dir, "MIXED.Svg.B64");
      const body = "<svg/>";
      await writeFile(p, Buffer.from(body, "utf8").toString("base64"), "utf8");
      const buf = await loadSvgFixture(p);
      expect(buf.toString("utf8")).toBe(body);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("svg-fixture-loader: whitespace tolerance", () => {
  it("strips trailing newlines / CR / tabs / spaces before decoding", async () => {
    const dir = await mkdtemp(join(tmpdir(), "svg-loader-"));
    try {
      const p = join(dir, "padded.svg.b64");
      const body = "<svg/>";
      const b64 = Buffer.from(body, "utf8").toString("base64");
      // Editor-realistic noise: trailing \n, mid-string \r\n, leading spaces.
      const noisy = "   " + b64.slice(0, 4) + "\r\n" + b64.slice(4) + "\n\t \n";
      await writeFile(p, noisy, "utf8");
      const buf = await loadSvgFixture(p);
      expect(buf.toString("utf8")).toBe(body);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("svg-fixture-loader: error paths", () => {
  it("throws TypeError on empty / non-string path", async () => {
    await expect(loadSvgFixture("")).rejects.toBeInstanceOf(TypeError);
    await expect(loadSvgFixture(null)).rejects.toBeInstanceOf(TypeError);
  });

  it("throws a descriptive Error when .svg.b64 is empty", async () => {
    const dir = await mkdtemp(join(tmpdir(), "svg-loader-"));
    try {
      const p = join(dir, "empty.svg.b64");
      await writeFile(p, "\n\n  \n", "utf8");
      await expect(loadSvgFixture(p)).rejects.toThrow(/empty \.svg\.b64/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("svg-fixture-loader: sync twin", () => {
  it("loadSvgFixtureSync produces byte-identical output", async () => {
    const p = join(ATTACKS, "svg_script_tag.svg.b64");
    const asyncBuf = await loadSvgFixture(p);
    const syncBuf = loadSvgFixtureSync(p);
    expect(syncBuf.equals(asyncBuf)).toBe(true);
  });
});
