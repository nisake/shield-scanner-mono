// =============================================================
// v1.20.0 T7-SVG-B64 — svg-fixture-loader regression (MCP)
// =============================================================
// Pins the contract that every v1.19.0 B1 polyglot-SVG attack fixture
// has a ".svg.b64" sibling and that the sibling round-trips through
// the canonical loader (tools/svg-fixture-loader.mjs) into a buffer
// the existing parseSvgBuffer can scan unchanged.
//
// Why MCP-side too: the core test pins the loader in isolation; this
// test pins the *integration* point — every attack fixture must be
// loadable through the .b64 path before tools/parity-check.mjs and the
// downstream parser harness can migrate.
// =============================================================

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { loadSvgFixture } from "../../../../tools/svg-fixture-loader.mjs";
import { parseSvgBuffer } from "../../server/parsers/svg.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ATTACKS = resolve(__dirname, "..", "fixtures", "attacks");

// The six v1.19.0 B1 polyglot SVG attack fixtures. Tuple: [stem,
// expected kebab id surfaced by parseSvgBuffer]. The parser is the
// authoritative source of truth for the kebab ids — we just verify
// that the .b64 round-trip yields a buffer with the same surface.
const FIXTURES = [
  ["svg_script_tag", "svg-script-element"],
  ["svg_onerror_handler", "svg-event-handler"],
  ["svg_javascript_href", "svg-javascript-href"],
  ["svg_foreignobject_prompt", "svg-foreignobject-html"],
  ["svg_cdata_instruction", "svg-cdata-section"],
  ["svg_use_external_ref", "svg-use-external-ref"],
];

describe("v1.20.0 T7-SVG-B64: every attack fixture has a .b64 sibling", () => {
  for (const [stem] of FIXTURES) {
    it(`${stem}.svg.b64 exists on disk`, () => {
      const p = join(ATTACKS, `${stem}.svg.b64`);
      expect(existsSync(p)).toBe(true);
    });
  }
});

describe("v1.20.0 T7-SVG-B64: .b64 decodes to the original SVG bytes", () => {
  for (const [stem] of FIXTURES) {
    it(`${stem}: round-trip matches .svg when both exist`, async () => {
      const svgPath = join(ATTACKS, `${stem}.svg`);
      const b64Path = join(ATTACKS, `${stem}.svg.b64`);
      const decoded = await loadSvgFixture(b64Path);
      expect(Buffer.isBuffer(decoded)).toBe(true);
      expect(decoded.length).toBeGreaterThan(0);
      if (existsSync(svgPath)) {
        const original = await readFile(svgPath);
        expect(decoded.equals(original)).toBe(true);
      }
    });
  }
});

describe("v1.20.0 T7-SVG-B64: parseSvgBuffer sees the same surface via .b64", () => {
  for (const [stem, expectedTech] of FIXTURES) {
    it(`${stem}: parseSvgBuffer surfaces ${expectedTech}`, async () => {
      const b64Path = join(ATTACKS, `${stem}.svg.b64`);
      const buf = await loadSvgFixture(b64Path);
      const result = await parseSvgBuffer(buf);
      const techs = new Set(
        (result.extraFindings || []).map((f) => f.technique),
      );
      expect(techs.has(expectedTech)).toBe(true);
    });
  }
});
