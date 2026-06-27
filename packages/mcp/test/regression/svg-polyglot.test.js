/**
 * v1.19.0 B1 — Polyglot SVG regression.
 *
 * Pins the 6 SVG-specific kebab ids the new svg.js parser emits:
 *   - svg-script-element        (danger)
 *   - svg-event-handler         (danger,   meta.attribute)
 *   - svg-javascript-href       (danger)
 *   - svg-foreignobject-html    (warning)
 *   - svg-cdata-section         (warning)
 *   - svg-use-external-ref      (warning,  meta.href)
 *
 * Invariants (every assertion in this file):
 *   - R12: technique is a fixed kebab-case literal; raw user text never
 *     enters the technique id. Dynamic scalar values ride `meta.{attribute,
 *     href}` only.
 *   - R13: category === 'suspiciousPatterns' (so scan-file.js folds them
 *     into the canonical 5-bucket schema; no new top-level key).
 *   - parseSvg is invoked directly (no scan-file dependency) so the
 *     fixture-loading contract is decoupled from the dispatcher.
 */

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import {
  parseSvg,
  parseSvgBuffer,
  detectSvgInjection,
} from "../../server/parsers/svg.js";
import { parseHtmlBuffer } from "../../server/parsers/html.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ATTACKS = join(__dirname, "..", "fixtures", "attacks");
const BENIGN = join(__dirname, "..", "fixtures", "benign");

function findTechniques(findings) {
  return new Set((findings || []).map((f) => f.technique));
}

describe("v1.19.0 B1 Polyglot SVG: kebab id surface", () => {
  it("svg_script_tag.svg emits svg-script-element with severity=danger", async () => {
    const p = join(ATTACKS, "svg_script_tag.svg");
    if (!existsSync(p)) return;
    const r = await parseSvg(p);
    const hits = (r.extraFindings || []).filter(
      (f) => f.technique === "svg-script-element",
    );
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits[0].severity).toBe("danger");
    expect(hits[0].category).toBe("suspiciousPatterns");
    expect(hits[0].element).toBe("svg:script");
  });

  it("svg_onerror_handler.svg emits svg-event-handler with meta.attribute", async () => {
    const p = join(ATTACKS, "svg_onerror_handler.svg");
    if (!existsSync(p)) return;
    const r = await parseSvg(p);
    const hits = (r.extraFindings || []).filter(
      (f) => f.technique === "svg-event-handler",
    );
    expect(hits.length).toBeGreaterThanOrEqual(2);
    // Every event-handler finding MUST carry meta.attribute (lower-case event
    // name) — that's the dynamic scalar the i18n format-string interpolates.
    for (const h of hits) {
      expect(h.severity).toBe("danger");
      expect(h.category).toBe("suspiciousPatterns");
      expect(h.meta).toBeDefined();
      expect(typeof h.meta.attribute).toBe("string");
      expect(h.meta.attribute).toMatch(/^on[a-z]+$/);
    }
    const attrs = new Set(hits.map((h) => h.meta.attribute));
    expect(attrs.has("onload")).toBe(true);
    expect(attrs.has("onerror") || attrs.has("onclick")).toBe(true);
  });

  it("svg_javascript_href.svg emits svg-javascript-href (href + xlink:href)", async () => {
    const p = join(ATTACKS, "svg_javascript_href.svg");
    if (!existsSync(p)) return;
    const r = await parseSvg(p);
    const hits = (r.extraFindings || []).filter(
      (f) => f.technique === "svg-javascript-href",
    );
    expect(hits.length).toBeGreaterThanOrEqual(2);
    for (const h of hits) {
      expect(h.severity).toBe("danger");
      expect(h.category).toBe("suspiciousPatterns");
    }
  });

  it("svg_foreignobject_prompt.svg emits svg-foreignobject-html", async () => {
    const p = join(ATTACKS, "svg_foreignobject_prompt.svg");
    if (!existsSync(p)) return;
    const r = await parseSvg(p);
    const hits = (r.extraFindings || []).filter(
      (f) => f.technique === "svg-foreignobject-html",
    );
    expect(hits.length).toBeGreaterThanOrEqual(1);
    expect(hits[0].severity).toBe("warning");
    expect(hits[0].category).toBe("suspiciousPatterns");
    expect(hits[0].element).toBe("svg:foreignObject");
  });

  it("svg_cdata_instruction.svg emits svg-cdata-section", async () => {
    const p = join(ATTACKS, "svg_cdata_instruction.svg");
    if (!existsSync(p)) return;
    const r = await parseSvg(p);
    const hits = (r.extraFindings || []).filter(
      (f) => f.technique === "svg-cdata-section",
    );
    expect(hits.length).toBeGreaterThanOrEqual(2);
    for (const h of hits) {
      expect(h.severity).toBe("warning");
      expect(h.category).toBe("suspiciousPatterns");
    }
  });

  it("svg_use_external_ref.svg emits svg-use-external-ref with meta.href; intra-doc #frag is silent", async () => {
    const p = join(ATTACKS, "svg_use_external_ref.svg");
    if (!existsSync(p)) return;
    const r = await parseSvg(p);
    const hits = (r.extraFindings || []).filter(
      (f) => f.technique === "svg-use-external-ref",
    );
    // 2 external (https://… + //evil…) — local `#local-mark` MUST NOT surface.
    expect(hits.length).toBe(2);
    for (const h of hits) {
      expect(h.severity).toBe("warning");
      expect(h.category).toBe("suspiciousPatterns");
      expect(h.meta).toBeDefined();
      expect(typeof h.meta.href).toBe("string");
      expect(h.meta.href.startsWith("#")).toBe(false);
    }
  });
});

describe("v1.19.0 B1 Polyglot SVG: benign fixtures stay silent", () => {
  it("benign_svg_logo.svg emits no SVG-polyglot findings", async () => {
    const p = join(BENIGN, "benign_svg_logo.svg");
    if (!existsSync(p)) return;
    const r = await parseSvg(p);
    const svgHits = (r.extraFindings || []).filter((f) =>
      String(f.technique || "").startsWith("svg-"),
    );
    expect(svgHits.length).toBe(0);
  });

  it("benign_svg_inline_style.svg keeps <use href='#local'> + https <a> silent", async () => {
    const p = join(BENIGN, "benign_svg_inline_style.svg");
    if (!existsSync(p)) return;
    const r = await parseSvg(p);
    const svgHits = (r.extraFindings || []).filter((f) =>
      String(f.technique || "").startsWith("svg-"),
    );
    expect(svgHits.length).toBe(0);
  });
});

describe("v1.19.0 B1 Polyglot SVG: R12 / R13 invariants", () => {
  it("R12: technique ids are fixed kebab literals; dynamic scalars ride meta only", async () => {
    const xml = `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><use href="https://evil/x.svg#i"/></svg>`;
    const findings = detectSvgInjection(xml);
    const allowed = new Set([
      "svg-script-element",
      "svg-event-handler",
      "svg-javascript-href",
      "svg-foreignobject-html",
      "svg-cdata-section",
      "svg-use-external-ref",
    ]);
    for (const f of findings) {
      expect(allowed.has(f.technique)).toBe(true);
      // Technique id must not contain whitespace / quotes / colons / numbers.
      expect(f.technique).toMatch(/^[a-z][a-z-]+$/);
    }
  });

  it("R13: every finding carries category=suspiciousPatterns", () => {
    const xml = `<svg xmlns="http://www.w3.org/2000/svg"><script>x</script><foreignObject/><![CDATA[y]]><a href="javascript:1">.</a></svg>`;
    const findings = detectSvgInjection(xml);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.category).toBe("suspiciousPatterns");
    }
  });
});

describe("v1.19.0 B1 Polyglot SVG: html.js extension covers inline <svg>", () => {
  it("parseHtmlBuffer surfaces svg-script-element when SVG is inline in HTML", async () => {
    const html = `<!doctype html><html><body><h1>hi</h1><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg></body></html>`;
    const r = await parseHtmlBuffer(Buffer.from(html, "utf8"));
    const hits = (r.extraFindings || []).filter(
      (f) => f.technique === "svg-script-element",
    );
    expect(hits.length).toBe(1);
  });

  it("parseHtmlBuffer surfaces svg-event-handler from inline body onclick when SVG-like attributes appear", async () => {
    const html = `<svg xmlns="http://www.w3.org/2000/svg" onload="evil()"></svg>`;
    const r = await parseHtmlBuffer(Buffer.from(html, "utf8"));
    const hits = (r.extraFindings || []).filter(
      (f) => f.technique === "svg-event-handler",
    );
    expect(hits.length).toBe(1);
    expect(hits[0].meta.attribute).toBe("onload");
  });
});

describe("v1.19.0 B1 Polyglot SVG: parseSvgBuffer Uint8Array path", () => {
  it("accepts a Node Buffer and returns the same kebab triples as parseSvg", async () => {
    const p = join(ATTACKS, "svg_script_tag.svg");
    if (!existsSync(p)) return;
    const buf = await readFile(p);
    const r = await parseSvgBuffer(buf);
    const techs = findTechniques(r.extraFindings);
    expect(techs.has("svg-script-element")).toBe(true);
  });
});
