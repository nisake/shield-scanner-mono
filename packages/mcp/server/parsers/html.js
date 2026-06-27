/**
 * HTML parser.
 * Used for .html, .htm, .xml files (.svg has its own dedicated parser since
 * v1.19.0 B1 — Polyglot SVG dispatch in parsers/index.js).
 *
 * Returns the raw source so the detector can run hidden-element checks on the
 * actual markup (not just extracted text).
 *
 * v1.19.0 B1: inline <svg> blocks inside HTML / XML get the same 6-detector
 * sweep as standalone .svg files. The Polyglot-SVG attack surface (script /
 * event-handler / javascript-href / foreignObject / CDATA / external use)
 * carries over byte-identically when an attacker pastes the malicious SVG
 * into an HTML wrapper, so we share `detectSvgInjection` from svg.js rather
 * than duplicate the regex set.
 */

import { readFile } from "node:fs/promises";
import { detectSvgInjection } from "./svg.js";

export async function parseHtml(filePath) {
  const text = await readFile(filePath, "utf8");
  return {
    text,
    fileType: "html",
    extraFindings: detectSvgInjection(text),
  };
}

/**
 * Parse HTML from a Buffer (used for recursive attachment scanning).
 */
export async function parseHtmlBuffer(buffer) {
  const text = Buffer.isBuffer(buffer)
    ? buffer.toString("utf8")
    : String(buffer);
  return {
    text,
    fileType: "html",
    extraFindings: detectSvgInjection(text),
  };
}
