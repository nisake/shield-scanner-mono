// =============================================================
//  Shield Scanner — SVG fixture loader (v1.20.0 T7-SVG-B64)
// =============================================================
// Loads SVG attack fixtures from disk while keeping the on-disk artifact
// non-renderable by Claude Desktop's file-preview inline-render path.
//
// Why this helper exists (v1.19.0 B1 side-effect):
//   * Claude Desktop's file preview inline-renders ".svg" files in the
//     transcript pane.
//   * Six attack fixtures (svg_*.svg) contain live <script>, onload=,
//     onerror=, javascript: hrefs — Desktop *executes* them on preview,
//     popping alert dialogs and (in principle) firing exfil network calls.
//   * Migrating the attack fixtures to ".svg.b64" (base64-encoded text) makes
//     Desktop treat them as opaque text — no inline render, no execution —
//     while keeping the raw payload byte-for-byte recoverable.
//
// Contract:
//   - loadSvgFixture(absPath): Promise<Buffer>
//     * ".svg.b64": read text, base64-decode, return Buffer of the original
//       SVG bytes. Strips a trailing newline if present (editors add one).
//     * ".svg":     read file as-is, return Buffer. Backward-compat for the
//       benign fixtures and any consumer that hasn't migrated yet.
//   - The returned Buffer is byte-identical to the original SVG, so any
//     parser (parseSvg / parseSvgBuffer / parseHtml) sees exactly the
//     same input it always has.
//
// R12 reminder: this file deals only with fixture I/O. No technique strings,
// no severity, no kebab ids — just bytes in, bytes out.
// =============================================================

import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";

/**
 * Load an SVG fixture from disk, transparently base64-decoding ".svg.b64"
 * files. Returns a Buffer with the original SVG bytes.
 *
 * @param {string} absPath Absolute path to a ".svg" or ".svg.b64" fixture.
 * @returns {Promise<Buffer>}
 */
export async function loadSvgFixture(absPath) {
  if (typeof absPath !== "string" || absPath.length === 0) {
    throw new TypeError("loadSvgFixture: absPath must be a non-empty string");
  }
  const lower = absPath.toLowerCase();
  if (lower.endsWith(".svg.b64")) {
    const text = await readFile(absPath, "utf8");
    // Strip ASCII whitespace (newlines / CR / tabs / spaces) so that editor-
    // added trailing newlines and accidental line wraps don't corrupt the
    // base64 token. Buffer.from(..., 'base64') already tolerates whitespace
    // in Node.js, but we normalize here so the contract is explicit.
    const compact = text.replace(/[\s]+/g, "");
    if (compact.length === 0) {
      throw new Error(`loadSvgFixture: empty .svg.b64 file at ${absPath}`);
    }
    return Buffer.from(compact, "base64");
  }
  // Plain ".svg" (benign fixtures, legacy callers): pass through.
  return await readFile(absPath);
}

/**
 * Synchronous twin of {@link loadSvgFixture}. Useful for harnesses that
 * can't await (e.g. early-init parity scaffolding). Browsers ship the same
 * logic via parsers-web — node-only helpers stay here.
 *
 * @param {string} absPath
 * @returns {Buffer}
 */
export function loadSvgFixtureSync(absPath) {
  // Synchronous twin: same contract as loadSvgFixture, just blocking I/O.
  if (typeof absPath !== "string" || absPath.length === 0) {
    throw new TypeError("loadSvgFixtureSync: absPath must be a non-empty string");
  }
  const lower = absPath.toLowerCase();
  if (lower.endsWith(".svg.b64")) {
    const text = readFileSync(absPath, "utf8");
    const compact = text.replace(/[\s]+/g, "");
    if (compact.length === 0) {
      throw new Error(`loadSvgFixtureSync: empty .svg.b64 file at ${absPath}`);
    }
    return Buffer.from(compact, "base64");
  }
  return readFileSync(absPath);
}
