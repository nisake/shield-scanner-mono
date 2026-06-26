/**
 * HTML parser.
 * Used for .html, .htm, .xml, .svg files.
 *
 * Returns the raw source so the detector can run hidden-element checks on the
 * actual markup (not just extracted text).
 */

import { readFile } from "node:fs/promises";

export async function parseHtml(filePath) {
  const text = await readFile(filePath, "utf8");
  return {
    text,
    fileType: "html",
    extraFindings: [],
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
    extraFindings: [],
  };
}
