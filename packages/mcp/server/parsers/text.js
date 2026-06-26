/**
 * Plain text parser.
 * Used for .txt, .md, .csv, .json files.
 *
 * Returns { text, fileType: "text", extraFindings: [] }.
 * Content is read as-is with UTF-8 encoding.
 */

import { readFile } from "node:fs/promises";

export async function parseText(filePath) {
  const text = await readFile(filePath, "utf8");
  return {
    text,
    fileType: "text",
    extraFindings: [],
  };
}

/**
 * Parse text from a Buffer (used for recursive attachment scanning).
 * Buffer is decoded as UTF-8.
 */
export async function parseTextBuffer(buffer) {
  const text = Buffer.isBuffer(buffer)
    ? buffer.toString("utf8")
    : String(buffer);
  return {
    text,
    fileType: "text",
    extraFindings: [],
  };
}
