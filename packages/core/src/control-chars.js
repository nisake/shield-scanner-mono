/**
 * Control character detection.
 *
 * Detects control characters (U+0000-U+001F excluding \t\n\r, U+007F-U+009F)
 * which can be used to hide malicious instructions or corrupt rendering.
 */

import { getControlCharName } from "./utils.js";

/**
 * Scan text for control characters.
 * Excludes normal whitespace (tab, LF, CR).
 * @param {string} content
 * @returns {Array} findings
 */
export function detectControlChars(content) {
  const findings = [];

  for (let i = 0; i < content.length; i++) {
    const cp = content.charCodeAt(i);
    const isC0 = cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d;
    const isC1 = cp >= 0x7f && cp <= 0x9f;

    if (isC0 || isC1) {
      findings.push({
        char: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        name: getControlCharName(cp),
        position: i,
        severity: "warning",
      });
    }
  }

  return findings;
}

/**
 * Strip control characters from text (sanitizer helper).
 * Preserves tab, LF, CR.
 */
export function stripControlChars(content) {
  // \x00-\x08, \x0B, \x0C, \x0E-\x1F, \x7F-\x9F
  return content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, "");
}
