/**
 * Hidden HTML element detection.
 *
 * Detects:
 * - Elements with style: display:none, visibility:hidden, opacity:0,
 *   tiny font-size, white-on-white, transparent, off-screen positioning
 * - hidden attribute
 * - <style> tags with hiding rules
 * - HTML comments with instruction-like text
 */

import * as cheerio from "cheerio";
import { escapeForDisplay, looksLikeInstruction } from "./utils.js";

const STYLE_CHECKS = [
  { pattern: /display\s*:\s*none/i, technique: "display: none" },
  { pattern: /visibility\s*:\s*hidden/i, technique: "visibility: hidden" },
  { pattern: /opacity\s*:\s*0(?:[;\s]|$)/i, technique: "opacity: 0" },
  { pattern: /font-size\s*:\s*[0-1](?:\.\d+)?px/i, technique: "Microscopic font-size" },
  {
    pattern:
      /color\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))\s*;?.*background(?:-color)?\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))/i,
    technique: "White text on white background",
  },
  {
    pattern: /color\s*:\s*(?:transparent|rgba\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0\s*\))/i,
    technique: "Transparent text",
  },
  {
    pattern: /position\s*:\s*absolute.*(?:left|top)\s*:\s*-\d{3,}/i,
    technique: "Off-screen positioning",
  },
  { pattern: /text-indent\s*:\s*-\d{3,}/i, technique: "text-indent off-screen" },
  {
    pattern: /overflow\s*:\s*hidden.*(?:width|height)\s*:\s*0/i,
    technique: "Zero-size overflow hidden",
  },
];

const CSS_HIDING_PATTERNS = [
  /display\s*:\s*none/i,
  /visibility\s*:\s*hidden/i,
  /opacity\s*:\s*0\b/i,
  /font-size\s*:\s*0/i,
  /color\s*:\s*transparent/i,
];

/**
 * Scan HTML content for hidden elements.
 * @param {string} content - HTML source
 * @returns {Array} findings
 */
export function detectHiddenElements(content) {
  const findings = [];
  const $ = cheerio.load(content, { xmlMode: false, decodeEntities: false });

  // Inspect every element's style attribute
  $("*").each((_, el) => {
    const style = $(el).attr("style") || "";
    const text = $(el).text().trim();

    // Pattern-based style checks
    for (const { pattern, technique } of STYLE_CHECKS) {
      if (pattern.test(style) && text.length > 0) {
        findings.push({
          element: el.tagName || "unknown",
          technique,
          content: escapeForDisplay(text.slice(0, 200)),
          severity: "danger",
        });
      }
    }

    // hidden attribute
    if ($(el).attr("hidden") !== undefined && text.length > 0) {
      findings.push({
        element: el.tagName || "unknown",
        technique: "hidden attribute",
        content: escapeForDisplay(text.slice(0, 200)),
        severity: "danger",
      });
    }

    // Same fg/bg color check
    const colorMatch = style.match(/(?:^|;)\s*color\s*:\s*([^;]+)/i);
    const bgMatch = style.match(/background(?:-color)?\s*:\s*([^;]+)/i);
    if (colorMatch && bgMatch && text.length > 0) {
      const fg = colorMatch[1].trim().toLowerCase();
      const bg = bgMatch[1].trim().toLowerCase();
      if (fg === bg) {
        findings.push({
          element: el.tagName || "unknown",
          technique: `Same fg/bg color (${fg})`,
          content: escapeForDisplay(text.slice(0, 200)),
          severity: "danger",
        });
      }
    }
  });

  // <style> tags with hiding rules
  $("style").each((_, el) => {
    const css = $(el).text();
    for (const p of CSS_HIDING_PATTERNS) {
      if (p.test(css)) {
        findings.push({
          element: "<style>",
          technique: `CSS rule: ${p.source}`,
          content: "(stylesheet contains hiding rules)",
          severity: "warning",
        });
      }
    }
  });

  // HTML comments with instruction-like text
  const commentRegex = /<!--([\s\S]*?)-->/g;
  let m;
  while ((m = commentRegex.exec(content)) !== null) {
    const commentText = m[1].trim();
    if (commentText.length > 10 && looksLikeInstruction(commentText)) {
      findings.push({
        element: "<!-- comment -->",
        technique: "HTML comment with instruction",
        content: escapeForDisplay(commentText.slice(0, 200)),
        severity: "warning",
      });
    }
  }

  return findings;
}

/**
 * Strip hidden elements from HTML (sanitizer helper).
 */
export function stripHiddenElements(content) {
  let result = content;

  // Remove elements with hiding styles
  result = result.replace(
    /<([a-z][a-z0-9]*)\b([^>]*?)style\s*=\s*"([^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:[;\s"])|font-size\s*:\s*0)[^"]*)"([^>]*)>[\s\S]*?<\/\1>/gi,
    "<!-- [REMOVED: hidden element] -->"
  );

  // Remove elements with hidden attribute
  result = result.replace(
    /<([a-z][a-z0-9]*)\b([^>]*?)\bhidden\b([^>]*)>[\s\S]*?<\/\1>/gi,
    "<!-- [REMOVED: hidden element] -->"
  );

  return result;
}
