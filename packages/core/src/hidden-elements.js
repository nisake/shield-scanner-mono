/**
 * Hidden HTML element detection.
 *
 * Detects:
 * - Elements with style: display:none, visibility:hidden, opacity:0,
 *   tiny font-size, white-on-white, transparent, off-screen positioning
 * - hidden attribute
 * - <style> tags with hiding rules
 * - HTML comments with instruction-like text
 *
 * Parser routing (v1.17.0):
 *   - Web bundle: env.htmlParser (DOMParser adapter via createWebEnv)
 *   - Node/MCP/tests with no setEnv(): _hidden-elements-default-parser.js
 *     lazy-builds a cheerio adapter and caches it.
 *   - The Web build (packages/web/build.mjs) stubs the default-parser module
 *     to drop cheerio + parse5 + htmlparser2 from the dist bundle (-270 KiB).
 *
 * CRITICAL semantic delta vs the pre-v1.17.0 raw-cheerio path:
 *   $(el).attr('hidden') (cheerio) returned `undefined` for absent.
 *   el.getAttribute('hidden') (adapter contract — both node and web wrap()
 *   normalize to null) returns `null` for absent.
 *   The comparator MUST be `!== null` here (a copy-paste of `!== undefined`
 *   would flag every element as having the hidden attribute).
 */

import { escapeForDisplay, looksLikeInstruction } from "./utils.js";
import { getEnv } from "./env/context.js";
import { getDefaultHtmlParser } from "./_hidden-elements-default-parser.js";

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
  const env = getEnv();
  const parser =
    env && env.htmlParser && typeof env.htmlParser.parse === "function"
      ? env.htmlParser
      : getDefaultHtmlParser();
  const doc = parser.parse(content);

  // Inspect every element's style attribute
  const elements = doc.querySelectorAll("*");
  for (const el of elements) {
    const style = el.getAttribute("style") || "";
    const text = (el.textContent || "").trim();

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

    // hidden attribute — CRITICAL: !== null (adapter contract returns null for
    // absent; the pre-v1.17.0 raw-cheerio code used !== undefined).
    if (el.getAttribute("hidden") !== null && text.length > 0) {
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
  }

  // <style> tags with hiding rules
  const styleTags = doc.getStyleTags();
  for (const el of styleTags) {
    const css = el.textContent || "";
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
  }

  // HTML comments with instruction-like text — regex on raw content (parser
  // agnostic). Cheerio and DOMParser disagree on how to surface comment nodes
  // (cheerio: $('*').contents() type==='comment'; DOMParser: createTreeWalker
  // SHOW_COMMENT). Sticking with regex avoids that divergence entirely.
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
