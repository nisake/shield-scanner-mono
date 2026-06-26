/**
 * Invisible Unicode character detection.
 *
 * Detects:
 * - Unicode Tags Block (U+E0000 - U+E007F) — known prompt injection vector
 * - Bidi control characters (U+202A-U+202E, U+2066-U+2069) — Trojan Source vector
 *   - Override chars (U+202D LRO / U+202E RLO) single = danger
 *   - Embedding chars (U+202A LRE / U+202B RLE / U+202C PDF) single = warning
 *   - Isolate chars (U+2066-U+2069 LRI/RLI/FSI/PDI) single = warning
 *   - ANY Bidi family >= 3 in same text = all upgraded to danger (over-use signal)
 * - Known invisible chars (zero-width, soft hyphen, etc.)
 * - Private Use Areas (PUA)
 *
 * NOTE on signature: detectInvisibleUnicode(content) returns Array<Finding>.
 * Caller (detector.js) must not change. Bidi findings carry an extra
 * `category: "bidi-control"` field; existing categories' findings are unchanged.
 */

import { getContext, loadRule } from "./utils.js";

// Cache rule data at module load
const { chars: INVISIBLE_CHAR_LIST } = loadRule("invisible-chars.json");
const INVISIBLE_CHAR_MAP = new Map(
  INVISIBLE_CHAR_LIST.map((c) => [parseInt(c.code, 16), c.name])
);

// Bidi control characters — handled with category-specific severity rules.
// Map<codepoint, { name, baseSeverity, kind }>
//   kind: "override" | "embedding" | "isolate"
//   baseSeverity: severity when this char appears alone (single occurrence)
const BIDI_CONTROLS = new Map([
  [0x202a, { name: "Left-to-Right Embedding (LRE)", baseSeverity: "warning", kind: "embedding" }],
  [0x202b, { name: "Right-to-Left Embedding (RLE)", baseSeverity: "warning", kind: "embedding" }],
  [0x202c, { name: "Pop Directional Formatting (PDF)", baseSeverity: "warning", kind: "embedding" }],
  [0x202d, { name: "Left-to-Right Override (LRO)", baseSeverity: "danger", kind: "override" }],
  [0x202e, { name: "Right-to-Left Override (RLO)", baseSeverity: "danger", kind: "override" }],
  [0x2066, { name: "Left-to-Right Isolate (LRI)", baseSeverity: "warning", kind: "isolate" }],
  [0x2067, { name: "Right-to-Left Isolate (RLI)", baseSeverity: "warning", kind: "isolate" }],
  [0x2068, { name: "First Strong Isolate (FSI)", baseSeverity: "warning", kind: "isolate" }],
  [0x2069, { name: "Pop Directional Isolate (PDI)", baseSeverity: "warning", kind: "isolate" }],
]);

// Bidi over-use threshold: if total Bidi-family chars in the text reaches this
// number, ALL Bidi findings are escalated to "danger" (excessive-use signal).
const BIDI_OVERUSE_THRESHOLD = 3;

/**
 * Scan text for invisible Unicode characters.
 * @param {string} content - The text to scan
 * @returns {Array} Array of finding objects
 */
export function detectInvisibleUnicode(content) {
  const findings = [];

  // First pass: count Bidi-family occurrences so we can apply the over-use rule.
  // Cheap O(n) scan; avoids needing a second pass through findings after the
  // main loop and keeps finding objects immutable once pushed.
  let bidiTotal = 0;
  for (let i = 0; i < content.length; i++) {
    const cp = content.codePointAt(i);
    if (cp === undefined) continue;
    if (BIDI_CONTROLS.has(cp)) bidiTotal++;
    if (cp > 0xffff) i++;
  }
  const bidiOverUse = bidiTotal >= BIDI_OVERUSE_THRESHOLD;

  for (let i = 0; i < content.length; i++) {
    const cp = content.codePointAt(i);
    if (cp === undefined) continue;

    // Unicode Tags Block (U+E0000 - U+E007F)
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      const asciiEquiv = cp - 0xe0000;
      const readable =
        asciiEquiv >= 0x20 && asciiEquiv <= 0x7e
          ? String.fromCharCode(asciiEquiv)
          : `0x${asciiEquiv.toString(16)}`;
      findings.push({
        char: `U+${cp.toString(16).toUpperCase().padStart(5, "0")}`,
        name: `Unicode Tag (ASCII: "${readable}")`,
        position: i,
        context: getContext(content, i),
        severity: "danger",
      });
      if (cp > 0xffff) i++; // surrogate pair
      continue;
    }

    // Bidi controls — handled BEFORE the generic INVISIBLE_CHAR_MAP check so
    // that the category-specific severity rules win over the JSON default.
    if (BIDI_CONTROLS.has(cp)) {
      const spec = BIDI_CONTROLS.get(cp);
      const severity = bidiOverUse ? "danger" : spec.baseSeverity;
      findings.push({
        char: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        name: spec.name,
        category: "bidi-control",
        kind: spec.kind,
        position: i,
        context: getContext(content, i),
        severity,
      });
      // Bidi chars are all BMP (<= U+2069), no surrogate-pair concern.
      continue;
    }

    // Known invisible chars (non-Bidi)
    if (INVISIBLE_CHAR_MAP.has(cp)) {
      findings.push({
        char: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        name: INVISIBLE_CHAR_MAP.get(cp),
        position: i,
        context: getContext(content, i),
        severity: "warning",
      });
    }

    // Private Use Area (BMP, SPUA-A, SPUA-B)
    if (
      (cp >= 0xe000 && cp <= 0xf8ff) ||
      (cp >= 0xf0000 && cp <= 0xffffd) ||
      (cp >= 0x100000 && cp <= 0x10fffd)
    ) {
      findings.push({
        char: `U+${cp.toString(16).toUpperCase()}`,
        name: "Private Use Area",
        position: i,
        context: getContext(content, i),
        severity: "warning",
      });
    }

    if (cp > 0xffff) i++; // skip surrogate pair low half
  }

  return findings;
}

/**
 * Remove all invisible Unicode characters from text.
 * Used by the sanitizer.
 */
export function stripInvisibleUnicode(content) {
  let result = content;

  // Remove Unicode Tags block
  result = result.replace(/[\u{E0000}-\u{E007F}]/gu, "");

  // Remove known invisible chars
  const codes = INVISIBLE_CHAR_LIST.map((c) => parseInt(c.code, 16));
  const regex = new RegExp(
    "[" +
      codes.map((c) => `\\u${c.toString(16).padStart(4, "0")}`).join("") +
      "]",
    "g"
  );
  result = result.replace(regex, "");

  return result;
}
