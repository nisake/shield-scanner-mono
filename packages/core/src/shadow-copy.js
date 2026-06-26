/**
 * Shadow Copy mechanism for obfuscation-aware detection (T1 + S22 integration).
 *
 * Builds read-only derived views of the original content for detection use ONLY.
 * The original `content` is NEVER mutated, and these shadows are NEVER returned
 * to the user (リスク#1 / リスク#12 absolute guardrails).
 *
 * Two shadows are produced:
 *   - invisibleStripped : ZWSP / ZWNJ / ZWJ / BOM / WJ / Mongolian VS / Soft Hyphen /
 *                         CGJ / Hangul filler / Tags block (U+E0000-U+E007F) /
 *                         Variation Selectors (U+FE00-U+FE0F, U+E0100-U+E01EF)
 *                         removed.
 *   - nfkcNormalized    : String.prototype.normalize("NFKC") applied once.
 *
 * Each shadow ships with a `shadowToOrig` Uint32Array that maps any
 * UTF-16 index in the shadow back to the original-text UTF-16 index in O(1).
 * Length = shadow.length + 1; the last slot is the original length as a sentinel
 * so callers can resolve `match.index + match[0].length` without bounds checks.
 *
 * `null` is returned when the shadow would be empty OR when it would be byte-
 * identical to the source (NFKC identity / no invisibles present) so callers
 * can cheaply skip the redundant scan.
 */

// Single-code-point invisibles to strip from invisibleStripped shadow.
const INVISIBLE_SINGLE = new Set([
  0x200b, // ZERO WIDTH SPACE
  0x200c, // ZERO WIDTH NON-JOINER
  0x200d, // ZERO WIDTH JOINER
  0xfeff, // ZERO WIDTH NO-BREAK SPACE / BOM
  0x2060, // WORD JOINER
  0x180e, // MONGOLIAN VOWEL SEPARATOR
  0x00ad, // SOFT HYPHEN
  0x034f, // COMBINING GRAPHEME JOINER
  0x1160, // HANGUL JUNGSEONG FILLER
]);

function isInvisibleCodePoint(cp) {
  if (INVISIBLE_SINGLE.has(cp)) return true;
  // Tags block (Unicode Tags, U+E0000-U+E007F)
  if (cp >= 0xe0000 && cp <= 0xe007f) return true;
  // Variation Selectors (VS1-VS16)
  if (cp >= 0xfe00 && cp <= 0xfe0f) return true;
  // Variation Selectors Supplement (VS17-VS256)
  if (cp >= 0xe0100 && cp <= 0xe01ef) return true;
  return false;
}

/**
 * Build the invisibleStripped shadow.
 *
 * Iterates by code point (handles surrogate pairs correctly) but tracks the
 * UTF-16 offset of each retained code unit so the mapping stays UTF-16-accurate
 * for downstream regex match indices.
 *
 * @param {string} content
 * @returns {{shadow: string, shadowToOrig: Uint32Array}|null}
 */
export function buildInvisibleStrippedShadow(content) {
  if (!content) return null;

  const outChars = [];
  const map = []; // shadow UTF-16 idx -> original UTF-16 idx
  let origIdx = 0;
  let removed = 0;

  for (const ch of content) {
    const cp = ch.codePointAt(0);
    const len = ch.length; // 1 for BMP, 2 for surrogate-pair (SMP)
    if (isInvisibleCodePoint(cp)) {
      removed++;
      origIdx += len;
      continue;
    }
    // Push one map entry per UTF-16 code unit of the retained char.
    for (let i = 0; i < len; i++) {
      map.push(origIdx + i);
    }
    outChars.push(ch);
    origIdx += len;
  }

  if (removed === 0) return null; // no transformation -> caller can skip

  const shadow = outChars.join("");
  if (shadow.length === 0) return null;

  // Sentinel: end-of-string maps to original length.
  map.push(content.length);

  return {
    shadow,
    shadowToOrig: Uint32Array.from(map),
  };
}

/**
 * Build the nfkcNormalized shadow.
 *
 * For each code point in `content`, NFKC-normalize that single code point and
 * push one map entry per UTF-16 code unit of the result, all pointing back at
 * the original code point's starting UTF-16 offset.
 *
 * Per-code-point normalization is an approximation of full-string NFKC: it
 * collapses the vast majority of bypass-relevant cases (Math Bold/Italic/Sans,
 * Fullwidth, super/subscript, ㍻㍼ era ligatures, ℡, ㈱, etc.) without losing
 * positional alignment to the original. Combining-mark composition that
 * crosses code-point boundaries is the documented trade-off; bypass payloads
 * in scope here don't depend on it.
 *
 * @param {string} content
 * @returns {{shadow: string, shadowToOrig: Uint32Array}|null}
 */
export function buildNfkcShadow(content) {
  if (!content) return null;

  const outChunks = [];
  const map = [];
  let origIdx = 0;
  let mutated = false;

  for (const ch of content) {
    const len = ch.length;
    const norm = ch.normalize("NFKC");
    if (norm !== ch) mutated = true;
    for (let i = 0; i < norm.length; i++) {
      map.push(origIdx);
    }
    outChunks.push(norm);
    origIdx += len;
  }

  if (!mutated) return null; // identity -> caller can skip

  const shadow = outChunks.join("");
  if (shadow.length === 0) return null;

  map.push(content.length); // sentinel

  return {
    shadow,
    shadowToOrig: Uint32Array.from(map),
  };
}

/**
 * Resolve a [shadowStart, shadowEnd) span back to original [origStart, origEnd).
 * Bounds-safe: clamps to sentinel.
 */
export function mapSpanToOriginal(shadowToOrig, shadowStart, shadowEnd) {
  const maxIdx = shadowToOrig.length - 1;
  const sStart = Math.min(Math.max(shadowStart, 0), maxIdx);
  const sEnd = Math.min(Math.max(shadowEnd, 0), maxIdx);
  return {
    start: shadowToOrig[sStart],
    end: shadowToOrig[sEnd],
  };
}
