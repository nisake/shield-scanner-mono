/**
 * Common utility functions for Shield Scanner core modules.
 */

/**
 * Get a ±radius char context window around a position in text.
 * Newlines are replaced with ↵ for display.
 *
 * Default radius is 25. Pass a larger value (e.g. 80) for `verbosity:'detailed'`
 * mode to widen the surrounding context shown for each finding.
 *
 * S20 grapheme-aware boundary contract:
 * - `start` snaps back (max 8) when the preceding char is a combining mark,
 *   ZWJ, Variation Selector, or emoji skin-tone modifier.
 * - `end` snaps forward (max 8) past combining/ZWJ/VS/skin-tone runs.
 * - Surrogate pairs are not split: a leading low surrogate is dropped, a
 *   trailing high surrogate is dropped (or extended one when room allows).
 * - We never call `String#normalize` (R1: sanitizer must stay byte-faithful).
 */
const COMBINING_RE = /\p{M}/u;
function isExtender(ch) {
  if (!ch) return false;
  const cp = ch.codePointAt(0);
  if (cp === 0x200d) return true; // ZWJ
  if (cp >= 0xfe00 && cp <= 0xfe0f) return true; // VS1-16
  if (cp >= 0xe0100 && cp <= 0xe01ef) return true; // VS17-256
  if (cp >= 0x1f3fb && cp <= 0x1f3ff) return true; // skin-tone modifiers
  return COMBINING_RE.test(ch);
}
function isLowSurrogate(code) {
  return code >= 0xdc00 && code <= 0xdfff;
}
function isHighSurrogate(code) {
  return code >= 0xd800 && code <= 0xdbff;
}

export function getContext(text, pos, matchLen = 1, radius = 25) {
  let start = Math.max(0, pos - radius);
  let end = Math.min(text.length, pos + matchLen + radius);
  const MAX_SNAP = 8;

  // Snap start backward: if the char AT `start` is an extender (combining /
  // ZWJ / VS / skin-tone), pull `start` back so we don't slice mid-grapheme.
  // Also avoid starting on a low surrogate (which would split a pair).
  let snapped = 0;
  while (start > 0 && snapped < MAX_SNAP) {
    const ch = text[start];
    const code = text.charCodeAt(start);
    if (isLowSurrogate(code)) {
      start--;
      snapped++;
      continue;
    }
    // Also handle the case where start is just past an extender — i.e. the
    // PREVIOUS char is an extender on the boundary side.
    if (ch && isExtender(ch)) {
      start--;
      snapped++;
      continue;
    }
    break;
  }

  // Snap end forward: include any trailing extenders / surrogate completers.
  snapped = 0;
  while (end < text.length && snapped < MAX_SNAP) {
    const code = text.charCodeAt(end);
    if (isLowSurrogate(code)) {
      // High surrogate is at end-1 already inside the window; extend by one.
      end++;
      snapped++;
      continue;
    }
    // Get the codepoint starting at end (handles surrogate pairs).
    const cp = text.codePointAt(end);
    const ch = String.fromCodePoint(cp);
    if (isExtender(ch)) {
      end += ch.length;
      snapped++;
      continue;
    }
    break;
  }

  // Don't end on a lone high surrogate — would split a pair.
  if (end > 0 && end <= text.length) {
    const prev = text.charCodeAt(end - 1);
    if (isHighSurrogate(prev)) {
      if (end < text.length) end++;
      else end--;
    }
  }

  const before = text.slice(start, pos).replace(/[\n\r]/g, "↵");
  const match = text.slice(pos, pos + matchLen).replace(/[\n\r]/g, "↵");
  const after = text.slice(pos + matchLen, end).replace(/[\n\r]/g, "↵");
  // S16-004: getContext uses U+29D7 / U+29D8 (⦗⦘) brackets to avoid collision
  // with the reveal-mode marker brackets U+27E6 / U+27E7 (⟦⟧), which are used
  // by _renderRevealMarkers for invisible/control codepoint labels. Keeping
  // these two layers visually distinct lets us safely render getContext output
  // inside a reveal-mode page without bracket ambiguity.
  return `${start > 0 ? "..." : ""}${before}⦗${match}⦘${after}${
    end < text.length ? "..." : ""
  }`;
}

/**
 * Severity ranking shared by compactSummary() and worst-status helpers.
 */
const SEVERITY_RANK = { safe: 0, info: 1, warning: 2, danger: 3 };

function rank(sev) {
  return SEVERITY_RANK[sev] ?? 0;
}

/**
 * Build a token-light summary of a detector result for `verbosity:'compact'`.
 *
 * Input shape: any object with `{ summary, findings }` (the same shape that
 * analyze() returns and that every scan tool produces). Also accepts an
 * email-style `{ summary, threats_by_section }` shape — we walk the section
 * objects and aggregate their per-category counts.
 *
 * Output: a tiny object with just counts + the worst severity + a one-line
 * human-readable string. NO findings array is included, so this is safe to
 * return to an LLM as the sole content payload without context blow-up.
 */
export function compactSummary(result) {
  if (!result || typeof result !== "object") {
    return {
      total_findings: 0,
      max_severity: "safe",
      categories: {},
      one_line: "⚠ 0 findings, max=safe",
    };
  }

  const summary = result.summary || {};
  const categories = {};
  let total = 0;
  let maxSeverity = "safe";

  // Pull category counts from either:
  //   (a) summary.byCategory  — present on analyze() output
  //   (b) findings buckets    — fallback for caller-merged shapes
  //   (c) threats_by_section  — scan_email shape (sections contain findings)
  if (summary.byCategory && typeof summary.byCategory === "object") {
    for (const [cat, n] of Object.entries(summary.byCategory)) {
      if (typeof n === "number" && n > 0) {
        categories[cat] = (categories[cat] || 0) + n;
        total += n;
      }
    }
  } else if (result.findings && typeof result.findings === "object") {
    for (const [cat, items] of Object.entries(result.findings)) {
      if (Array.isArray(items) && items.length > 0) {
        categories[cat] = items.length;
        total += items.length;
      }
    }
  } else if (
    result.threats_by_section &&
    typeof result.threats_by_section === "object"
  ) {
    for (const sectionFindings of Object.values(result.threats_by_section)) {
      if (!sectionFindings) continue;
      if (Array.isArray(sectionFindings)) {
        // structural-style flat array — bucket under "structural"
        if (sectionFindings.length > 0) {
          categories.structural =
            (categories.structural || 0) + sectionFindings.length;
          total += sectionFindings.length;
        }
        continue;
      }
      for (const [cat, items] of Object.entries(sectionFindings)) {
        if (Array.isArray(items) && items.length > 0) {
          categories[cat] = (categories[cat] || 0) + items.length;
          total += items.length;
        }
      }
    }
  }

  // Prefer the summary's own status/severity counts if present.
  if (summary.status && rank(summary.status) > rank(maxSeverity)) {
    maxSeverity = summary.status;
  }
  if (typeof summary.dangerCount === "number" && summary.dangerCount > 0) {
    maxSeverity = "danger";
  } else if (
    typeof summary.warningCount === "number" &&
    summary.warningCount > 0 &&
    rank("warning") > rank(maxSeverity)
  ) {
    maxSeverity = "warning";
  }

  // Prefer summary.total when present — keeps counts consistent with the
  // severity-based counting that buildSummary() does inside detector.js.
  if (typeof summary.total === "number") total = summary.total;

  const out = {
    total_findings: total,
    max_severity: maxSeverity,
    categories,
    one_line: `⚠ ${total} findings, max=${maxSeverity}`,
  };
  // S18: surface topFindings (if already computed upstream by analyze()) in
  // snake_case so the LLM JSON contract stays consistent with one_line /
  // total_findings. Never re-computes - if analyze() did not run (caller
  // passed a hand-rolled shape), we just omit the field.
  if (Array.isArray(summary.topFindings) && summary.topFindings.length > 0) {
    out.top_findings = summary.topFindings;
  }
  return out;
}

/**
 * Expand each finding with a wider context window for `verbosity:'detailed'`.
 *
 * Pure function — returns a new findings object; does not mutate the input.
 * Only entries that already carry a numeric `position` get a `context_wide`
 * field appended; everything else is passed through untouched.
 *
 * `originalText` is required: we re-slice from it using each finding's
 * `position` and (when present) `matchLen` / `original.length`.
 */
export function expandFindingsContext(findings, originalText, radius = 80) {
  if (!findings || typeof findings !== "object" || typeof originalText !== "string") {
    return findings;
  }
  const out = {};
  for (const [cat, items] of Object.entries(findings)) {
    if (!Array.isArray(items)) {
      out[cat] = items;
      continue;
    }
    out[cat] = items.map((item) => {
      if (!item || typeof item.position !== "number") return item;
      const matchLen =
        (typeof item.matchLen === "number" && item.matchLen) ||
        (typeof item.original === "string" && item.original.length) ||
        (typeof item.char === "string" && item.char.length) ||
        1;
      return {
        ...item,
        context_wide: getContext(originalText, item.position, matchLen, radius),
      };
    });
  }
  return out;
}

/**
 * Escape HTML special chars for safe display in reports.
 */
export function escapeForDisplay(text) {
  if (typeof text !== "string") return String(text);
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Get human-readable name for a control character.
 */
export function getControlCharName(cp) {
  const names = {
    0x00: "NULL", 0x01: "SOH", 0x02: "STX", 0x03: "ETX", 0x04: "EOT",
    0x05: "ENQ", 0x06: "ACK", 0x07: "BEL", 0x08: "BS",  0x0B: "VT",
    0x0C: "FF",   0x0E: "SO",  0x0F: "SI",  0x10: "DLE", 0x11: "DC1",
    0x12: "DC2",  0x13: "DC3", 0x14: "DC4", 0x15: "NAK", 0x16: "SYN",
    0x17: "ETB",  0x18: "CAN", 0x19: "EM",  0x1A: "SUB", 0x1B: "ESC",
    0x1C: "FS",   0x1D: "GS",  0x1E: "RS",  0x1F: "US",  0x7F: "DEL",
    0x80: "PAD",  0x81: "HOP", 0x82: "BPH", 0x83: "NBH", 0x84: "IND",
    0x85: "NEL",  0x86: "SSA", 0x87: "ESA", 0x88: "HTS", 0x89: "HTJ",
    0x8A: "VTS",  0x8B: "PLD", 0x8C: "PLU", 0x8D: "RI",  0x8E: "SS2",
    0x8F: "SS3",  0x90: "DCS", 0x91: "PU1", 0x92: "PU2", 0x93: "STS",
    0x94: "CCH",  0x95: "MW",  0x96: "SPA", 0x97: "EPA", 0x98: "SOS",
    0x99: "SGCI", 0x9A: "SCI", 0x9B: "CSI", 0x9C: "ST",  0x9D: "OSC",
    0x9E: "PM",   0x9F: "APC",
  };
  return names[cp] || `Control (0x${cp.toString(16)})`;
}

/**
 * Heuristic: does this text look like an attempt to instruct an AI?
 * Used to flag suspicious content in comments, metadata, and notes.
 *
 * S7 contract (false-positive reduction):
 * - Inputs shorter than 40 chars never qualify (too little context to judge).
 * - At least 2 distinct patterns must hit at DIFFERENT positions — single
 *   "system" or "reveal" matches are not enough (catalog text, alt text,
 *   product metadata routinely contain one of these in isolation).
 */
export function looksLikeInstruction(text) {
  if (!text || typeof text !== "string") return false;
  if (text.length < 40) return false;
  const patterns = [
    /ignore/i, /instruction/i, /system/i, /prompt/i, /override/i,
    /you\s+are/i, /act\s+as/i, /pretend/i, /do\s+not/i, /must\s+not/i,
    /forget/i, /disregard/i, /bypass/i, /reveal/i, /admin/i,
  ];
  const positions = [];
  for (const p of patterns) {
    // Reset state per pattern (we don't reuse the regex; .exec gives us .index).
    const re = new RegExp(p.source, p.flags);
    const m = re.exec(text);
    if (m) positions.push(m.index);
    if (positions.length >= 2) {
      // Need two HITS at distinct positions.
      const unique = new Set(positions);
      if (unique.size >= 2) return true;
    }
  }
  return false;
}

/**
 * Load a JSON rule file via the env-abstract rulesLoader.
 *
 * Resolution order:
 *   1. If setEnv() was called with an env exposing rulesLoader -> use it.
 *      (Web entrypoints MUST call setEnv(createWebEnv()) before any detector
 *      module is imported, because detectors invoke loadRule() at module
 *      init time.)
 *   2. Otherwise, fall back to a Node fs default that reads from
 *      packages/core/data/. This keeps the MCP/CLI side working without any
 *      explicit env setup.
 *
 * Accepts both "homoglyphs" and "homoglyphs.json" for back-compat with the
 * legacy MCP-side loadRule(filename) signature.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { getEnv } from "./env/context.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// packages/core/src/utils.js -> packages/core/data/
const DEFAULT_RULES_DIR = join(__dirname, "..", "data");

const _fallbackCache = new Map();

function _nodeFallbackLoad(name) {
  if (_fallbackCache.has(name)) return _fallbackCache.get(name);
  const filename = name.endsWith(".json") ? name : `${name}.json`;
  const path = join(DEFAULT_RULES_DIR, filename);
  const data = JSON.parse(readFileSync(path, "utf8"));
  _fallbackCache.set(name, data);
  return data;
}

export function loadRule(name) {
  const env = getEnv();
  if (env && env.rulesLoader && typeof env.rulesLoader.loadRule === "function") {
    // Normalize: legacy callers pass "homoglyphs.json", env loaders accept both
    const key = name.endsWith(".json") ? name.slice(0, -5) : name;
    return env.rulesLoader.loadRule(key);
  }
  return _nodeFallbackLoad(name);
}
