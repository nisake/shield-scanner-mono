/**
 * S18: Priority scoring + topFindings selector.
 *
 * Assigns each finding a `priority` (integer 0-100) so downstream consumers
 * (LLMs reading the JSON, the Web UI banner) can answer "what should I look at
 * first?" without re-deriving severity heuristics on every consumer.
 *
 * Key contracts (must-fix list from review):
 *
 *   1. `computePriority(category, severity, position, contentLength)`
 *      - 4-primitive signature so it can be called from anywhere (no finding
 *        object required).
 *      - When `position` is undefined / null / non-numeric, `prominence` falls
 *        back to 1.0 (neutral). hiddenHtml findings have no numeric position;
 *        without this guard their priority would be NaN.
 *      - For long content (> 2000 chars) the "head of prompt boost" is OFF
 *        - long documents have findings anywhere, so head-bias would mislead.
 *
 *   2. `CATEGORY_WEIGHTS` is the SINGLE source of truth for both MCP and Web.
 *      The Web version (index.html) MUST mirror this table verbatim. A
 *      `?? 1.0` fallback in computePriority is the insurance against future
 *      categories not listed here.
 *
 *   3. `buildTopFindings(findings, limit = 5)`:
 *      - `severity === 'info' | 'safe' | undefined` are filtered out (legit
 *        emoji VS / single Math char will not surface on the banner).
 *      - Per-category cap of 2 - a document full of bidi controls cannot
 *        monopolise the entire top-5 list.
 *      - The `label` field is sourced from detector-controlled strings only
 *        (`pattern` / `name` / `technique` / `type` / `kind`). User-supplied
 *        `matched` / `original` / `content` / `replacement` are NEVER read
 *        into the label - R12 hard rule (no raw user text leaking into the
 *        summary surface).
 *
 *   4. `attachPriorities(findings, contentLength)`:
 *      - Mutates each finding in place to add `priority`.
 *      - suspiciousPatterns entries with no severity field default to 'danger'
 *        (matches detector.js#countBySeverity defaultSev='danger').
 */

/**
 * Per-category multiplier. Stays in sync with the Web mirror in index.html.
 *
 * Rationale:
 *   - hiddenHtml / bidiOverride at 1.20: most "invisible to the user" attack
 *     family (display:none, markdown image exfil, Trojan Source).
 *   - suspiciousPatterns at 1.10: direct intent-injection signals.
 *   - invisibleUnicode / variationSelectors / combiningChars at 1.05: medium-
 *     stealth obfuscation channels.
 *   - homoglyphs / mathSymbolBypass at 1.00: visual mimicry (often only
 *     warning-level on its own).
 *   - controlChars at 0.95: legitimate uses exist (rare BEL in old logs);
 *     keep it just below the neutral line.
 */
export const CATEGORY_WEIGHTS = {
  hiddenHtml: 1.20,
  bidiOverride: 1.20,
  suspiciousPatterns: 1.10,
  invisibleUnicode: 1.05,
  variationSelectors: 1.05,
  combiningChars: 1.05,
  homoglyphs: 1.00,
  mathSymbolBypass: 1.00,
  controlChars: 0.95,
};

/**
 * Severity -> base score. Anything not in the map falls back to `info` (10).
 */
export const SEVERITY_BASE = {
  danger: 70,
  warning: 35,
  info: 10,
  safe: 5,
};

/**
 * Map an item-level `category` tag (set by detectors like invisible-unicode.js
 * for bidi-control findings) to the priority bucket whose weight should apply.
 *
 * Today the only item-level category we surface is `bidi-control`. We map it
 * to the `bidiOverride` bucket so a Trojan-Source RLO finding gets the same
 * 1.20 multiplier as the Web build (which already uses a `bidiOverride`
 * bucket directly). Without this hook, the MCP path would score it at the
 * generic `invisibleUnicode` rate (1.05), creating a 12-point MCP/Web drift.
 *
 * Other reserved tag values (`math-bypass`, `combining-stack`,
 * `variation-selector`) are listed so the table stays a single source of
 * truth — current detectors don't emit them yet.
 */
const ITEM_CATEGORY_TO_BUCKET = {
  "bidi-control": "bidiOverride",
  "math-bypass": "mathSymbolBypass",
  "combining-stack": "combiningChars",
  "variation-selector": "variationSelectors",
};

/**
 * Resolve the effective category-weight bucket for a finding.
 *
 * `bucketCategory` is the parent category (e.g. `invisibleUnicode`).
 * `itemCategory` is the optional finding-level category tag (e.g.
 * `bidi-control`). The item-level tag wins when it maps to a known bucket so
 * MCP and Web score identical attacks identically (drift contract).
 */
function resolveCategoryWeight(bucketCategory, itemCategory) {
  if (typeof itemCategory === "string") {
    const mapped = ITEM_CATEGORY_TO_BUCKET[itemCategory];
    if (mapped && CATEGORY_WEIGHTS[mapped] !== undefined) {
      return CATEGORY_WEIGHTS[mapped];
    }
  }
  return CATEGORY_WEIGHTS[bucketCategory] ?? 1.0;
}

/**
 * Pure scoring function. Returns an integer in [0, 100].
 *
 * @param {string} category
 * @param {string} severity
 * @param {number|undefined|null} position  - UTF-16 index in original content
 * @param {number} contentLength            - length of the original content
 * @param {string} [itemCategory]           - optional item-level category tag
 *                                            (e.g. "bidi-control"). Overrides
 *                                            the parent bucket weight when it
 *                                            maps to a known bucket.
 * @returns {number}
 */
export function computePriority(category, severity, position, contentLength, itemCategory) {
  const severityBase = SEVERITY_BASE[severity] ?? SEVERITY_BASE.info;
  const categoryWeight = resolveCategoryWeight(category, itemCategory);

  // prominence: small boost (max +15%) for findings in the first 1/N of the
  // content. Only applied when:
  //   - `position` is a real number
  //   - `contentLength` is positive
  //   - the document is short (<= 2000 chars). For longer documents the
  //     "head of prompt" heuristic stops being a reliable signal, so we
  //     drop it entirely (must-fix #7).
  let prominence = 1.0;
  if (
    typeof position === "number" &&
    Number.isFinite(position) &&
    typeof contentLength === "number" &&
    contentLength > 0 &&
    contentLength <= 2000
  ) {
    const head = Math.max(0, 1 - position / contentLength);
    prominence = 1 + 0.15 * head;
  }

  const score = severityBase * categoryWeight * prominence;
  return Math.round(Math.min(100, Math.max(0, score)));
}

/**
 * Pick a reason tag for a finding. Purely advisory metadata so the
 * UI / LLM consumer can explain *why* a finding ranks high without leaking
 * any raw user text.
 *
 * @param {string} category
 * @param {string} severity
 * @param {number|undefined} position
 * @param {number} contentLength
 * @returns {string}
 */
function reasonFor(category, severity, position, contentLength, itemCategory) {
  if (severity === "danger" && category === "suspiciousPatterns") {
    return "danger-pattern";
  }
  // Item-level bidi-control tag wins: the finding is in the invisibleUnicode
  // bucket but scored as bidiOverride (1.20). Mirror that in the reason tag
  // so the trace is honest.
  if (itemCategory === "bidi-control") return "hidden-html-category-weight";
  if (category === "hiddenHtml") return "hidden-html-category-weight";
  if (category === "bidiOverride") return "hidden-html-category-weight";
  if (
    typeof position === "number" &&
    Number.isFinite(position) &&
    contentLength > 0 &&
    contentLength <= 2000 &&
    position <= contentLength * 0.15
  ) {
    return "head-of-prompt-boost";
  }
  if (severity === "warning") return "warning-pattern";
  return "category-weight";
}

/**
 * Attach `priority` (and `priorityReason` for trace-debugging) to each finding
 * across every category bucket.
 *
 * Mutates in place - the caller already owns the findings object emitted by
 * analyze(). suspiciousPatterns entries with no explicit severity default to
 * 'danger' so the count and priority stay consistent with buildSummary.
 *
 * @param {Object} findings - `{ [category]: Finding[] }`
 * @param {number} contentLength
 */
export function attachPriorities(findings, contentLength) {
  if (!findings || typeof findings !== "object") return findings;
  for (const [category, items] of Object.entries(findings)) {
    if (!Array.isArray(items)) continue;
    for (const item of items) {
      if (!item || typeof item !== "object") continue;
      // suspiciousPatterns has historically been treated as danger when no
      // explicit severity field exists. Stay consistent.
      const sev =
        item.severity ||
        (category === "suspiciousPatterns" ? "danger" : "info");
      const pos = typeof item.position === "number" ? item.position : undefined;
      // Pass item-level category tag (e.g. "bidi-control") so a Trojan-Source
      // RLO scores at bidiOverride=1.20 not invisibleUnicode=1.05 — keeps MCP
      // and Web byte-equivalent (drift contract).
      const itemCat = typeof item.category === "string" ? item.category : undefined;
      const p = computePriority(category, sev, pos, contentLength, itemCat);
      item.priority = p;
      item.priorityReason = reasonFor(category, sev, pos, contentLength, itemCat);
    }
  }
  return findings;
}

/**
 * Sanitise a detector-controlled string into a safe banner label.
 *
 * R12: raw user text MUST NOT enter `label`. Detector-controlled strings (e.g.
 * pattern names from the JSON rules) should never contain controls or bidi
 * formatting, but we strip them defensively anyway. Codepoint-by-codepoint so
 * the source stays portable across editors / line endings.
 */
function safeLabel(s) {
  if (typeof s !== "string") return "";
  let cleaned = "";
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    // C0: 0x00-0x1F, DEL: 0x7F, C1: 0x80-0x9F
    if (cp <= 0x1f || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) continue;
    // Zero-width: ZWSP, ZWNJ, ZWJ, ZWNBSP
    if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff) continue;
    // Bidi formatting: LRM/RLM, LRE/RLE/PDF/LRO/RLO, LRI/RLI/FSI/PDI
    if (cp === 0x200e || cp === 0x200f) continue;
    if (cp >= 0x202a && cp <= 0x202e) continue;
    if (cp >= 0x2066 && cp <= 0x2069) continue;
    cleaned += s[i];
  }
  if (cleaned.length <= 60) return cleaned;
  return cleaned.slice(0, 57) + "...";
}

/**
 * Derive the label for a finding from detector-controlled fields only.
 * Order of preference: pattern -> name -> technique -> type -> kind -> category.
 *
 * NEVER reads `matched` / `original` / `content` / `replacement` (R12).
 */
function labelFor(finding, category) {
  const candidates = [
    finding.pattern,
    finding.name,
    finding.technique,
    finding.type,
    finding.kind,
  ];
  for (const c of candidates) {
    if (typeof c === "string" && c.length > 0) return safeLabel(c);
  }
  return safeLabel(category);
}

/**
 * Pattern names that are inherently noisy in chat-log / transcript paste-ins.
 * A document containing a single `Human:` and a single `Assistant:` line — the
 * shape of every ChatGPT/Claude conversation paste — would otherwise eat both
 * suspiciousPatterns slots in the banner with no actionable signal.
 *
 * Policy: these patterns must fire 3+ times in the *same finding bucket* before
 * they're eligible for `topFindings`. The findings still appear in
 * `findings.suspiciousPatterns` (consumers can render them inline) — only the
 * banner surface filters them out.
 *
 * The rule names mirror `server/rules/suspicious-patterns.json` verbatim.
 */
const TRANSCRIPT_NOISE_PATTERNS = new Set([
  "Conversation turn marker", // Human: / Assistant:
  "Alpaca format marker",     // ### Instruction / ### Response
  "Llama2 system marker",     // <<SYS>> / <</SYS>>
  // v1.10.0 Theme B: markdown heading role impersonation (## System: / ### Assistant:).
  // Single-occurrence headings appear constantly in technical docs / blogs about
  // chat APIs, so the 3-hit threshold gates banner surfacing; the finding itself
  // still appears in findings.suspiciousPatterns.
  "Markdown heading impersonation",
]);
const TRANSCRIPT_NOISE_MIN_HITS = 3;

/**
 * Count how many times each transcript-noise pattern fires inside the
 * suspiciousPatterns bucket. Returned as a Map(patternName -> count).
 */
function countTranscriptNoise(items) {
  const counts = new Map();
  if (!Array.isArray(items)) return counts;
  for (const it of items) {
    if (!it || typeof it !== "object") continue;
    if (TRANSCRIPT_NOISE_PATTERNS.has(it.pattern)) {
      counts.set(it.pattern, (counts.get(it.pattern) || 0) + 1);
    }
  }
  return counts;
}

/**
 * Build the top-priority finding list for the summary surface.
 *
 * Filters out info/safe/undefined severity, sorts by priority desc (tiebreak:
 * category alphabetic), and enforces a per-category cap of 2 entries.
 *
 * Each output entry has the shape:
 *   { category, idx, priority, severity, label, reason }
 *
 * `idx` is the position of the finding in its category array - consumers can
 * jump straight to it without searching.
 *
 * @param {Object} findings
 * @param {number} [limit=5]
 * @returns {Array}
 */
export function buildTopFindings(findings, limit = 5) {
  if (!findings || typeof findings !== "object") return [];

  // Bug #5: transcript-noise patterns are only banner-eligible when they
  // fire >= 3 times in the suspiciousPatterns bucket. Compute once.
  const noiseCounts = countTranscriptNoise(findings.suspiciousPatterns);

  const flat = [];
  for (const [category, items] of Object.entries(findings)) {
    if (!Array.isArray(items)) continue;
    items.forEach((item, idx) => {
      if (!item || typeof item !== "object") return;
      const sev =
        item.severity ||
        (category === "suspiciousPatterns" ? "danger" : undefined);
      // Filter out info / safe / undefined - banner is for actionable items.
      if (sev !== "danger" && sev !== "warning") return;
      // Bug #5: transcript-noise filter. Chat-log paste-ins legitimately
      // contain a `Human:` and an `Assistant:` line each — without this
      // filter, those two findings would fully consume the
      // suspiciousPatterns per-category cap (=2) and the banner would
      // surface zero actionable items. Only let the pattern through the
      // banner if it fires >= TRANSCRIPT_NOISE_MIN_HITS (3) in the bucket.
      if (
        category === "suspiciousPatterns" &&
        TRANSCRIPT_NOISE_PATTERNS.has(item.pattern) &&
        (noiseCounts.get(item.pattern) || 0) < TRANSCRIPT_NOISE_MIN_HITS
      ) {
        return;
      }
      const priority =
        typeof item.priority === "number" ? item.priority : undefined;
      if (priority === undefined) return;
      // Banner chip surfaces `bidiOverride` for bidi-control findings so users
      // see the same category label as the Web build. This is OUTPUT-ONLY:
      // summary.byCategory stays at the 5-key shape (R13) because it counts
      // BUCKETS, not chip labels. `bucketCategory` preserves the actual
      // findings-object key so consumers can still jump to the original entry.
      const displayCategory =
        item && item.category === "bidi-control" ? "bidiOverride" : category;
      flat.push({
        category: displayCategory,
        bucketCategory: category,
        idx,
        priority,
        severity: sev,
        label: labelFor(item, displayCategory),
        reason: item.priorityReason || "category-weight",
      });
    });
  }

  // Sort: priority desc, then category alphabetic (stable for equal priority).
  flat.sort((a, b) => {
    if (b.priority !== a.priority) return b.priority - a.priority;
    if (a.category < b.category) return -1;
    if (a.category > b.category) return 1;
    return a.idx - b.idx;
  });

  // Per-category cap = 2.
  const perCat = new Map();
  const out = [];
  for (const entry of flat) {
    if (out.length >= limit) break;
    const seen = perCat.get(entry.category) || 0;
    if (seen >= 2) continue;
    perCat.set(entry.category, seen + 1);
    out.push(entry);
  }
  return out;
}
