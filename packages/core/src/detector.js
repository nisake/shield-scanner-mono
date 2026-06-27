/**
 * Main detector: orchestrates all detection categories.
 *
 * Integrated (Phase 2 + Phase 4 + S2 + S4):
 *   - invisibleUnicode  : invisible-unicode.js  (bidi-control sub-category exposed)
 *   - variationSelector : variation-selectors.js (M1, folded into invisibleUnicode)
 *   - mathBypass        : math-bypass.js        (M3, folded into homoglyphs)
 *   - combiningChars    : combining-chars.js    (S2, folded into invisibleUnicode —
 *                                                Zalgo / stacked-diacritic abuse)
 *   - markdownExfil     : markdown-exfil.js     (S4, folded into hiddenHtml —
 *                                                Markdown image URL data-exfil)
 *
 * Usage:
 *   const result = analyze(text, { fileType: "html"|"markdown"|"text", categories: [...] });
 */

import { detectInvisibleUnicode } from "./invisible-unicode.js";
import { detectControlChars } from "./control-chars.js";
import { detectHiddenElements } from "./hidden-elements.js";
import { detectMarkdownExfil } from "./markdown-exfil.js";
import {
  detectSuspiciousPatterns,
  scanShadowForSuspiciousPatterns,
} from "./suspicious-patterns.js";
import { detectHomoglyphs } from "./homoglyphs.js";
import { detectVariationSelectors } from "./variation-selectors.js";
import { detectMathBypass } from "./math-bypass.js";
import { detectCombiningChars } from "./combining-chars.js";
import {
  buildInvisibleStrippedShadow,
  buildNfkcShadow,
} from "./shadow-copy.js";
import { attachPriorities, buildTopFindings } from "./priority.js";
import { detectFormulaInjection } from "./formula-injection.js";
// v1.19.0 B4: structured-text frontmatter (YAML / TOML / JSON-LD) detector.
// Folds into the existing suspiciousPatterns bucket (R13 5-bucket invariant
// preserved). Auto-fires on fileType="markdown" (frontmatter + embedded
// JSON-LD) or fileType="html" (JSON-LD blocks).
import { detectStructuredTextFrontmatter } from "./structured-text-frontmatter.js";
// v1.19.0 D1: Encoded payload decode pipeline (Base64 / Hex / Punycode / HTML
// entity). Folds into the existing suspiciousPatterns bucket (R13 invariant
// preserved). Runs on ALL fileTypes — encoded payloads are file-format-
// agnostic (a base64 instruction can hide in plain text, markdown, or HTML
// alike). R12 critical: decoded raw text NEVER reaches the response body —
// the detector emits kebab IDs + byte-range meta only.
import { detectEncodedPayloads } from "./encoded-decoder.js";

export const ALL_CATEGORIES = [
  "invisibleUnicode",
  "controlChars",
  "hiddenHtml",
  "suspiciousPatterns",
  "homoglyphs",
];

// File types that should trigger the HTML-comment / hidden-element checks.
// Markdown supports embedded HTML (including <!-- ... --> comments), so a
// .md / .mdc / .cursorrules file containing instruction-bearing comments needs
// the same hidden-element sweep as plain HTML. (QW5)
const HIDDEN_ELEMENT_FILETYPES = new Set(["html", "markdown"]);

// v1.18.0 streaming wire: detectors (invisible-unicode / control-chars /
// homoglyphs) auto-chunk inputs > 5MB internally. detector.js advertises this
// at the analyze() summary level via `summary.streamed:true` +
// `summary.chunkCount` so callers can tell streaming kicked in without having
// to re-measure. The constants below must stay aligned with the individual
// detector modules (we duplicate rather than import to avoid an extra source
// of truth dependency at the analyze() entry).
const STREAM_THRESHOLD = 5 * 1024 * 1024;
const STREAM_CHUNK_SIZE = 1024 * 1024;

/**
 * v1.18.0: returns true when analyze() considers the input large enough to
 * have triggered the per-detector streaming path. Exposed for tests and for
 * downstream tooling (the benchmark task) that wants to know the gate
 * decision without invoking analyze().
 *
 * @param {string} content
 * @returns {boolean}
 */
export function shouldStream(content) {
  return typeof content === "string" && content.length > STREAM_THRESHOLD;
}

/**
 * v1.18.0: number of chunks the streaming path produces for a given content
 * length. Matches the math used by invisible-unicode.js / control-chars.js /
 * homoglyphs.js (advance = CHUNK_SIZE, last chunk absorbs the tail).
 */
function computeChunkCount(len) {
  if (len <= 0) return 0;
  return Math.max(1, Math.ceil(len / STREAM_CHUNK_SIZE));
}

/**
 * Analyze content for all threat categories.
 *
 * @param {string} content - Text to analyze
 * @param {Object} options
 * @param {string} [options.fileType] - "text" | "html" | "markdown" | "xlsx" | "csv" | "archive"
 * @param {string[]} [options.categories] - Limit to specific categories
 * @returns {Object} Findings grouped by category + summary
 *
 * S13: when `fileType === 'archive'` the parser layer is responsible for
 * recursive entry dispatch + emitting `summary.archive`. analyze() itself
 * just performs the standard 5-category sweep on the (usually empty) flat
 * text concatenation that the parser emits — bomb / zip-slip / depth / etc.
 * are merged in via `mergeFindings({ archive: ... })` at the parser layer.
 */
export function analyze(content, options = {}) {
  const {
    fileType = "text",
    categories = ALL_CATEGORIES,
  } = options;

  const findings = {
    invisibleUnicode: [],
    controlChars: [],
    hiddenHtml: [],
    suspiciousPatterns: [],
    homoglyphs: [],
  };

  const wanted = new Set(categories);

  if (wanted.has("invisibleUnicode")) {
    // Base invisible-unicode pass (Tags block, Bidi controls, PUA, etc.)
    const base = detectInvisibleUnicode(content);
    // M1: Variation Selector detection. Findings live under the same
    // invisibleUnicode bucket so the existing finding-schema (one array per
    // category) stays intact. Severity-based summary counting (below) keeps
    // info-level VS noise out of the warning/danger totals.
    const vs = detectVariationSelectors(content);
    // S2: Combining-mark stack detection (Zalgo). Same fold pattern as M1 —
    // findings live under invisibleUnicode so the existing finding-schema
    // (one array per category) stays intact. Severity-based summary counting
    // means single legitimate diacritics never escalate the warning total
    // (the detector itself suppresses depth < 8 by design).
    //
    // Note on shadow-copy interaction: we deliberately do NOT feed a
    // combining-stripped shadow into the suspicious-patterns scanner.
    // Stacked combiners on a Latin 'a' still leave the base 'a' intact, so
    // pattern hits like 'ignore' already match the original text directly —
    // adding another shadow would only inflate noise without new coverage.
    const cc = detectCombiningChars(content);
    findings.invisibleUnicode = base.concat(vs, cc);
  }
  if (wanted.has("controlChars")) {
    findings.controlChars = detectControlChars(content);
  }
  if (wanted.has("hiddenHtml") && HIDDEN_ELEMENT_FILETYPES.has(fileType)) {
    // QW5: Markdown documents can embed HTML, so we sweep them with the same
    // hidden-element detector (the HTML-comment branch in particular catches
    // <!-- ignore previous instructions --> style payloads inside .md files).
    //
    // S4: Markdown image URL exfiltration. ![alt](http://attacker/?prompt=...)
    // and the equivalent <img src="..."> form ride the same fileType gating
    // (html + markdown). Findings live under the same `hiddenHtml` bucket —
    // we do NOT introduce a new top-level byCategory key so baseline.test.js's
    // strict toEqual on `summary.byCategory` keeps working. R13 hard rule.
    const hidden = detectHiddenElements(content);
    const exfil = detectMarkdownExfil(content);
    findings.hiddenHtml = hidden.concat(exfil);
  }
  if (wanted.has("suspiciousPatterns")) {
    const direct = detectSuspiciousPatterns(content);

    // Shadow-copy pass: detect obfuscation-bypass variants (zero-width insertion
    // T1, math-alphanumeric S22, Tags-block, fullwidth, etc.) by scanning derived
    // views of the content with the same patterns. The original `content` is
    // never mutated and the shadows never leave detector.js — they are pure
    // detection scaffolding.
    const shadowFindings = [];
    const invStripped = buildInvisibleStrippedShadow(content);
    if (invStripped) {
      shadowFindings.push(
        ...scanShadowForSuspiciousPatterns(
          invStripped.shadow,
          invStripped.shadowToOrig,
          "invisibleStripped",
          content
        )
      );
    }
    const nfkc = buildNfkcShadow(content);
    if (nfkc) {
      shadowFindings.push(
        ...scanShadowForSuspiciousPatterns(
          nfkc.shadow,
          nfkc.shadowToOrig,
          "nfkcNormalized",
          content
        )
      );
    }

    findings.suspiciousPatterns = mergeShadowFindings(direct, shadowFindings);

    // S10: CSV/XLSX formula-injection fold. Findings carry
    // `category: 'formula-injection' | 'formula-prefix'` (item-level tag for
    // routing/scoring) but land in the existing suspiciousPatterns bucket so
    // the R13 5-key byCategory invariant is preserved. HIDDEN_ELEMENT_FILETYPES
    // is intentionally NOT extended — XLSX/CSV must NOT route through cheerio
    // (the parser emits pre-categorized extras instead).
    if (fileType === "xlsx" || fileType === "csv") {
      findings.suspiciousPatterns.push(
        ...detectFormulaInjection(content, fileType)
      );
    }
    // v1.19.0 B4: structured-text frontmatter / JSON-LD scan.
    // Auto-dispatch by fileType — yaml / toml standalone files come via the
    // parser registry (.yml / .yaml / .toml), markdown frontmatter rides the
    // "markdown" fileType, embedded JSON-LD rides "html" or "markdown".
    // Findings land in suspiciousPatterns (R13 fold). Kebab IDs:
    //   - frontmatter-prompt-injection / yaml-dangerous-tag / yaml-anchor-bomb
    //   - jsonld-description-injection / toml-instruction-key
    if (
      fileType === "markdown" ||
      fileType === "html" ||
      fileType === "yaml" ||
      fileType === "toml"
    ) {
      const fmt =
        fileType === "yaml"
          ? "yaml"
          : fileType === "toml"
            ? "toml"
            : "auto";
      findings.suspiciousPatterns.push(
        ...detectStructuredTextFrontmatter(content, { format: fmt })
      );
    }
    // v1.19.0 D1: Encoded payload decode pipeline.
    // File-format-agnostic — runs on every analyze() call regardless of
    // fileType. Findings land in suspiciousPatterns (R13 fold). Kebab IDs:
    //   - encoded-base64-instruction / encoded-hex-instruction
    //   - encoded-html-entity-instruction / punycode-host-homograph
    //   - multi-layer-encoded-payload
    // R12 (critical): decoded raw text NEVER appears in any finding field.
    // Only kebab `pattern`, fixed `matched` placeholder, raw byte-range
    // meta, and enum encoding class are surfaced. See encoded-decoder.js
    // module header for the absolute R12 design rules.
    findings.suspiciousPatterns.push(
      ...detectEncodedPayloads(content)
    );
  }
  if (wanted.has("homoglyphs")) {
    // M3: Mathematical Alphanumeric bypass is a visual-mimicry attack — same
    // family as homoglyphs — so it shares the homoglyphs bucket. Severity-
    // based counting (below) prevents single-char "info" math hits from
    // inflating the warning total on legitimate scientific text.
    const homo = detectHomoglyphs(content);
    const math = detectMathBypass(content);
    findings.homoglyphs = homo.concat(math);
  }

  // v1.19.0 A2: heuristics context tuning. After all detection runs but BEFORE
  // priority/banner selection, walk every finding and attach context flags
  // (inCodeBlock / inQuote / inUrlQuery) based on its `position` relative to
  // pre-computed markdown / HTML / URL ranges. Then nudge severity:
  //   - inCodeBlock | inQuote -> step DOWN one tier (warning -> notice / notice ->
  //     info) for non-load-bearing categories (variation-selector / homoglyph /
  //     suspicious-pattern excluding TRANSCRIPT_NOISE / R21 heading rule).
  //   - inUrlQuery -> ASCII-smuggling signal, step UP for VS / invisible-unicode
  //     and emit dedicated kebab IDs ('url-query-variation-selector' /
  //     'url-query-invisible-unicode').
  // R13 5-key invariant unchanged — flags ride on existing finding objects via
  // meta.{inCodeBlock,inQuote,inUrlQuery}; no new byCategory keys.
  applyContextFlags(content, fileType, findings);

  // S18: attach `priority` (0-100) to every finding BEFORE we hand the object
  // out. buildTopFindings then reads back those priorities to pick the banner.
  // Order matters - topFindings filter on priority, so priorities must exist
  // first.
  attachPriorities(findings, content.length);

  // v1.18.0: surface streaming status as a sibling key on `summary` (does NOT
  // touch byCategory; R13 5-key invariant preserved). Only emitted when the
  // streaming path actually fired, so non-streaming callers see no schema
  // drift. `chunkCount` mirrors the chunk math used internally by the three
  // streamed detectors (invisible-unicode / control-chars / homoglyphs).
  const streamingExtras = shouldStream(content)
    ? { streamed: true, chunkCount: computeChunkCount(content.length) }
    : null;

  return {
    findings,
    summary: buildSummary(findings, { streaming: streamingExtras }),
  };
}

/**
 * v1.19.0 A2: heuristics context tuning — pre-compute markdown/HTML/URL
 * context ranges so per-finding lookup is O(log N) via interval list.
 *
 * Detected contexts (low-risk syntactic signals, not value-based):
 *   - Markdown fenced code blocks: ``` ... ``` and ~~~ ... ~~~ across lines.
 *   - Markdown inline code: `...` (single backtick, single line).
 *   - HTML <pre>...</pre> and <code>...</code>.
 *   - Markdown blockquotes: lines starting with `>` (after optional indent).
 *   - URL query strings: substring after `?` of an http(s) URL up to the next
 *     whitespace / `)` / `]` / `>` / quote.
 *
 * Why pre-compute: walking 100+ findings against a string each time would be
 * O(N*M). Single-pass extraction → 3 sorted interval arrays. Per-finding check
 * is binary-search → O(log N).
 *
 * Returns `{ codeBlocks, quotes, urlQueries }` where each array is sorted by
 * `start` and entries are `[start, end)` UTF-16 positions in `content`.
 *
 * R12 contract: returned ranges are anchors only — the raw content is never
 * surfaced through these (only meta.in{CodeBlock,Quote,UrlQuery} boolean flags
 * land on findings).
 *
 * @param {string} content
 * @param {string} fileType
 * @returns {{ codeBlocks: Array<[number, number]>, quotes: Array<[number, number]>, urlQueries: Array<[number, number]> }}
 */
function buildContextRanges(content, fileType) {
  const codeBlocks = [];
  const quotes = [];
  const urlQueries = [];
  if (typeof content !== "string" || content.length === 0) {
    return { codeBlocks, quotes, urlQueries };
  }

  // --- Markdown fenced code blocks: ``` ... ``` / ~~~ ... ~~~ -------------
  // Conservative: require fence at line start (after optional whitespace).
  // Track unmatched open as covering to EOF.
  {
    const fenceRe = /(^|\n)[ \t]{0,3}(`{3,}|~{3,})[^\n]*\n/g;
    let m;
    let openStart = -1;
    let openFence = "";
    while ((m = fenceRe.exec(content)) !== null) {
      const fence = m[2];
      const lineStart = m.index + m[1].length;
      const afterFenceLine = m.index + m[0].length;
      if (openStart === -1) {
        openStart = afterFenceLine;
        openFence = fence[0]; // ` or ~
      } else if (fence[0] === openFence && fence.length >= openFence.length) {
        // Closing fence (same char family, length >= opening).
        // The closing fence line itself is the END marker — content range stops
        // at lineStart of the closing fence.
        codeBlocks.push([openStart, lineStart]);
        openStart = -1;
        openFence = "";
      }
    }
    if (openStart !== -1) {
      codeBlocks.push([openStart, content.length]);
    }
  }

  // --- Markdown inline code: `...` (single backtick) ----------------------
  // Only inside a single line; multi-backtick code spans (``...``) ride the
  // same regex variant. We skip ranges already inside a fenced block to avoid
  // double-counting.
  {
    const inlineRe = /`([^`\n]+)`/g;
    let m;
    while ((m = inlineRe.exec(content)) !== null) {
      const start = m.index + 1;
      const end = m.index + m[0].length - 1;
      if (!isInsideAnyRange(start, codeBlocks)) {
        codeBlocks.push([start, end]);
      }
    }
  }

  // --- HTML <pre>...</pre> and <code>...</code> ---------------------------
  // Cheap regex sweep — sufficient because the helper only needs to know if a
  // finding sits *inside* the tag's content; perfect parser fidelity is not
  // required for a severity-nudge signal.
  {
    const tagRe = /<(pre|code)\b[^>]*>([\s\S]*?)<\/\1>/gi;
    let m;
    while ((m = tagRe.exec(content)) !== null) {
      const innerStart = m.index + m[0].indexOf(">") + 1;
      const innerEnd = m.index + m[0].length - (m[1].length + 3); // </tag>
      if (innerEnd > innerStart) {
        codeBlocks.push([innerStart, innerEnd]);
      }
    }
  }

  // --- Markdown blockquotes: lines starting with `>` ----------------------
  {
    let lineStart = 0;
    for (let i = 0; i <= content.length; i++) {
      if (i === content.length || content.charCodeAt(i) === 0x0a) {
        // Inspect [lineStart, i).
        let j = lineStart;
        while (j < i && (content.charCodeAt(j) === 0x20 || content.charCodeAt(j) === 0x09)) j++;
        if (j < i && content.charCodeAt(j) === 0x3e /* '>' */) {
          quotes.push([lineStart, i]);
        }
        lineStart = i + 1;
      }
    }
  }

  // --- URL query strings (http/https) -------------------------------------
  // Match http://... or https://... and pick the substring after the FIRST '?'
  // up to the URL terminator. We use a permissive URL-char class so query VS
  // / homoglyph payloads inside the query span are captured.
  {
    const urlRe = /https?:\/\/[^\s<>'"`)]+/gi;
    let m;
    while ((m = urlRe.exec(content)) !== null) {
      const full = m[0];
      const qIdx = full.indexOf("?");
      if (qIdx === -1) continue;
      const start = m.index + qIdx + 1;
      const end = m.index + full.length;
      if (end > start) urlQueries.push([start, end]);
    }
  }

  codeBlocks.sort((a, b) => a[0] - b[0]);
  quotes.sort((a, b) => a[0] - b[0]);
  urlQueries.sort((a, b) => a[0] - b[0]);
  // fileType reserved for future per-format gating (e.g. always-true for
  // 'markdown'); current logic applies to all text-shaped inputs.
  void fileType;
  return { codeBlocks, quotes, urlQueries };
}

function isInsideAnyRange(pos, ranges) {
  // Linear scan — ranges are sorted by start so we can early-exit once start>pos.
  for (const [s, e] of ranges) {
    if (s > pos) break;
    if (pos >= s && pos < e) return true;
  }
  return false;
}

/**
 * v1.19.0 A2: extract context flags for a single finding (position-based).
 *
 * Returns `{ inCodeBlock, inQuote, inUrlQuery }` booleans. Findings whose
 * `position` is missing / non-numeric get all-false (R12 safety: never assume
 * an unknown anchor lives inside a syntactically-protected span).
 *
 * @param {{ codeBlocks: Array, quotes: Array, urlQueries: Array }} ranges
 * @param {{ position?: number }} finding
 * @returns {{ inCodeBlock: boolean, inQuote: boolean, inUrlQuery: boolean }}
 */
function extractContextFlags(ranges, finding) {
  const pos = finding && typeof finding.position === "number" ? finding.position : -1;
  if (pos < 0) return { inCodeBlock: false, inQuote: false, inUrlQuery: false };
  return {
    inCodeBlock: isInsideAnyRange(pos, ranges.codeBlocks),
    inQuote: isInsideAnyRange(pos, ranges.quotes),
    inUrlQuery: isInsideAnyRange(pos, ranges.urlQueries),
  };
}

// Severity one-step-down ladder used by code-fence / quote suppression.
// `info` / `safe` are floor states — no further demotion.
const SEVERITY_STEP_DOWN = {
  danger: "warning",
  warning: "notice",
  notice: "info",
};

/**
 * R21 hard rule: heading TRANSCRIPT_NOISE suppression already lives in
 * priority.js#buildTopFindings; do not touch its severity here. Pattern names
 * listed below are the canonical TRANSCRIPT_NOISE family — context flags are
 * still attached for downstream tooling, but severity is left alone.
 */
const TRANSCRIPT_NOISE_PATTERNS = new Set([
  "Conversation turn marker",
  "Alpaca format marker",
  "Llama2 system marker",
  "Markdown heading impersonation",
]);

/**
 * v1.19.0 A2: walk every finding bucket, attach `meta.{inCodeBlock,inQuote,
 * inUrlQuery}`, and apply the severity nudge. Mutates `findings` in place.
 *
 * Severity policy:
 *   1. (inCodeBlock || inQuote) and finding is NOT TRANSCRIPT_NOISE / R21 →
 *      step severity down once via SEVERITY_STEP_DOWN.
 *   2. invisibleUnicode finding with inUrlQuery=true → severity stepped UP to
 *      `danger` (if not already), and:
 *        - VS findings get retagged `technique = 'url-query-variation-selector'`
 *          (kebab id, suspiciousPatterns category fold — but bucket stays
 *          invisibleUnicode per R13).
 *        - Other invisible-unicode findings get retagged
 *          `technique = 'url-query-invisible-unicode'`.
 *      `meta.host` / `meta.queryKey` / `meta.codepoint` are added best-effort
 *      from the URL string around `finding.position`.
 *
 * R13 contract: no new top-level byCategory keys; findings stay in their
 * original bucket. Kebab IDs are emitted via finding.technique and the
 * separately-added i18n entries, mirroring the v1.15.0 embedded-binary
 * refactor pattern.
 */
function applyContextFlags(content, fileType, findings) {
  const ranges = buildContextRanges(content, fileType);
  for (const [bucket, arr] of Object.entries(findings)) {
    if (!Array.isArray(arr)) continue;
    for (const f of arr) {
      const flags = extractContextFlags(ranges, f);
      if (!flags.inCodeBlock && !flags.inQuote && !flags.inUrlQuery) continue;
      // Attach meta flags (additive — never clobber existing meta keys).
      const meta = f.meta && typeof f.meta === "object" ? f.meta : {};
      if (flags.inCodeBlock) meta.inCodeBlock = true;
      if (flags.inQuote) meta.inQuote = true;
      if (flags.inUrlQuery) meta.inUrlQuery = true;
      f.meta = meta;

      // --- URL-query asymmetry: VS / invisibleUnicode → step UP + kebab id --
      if (flags.inUrlQuery && bucket === "invisibleUnicode") {
        const enrichedMeta = enrichUrlQueryMeta(content, ranges.urlQueries, f);
        Object.assign(f.meta, enrichedMeta);
        const isVS = f.type === "variationSelector" || (typeof f.char === "string" && /^U\+(FE0[0-9A-F]|E01[0-9A-F][0-9A-F])/.test(f.char));
        f.technique = isVS
          ? "url-query-variation-selector"
          : "url-query-invisible-unicode";
        // ASCII smuggling inside URL query is high-confidence → upgrade to
        // danger. Skip if already danger (no-op).
        if (f.severity !== "danger") f.severity = "danger";
        continue; // URL-query upgrade wins over code/quote downgrade.
      }

      // --- Code-fence / quote suppression ----------------------------------
      if (flags.inCodeBlock || flags.inQuote) {
        // R21 hard rule: heading TRANSCRIPT_NOISE patterns keep their severity
        // (and their 3-hit banner gating in priority.js handles the FP risk).
        const patternName = f.pattern;
        if (
          bucket === "suspiciousPatterns" &&
          typeof patternName === "string" &&
          TRANSCRIPT_NOISE_PATTERNS.has(patternName)
        ) {
          continue;
        }
        const cur = f.severity;
        const next = SEVERITY_STEP_DOWN[cur];
        if (next) f.severity = next;
      }
    }
  }
}

/**
 * Best-effort: pull (host, queryKey, codepoint) out of the URL around a
 * `finding.position`. Returns a plain object suitable for `Object.assign` onto
 * meta. Never throws; on any parse miss returns `{}`.
 */
function enrichUrlQueryMeta(content, urlQueries, finding) {
  const pos = finding && typeof finding.position === "number" ? finding.position : -1;
  if (pos < 0) return {};
  // Find the enclosing URL-query range, then walk backward to the http(s):// start.
  let qStart = -1;
  let qEnd = -1;
  for (const [s, e] of urlQueries) {
    if (s > pos) break;
    if (pos >= s && pos < e) { qStart = s; qEnd = e; break; }
  }
  if (qStart < 0) return {};
  // Backward search for the URL scheme.
  const headWin = content.slice(Math.max(0, qStart - 2048), qStart);
  const schemeMatch = headWin.match(/https?:\/\/[^\s<>'"`)]+\?$/i);
  let host = null;
  if (schemeMatch) {
    const urlHead = schemeMatch[0];
    const hostMatch = urlHead.match(/^https?:\/\/([^\/?#]+)/i);
    if (hostMatch) host = hostMatch[1].toLowerCase();
  }
  // Query key: scan back from `pos` to the previous `?` or `&`, then up to `=`.
  let keyStart = pos;
  while (keyStart > qStart && content[keyStart - 1] !== "&" && content[keyStart - 1] !== "?") {
    keyStart--;
  }
  let keyEnd = keyStart;
  while (keyEnd < qEnd && content[keyEnd] !== "=" && content[keyEnd] !== "&") {
    keyEnd++;
  }
  // R12 (critical): never echo raw user text into meta. We only surface the
  // CODEPOINT (numeric) of the offending char, plus the host (parsed by URL
  // grammar) and queryKey *length* — not the key itself, which is attacker-
  // controllable.
  const cp = content.codePointAt(pos);
  const out = {};
  if (host) out.host = host;
  if (keyEnd > keyStart) out.queryKey = `key#${keyEnd - keyStart}`;
  if (typeof cp === "number") out.codepoint = `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
  return out;
}

/**
 * Merge direct + shadow suspicious-pattern findings with dedup.
 *
 * Dedup key: `${pattern}|${position}|${matchLen}`.
 *   - If a direct (non-shadow) finding already covers the same (pattern, span),
 *     drop the shadow finding (the direct hit is the canonical signal).
 *   - If two shadows produce the same (pattern, span), keep one finding and
 *     fold the second source into `shadowSource` as an array.
 *
 * Direct findings are preserved verbatim (no severity / shape changes), so the
 * existing baseline/attack tests stay green.
 */
function mergeShadowFindings(directFindings, shadowFindings) {
  const out = [...directFindings];
  const directKeys = new Set();
  for (const f of directFindings) {
    const len = (typeof f.matchLen === "number" && f.matchLen) ||
      (typeof f.matched === "string" && f.matched.length) || 1;
    directKeys.add(`${f.pattern}|${f.position}|${len}`);
  }

  const shadowIndex = new Map(); // key -> index into `out`
  for (const sf of shadowFindings) {
    const key = `${sf.pattern}|${sf.position}|${sf.matchLen}`;
    // Direct hit wins — skip the shadow finding entirely.
    if (directKeys.has(key)) continue;

    if (shadowIndex.has(key)) {
      // Already added by the other shadow — fold this source in.
      const existing = out[shadowIndex.get(key)];
      const sources = Array.isArray(existing.shadowSource)
        ? existing.shadowSource
        : [existing.shadowSource];
      if (!sources.includes(sf.shadowSource)) {
        sources.push(sf.shadowSource);
      }
      existing.shadowSource = sources;
      existing.type = `shadow:${sources.join("+")}`;
      continue;
    }
    out.push(sf);
    shadowIndex.set(key, out.length - 1);
  }
  return out;
}

/**
 * S20: Enrich findings with a `contextLocation` string (leaf-set + prefix).
 *
 * - `findings` is the analyze() `findings` object (category buckets of arrays)
 *   OR a flat array of finding-like objects (used for extraFindings buckets).
 * - `locationTags` is one or an array of `{ kind, index, label }` tags. The
 *   `label` field is what gets prefixed (e.g. "Page 3", "Slide 2", "Subject").
 * - If a finding already has `contextLocation`, we prepend `"<label> > <existing>"`.
 *   Otherwise we leaf-set `contextLocation = label`. Multiple tags are joined
 *   with `" > "` left-to-right (outer-most first).
 *
 * Pure function — returns a new object/array; never mutates input. Does NOT
 * touch `mergeFindings` or `buildSummary` (those run elsewhere in the pipeline).
 */
export function enrichFindingsLocation(findings, locationTags) {
  if (!findings) return findings;
  const tagsArr = Array.isArray(locationTags) ? locationTags : [locationTags];
  const labels = tagsArr
    .map((t) => (t && typeof t.label === "string" ? t.label : null))
    .filter((s) => s && s.length > 0);
  if (labels.length === 0) return findings;
  const prefix = labels.join(" > ");

  function enrichOne(item) {
    if (!item || typeof item !== "object") return item;
    if (typeof item.contextLocation === "string" && item.contextLocation.length > 0) {
      // Don't double-prefix if the existing string already starts with our prefix.
      if (item.contextLocation === prefix || item.contextLocation.startsWith(prefix + " > ")) {
        return item;
      }
      return { ...item, contextLocation: `${prefix} > ${item.contextLocation}` };
    }
    return { ...item, contextLocation: prefix };
  }

  if (Array.isArray(findings)) {
    return findings.map(enrichOne);
  }
  const out = {};
  for (const [k, v] of Object.entries(findings)) {
    out[k] = Array.isArray(v) ? v.map(enrichOne) : v;
  }
  return out;
}

/**
 * Merge additional findings (from file parsers) into a base result.
 *
 * S13: extended to merge across all 5 buckets (previously only `hiddenHtml`).
 * ZIP entries can emit findings of any category via recursive dispatchBuffer
 * (e.g. an XLSM inside a ZIP surfaces formula-injection in suspiciousPatterns,
 * an EML attachment surfaces invisibleUnicode etc.). The archive parser passes
 * those bucketed findings through `additional.{invisibleUnicode,...}` and the
 * archive structural summary through `additional.archive`. R13 stays intact:
 * the 5-bucket schema is preserved; only the sibling `summary.archive` key
 * (mirroring `bidiControl` / `topFindings`) is added.
 */
export function mergeFindings(baseResult, additional) {
  const add = additional || {};
  const merged = {
    findings: {
      invisibleUnicode: [
        ...baseResult.findings.invisibleUnicode,
        ...(add.invisibleUnicode || []),
      ],
      controlChars: [
        ...baseResult.findings.controlChars,
        ...(add.controlChars || []),
      ],
      hiddenHtml: [
        ...baseResult.findings.hiddenHtml,
        ...(add.hiddenHtml || []),
      ],
      suspiciousPatterns: [
        ...baseResult.findings.suspiciousPatterns,
        ...(add.suspiciousPatterns || []),
      ],
      homoglyphs: [
        ...baseResult.findings.homoglyphs,
        ...(add.homoglyphs || []),
      ],
    },
  };
  // S18: priorities are per-finding so re-attaching after a merge keeps the
  // new (concatenated) bucket consistent. We don't have access to the original
  // content length here (mergeFindings is called by file-parser tools with
  // additional findings appended), so pass the longer of the two sides as a
  // best-effort - it only affects the head-of-prompt boost and stays inside
  // the [0,100] clamp regardless.
  const contentLen =
    Math.max(
      (baseResult && baseResult.contentLength) || 0,
      (add && add.contentLength) || 0,
    ) || 2001; // > 2000 disables the head boost entirely (safe default)
  attachPriorities(merged.findings, contentLen);
  // S13: pre-existing archive summary on baseResult (when a nested parser
  // already accumulated one) merges with the additional archive summary so
  // recursive ZIP-in-ZIP counts roll up correctly.
  const archiveExtras = mergeArchiveSummaries(
    baseResult && baseResult.summary && baseResult.summary.archive,
    add.archive,
  );
  merged.summary = buildSummary(merged.findings, { archive: archiveExtras });
  return merged;
}

/**
 * S13: shape of `summary.archive`. Returned by `_emptyArchiveSummary()` and
 * accumulated via `mergeArchiveSummaries()`. Parsers populate it; detector
 * never invents archive findings on its own.
 *
 *   {
 *     scanned: number,              // # archives walked at this level + nested
 *     bomb: number,                 // AR-01 hits (ratio block / total cap)
 *     depth: number,                // AR-02 hits (nest depth cap)
 *     protected: number,            // AR-04 hits (encrypted entry / archive)
 *     entryCap: number,             // AR-07 hits (entry-count cap)
 *     maxRatio: number,             // peak compression ratio observed
 *     maxDepth: number,             // deepest recursion reached
 *     totalEntries: number,         // sum of entries enumerated
 *     totalUncompressedBytes: number,
 *     skippedEntries: number,       // entries skipped due to per-entry cap
 *   }
 */
function _emptyArchiveSummary() {
  return {
    scanned: 0,
    bomb: 0,
    depth: 0,
    protected: 0,
    entryCap: 0,
    maxRatio: 0,
    maxDepth: 0,
    totalEntries: 0,
    totalUncompressedBytes: 0,
    skippedEntries: 0,
  };
}

function mergeArchiveSummaries(a, b) {
  if (!a && !b) return null;
  const out = _emptyArchiveSummary();
  const sources = [a, b].filter(Boolean);
  for (const s of sources) {
    out.scanned += s.scanned || 0;
    out.bomb += s.bomb || 0;
    out.depth += s.depth || 0;
    out.protected += s.protected || 0;
    out.entryCap += s.entryCap || 0;
    out.totalEntries += s.totalEntries || 0;
    out.totalUncompressedBytes += s.totalUncompressedBytes || 0;
    out.skippedEntries += s.skippedEntries || 0;
    if ((s.maxRatio || 0) > out.maxRatio) out.maxRatio = s.maxRatio || 0;
    if ((s.maxDepth || 0) > out.maxDepth) out.maxDepth = s.maxDepth || 0;
  }
  return out;
}

/**
 * Count items in `arr` whose `.severity` matches `sev`.
 * Items without an explicit severity are treated as `defaultSev` so existing
 * detectors that pre-date the severity field continue to count as before.
 */
function countBySeverity(arr, sev, defaultSev = null) {
  let n = 0;
  for (const f of arr) {
    const s = f.severity || defaultSev;
    if (s === sev) n++;
  }
  return n;
}

function buildSummary(findings, extras = {}) {
  // Severity-based counting everywhere so VS / Math `info` findings (legit
  // emoji / IVS / single math char) never inflate the warning total.
  const totalDanger =
    countBySeverity(findings.invisibleUnicode, "danger") +
    countBySeverity(findings.hiddenHtml, "danger") +
    // suspicious-patterns historically had no `severity` field on every entry;
    // its findings are always treated as danger, matching legacy behavior.
    countBySeverity(findings.suspiciousPatterns, "danger", "danger") +
    countBySeverity(findings.homoglyphs, "danger");

  const totalWarning =
    countBySeverity(findings.invisibleUnicode, "warning") +
    countBySeverity(findings.controlChars, "warning", "warning") +
    countBySeverity(findings.hiddenHtml, "warning") +
    // S5: suspicious-patterns.json now carries an optional `severity` field
    // ("warning" for generic conversation-format markers like `Human:` /
    // `### Instruction`). Default severity remains "danger", so this addition
    // doesn't change counts for any pre-S5 pattern.
    countBySeverity(findings.suspiciousPatterns, "warning") +
    countBySeverity(findings.homoglyphs, "warning", "warning");

  const total = totalDanger + totalWarning;

  let status;
  if (totalDanger > 0) status = "danger";
  else if (totalWarning > 0) status = "warning";
  else status = "safe";

  // M2: surface the bidi-control breakdown as its own sub-summary. We do NOT
  // add a new top-level key to `byCategory` because baseline.test.js pins that
  // object with `toEqual` (strict shape). Putting the breakdown on a sibling
  // key keeps the existing schema intact while still letting downstream UIs
  // show Trojan-Source / over-use stats separately from the generic
  // invisibleUnicode count.
  const bidiBreakdown = summarizeBidi(findings.invisibleUnicode);

  return {
    status,
    total,
    dangerCount: totalDanger,
    warningCount: totalWarning,
    // S12: severity breakdown as a sibling key — mirrors dangerCount/warningCount
    // in an object shape so consumers can do `summary.bySeverity.danger` without
    // touching the top-level counts. Safe to add: not part of byCategory (the
    // R13 5-key invariant pinned by baseline.test.js stays intact), and the
    // documented summary contract in s12-final-spec.json references this exact
    // path (`bySeverity.danger` / `bySeverity.warning`).
    bySeverity: {
      danger: totalDanger,
      warning: totalWarning,
    },
    byCategory: {
      invisibleUnicode: findings.invisibleUnicode.length,
      controlChars: findings.controlChars.length,
      hiddenHtml: findings.hiddenHtml.length,
      suspiciousPatterns: findings.suspiciousPatterns.length,
      homoglyphs: findings.homoglyphs.length,
    },
    bidiControl: bidiBreakdown,
    // S18: top-priority findings (up to 5, severity >= warning, per-category
    // cap = 2). Added as a SIBLING key to byCategory / bidiControl - we do
    // NOT add a new key to byCategory (baseline.test.js pins that shape with
    // strict toEqual; R13).
    topFindings: buildTopFindings(findings, 5),
    // S13: archive structural summary (bomb / depth / protected / entryCap +
    // aggregate counters). Sibling key — does NOT touch byCategory. Only
    // populated when a parser passes an archive payload through mergeFindings;
    // for plain text / HTML / Markdown analyze() calls this is omitted entirely
    // so the v1.7.0 summary shape is unchanged for non-archive callers (R13
    // baseline.test.js stays green without rewrites).
    ...(extras && extras.archive ? { archive: extras.archive } : {}),
    // v1.18.0: streaming flags (sibling keys). Only emitted when analyze()
    // determined the input crossed the streaming threshold (>5MB). Both keys
    // are added together so callers can branch on `summary.streamed`.
    ...(extras && extras.streaming
      ? {
          streamed: extras.streaming.streamed,
          chunkCount: extras.streaming.chunkCount,
        }
      : {}),
  };
}

/**
 * Build the bidi-control sub-summary from the invisibleUnicode bucket.
 *
 * Looks at entries tagged `category: "bidi-control"` (set by
 * invisible-unicode.js after the Phase 4 refactor) and counts them by `kind`
 * (override / embedding / isolate) and by severity. `total: 0` is returned
 * when no bidi findings are present so consumers can safely read every field.
 */
function summarizeBidi(invisibleFindings) {
  const out = {
    total: 0,
    override: 0,
    embedding: 0,
    isolate: 0,
    danger: 0,
    warning: 0,
  };
  for (const f of invisibleFindings) {
    if (f.category !== "bidi-control") continue;
    out.total++;
    if (f.kind === "override") out.override++;
    else if (f.kind === "embedding") out.embedding++;
    else if (f.kind === "isolate") out.isolate++;
    if (f.severity === "danger") out.danger++;
    else if (f.severity === "warning") out.warning++;
  }
  return out;
}

/**
 * Format a scan result as a plain-text report (for clipboard / logs).
 */
export function formatReport(result, meta = {}) {
  const { fileName = "(unknown)", scannedAt = new Date().toISOString() } = meta;
  const { findings, summary } = result;
  const lines = [
    "=== Shield Scanner Report ===",
    `File: ${fileName}`,
    `Date: ${scannedAt}`,
    `Status: ${summary.status.toUpperCase()}`,
    `Total findings: ${summary.total} (danger: ${summary.dangerCount}, warning: ${summary.warningCount})`,
    "",
  ];

  const categoryLabels = [
    ["Invisible Unicode", "invisibleUnicode"],
    ["Control Characters", "controlChars"],
    ["Hidden HTML", "hiddenHtml"],
    ["Suspicious Patterns", "suspiciousPatterns"],
    ["Homoglyphs", "homoglyphs"],
  ];

  for (const [label, key] of categoryLabels) {
    const items = findings[key];
    lines.push(`[${label}] ${items.length} found`);
    for (const item of items) {
      if (item.char) {
        lines.push(`  - ${item.name || item.type || ""} ${item.char} at pos ${item.position}`);
      } else if (item.pattern) {
        lines.push(`  - ${item.pattern}: ${item.matched}`);
      } else if (item.technique) {
        lines.push(`  - ${item.technique} in <${item.element}>`);
      } else if (item.original) {
        lines.push(
          `  - ${item.original} -> ${item.replacement} at pos ${item.position}`
        );
      } else if (item.normalized) {
        // Math-bypass finding: show the "looks like" rendering.
        lines.push(
          `  - ${item.type || "mathAlphanumeric"} ${item.codePoint} ~ "${item.normalized}" at pos ${item.position}`
        );
      } else if (item.type === "combiningStack") {
        // S2: combining-mark stack (Zalgo). Same layout family as M1/M3:
        // a single line per run, mention base + stack depth so readers can
        // gauge the severity without unfolding the whole context window.
        const baseLabel =
          item.baseCodePoint === null
            ? "(no base)"
            : `U+${item.baseCodePoint
                .toString(16)
                .toUpperCase()
                .padStart(item.baseCodePoint > 0xffff ? 5 : 4, "0")}`;
        lines.push(
          `  - combiningStack depth=${item.stackDepth} on ${baseLabel} at pos ${item.position}`
        );
      }
    }
    lines.push("");
  }

  if (summary.bidiControl && summary.bidiControl.total > 0) {
    lines.push(
      `[Bidi-Control breakdown] total=${summary.bidiControl.total} ` +
        `override=${summary.bidiControl.override} ` +
        `embedding=${summary.bidiControl.embedding} ` +
        `isolate=${summary.bidiControl.isolate} ` +
        `(danger=${summary.bidiControl.danger}, warning=${summary.bidiControl.warning})`
    );
    lines.push("");
  }

  // S13: archive structural breakdown — only printed when the parser layer
  // populated summary.archive. Mirrors the bidiControl block above.
  if (summary.archive && summary.archive.scanned > 0) {
    const a = summary.archive;
    const ratioStr = a.maxRatio === Infinity ? "inf" : a.maxRatio.toFixed(1);
    lines.push(
      `[Archive breakdown] scanned=${a.scanned} ` +
        `entries=${a.totalEntries} ` +
        `bomb=${a.bomb} depth=${a.depth} protected=${a.protected} ` +
        `entryCap=${a.entryCap} skipped=${a.skippedEntries} ` +
        `maxRatio=${ratioStr} maxDepth=${a.maxDepth}`
    );
    lines.push("");
  }

  return lines.join("\n");
}
