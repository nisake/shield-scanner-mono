/**
 * v1.19.0 B4: Structured-text frontmatter detector.
 *
 * Attack model: LLM ingestion pipelines now routinely consume Markdown blog
 * posts, static-site config, and schema.org structured data. These shapes have
 * three things in common:
 *   1. They separate "metadata" from "body" — the metadata is often invisible
 *      in the rendered view but still gets fed to downstream tools.
 *   2. They use rich text values where attackers can hide instructions.
 *   3. Standard parsers (PyYAML, js-yaml in unsafe mode, custom tag handlers)
 *      can be coerced into executing code via YAML tags (CVE-2017-18342 family).
 *
 * What this detector covers:
 *   - Markdown frontmatter delimited by `---` (YAML) or `+++` (TOML) at the
 *     very top of the input, plus standalone .yml / .yaml / .toml files.
 *   - JSON-LD blocks: `<script type="application/ld+json">…</script>`.
 *
 * What gets emitted (all kebab IDs land in suspiciousPatterns — R13 fold):
 *   - frontmatter-prompt-injection : key value contains an instruction shape
 *     (ignore-previous / system-prompt / disregard-above / pretend-you-are…)
 *     meta: { format: 'yaml-frontmatter' | 'toml-frontmatter' | 'yaml-file'
 *                   | 'toml-file', key }
 *   - yaml-dangerous-tag           : !!python/object/apply, !!js/function,
 *                                    !ruby/object — CVE-2017-18342 family.
 *     meta: { tagName }
 *   - yaml-anchor-bomb             : anchor / alias depth exceeded DoS cap.
 *     meta: { depth }
 *   - jsonld-description-injection : JSON-LD `description` / `name` /
 *                                    `articleBody` carries an instruction
 *                                    shape.
 *     meta: { field }
 *   - toml-instruction-key         : TOML key whose name itself matches an
 *                                    instruction shape ('inject-this-prompt'
 *                                    style key, regardless of value).
 *     meta: { key }
 *
 * Caps (R12 / DoS):
 *   - MAX_INPUT_BYTES   : skip detector entirely on huge inputs
 *   - MAX_YAML_DEPTH    : anchor / alias resolution cap (billion-laughs)
 *   - MAX_ANCHOR_COUNT  : per-doc anchor budget
 *   - MAX_FINDINGS      : per-input finding budget
 *
 * R12 contract:
 *   - `meta.key` / `meta.field` / `meta.tagName` are sanitized via the kebab
 *     allowlist + length cap (≤ 64 chars). Attacker-controlled raw text never
 *     appears in `technique` (which stays a fixed kebab id).
 *   - `content` is the key (escaped, ≤ 200 chars). The raw value never lands
 *     in finding.content — only the trigger-phrase classification does.
 *
 * R13 fold: every finding ships `category: 'suspiciousPatterns'` so the parser
 * route (which routes extras through `additional.suspiciousPatterns`) keeps
 * the existing 5-bucket invariant. We do NOT introduce a new top-level
 * byCategory key.
 *
 * No external dependencies — mini-parsers handle YAML / TOML / JSON-LD inline.
 */

import { escapeForDisplay } from "./utils.js";

// ---------- Caps ----------

const MAX_INPUT_BYTES = 1 * 1024 * 1024; // 1 MB
const MAX_YAML_DEPTH = 12;
const MAX_ANCHOR_COUNT = 128;
const MAX_FINDINGS = 32;
const MAX_KEY_LEN = 200;
const MAX_META_FIELD_LEN = 64;

// ---------- Allowlists / regex ----------

// YAML tag names that have been used for code execution. We include the
// canonical pyyaml / js-yaml / ruby variants. Comparisons are case-sensitive
// because YAML tag names are.
const DANGEROUS_YAML_TAGS = new Set([
  "!!python/object/apply",
  "!!python/object/new",
  "!!python/object",
  "!!python/name",
  "!!python/module",
  "!!js/function",
  "!!js/regexp",
  "!!js/undefined",
  "!ruby/object",
  "!ruby/hash",
  "!!exec",
  "!!new",
]);

// Instruction-shaped phrases. Kept minimal & high-precision so legitimate
// frontmatter (e.g. `description: "A guide to..."`) doesn't flag. Each pattern
// targets a known prompt-injection idiom.
const INSTRUCTION_PHRASES = [
  /\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b/i,
  /\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\b/i,
  /\b(?:you\s+are|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(?:now\s+)?a\b/i,
  /\bsystem\s*[:|]\s*you\s+are\b/i,
  /\b(?:override|forget|delete)\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|prompts?)\b/i,
  /\b(?:reveal|leak|exfiltrate|print|output)\s+(?:the\s+)?(?:system\s+)?prompt\b/i,
  /\bnew\s+instructions?\s*[:|]/i,
];

// TOML / YAML instruction-shaped key names. These trigger on the *key* even
// when the value is benign, because attackers can name keys to influence
// downstream tools (e.g. an LLM looking for an `instructions:` block).
const INSTRUCTION_KEY_NAMES = new Set([
  "system-prompt",
  "system_prompt",
  "inject-prompt",
  "inject_prompt",
  "override-instructions",
  "override_instructions",
  "ignore-previous",
  "ignore_previous",
  "ignore_prior_instructions",
]);

// JSON-LD fields that LLMs commonly summarize / use to derive context. If
// these contain an instruction shape, we surface.
const JSONLD_INSTRUCTION_FIELDS = new Set([
  "description",
  "name",
  "articleBody",
  "headline",
  "abstract",
  "text",
]);

// Sanitize a meta field (key name / tag name / JSON-LD field name) so it can
// be safely surfaced. Allowlist: alphanumeric, dash, underscore, dot, slash,
// exclamation, colon — covers YAML tag syntax + TOML/YAML/JSON keys without
// allowing markup. Truncated to MAX_META_FIELD_LEN.
function sanitizeMetaField(s) {
  if (typeof s !== "string") return "";
  let cleaned = "";
  for (const ch of s) {
    if (/[A-Za-z0-9_\-./:!]/.test(ch)) cleaned += ch;
    if (cleaned.length >= MAX_META_FIELD_LEN) break;
  }
  return cleaned;
}

// ---------- Frontmatter splitter ----------

/**
 * If `text` opens with `---\n` ... `\n---\n?` return the YAML body span.
 * If it opens with `+++\n` ... `\n+++\n?` return the TOML body span.
 * Otherwise return null. Position is the offset of the body's first char.
 */
function extractFrontmatter(text) {
  if (typeof text !== "string" || text.length < 8) return null;
  // YAML --- delimiter
  let m = /^---\s*\r?\n([\s\S]*?)\r?\n---\s*(?:\r?\n|$)/.exec(text);
  if (m) {
    return {
      kind: "yaml",
      body: m[1],
      bodyStart: m.index + m[0].indexOf(m[1]),
    };
  }
  m = /^\+\+\+\s*\r?\n([\s\S]*?)\r?\n\+\+\+\s*(?:\r?\n|$)/.exec(text);
  if (m) {
    return {
      kind: "toml",
      body: m[1],
      bodyStart: m.index + m[0].indexOf(m[1]),
    };
  }
  return null;
}

// ---------- YAML mini-parser ----------

/**
 * Walk YAML body line-by-line. Goals:
 *   - Detect dangerous tags (DANGEROUS_YAML_TAGS) anywhere in the body.
 *   - Detect anchor/alias bombs (anchors > MAX_ANCHOR_COUNT OR nesting depth
 *     exceeds MAX_YAML_DEPTH).
 *   - Surface keys whose values contain INSTRUCTION_PHRASES.
 *
 * Returns an array of "raw findings" (shape: {kind, key|tagName|depth, valuePos}).
 * Caller wraps these into the public finding shape.
 *
 * This is intentionally a *mini* parser — it does NOT support every YAML
 * construct (flow mappings, complex keys, multi-line scalars beyond simple
 * blocks). The goal is to surface high-confidence injection signals, not to
 * round-trip arbitrary YAML.
 */
function scanYaml(body, bodyStart) {
  const raws = [];
  if (typeof body !== "string" || body.length === 0) return raws;

  let anchorCount = 0;
  let maxDepth = 0;
  let depthBombSeen = false;
  const lines = body.split(/\r?\n/);
  let cursor = bodyStart;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineStart = cursor;
    cursor += line.length + 1; // +1 for the newline we split on

    if (raws.length >= MAX_FINDINGS) break;

    // Strip trailing comment (after a `# ` that is not inside quotes — naive
    // but adequate; we don't parse multiline strings here).
    const stripped = stripYamlComment(line);
    if (!stripped.trim()) continue;

    // Indent depth (in spaces). Used for anchor-bomb depth cap.
    const indent = line.match(/^(\s*)/)[1].length;
    const depth = Math.floor(indent / 2) + 1;
    if (depth > maxDepth) maxDepth = depth;

    // Dangerous tag scan. YAML tags are `!shorthand` or `!!verbatim` and
    // commonly take the form `!!python/object/apply:os.system` where the
    // colon separates the tag name from its argument. We match the bare tag
    // (no trailing `:`) and then check against the dangerous allowlist via
    // both exact match and prefix-match (so `!!python/object/apply:os.system`
    // hits the `!!python/object/apply` allowlist entry).
    const tagRe = /(!{1,2}[A-Za-z0-9_/.\-]+)/g;
    let tm;
    while ((tm = tagRe.exec(stripped)) !== null) {
      const tag = tm[1];
      let hit = null;
      if (DANGEROUS_YAML_TAGS.has(tag)) {
        hit = tag;
      } else {
        for (const dt of DANGEROUS_YAML_TAGS) {
          if (tag === dt || tag.startsWith(dt + ":") || tag.startsWith(dt + "/")) {
            hit = dt;
            break;
          }
        }
      }
      if (hit) {
        raws.push({
          kind: "yaml-dangerous-tag",
          tagName: hit,
          position: lineStart + line.indexOf(tag),
        });
        if (raws.length >= MAX_FINDINGS) break;
      }
    }

    // Anchor count. Match `&anchor` definitions AND `*alias` references —
    // billion-laughs shapes do most of their damage by referencing thousands
    // of times, so counting alias references is what nails the DoS surface.
    const anchorMatches = stripped.match(/[&*][A-Za-z_][A-Za-z0-9_-]*/g);
    if (anchorMatches) anchorCount += anchorMatches.length;

    // key: value detection (simple block-style only).
    const kv = stripped.match(/^\s*([A-Za-z_][A-Za-z0-9_\-.]*)\s*:\s*(.*)$/);
    if (kv) {
      const rawKey = kv[1];
      const rawValue = kv[2];

      // Instruction-key direct hit (yaml file uses same surface as TOML).
      const lcKey = rawKey.toLowerCase();
      if (INSTRUCTION_KEY_NAMES.has(lcKey)) {
        raws.push({
          kind: "instruction-key",
          key: rawKey,
          position: lineStart + line.indexOf(rawKey),
        });
      }

      // Instruction phrase inside the value.
      if (rawValue && phraseMatches(rawValue)) {
        raws.push({
          kind: "instruction-value",
          key: rawKey,
          position: lineStart + line.indexOf(rawKey),
        });
      }
    }
  }

  if (anchorCount > MAX_ANCHOR_COUNT && !depthBombSeen) {
    raws.push({
      kind: "yaml-anchor-bomb",
      depth: anchorCount,
      position: bodyStart,
    });
    depthBombSeen = true;
  } else if (maxDepth > MAX_YAML_DEPTH) {
    raws.push({
      kind: "yaml-anchor-bomb",
      depth: maxDepth,
      position: bodyStart,
    });
  }
  return raws;
}

function stripYamlComment(line) {
  // Strip `# comment` only when not inside quotes. We track a single-char quote
  // state; nesting is not relevant for line-scoped comments.
  let inQuote = 0;
  for (let i = 0; i < line.length; i++) {
    const ch = line.charCodeAt(i);
    if (inQuote === 0) {
      if (ch === 0x22 /* " */ || ch === 0x27 /* ' */) {
        inQuote = ch;
      } else if (ch === 0x23 /* # */ && (i === 0 || line[i - 1] === " ")) {
        return line.slice(0, i);
      }
    } else if (ch === inQuote) {
      inQuote = 0;
    }
  }
  return line;
}

function phraseMatches(s) {
  if (typeof s !== "string" || !s) return false;
  for (const re of INSTRUCTION_PHRASES) {
    if (re.test(s)) return true;
  }
  return false;
}

// ---------- TOML mini-parser ----------

function scanToml(body, bodyStart) {
  const raws = [];
  if (typeof body !== "string" || body.length === 0) return raws;
  const lines = body.split(/\r?\n/);
  let cursor = bodyStart;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineStart = cursor;
    cursor += line.length + 1;
    if (raws.length >= MAX_FINDINGS) break;

    const trimmed = line.replace(/#.*$/, "").trim();
    if (!trimmed) continue;
    if (trimmed.startsWith("[")) continue; // section header

    const kv = trimmed.match(/^([A-Za-z_][A-Za-z0-9_\-.]*)\s*=\s*(.*)$/);
    if (!kv) continue;

    const rawKey = kv[1];
    const rawValue = kv[2];

    // Instruction-key direct hit.
    if (INSTRUCTION_KEY_NAMES.has(rawKey.toLowerCase())) {
      raws.push({
        kind: "toml-instruction-key",
        key: rawKey,
        position: lineStart + line.indexOf(rawKey),
      });
    }

    if (rawValue && phraseMatches(rawValue)) {
      raws.push({
        kind: "instruction-value",
        key: rawKey,
        position: lineStart + line.indexOf(rawKey),
      });
    }
  }
  return raws;
}

// ---------- JSON-LD scanner ----------

const RE_JSONLD = /<script\b[^>]*\btype\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;

function scanJsonLd(text) {
  const raws = [];
  if (typeof text !== "string" || !text.includes("ld+json")) return raws;
  let m;
  RE_JSONLD.lastIndex = 0;
  while ((m = RE_JSONLD.exec(text)) !== null) {
    if (raws.length >= MAX_FINDINGS) break;
    const blockBody = m[1];
    const blockStart = m.index + m[0].indexOf(blockBody);
    let parsed;
    try {
      parsed = JSON.parse(blockBody);
    } catch {
      continue;
    }
    walkJsonLdValue(parsed, "", blockStart, raws);
  }
  return raws;
}

function walkJsonLdValue(node, path, blockStart, raws, depthLeft = MAX_YAML_DEPTH) {
  if (raws.length >= MAX_FINDINGS) return;
  if (depthLeft <= 0) return;
  if (node === null || node === undefined) return;
  if (Array.isArray(node)) {
    for (const v of node) {
      walkJsonLdValue(v, path, blockStart, raws, depthLeft - 1);
      if (raws.length >= MAX_FINDINGS) return;
    }
    return;
  }
  if (typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (raws.length >= MAX_FINDINGS) return;
      if (typeof v === "string" && JSONLD_INSTRUCTION_FIELDS.has(k) && phraseMatches(v)) {
        raws.push({
          kind: "jsonld-description-injection",
          field: k,
          position: blockStart,
        });
      } else if (v && typeof v === "object") {
        walkJsonLdValue(v, `${path}.${k}`, blockStart, raws, depthLeft - 1);
      }
    }
  }
}

// ---------- Public API ----------

/**
 * Detect injection / dangerous tag / DoS patterns in structured text bundles.
 *
 * @param {string} content
 * @param {object} [opts]
 * @param {string} [opts.format] — 'markdown' | 'yaml' | 'toml' | 'html' |
 *                                  undefined (auto-detect).
 * @returns {Array} findings (kebab id technique, suspiciousPatterns category)
 */
export function detectStructuredTextFrontmatter(content, opts = {}) {
  if (typeof content !== "string" || !content) return [];
  if (content.length > MAX_INPUT_BYTES) return [];

  const findings = [];
  const format = opts.format || "auto";

  // ---- Standalone YAML / TOML files ----
  if (format === "yaml") {
    const raws = scanYaml(content, 0);
    for (const r of raws) appendFinding(findings, r, content, "yaml-file");
    return findings;
  }
  if (format === "toml") {
    const raws = scanToml(content, 0);
    for (const r of raws) appendFinding(findings, r, content, "toml-file");
    return findings;
  }

  // ---- Markdown frontmatter (delimited) ----
  const fm = extractFrontmatter(content);
  if (fm) {
    const raws =
      fm.kind === "yaml"
        ? scanYaml(fm.body, fm.bodyStart)
        : scanToml(fm.body, fm.bodyStart);
    const labelFormat =
      fm.kind === "yaml" ? "yaml-frontmatter" : "toml-frontmatter";
    for (const r of raws) appendFinding(findings, r, content, labelFormat);
  }

  // ---- JSON-LD blocks (always scanned when present) ----
  if (content.includes("ld+json")) {
    const raws = scanJsonLd(content);
    for (const r of raws) appendFinding(findings, r, content, "jsonld");
  }

  return findings;
}

function appendFinding(findings, raw, content, format) {
  if (findings.length >= MAX_FINDINGS) return;
  const baseLen = 1;
  let technique;
  const meta = { format };

  switch (raw.kind) {
    case "yaml-dangerous-tag":
      technique = "yaml-dangerous-tag";
      meta.tagName = sanitizeMetaField(raw.tagName);
      break;
    case "yaml-anchor-bomb":
      technique = "yaml-anchor-bomb";
      meta.depth = typeof raw.depth === "number" ? raw.depth : 0;
      break;
    case "jsonld-description-injection":
      technique = "jsonld-description-injection";
      meta.field = sanitizeMetaField(raw.field);
      break;
    case "toml-instruction-key":
      technique = "toml-instruction-key";
      meta.key = sanitizeMetaField(raw.key);
      break;
    case "instruction-key":
    case "instruction-value":
      technique = "frontmatter-prompt-injection";
      meta.key = sanitizeMetaField(raw.key);
      break;
    default:
      return;
  }

  const keyForContent =
    raw.key || raw.tagName || raw.field || meta.format || "";
  findings.push({
    element: "structured-text",
    technique,
    content: escapeForDisplay(String(keyForContent).slice(0, MAX_KEY_LEN)),
    position: raw.position,
    matchLen: baseLen,
    severity: "danger",
    category: "suspiciousPatterns",
    meta,
  });
}

// Export for tests / harness introspection.
export const _CAPS = Object.freeze({
  MAX_INPUT_BYTES,
  MAX_YAML_DEPTH,
  MAX_ANCHOR_COUNT,
  MAX_FINDINGS,
});
