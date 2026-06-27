/**
 * Tool: scan_mcp_descriptor (v1.18.0)
 *
 * Scans MCP tool descriptors for poisoning attacks. Targets CVE-2025-54136 /
 * OWASP MCP03:2025 class threats — adversarial / silently-mutated tool
 * descriptions, hidden instructions in tool metadata, name-shadowing, and
 * rug-pull (signed-then-swapped) descriptor swaps.
 *
 * Input:
 *   - `descriptor` (string)  : raw JSON of an mcp.json / claude_desktop_config.json
 *                              / tools-list response. EITHER this OR `path`.
 *   - `path`       (string)  : absolute path to such a JSON file.
 *   - `baselinePath` (string): optional path to a previous descriptor JSON used
 *                              for the rug-pull SHA256 diff. SAME shape as the
 *                              current input (tools list or {mcpServers:{...}}).
 *
 * Output:
 *   Standard analyze()-shaped result (`summary` + `findings`), with all new
 *   MCP-descriptor signals folded into `findings.suspiciousPatterns` so the
 *   R13 5-bucket byCategory invariant is preserved.
 *
 * R12 hard rule: descriptor user-text is NEVER echoed verbatim into the
 * response body. Only:
 *   - the detector-controlled kebab id (`technique`)
 *   - the detector-controlled `pattern` string (English label)
 *   - controlled meta fields (`toolName` (sanitized), `descriptorPath`,
 *     `baselineHashFirst8`, `currentHashFirst8`, `severity`)
 * are emitted. The underlying `analyze()` pass on the description text already
 * runs `escapeForDisplay` on `matched`, so existing suspiciousPatterns hits
 * stay R12-compliant.
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { analyze, mergeFindings, formatReport } from "@shield-scanner/core";
import { compactSummary } from "@shield-scanner/core";

// --- Detector controls ---------------------------------------------------

// Hidden / role-style instructions a benign descriptor MUST NOT contain. We
// keep this list narrow (high-precision, low-recall) — generic LLM prose like
// "Use this tool to send messages" is normal; this scanner is specifically
// looking for descriptor-level prompt injection.
const HIDDEN_INSTRUCTION_RES = [
  /\bignore\s+(?:all\s+)?previous\s+(?:instructions?|rules?|prompts?)\b/i,
  /\bdisregard\s+(?:all\s+)?previous\s+(?:instructions?|rules?)\b/i,
  /^[\s>*-]*system\s*:\s*(?:you\s+are|act\s+as|never|always)/im,
  /^[\s>*-]*assistant\s*:\s*(?:you\s+are|never|always)/im,
  /\bdeveloper\s+mode\b/i,
  /<\|im_start\|>\s*(?:system|user|assistant)/i,
  /<\|start_header_id\|>\s*(?:system|user|assistant)\s*<\|end_header_id\|>/i,
  /\bnew\s+(?:system|safety)\s+prompt\b/i,
  /\boverride\s+(?:safety|guard|policy)/i,
];

// Unicode Tags block + a representative slice of invisible / bidi controls
// that have NO legitimate use in a tool description. analyze() already covers
// most of these, but we keep an explicit check so descriptor-level signal
// surfaces under the dedicated mcp-descriptor-injection kebab id (not just as
// a generic invisibleUnicode hit).
const INVISIBLE_SIGNAL_RE = /[\u{E0000}-\u{E007F}‪-‮⁦-⁩​‌‍‎‏﻿]/u;

// Mixed-script signal: if a description contains BOTH ASCII letters and
// Cyrillic letters whose canonical homoglyph counterparts exist in ASCII,
// that's strong evidence of a homoglyph spoof. We only fire this signal
// when the description LOOKS like English (>= 8 ASCII letters) to avoid
// flagging Cyrillic-language descriptions.
const CYRILLIC_HOMOGLYPH_RE = /[аеорсхуиӏ]/;
const ASCII_LETTER_RE = /[A-Za-z]/g;

// --- Public entry --------------------------------------------------------

export async function scanMcpDescriptor({
  descriptor,
  path,
  baselinePath,
  verbosity = "normal",
} = {}) {
  if (typeof descriptor !== "string" && typeof path !== "string") {
    throw new Error(
      "scan_mcp_descriptor: either 'descriptor' (raw JSON string) or 'path' is required",
    );
  }

  // 1. Load the current descriptor payload.
  let rawCurrent;
  let descriptorPath = "(inline)";
  if (typeof path === "string" && path.length > 0) {
    rawCurrent = await readFile(path, "utf8");
    descriptorPath = path;
  } else {
    rawCurrent = descriptor;
  }

  let parsed;
  try {
    parsed = JSON.parse(rawCurrent);
  } catch (err) {
    throw new Error(
      `scan_mcp_descriptor: input is not valid JSON (${err.message})`,
    );
  }

  // 2. Extract the canonical list of tool descriptors.
  const tools = extractTools(parsed);

  // 3. Collect findings — each kebab id is a controlled string surfaced via
  //    the suspiciousPatterns bucket.
  const extras = []; // suspiciousPatterns extras

  // a) Per-tool analyze() on the joined descriptor text + descriptor-level
  //    injection heuristics.
  for (const tool of tools) {
    const safeName = sanitizeToolName(tool.name);
    const descrText = stringifyDescriptor(tool);

    // a-1) Hidden instructions phrase scan.
    for (const re of HIDDEN_INSTRUCTION_RES) {
      if (re.test(descrText)) {
        extras.push(buildExtra({
          pattern: "MCP hidden instruction in description",
          technique: "mcp-hidden-instruction-in-description",
          severity: "danger",
          meta: {
            toolName: safeName,
            descriptorPath,
          },
        }));
        break; // one hit per tool is enough — we just need to surface the signal
      }
    }

    // a-2) Descriptor injection: invisible unicode / bidi / Tags-block /
    //      mixed-script homoglyph in the description. This is the
    //      "Tags smuggling" + "homoglyph" branch.
    if (INVISIBLE_SIGNAL_RE.test(descrText) || hasMixedScriptHomoglyph(descrText)) {
      extras.push(buildExtra({
        pattern: "MCP descriptor injection",
        technique: "mcp-descriptor-injection",
        severity: "danger",
        meta: {
          toolName: safeName,
          descriptorPath,
        },
      }));
    } else {
      // a-3) Run the standard analyze() against the descriptor text.
      //      If analyze() finds ANY suspicious / invisible / homoglyph hit,
      //      surface a single descriptor-injection signal (the raw findings
      //      themselves stay folded under suspiciousPatterns via mergeFindings
      //      below — see "b)" — so the user can drill in).
      const sub = analyze(descrText, { fileType: "text" });
      const hasInjectionHit =
        (sub.summary?.byCategory?.suspiciousPatterns || 0) > 0 ||
        (sub.summary?.byCategory?.invisibleUnicode || 0) > 0 ||
        (sub.summary?.byCategory?.homoglyphs || 0) > 0;
      if (hasInjectionHit) {
        extras.push(buildExtra({
          pattern: "MCP descriptor injection",
          technique: "mcp-descriptor-injection",
          severity: "warning",
          meta: {
            toolName: safeName,
            descriptorPath,
          },
        }));
      }
    }
  }

  // b) Shadow-tool collision (duplicate names within a single descriptor).
  const nameCounts = new Map();
  for (const tool of tools) {
    const key = typeof tool.name === "string" ? tool.name : "(unnamed)";
    nameCounts.set(key, (nameCounts.get(key) || 0) + 1);
  }
  for (const [name, n] of nameCounts.entries()) {
    if (n >= 2) {
      extras.push(buildExtra({
        pattern: "MCP shadow-tool collision",
        technique: "mcp-shadow-tool-collision",
        severity: "danger",
        meta: {
          toolName: sanitizeToolName(name),
          descriptorPath,
          collisionCount: n,
        },
      }));
    }
  }

  // c) Rug-pull detection: SHA256 hash diff vs the optional baseline.
  if (typeof baselinePath === "string" && baselinePath.length > 0) {
    let rawBaseline;
    try {
      rawBaseline = await readFile(baselinePath, "utf8");
    } catch (err) {
      throw new Error(
        `scan_mcp_descriptor: cannot read baselinePath (${err.message})`,
      );
    }
    const baselineHash = sha256(normalizeForHash(rawBaseline));
    const currentHash = sha256(normalizeForHash(rawCurrent));
    if (baselineHash !== currentHash) {
      extras.push(buildExtra({
        pattern: "MCP rug-pull detected",
        technique: "mcp-rug-pull-detected",
        severity: "danger",
        meta: {
          descriptorPath,
          baselineHashFirst8: baselineHash.slice(0, 8),
          currentHashFirst8: currentHash.slice(0, 8),
        },
      }));
    }
  }

  // 4. Build the standard analyze()-shaped result. We seed with an empty
  //    analyze() so the byCategory 5-key invariant + topFindings are computed
  //    by the canonical pipeline, then splice the extras into suspiciousPatterns
  //    via mergeFindings (R13).
  const baseResult = analyze("", { fileType: "text" });
  const merged = mergeFindings(baseResult, { suspiciousPatterns: extras });

  if (verbosity === "compact") {
    return {
      verbosity: "compact",
      ...compactSummary(merged),
      toolsScanned: tools.length,
    };
  }

  const report = formatReport(merged, {
    fileName: descriptorPath,
    scannedAt: new Date().toISOString(),
  });

  return {
    verbosity,
    summary: merged.summary,
    findings: merged.findings,
    toolsScanned: tools.length,
    descriptorPath,
    report,
  };
}

// --- Helpers -------------------------------------------------------------

/**
 * Pull a normalized tool list out of any of the common descriptor shapes:
 *   - {tools: [...]}                       (MCP tools/list response)
 *   - [...]                                (already a tool list)
 *   - {mcpServers: {name: {tools: [...]}}} (cursor / claude_desktop_config)
 *   - {mcpServers: {name: {...}}}          (server-level entry only — counted
 *                                           as a single descriptor)
 *
 * Each yielded item carries at minimum a `name` string; `description` and
 * `inputSchema` are optional.
 */
function extractTools(parsed) {
  if (!parsed || typeof parsed !== "object") return [];
  if (Array.isArray(parsed)) {
    return parsed.filter((t) => t && typeof t === "object");
  }
  if (Array.isArray(parsed.tools)) {
    return parsed.tools.filter((t) => t && typeof t === "object");
  }
  const out = [];
  if (parsed.mcpServers && typeof parsed.mcpServers === "object") {
    for (const [serverName, entry] of Object.entries(parsed.mcpServers)) {
      if (!entry || typeof entry !== "object") continue;
      if (Array.isArray(entry.tools)) {
        for (const t of entry.tools) {
          if (t && typeof t === "object") {
            out.push({
              ...t,
              name: typeof t.name === "string" ? `${serverName}:${t.name}` : serverName,
            });
          }
        }
      } else {
        // server-level descriptor only (command/args/env). Surface the
        // server entry so descriptor injection in command/args is still
        // visible. Use the server name as the tool name.
        out.push({ name: serverName, description: stringifyForDescriptor(entry) });
      }
    }
  }
  return out;
}

/**
 * Flatten a tool descriptor into a single string for text-level analysis.
 * We deliberately concatenate name + description + JSON-stringified schema so
 * Tags-block / invisible Unicode / phrase signals in ANY part surface.
 */
function stringifyDescriptor(tool) {
  const parts = [];
  if (typeof tool.name === "string") parts.push(tool.name);
  if (typeof tool.description === "string") parts.push(tool.description);
  if (tool.inputSchema && typeof tool.inputSchema === "object") {
    try {
      parts.push(JSON.stringify(tool.inputSchema));
    } catch {
      /* circular-ref safety net — should never trigger on real MCP schemas */
    }
  }
  return parts.join("\n");
}

function stringifyForDescriptor(entry) {
  try {
    return JSON.stringify(entry);
  } catch {
    return "";
  }
}

/**
 * Sanitize a tool name for inclusion in meta (R12). We strip control chars,
 * bidi controls, Tags block, and clip length so a tool named with a hidden
 * payload cannot use this scanner's response as an oracle.
 */
function sanitizeToolName(name) {
  if (typeof name !== "string") return "(unnamed)";
  // Strip Tags block + bidi/zero-width + control chars; clip to 80 chars.
  const cleaned = name
    .replace(/[\u{E0000}-\u{E007F}]/gu, "")
    .replace(/[‪-‮⁦-⁩​-‏﻿]/g, "")
    .replace(/[\x00-\x1F\x7F]/g, "")
    .slice(0, 80);
  return cleaned.length > 0 ? cleaned : "(empty)";
}

/**
 * Mixed-script homoglyph heuristic for descriptor text.
 *
 * Fires only when there is significant ASCII English content (>= 8 ASCII
 * letters) AND at least one Cyrillic letter whose canonical homoglyph
 * lives in ASCII. This keeps legitimate Russian/Ukrainian descriptions
 * out of the danger bucket.
 */
function hasMixedScriptHomoglyph(text) {
  if (typeof text !== "string" || text.length === 0) return false;
  const asciiMatches = text.match(ASCII_LETTER_RE);
  if (!asciiMatches || asciiMatches.length < 8) return false;
  return CYRILLIC_HOMOGLYPH_RE.test(text);
}

/**
 * Normalize a JSON blob for hashing. We re-parse → recursive sorted-key
 * stringify so cosmetic whitespace / key-order changes don't trigger
 * rug-pull false positives. Falls back to raw text if the input is somehow
 * not round-trippable (caller already validated it parses).
 */
function normalizeForHash(raw) {
  try {
    const obj = JSON.parse(raw);
    return canonicalize(obj);
  } catch {
    return raw;
  }
}

function canonicalize(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  const keys = Object.keys(value).sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + canonicalize(value[k]))
      .join(",") +
    "}"
  );
}

function sha256(s) {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/**
 * Build a finding shape compatible with the suspiciousPatterns bucket.
 * R12 — only detector-controlled fields. NO raw descriptor text leaks.
 */
function buildExtra({ pattern, technique, severity, meta }) {
  return {
    pattern,
    technique,
    severity,
    category: "suspiciousPatterns",
    matched: "(redacted — see meta)",
    position: 0,
    matchLen: 0,
    context: "",
    meta: meta || undefined,
  };
}
