/**
 * @shield-scanner/core — barrel.
 *
 * Re-exports the pure detection / sanitization / priority pipeline. Env-
 * specific adapters live under ./env/{node,web}/.
 *
 * Node usage (default, no setup required):
 *   import { analyze, sanitize } from "@shield-scanner/core";
 *
 * Web usage (must wire env BEFORE any detector module is imported):
 *   import { setEnv } from "@shield-scanner/core/env";
 *   import { createWebEnv } from "@shield-scanner/core/env/web";
 *   setEnv(createWebEnv());
 *   const { analyze } = await import("@shield-scanner/core");
 */

// Pipeline orchestration
import {
  analyze as _analyzeImpl,
  ALL_CATEGORIES as _ALL_CATEGORIES,
} from "./detector.js";
export {
  ALL_CATEGORIES,
  mergeFindings,
  enrichFindingsLocation,
  formatReport,
} from "./detector.js";
export { sanitize, stripFormulaPrefix } from "./sanitizer.js";

// v1.18.0 — detector benchmark / profile hook.
// analyze() gains an optional `options.profile:true` flag. When set, the
// returned `result.summary.profile` carries per-detector timing:
//   profile = {
//     totalMs: number,   // wall-clock for the whole analyze() call
//     detectors: [       // ordered, one entry per measured detector
//       { name: "invisibleUnicode", ms: 1.234, calls: 1 },
//       ...
//     ],
//   }
// When `profile` is absent / false, `summary.profile` is omitted entirely so
// the v1.17.x summary shape (R13 5-bucket byCategory + sibling keys) is
// byte-identical for every existing caller. The detector pipeline itself is
// re-run in profile mode using the same individual detectors that
// detector.js wires (re-imported here as private locals) — we do NOT touch
// detector.js or any leaf detector module to preserve the byte-identical
// MCP↔Web parity contract on the non-profile path.
import { detectInvisibleUnicode as _detectInvisibleUnicodeImpl } from "./invisible-unicode.js";
import { detectVariationSelectors as _detectVariationSelectorsImpl } from "./variation-selectors.js";
import { detectCombiningChars as _detectCombiningCharsImpl } from "./combining-chars.js";
import { detectControlChars as _detectControlCharsImpl } from "./control-chars.js";
import { detectHiddenElements as _detectHiddenElementsImpl } from "./hidden-elements.js";
import { detectMarkdownExfil as _detectMarkdownExfilImpl } from "./markdown-exfil.js";
import {
  detectSuspiciousPatterns as _detectSuspiciousPatternsImpl,
  scanShadowForSuspiciousPatterns as _scanShadowForSuspiciousPatternsImpl,
} from "./suspicious-patterns.js";
import { detectHomoglyphs as _detectHomoglyphsImpl } from "./homoglyphs.js";
import { detectMathBypass as _detectMathBypassImpl } from "./math-bypass.js";
import { detectFormulaInjection as _detectFormulaInjectionImpl } from "./formula-injection.js";
import {
  buildInvisibleStrippedShadow as _buildInvisibleStrippedShadowImpl,
  buildNfkcShadow as _buildNfkcShadowImpl,
} from "./shadow-copy.js";

// HTML-comment / hidden-element sweep gate. Must match detector.js exactly so
// the profile pass walks the same detectors that the non-profile pass would.
const _HIDDEN_ELEMENT_FILETYPES_PROFILE = new Set(["html", "markdown"]);

function _perfNow() {
  // Prefer the standard `performance.now()` when available (Node >= 16,
  // browsers). Falls back to Date.now() in environments that lack it (the
  // bench harness explicitly forbids unguarded Date.now() at runtime — but a
  // fallback is acceptable here because profile mode is opt-in / dev-only).
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}

/**
 * Public analyze() — pass-through to the orchestrator on the default path.
 * Adds `summary.profile` only when `options.profile === true`.
 */
export function analyze(content, options = {}) {
  if (!options || options.profile !== true) {
    return _analyzeImpl(content, options);
  }

  const fileType = options.fileType || "text";
  const categories = options.categories || _ALL_CATEGORIES;
  const wanted = new Set(categories);

  const t0 = _perfNow();
  const samples = [];
  function _measure(name, fn) {
    const s = _perfNow();
    const out = fn();
    const e = _perfNow();
    samples.push({ name, ms: e - s, calls: 1 });
    return out;
  }

  // Run each detector individually (timed) so we can attach per-call ms to
  // the result. We deliberately rebuild the same fold pattern detector.js
  // uses — folding VS + combining into invisibleUnicode, etc. — but only to
  // produce the profile table. The canonical analyze() call (below) is what
  // produces the actual findings + summary so we never diverge from the
  // single source of truth on the user-visible output.
  if (wanted.has("invisibleUnicode")) {
    _measure("invisibleUnicode", () => _detectInvisibleUnicodeImpl(content));
    _measure("variationSelectors", () => _detectVariationSelectorsImpl(content));
    _measure("combiningChars", () => _detectCombiningCharsImpl(content));
  }
  if (wanted.has("controlChars")) {
    _measure("controlChars", () => _detectControlCharsImpl(content));
  }
  if (
    wanted.has("hiddenHtml") &&
    _HIDDEN_ELEMENT_FILETYPES_PROFILE.has(fileType)
  ) {
    _measure("hiddenElements", () => _detectHiddenElementsImpl(content));
    _measure("markdownExfil", () => _detectMarkdownExfilImpl(content));
  }
  if (wanted.has("suspiciousPatterns")) {
    _measure("suspiciousPatterns", () => _detectSuspiciousPatternsImpl(content));
    const invStripped = _measure("buildInvisibleStrippedShadow", () =>
      _buildInvisibleStrippedShadowImpl(content)
    );
    if (invStripped) {
      _measure("shadowSuspiciousInvisibleStripped", () =>
        _scanShadowForSuspiciousPatternsImpl(
          invStripped.shadow,
          invStripped.shadowToOrig,
          "invisibleStripped",
          content
        )
      );
    }
    const nfkc = _measure("buildNfkcShadow", () => _buildNfkcShadowImpl(content));
    if (nfkc) {
      _measure("shadowSuspiciousNfkc", () =>
        _scanShadowForSuspiciousPatternsImpl(
          nfkc.shadow,
          nfkc.shadowToOrig,
          "nfkcNormalized",
          content
        )
      );
    }
    if (fileType === "xlsx" || fileType === "csv") {
      _measure("formulaInjection", () =>
        _detectFormulaInjectionImpl(content, fileType)
      );
    }
  }
  if (wanted.has("homoglyphs")) {
    _measure("homoglyphs", () => _detectHomoglyphsImpl(content));
    _measure("mathBypass", () => _detectMathBypassImpl(content));
  }

  // Canonical pass — produces the actual findings/summary. This is the same
  // call site every other consumer uses, so byte-identical output is
  // guaranteed by construction.
  const result = _analyzeImpl(content, options);
  const t1 = _perfNow();

  // Attach the profile as a sibling key under `summary` (next to `bidiControl`
  // / `topFindings` / `archive`). R13 5-bucket `byCategory` invariant is NOT
  // touched.
  result.summary = {
    ...result.summary,
    profile: {
      totalMs: t1 - t0,
      detectors: samples,
    },
  };
  return result;
}

// S10: CSV/XLSX formula-injection detector + OPC helpers (shared by xlsx /
// docx / pptx parsers). Lives under the existing suspiciousPatterns bucket —
// no new top-level byCategory key is introduced (R13).
export { detectFormulaInjection } from "./formula-injection.js";
export {
  parseRelationships,
  parseContentTypes,
  normalizeXlfn,
  normalizeFormulaPrefix,
} from "./opc-helpers.js";

// S13: ZIP/archive recursive-scan primitives. Same R13 routing rules as S10 —
// zip-slip / suspicious-ext / Office-rename fold into suspiciousPatterns; bomb /
// depth / encrypted / entry-cap live on `summary.archive` sibling key. Helpers
// here are env-free so MCP + Web + parity-check + unit tests can all import
// directly without setEnv() wiring.
export {
  detectZipSlip,
  classifySuspiciousExt,
  isOfficePackageRename,
  detectMagicBytesIsZip,
  computeBombRatio,
  ARCHIVE_CAPS,
  DANGEROUS_ARCHIVE_EXTS,
} from "./archive-detection.js";

// Priority / shadow-copy / decoded-redaction
export {
  attachPriorities,
  buildTopFindings,
  computePriority,
  CATEGORY_WEIGHTS,
  SEVERITY_BASE,
} from "./priority.js";
export {
  buildInvisibleStrippedShadow,
  buildNfkcShadow,
  mapSpanToOriginal,
} from "./shadow-copy.js";
export * as decodedRedaction from "./decoded-redaction.js";
export { redactDecodedFindings } from "./decoded-redaction.js";

// Individual detectors (for fine-grained callers / tests)
export {
  detectInvisibleUnicode,
  stripInvisibleUnicode,
} from "./invisible-unicode.js";
export {
  detectControlChars,
  stripControlChars,
} from "./control-chars.js";
export {
  detectHiddenElements,
  stripHiddenElements,
} from "./hidden-elements.js";
export {
  detectSuspiciousPatterns,
  stripSuspiciousPatterns,
  scanShadowForSuspiciousPatterns,
} from "./suspicious-patterns.js";
export {
  detectHomoglyphs,
  normalizeHomoglyphs,
  auditHomoglyphMap,
} from "./homoglyphs.js";
export { detectVariationSelectors } from "./variation-selectors.js";
export { detectMathBypass } from "./math-bypass.js";
export { detectCombiningChars } from "./combining-chars.js";
export { detectMarkdownExfil } from "./markdown-exfil.js";

// Utils
export {
  getContext,
  compactSummary,
  expandFindingsContext,
  escapeForDisplay,
  getControlCharName,
  looksLikeInstruction,
  loadRule,
} from "./utils.js";

// PDF-DEEP / EML R12 context-location sanitizer (v1.6.x followup).
// Strips bidi / zero-width / ANSI / line-injection from finding contextLocation
// fields so attachment filenames cannot be used as a UI re-render oracle.
export { sanitizeContextLocation } from "./context-sanitizer.js";

// PDF-DEEP-05 (v1.9.0): structure-tree walker for image XObject /Alt /ActualText
// extraction. Pure helpers — env-free so MCP + Web + parity-check + unit tests
// can all import directly without setEnv() wiring. R13 routing: yielded text is
// surfaced via the parser's pushText so it folds into the existing 5 buckets.
export {
  walkStructTree,
  PDF_STRUCT_CAPS,
  sanitizeStructKey,
} from "./pdf-struct.js";

// v1.19.0 B4: Structured-text frontmatter detector (YAML / TOML / JSON-LD).
// Auto-fires on markdown frontmatter + JSON-LD; standalone .yml/.yaml/.toml
// files are dispatched via the parser registry with fileType="yaml"|"toml".
// Findings land in the existing suspiciousPatterns bucket (R13 fold).
export { detectStructuredTextFrontmatter } from "./structured-text-frontmatter.js";

// v1.19.0 D1: Encoded payload decode pipeline (Base64 / Hex / Punycode /
// HTML entity). Pure detector — runs on every analyze() call regardless of
// fileType. Findings land in the existing suspiciousPatterns bucket (R13
// fold). R12: decoded raw text NEVER appears in any finding field; only
// kebab id + raw byte-range meta + enum encoding class are surfaced.
export {
  detectEncodedPayloads,
  ENCODED_DECODER_CAPS,
  ENCODED_KEBAB,
  ENCODED_PLACEHOLDER_MATCHED,
} from "./encoded-decoder.js";
