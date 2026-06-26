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
export {
  analyze,
  ALL_CATEGORIES,
  mergeFindings,
  enrichFindingsLocation,
  formatReport,
} from "./detector.js";
export { sanitize, stripFormulaPrefix } from "./sanitizer.js";

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
