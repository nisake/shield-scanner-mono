/**
 * Web rules-loader adapter.
 *
 * Bundles rules JSON at build time via `with { type: "json" }` import
 * attributes. Web build (vite / esbuild target=es2022) inlines them.
 *
 * Path: packages/core/src/env/web/rules-loader.js
 *   -> packages/core/data/<name>.json
 */
import invisibleChars from "../../../data/invisible-chars.json" with { type: "json" };
import homoglyphs from "../../../data/homoglyphs.json" with { type: "json" };
import suspiciousPatterns from "../../../data/suspicious-patterns.json" with { type: "json" };
import exfilPatterns from "../../../data/exfil-patterns.json" with { type: "json" };
import formulaInjection from "../../../data/formula-injection.json" with { type: "json" };
import archiveDetection from "../../../data/archive-detection.json" with { type: "json" };

const RULES = {
  "invisible-chars": invisibleChars,
  "homoglyphs": homoglyphs,
  "suspicious-patterns": suspiciousPatterns,
  "exfil-patterns": exfilPatterns,
  "formula-injection": formulaInjection,
  "archive-detection": archiveDetection,
};

export function createWebRulesLoader() {
  return {
    loadRule(name) {
      // Accept both "homoglyphs" and "homoglyphs.json"
      const key = name.endsWith(".json") ? name.slice(0, -5) : name;
      const rule = RULES[key];
      if (!rule) throw new Error(`Unknown rule: ${name}`);
      return rule;
    },
  };
}
