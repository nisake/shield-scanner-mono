/**
 * Node rules-loader adapter.
 *
 * Reads JSON files from a directory using node:fs. Default rulesDir resolves
 * to packages/core/data/ relative to this file. MCP entrypoint may override
 * with createNodeRulesLoader({ rulesDir }) when bundling custom rules.
 *
 * Cache: per-instance Map. Repeat loadRule(name) calls return the cached
 * object reference.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// packages/core/src/env/node/rules-loader.js -> packages/core/data/
const DEFAULT_RULES_DIR = join(__dirname, "..", "..", "..", "data");

export function createNodeRulesLoader(rulesDir = DEFAULT_RULES_DIR) {
  const cache = new Map();
  return {
    loadRule(name) {
      // Normalize cache key: accept both "homoglyphs" and "homoglyphs.json"
      // for back-compat with the legacy MCP-side loadRule(filename) signature.
      const key = name.endsWith(".json") ? name.slice(0, -5) : name;
      if (cache.has(key)) return cache.get(key);
      const path = join(rulesDir, `${key}.json`);
      const data = JSON.parse(readFileSync(path, "utf8"));
      cache.set(key, data);
      return data;
    },
  };
}
