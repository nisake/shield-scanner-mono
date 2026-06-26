/**
 * Node env factory — bundles rules-loader + html-parser for MCP / CLI use.
 *
 * Usage:
 *   import { createNodeEnv } from "@shield-scanner/core/env/node";
 *   import { setEnv } from "@shield-scanner/core/env";
 *   setEnv(createNodeEnv());
 *   // ...then import detectors
 */
import { createNodeRulesLoader } from "./rules-loader.js";
import { createCheerioHtmlParser } from "./html-parser.js";

export { createNodeRulesLoader, createCheerioHtmlParser };

export function createNodeEnv(opts = {}) {
  return {
    rulesLoader: createNodeRulesLoader(opts.rulesDir),
    htmlParser: createCheerioHtmlParser(),
  };
}
