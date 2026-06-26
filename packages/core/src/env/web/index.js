/**
 * Web env factory — bundles inline JSON rules + DOMParser for browser use.
 *
 * Usage (Web entrypoint):
 *   import { setEnv } from "@shield-scanner/core/env";
 *   import { createWebEnv } from "@shield-scanner/core/env/web";
 *   setEnv(createWebEnv());
 *   // ...then import detectors
 */
import { createWebRulesLoader } from "./rules-loader.js";
import { createDomHtmlParser } from "./html-parser.js";

export { createWebRulesLoader, createDomHtmlParser };

export function createWebEnv() {
  return {
    rulesLoader: createWebRulesLoader(),
    htmlParser: createDomHtmlParser(),
  };
}
