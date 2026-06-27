/**
 * Default HTML parser for detectHiddenElements (Node-only fallback).
 *
 * Mirrors the utils.js#loadRule resolution pattern: when no env.htmlParser
 * is wired (e.g. unit tests that import detectHiddenElements directly, or
 * the MCP server entrypoint that never calls setEnv), we lazily build a
 * cheerio-backed parser and cache it as a module-singleton.
 *
 * The Web bundle replaces this module with an empty stub via the
 * nodeStubPlugin in packages/web/build.mjs, so cheerio + parse5 + htmlparser2
 * + cheerio-select + dom-serializer + entities are dropped from the dist
 * bundle. In the browser, createWebEnv() always wires env.htmlParser to a
 * DOMParser-backed adapter, so this fallback path is unreachable.
 */
import { createCheerioHtmlParser } from "./env/node/html-parser.js";

let _cached = null;

export function getDefaultHtmlParser() {
  if (!_cached) _cached = createCheerioHtmlParser();
  return _cached;
}
