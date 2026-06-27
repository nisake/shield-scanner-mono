// Parser registry / dispatcher (Web side) — v1.19.0 B1.
//
// app.js currently inlines its own ext → parser switch in handleFile() (see
// L143-L151). This module exists as the dispatch helper for:
//   - the SVG-polyglot parity test (test-svg-polyglot.mjs) — imports
//     `recognizeExt` + `dispatchBuffer` here so the routing contract is
//     pinned for both .svg standalone files and image/svg+xml MIME values
//     coming out of EML / DOCX attachments
//   - tools/parity-check.mjs SVG_FIXTURES section (Web route)
//   - a future app.js refactor that consolidates the ext switch
//
// The MIME map is the same string set as packages/mcp/server/parsers/index.js
// `MIME_EXT_MAP` — kept in sync byte-identically (parity contract).

import { parseSvg } from './svg.js';
import { parseHtml } from './html.js';

const SVG_EXTS = new Set(['svg']);
const HTML_EXTS = new Set(['html', 'htm', 'xml']);

export const MIME_EXT_MAP = new Map([
  ['image/svg+xml', 'svg'],
]);

/**
 * Map a Content-Type / MIME string to a normalized extension. Returns null
 * for unrecognized MIMEs so callers can fall through to ext-based dispatch.
 */
export function recognizeMime(mime) {
  if (typeof mime !== 'string' || mime.length === 0) return null;
  const norm = mime.split(';')[0].trim().toLowerCase();
  return MIME_EXT_MAP.get(norm) || null;
}

/**
 * Normalize a filename-or-extension into the lowercase no-dot form used by
 * the dispatcher (e.g. 'foo.SVG' → 'svg').
 */
export function recognizeExt(nameOrExt) {
  if (typeof nameOrExt !== 'string' || !nameOrExt) return null;
  const last = nameOrExt.split('.').pop();
  if (!last) return null;
  return last.toLowerCase();
}

/**
 * Route a buffer (Uint8Array / ArrayBuffer / string) to the right parser
 * based on an extension or MIME hint. Returns the parser result with the
 * canonical Web envelope `{text, fileType, hiddenFindings}`.
 *
 * Returns null when the extension is not dispatchable here (caller should
 * fall back to its own routing — app.js currently owns docx/pdf/pptx/xlsx/
 * csv/image/zip dispatch).
 */
export async function dispatchBuffer(buffer, { ext, mime } = {}) {
  const fromMime = recognizeMime(mime);
  const resolved = fromMime || recognizeExt(ext) || null;
  if (!resolved) return null;
  if (SVG_EXTS.has(resolved)) return parseSvg(buffer);
  if (HTML_EXTS.has(resolved)) return parseHtml(buffer);
  return null;
}

export { parseSvg, parseHtml };

// ---------------------------------------------------------------------------
// v1.19.0 B4: Structured-text dispatch (.yml / .yaml / .toml).
//
// Standalone YAML / TOML files are parsed as plain text on the Web side and
// tagged with fileType="yaml" | "toml" so core's analyze() runs the
// structured-text-frontmatter detector with the correct format hint. The Web
// parser is intentionally minimal — no file-system access; the caller provides
// the text decoded from the upload. R13 fold: every finding routes through
// the existing suspiciousPatterns bucket.
// ---------------------------------------------------------------------------
const STRUCTURED_YAML_EXTS = new Set(['yml', 'yaml']);
const STRUCTURED_TOML_EXTS = new Set(['toml']);
const STRUCTURED_TEXT_EXTS = new Set([
  ...STRUCTURED_YAML_EXTS,
  ...STRUCTURED_TOML_EXTS,
]);

export function recognizeStructuredTextExt(nameOrExt) {
  const norm = recognizeExt(nameOrExt);
  if (!norm) return null;
  if (STRUCTURED_YAML_EXTS.has(norm)) return 'yaml';
  if (STRUCTURED_TOML_EXTS.has(norm)) return 'toml';
  return null;
}

export async function parseStructuredTextBuffer(input, ext) {
  const norm = recognizeExt(ext);
  if (!norm || !STRUCTURED_TEXT_EXTS.has(norm)) return null;
  let text;
  if (typeof input === 'string') {
    text = input;
  } else if (input instanceof ArrayBuffer) {
    text = new TextDecoder('utf-8').decode(new Uint8Array(input));
  } else if (ArrayBuffer.isView(input)) {
    text = new TextDecoder('utf-8').decode(input);
  } else {
    text = String(input);
  }
  const fileType = STRUCTURED_YAML_EXTS.has(norm) ? 'yaml' : 'toml';
  return { text, fileType, hiddenFindings: [] };
}

export const STRUCTURED_TEXT_DISPATCH = Object.freeze({
  exts: Array.from(STRUCTURED_TEXT_EXTS),
  yamlExts: Array.from(STRUCTURED_YAML_EXTS),
  tomlExts: Array.from(STRUCTURED_TOML_EXTS),
});

// ---------------------------------------------------------------------------
// v1.20.0 T1-ODT: OpenDocument Text (.odt) parser surface (Web mirror).
//
// Byte-identical with the MCP packages/mcp/server/parsers/index.js ODT
// declaration. Exposes the ext set and the parseOdt function for the
// app.js dispatcher and the test-s22-odt.mjs harness. All findings fold to
// suspiciousPatterns (R13 5-key invariant intact). Appended at file end so
// concurrent T2 / T3 parser additions stay merge-clean.
// ---------------------------------------------------------------------------
import { parseOdt } from './odt.js';
const ODT_EXTS = new Set(['odt']);

export const ODT_DISPATCH = Object.freeze({
  exts: Array.from(ODT_EXTS),
});

export { parseOdt };

// ---------------------------------------------------------------------------
// v1.20.0 T2-ODS: OpenDocument Spreadsheet (.ods) parser surface (Web mirror).
//
// Byte-identical with the MCP packages/mcp/server/parsers/index.js ODS
// declaration. Exposes the ext set and the parseOds function for the
// app.js dispatcher and the test-s22-ods.mjs harness. All findings fold to
// suspiciousPatterns (R13 5-key invariant intact). Appended after T1-ODT so
// the ODF cluster (odp/odt/ods) sits together at the tail of the file.
// ---------------------------------------------------------------------------
import { parseOds } from './ods.js';
const ODS_EXTS = new Set(['ods']);

export const ODS_DISPATCH = Object.freeze({
  exts: Array.from(ODS_EXTS),
});

export { parseOds };
