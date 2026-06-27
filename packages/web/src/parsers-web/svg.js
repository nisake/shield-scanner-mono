// SVG parser (v1.19.0 B1 — Polyglot SVG).
// Mirror of packages/mcp/server/parsers/svg.js byte-identically — see that
// file's header for the threat model. parity-check.mjs SVG_FIXTURES section
// pins the (category, severity, technique) triple set across MCP and Web.
//
// Detection envelope (6 kebab ids, fold to suspiciousPatterns under R13):
//   - svg-script-element
//   - svg-event-handler        (meta.attribute)
//   - svg-javascript-href
//   - svg-foreignobject-html
//   - svg-cdata-section
//   - svg-use-external-ref     (meta.href)
//
// R12 invariant: kebab id is fixed, only detector-controlled meta fields
// (attribute name, href target) ride alongside. Raw user text never lands
// in the technique id.

import { escapeForDisplay } from '@shield-scanner/core';

const SVG_MAX_BYTES = 5 * 1024 * 1024;
const SVG_MAX_PER_RULE_FINDINGS = 32;

const ON_HANDLER_RE = /\s(on[a-z]{1,30})\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
const SCRIPT_OPEN_RE = /<script\b[^>]*>/gi;
const FOREIGNOBJECT_OPEN_RE = /<foreignObject\b[^>]*>/gi;
const CDATA_RE = /<!\[CDATA\[([\s\S]*?)\]\]>/g;
const HREF_RE = /\s(?:xlink:href|href)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;
const USE_TAG_RE = /<use\b([^>]*)>/gi;

export function detectSvgInjection(xml) {
  if (typeof xml !== 'string' || xml.length === 0) return [];
  const findings = [];

  let scriptCount = 0;
  for (const m of xml.matchAll(SCRIPT_OPEN_RE)) {
    if (scriptCount >= SVG_MAX_PER_RULE_FINDINGS) break;
    scriptCount++;
    findings.push({
      element: 'svg:script',
      technique: 'svg-script-element',
      severity: 'danger',
      category: 'suspiciousPatterns',
      content: escapeForDisplay(m[0].slice(0, 200)),
    });
  }

  let handlerCount = 0;
  ON_HANDLER_RE.lastIndex = 0;
  let h;
  while ((h = ON_HANDLER_RE.exec(xml)) !== null) {
    if (handlerCount >= SVG_MAX_PER_RULE_FINDINGS) break;
    handlerCount++;
    const attr = (h[1] || '').toLowerCase();
    const val = h[2] !== undefined ? h[2] : h[3] !== undefined ? h[3] : h[4] || '';
    findings.push({
      element: 'svg attribute',
      technique: 'svg-event-handler',
      severity: 'danger',
      category: 'suspiciousPatterns',
      meta: { attribute: attr },
      content: escapeForDisplay(val.slice(0, 200)),
    });
  }

  let jshrefCount = 0;
  HREF_RE.lastIndex = 0;
  let hr;
  while ((hr = HREF_RE.exec(xml)) !== null) {
    if (jshrefCount >= SVG_MAX_PER_RULE_FINDINGS) break;
    const raw = hr[1] !== undefined ? hr[1] : hr[2] !== undefined ? hr[2] : hr[3] || '';
    const stripped = raw.replace(/^[\s -]+/, '').toLowerCase();
    if (stripped.startsWith('javascript:')) {
      jshrefCount++;
      findings.push({
        element: 'svg href',
        technique: 'svg-javascript-href',
        severity: 'danger',
        category: 'suspiciousPatterns',
        content: escapeForDisplay(raw.slice(0, 200)),
      });
    }
  }

  let foCount = 0;
  for (const m of xml.matchAll(FOREIGNOBJECT_OPEN_RE)) {
    if (foCount >= SVG_MAX_PER_RULE_FINDINGS) break;
    foCount++;
    findings.push({
      element: 'svg:foreignObject',
      technique: 'svg-foreignobject-html',
      severity: 'warning',
      category: 'suspiciousPatterns',
      content: escapeForDisplay(m[0].slice(0, 200)),
    });
  }

  let cdataCount = 0;
  CDATA_RE.lastIndex = 0;
  let cm;
  while ((cm = CDATA_RE.exec(xml)) !== null) {
    if (cdataCount >= SVG_MAX_PER_RULE_FINDINGS) break;
    cdataCount++;
    const body = cm[1] || '';
    findings.push({
      element: 'svg CDATA section',
      technique: 'svg-cdata-section',
      severity: 'warning',
      category: 'suspiciousPatterns',
      content: escapeForDisplay(body.slice(0, 200)),
    });
  }

  let useCount = 0;
  USE_TAG_RE.lastIndex = 0;
  let um;
  while ((um = USE_TAG_RE.exec(xml)) !== null) {
    if (useCount >= SVG_MAX_PER_RULE_FINDINGS) break;
    const inner = um[1] || '';
    const hm = /\s(?:xlink:href|href)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i.exec(inner);
    if (!hm) continue;
    const raw = hm[1] !== undefined ? hm[1] : hm[2] !== undefined ? hm[2] : hm[3] || '';
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    useCount++;
    findings.push({
      element: 'svg:use',
      technique: 'svg-use-external-ref',
      severity: 'warning',
      category: 'suspiciousPatterns',
      meta: { href: trimmed.slice(0, 200) },
      content: escapeForDisplay(um[0].slice(0, 200)),
    });
  }

  return findings;
}

export async function parseSvg(buffer) {
  let text;
  if (typeof buffer === 'string') {
    text = buffer.slice(0, SVG_MAX_BYTES);
  } else if (buffer && typeof buffer.byteLength === 'number') {
    // ArrayBuffer / Uint8Array path (browser FileReader.readAsArrayBuffer)
    const u8 =
      buffer instanceof Uint8Array
        ? buffer
        : new Uint8Array(buffer);
    const capped = u8.byteLength > SVG_MAX_BYTES ? u8.slice(0, SVG_MAX_BYTES) : u8;
    text = new TextDecoder('utf-8').decode(capped);
  } else {
    text = String(buffer || '').slice(0, SVG_MAX_BYTES);
  }
  const hiddenFindings = detectSvgInjection(text);
  return {
    text,
    fileType: 'html',
    hiddenFindings,
  };
}
