// HTML parser (Web mirror) — v1.19.0 B1.
// Mirror of packages/mcp/server/parsers/html.js. Exists primarily for the
// parsers-web/index.js dispatch helper and the SVG-polyglot parity test —
// app.js still routes .html/.htm/.xml/.svg through the text-mode readAsText
// path into analyze({fileType:'html'}), so the central detector remains the
// production code path for those extensions in the browser bundle.
//
// v1.19.0 B1: shares detectSvgInjection with svg.js so inline <svg>...</svg>
// blocks pasted into an HTML wrapper get the same 6 Polyglot-SVG checks.

import { detectSvgInjection } from './svg.js';

export async function parseHtml(buffer) {
  let text;
  if (typeof buffer === 'string') {
    text = buffer;
  } else if (buffer && typeof buffer.byteLength === 'number') {
    const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    text = new TextDecoder('utf-8').decode(u8);
  } else {
    text = String(buffer || '');
  }
  return {
    text,
    fileType: 'html',
    hiddenFindings: detectSvgInjection(text),
  };
}
