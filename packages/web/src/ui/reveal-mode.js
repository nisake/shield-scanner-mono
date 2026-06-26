// S16 Reveal Mode helpers - extracted from index.html L4188-L4319
// Web-only: HTML rendering of invisible-char markers (escape+span output)
import { escapeForDisplay } from '@shield-scanner/core';

// --- S16 Reveal Mode helpers ---
// Maps invisible / control / VS / bidi / tag / PUA codepoints to short
// human-readable marker labels. Returns null for visible characters so the
// caller can render them normally (escaped). R12: marker labels are
// detector-controlled, never raw user input.
function _invisibleMarkerLabel(cp) {
  // Zero-width and joiners
  if (cp === 0x200B) return 'ZWSP';
  if (cp === 0x200C) return 'ZWNJ';
  if (cp === 0x200D) return 'ZWJ';
  if (cp === 0x2060) return 'WJ';
  if (cp === 0xFEFF) return 'BOM';
  if (cp === 0x00AD) return 'SHY';
  if (cp === 0x180E) return 'MVS';
  if (cp === 0x3164 || cp === 0x115F || cp === 0x1160) return 'HFILL';
  // Bidi
  if (cp === 0x200E) return 'LRM';
  if (cp === 0x200F) return 'RLM';
  if (cp === 0x202A) return 'LRE';
  if (cp === 0x202B) return 'RLE';
  if (cp === 0x202C) return 'PDF-bidi';
  if (cp === 0x202D) return 'LRO';
  if (cp === 0x202E) return 'RLO';
  if (cp === 0x2066) return 'LRI';
  if (cp === 0x2067) return 'RLI';
  if (cp === 0x2068) return 'FSI';
  if (cp === 0x2069) return 'PDI';
  // Tags block
  if (cp >= 0xE0000 && cp <= 0xE007F) {
    // E0020..E007E = tag-ASCII for the printable range; show readable form
    if (cp >= 0xE0020 && cp <= 0xE007E) {
      return 'TAG-' + String.fromCharCode(cp - 0xE0000);
    }
    return 'TAG-U+' + cp.toString(16).toUpperCase();
  }
  // Variation selectors
  if (cp >= 0xFE00 && cp <= 0xFE0F) return 'VS-' + (cp - 0xFE00 + 1);
  if (cp >= 0xE0100 && cp <= 0xE01EF) return 'VS-' + (cp - 0xE0100 + 17);
  // C0 control (keep TAB/LF/CR visible as whitespace)
  if (cp < 0x20 && cp !== 0x09 && cp !== 0x0A && cp !== 0x0D) {
    const namedC0 = { 0x07: 'BEL', 0x08: 'BS', 0x0B: 'VT', 0x0C: 'FF', 0x1B: 'ESC' };
    return namedC0[cp] || ('C0-' + cp.toString(16).toUpperCase().padStart(2, '0'));
  }
  if (cp === 0x7F) return 'DEL';
  // C1 control
  if (cp >= 0x80 && cp <= 0x9F) {
    return 'C1-' + cp.toString(16).toUpperCase().padStart(2, '0');
  }
  // PUA
  if (cp >= 0xE000 && cp <= 0xF8FF) return 'PUA-' + cp.toString(16).toUpperCase();
  if (cp >= 0xF0000 && cp <= 0xFFFFD) return 'PUA-' + cp.toString(16).toUpperCase();
  if (cp >= 0x100000 && cp <= 0x10FFFD) return 'PUA-' + cp.toString(16).toUpperCase();
  // Combining diacritical marks (common range only; Zalgo stacks)
  if (cp >= 0x0300 && cp <= 0x036F) return 'COMB-' + cp.toString(16).toUpperCase();
  return null;
}

// Renders a string with invisible chars replaced by marker spans. All
// visible chars are HTML-escaped. R12: returned HTML contains only
// detector-controlled labels and escaped user bytes — never raw HTML.
//
// S16-002 fix: input may already contain HTML entities (e.g. when called on
// the output of getContext() which pre-escapes). Detect &amp; / &lt; / &gt;
// / &quot; / &#39; / &#NN; / &#xHH; sequences and pass them through verbatim
// rather than re-escaping the leading `&` into `&amp;` (which would render
// `&lt;script&gt;` as the literal text "&lt;script&gt;").
//
// S16-003 fix: a single base char + N combining marks (Zalgo text) was
// emitting N separate ⟦COMB-XXX⟧ spans, burying the base character. Collapse
// runs of consecutive U+0300-036F combining marks into one ⟦COMB×N⟧ span.
const _ENTITY_RE = /^&(?:amp|lt|gt|quot|#39|#\d+|#x[0-9a-fA-F]+);/;
function _renderRevealMarkers(s) {
  if (s == null) return '';
  const str = String(s);
  let out = '';
  let i = 0;
  while (i < str.length) {
    // Pass-through pre-escaped HTML entities (S16-002).
    if (str.charCodeAt(i) === 0x26 /* '&' */) {
      const tail = str.slice(i, i + 12);
      const m = tail.match(_ENTITY_RE);
      if (m) {
        out += m[0];
        i += m[0].length;
        continue;
      }
    }
    // Decode codepoint (handle surrogate pair).
    const cp = str.codePointAt(i);
    const ch = String.fromCodePoint(cp);
    // S16-003: collapse runs of combining marks U+0300-036F into one span.
    if (cp >= 0x0300 && cp <= 0x036F) {
      let runLen = 0;
      let j = i;
      while (j < str.length) {
        const cp2 = str.codePointAt(j);
        if (cp2 >= 0x0300 && cp2 <= 0x036F) {
          runLen++;
          j += String.fromCodePoint(cp2).length;
        } else {
          break;
        }
      }
      const label = runLen === 1
        ? ('COMB-' + cp.toString(16).toUpperCase())
        : ('COMB×' + runLen);
      out += `<span class="reveal-marker" title="U+0300-036F combining run length ${runLen}">⟦${label}⟧</span>`;
      i = j;
      continue;
    }
    const label = _invisibleMarkerLabel(cp);
    if (label !== null) {
      out += `<span class="reveal-marker" title="U+${cp.toString(16).toUpperCase()}">⟦${label}⟧</span>`;
    } else {
      out += escapeForDisplay(ch);
    }
    i += ch.length;
  }
  return out;
}

// Value-cell renderer used by displayResults. When reveal mode is off,
// returns the string verbatim (preserves legacy behavior — some category
// renderers historically inserted pre-built HTML here). When reveal mode
// is on, returns escape+marker HTML so invisible chars become visible.
function _renderValueCell(s) {
  if (!_revealMode) return s == null ? '' : String(s);
  return _renderRevealMarkers(s);
}

let _revealMode = false;
let _diffViewVisible = false;

function _setRevealMode(v) { _revealMode = !!v; }
function _getRevealMode() { return _revealMode; }
function _setDiffViewVisible(v) { _diffViewVisible = !!v; }
function _getDiffViewVisible() { return _diffViewVisible; }
export { _invisibleMarkerLabel, _renderRevealMarkers, _renderValueCell,
  _setRevealMode, _getRevealMode, _setDiffViewVisible, _getDiffViewVisible };
