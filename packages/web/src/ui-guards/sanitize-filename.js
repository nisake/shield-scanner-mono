// R16: filename display sanitization - extracted from index.html L1150-L1189

// Helper — strip / replace invisible & dangerous codepoints in filenames
// before they hit the DOM. escapeForDisplay neutralises &/</> but not Bidi
// or Tag-block characters that visually reverse or hide filename segments.
// Returns a string safe to pass to escapeForDisplay (still need that for HTML).
function _sanitizeFilenameForDisplay(name) {
  if (name == null) return '';
  let out = '';
  for (const ch of String(name)) {
    const cp = ch.codePointAt(0);
    // Strip bidi controls, zero-width family, tag block, variation
    // selectors, BOM, soft hyphen, Hangul fillers — all categories that
    // can spoof or hide filename segments.
    if (
      (cp >= 0x2000 && cp <= 0x200F) ||  // EN/EM-spaces + ZW family + LRM/RLM
      (cp >= 0x202A && cp <= 0x202E) ||  // bidi embed/override
      cp === 0x2028 || cp === 0x2029 ||  // S21FIX-001: line / paragraph separators
      (cp >= 0x2066 && cp <= 0x2069) ||  // bidi isolate
      (cp >= 0x206A && cp <= 0x206F) ||  // deprecated formatting
      cp === 0x00A0 ||                   // S21FIX-001: NBSP
      cp === 0x00AD ||                   // soft hyphen
      cp === 0x1680 ||                   // S21FIX-001: Ogham space mark
      cp === 0x202F || cp === 0x205F ||  // S21FIX-001: narrow NBSP / medium math space
      cp === 0x3000 ||                   // S21FIX-001: ideographic space
      cp === 0xFEFF ||                   // BOM / ZWNBSP
      cp === 0x180E ||                   // MVS
      cp === 0x3164 || cp === 0x115F || cp === 0x1160 ||
      (cp >= 0xE0000 && cp <= 0xE007F) ||  // tag block
      (cp >= 0xFE00 && cp <= 0xFE0F) ||    // VS-1..16
      (cp >= 0xE0100 && cp <= 0xE01EF) ||  // VS-17..256
      (cp < 0x20 && cp !== 0x09 && cp !== 0x0A && cp !== 0x0D) || // C0
      cp === 0x7F ||                       // DEL
      (cp >= 0x80 && cp <= 0x9F)           // C1
    ) {
      out += '◌';  // dotted-circle stand-in keeps the position visible
      continue;
    }
    out += ch;
  }
  return out;
}

export { _sanitizeFilenameForDisplay };
