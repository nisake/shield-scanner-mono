/**
 * Context-location sanitizer.
 *
 * Many parsers (PDF / EML attachments) thread the raw filename through into
 * `extraFinding.contextLocation` as `Attachment <filename>`. Raw filenames
 * can carry:
 *   - newlines / tab / carriage return (line-injection into UI rendering)
 *   - ANSI escape sequences (CSI / OSC) that re-color terminal output and
 *     bidi-spoof tail / less
 *   - zero-width joiner / non-joiner / formatter codepoints that hide content
 *   - bidi override controls (LRO / RLO / FSI / PDI / LRI / RLI / PDF / LRM /
 *     RLM / ALM) that perform extension-spoofing
 *
 * Guardrail R12 (no raw-text echo): contextLocation is rendered in scan
 * output and bulk-UI tooltips. We strip the high-risk codepoints to a single
 * `?` placeholder so the field stays human-readable but cannot be used as a
 * secondary injection oracle.
 *
 * Hard length cap: 200 chars (matches the existing per-finding content cap).
 *
 * Pure function — no I/O, no dependency on env.
 */

// Bidi overrides + isolate controls + LRM/RLM/ALM.
//   U+202A LRE, U+202B RLE, U+202C PDF, U+202D LRO, U+202E RLO
//   U+2066 LRI, U+2067 RLI, U+2068 FSI, U+2069 PDI
//   U+200E LRM, U+200F RLM, U+061C ALM
const BIDI_CONTROLS_RE = /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/g;

// Zero-width / formatter codepoints:
//   U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM, U+2060 WJ
//   U+180E MONGOLIAN VOWEL SEPARATOR
const ZERO_WIDTH_RE = /[\u200b-\u200d\ufeff\u2060\u180e]/g;

// ANSI / CSI / OSC escape sequences. ESC (U+001B) plus payload:
//   CSI:  ESC [ params? intermediates? final     final in [@-~] (0x40-0x7E)
//   OSC:  ESC ] body  ST (ESC \) | BEL (U+0007)
//   Misc: 2-byte ESC <single 0x40-0x5F> (C1 introducer)
// Lone ESC: also stripped so a malformed prefix can't leak. Anchored on the
// ESC byte so we never eat plain `[` or `]` in legitimate filenames.
const ANSI_ESC_RE = /\u001b\[[0-?]*[ -\/]*[@-~]|\u001b\][\s\S]*?(?:\u0007|\u001b\\)|\u001b[@-_]|\u001b/g;

// C0 controls (0x00-0x1F) minus ESC (0x1B) + DEL (0x7F) + C1 line terminators:
//   U+0085 NEL, U+2028 LSEP, U+2029 PSEP
const WHITESPACE_CONTROL_RE = /[\u0000-\u001a\u001c-\u001f\u007f\u0085\u2028\u2029]/g;

/**
 * Make a string safe to use as a finding's contextLocation.
 *
 * @param {unknown} s
 * @returns {string}
 */
export function sanitizeContextLocation(s) {
  if (s == null) return "";
  let out = String(s);
  // ANSI first — it embeds bracket+letter sequences that would otherwise be
  // partially leaked once we strip individual whitespace bytes.
  out = out.replace(ANSI_ESC_RE, "?");
  out = out.replace(WHITESPACE_CONTROL_RE, "?");
  out = out.replace(BIDI_CONTROLS_RE, "?");
  out = out.replace(ZERO_WIDTH_RE, "?");
  // Hard cap: keep contextLocation rendering bounded.
  if (out.length > 200) out = out.slice(0, 200);
  return out;
}

export default sanitizeContextLocation;
