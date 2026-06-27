/**
 * v1.19.0 B2 — RTF parser.
 *
 * Detects RTF (Rich Text Format) control-word / object injection vectors that
 * have been used in CVE-2023-21716 (RTF font-table heap overflow) and the
 * Equation Editor macro-execution chain. Prior to this parser, EML attachments
 * and ZIP entries with `.rtf` extension fell through the unknown-extension
 * silent-skip path, so renaming a malicious `.docx` to `.rtf` bypassed the
 * scanner end-to-end.
 *
 * Scope (all 6 fold to suspiciousPatterns — R13 5-key invariant intact):
 *   - rtf-ole-object         (\objdata / \objclass — embedded OLE object,
 *                              danger; meta.objclass)
 *   - rtf-field-hyperlink    (\field { HYPERLINK ... } — sanitized URL,
 *                              warning; meta.url)
 *   - rtf-hidden-text-v      (\v hidden-text flag with non-trivial body,
 *                              warning; meta.charCount)
 *   - rtf-microscopic-font   (\fsN with N <= 8 i.e. <= 4pt, warning;
 *                              meta.fontSize is the decoded pt value)
 *   - rtf-binary-block       (\binN raw binary blob > MIN_BIN bytes,
 *                              warning; meta.byteCount)
 *   - rtf-unknown-destination (\*\unknownword destination — RTF reader is
 *                              required to skip but exploitable for
 *                              parser-differential smuggling, warning;
 *                              meta.destination)
 *
 * Guardrails:
 *   - R12: no raw RTF body text re-surfaced. content + meta carry only
 *          detector-controlled strings (control word name, decoded font size,
 *          byte count, sanitized URL). meta values are passed through
 *          escapeForDisplay and length-capped.
 *   - R13: every finding carries `category: 'suspiciousPatterns'`.
 *   - R14: no new external dependency — hand-rolled lexer (≈100 LOC).
 *   - Defensive cap: RTF_MAX_BYTES = 10 MB (matches CSV / XLSX caps).
 *   - Defensive cap: control-word emit cap = 50 per kebab id, then quiet.
 */

import { readFile } from "node:fs/promises";
import { escapeForDisplay } from "@shield-scanner/core";

const RTF_MAX_BYTES = 10 * 1024 * 1024;
const META_STR_CAP = 200;
// Don't fire rtf-binary-block on tiny (< 8 byte) \bin runs — those are
// frequently legitimate encoded font-name escapes in the document header.
const MIN_BINARY_BLOCK_BYTES = 8;
// Microscopic font threshold: \fsN encodes N half-points, so 8 == 4pt.
const MICROSCOPIC_HALF_POINTS = 8;
// Per-kebab finding cap (R12 noise control).
const PER_KEBAB_CAP = 50;

// RTF reader is required to skip an unknown destination introduced by `\*`.
// We allow-list a small set of common-and-benign destinations so the noisy
// long-tail of real-world RTFs stays quiet.
const KNOWN_DESTINATIONS = new Set([
  "fonttbl", "colortbl", "stylesheet", "info", "title", "author", "operator",
  "company", "category", "keywords", "subject", "comment", "doccomm",
  "generator", "creatim", "revtim", "version", "vern", "edmins", "nofpages",
  "nofwords", "nofchars", "nofcharsws", "id", "rsidtbl", "rsidroot",
  "themedata", "colorschememapping", "latentstyles", "lsdlockedexcept",
  "datastore", "userprops", "propname", "staticval", "listtable",
  "listoverridetable", "list", "listlevel", "listoverride", "listname",
  "listrestarthdn", "listtemplateid", "listsimple", "listhybrid", "leveltext",
  "levelnumbers", "fldinst", "fldrslt", "shppict", "nonshppict",
  "panose", "falt", "shp", "shpinst", "shptxt", "shppict", "headerl",
  "headerr", "headerf", "footerl", "footerr", "footerf", "header", "footer",
  "headery", "footery", "pict", "pntext", "pntxta", "pntxtb",
  "atnauthor", "atndate", "atnid", "atnref", "atrfstart", "atrfend",
  "annotation",
]);

// Unicode normalization for control-word destination matching. RTF control
// words are case-sensitive ASCII per spec, so a plain lowercase compare is
// enough.
function _normDest(s) {
  return String(s || "").toLowerCase();
}

function _cap(s) {
  if (typeof s !== "string") return null;
  const slice = s.length > META_STR_CAP ? s.slice(0, META_STR_CAP) : s;
  return escapeForDisplay(slice);
}

/**
 * Sanitize a URL discovered in `\field { HYPERLINK "..." }`. We only echo the
 * scheme + host (no path/query) to avoid surfacing user-controlled credential
 * material via the report. R12: detector-controlled meta only.
 */
function _sanitizeFieldUrl(rawUrl) {
  if (typeof rawUrl !== "string") return null;
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;
  // Strip surrounding quotes.
  const stripped = trimmed.replace(/^["']|["']$/g, "");
  try {
    const u = new URL(stripped);
    const safe = `${u.protocol}//${u.host}`;
    return _cap(safe);
  } catch {
    // Not a parseable URL — fall back to a length-capped opaque echo so the
    // analyst still sees the channel existed. escapeForDisplay scrubs control
    // bytes.
    return _cap(stripped);
  }
}

export async function parseRtf(filePath) {
  const buffer = await readFile(filePath);
  return parseRtfBuffer(buffer);
}

/**
 * Parse an RTF document from a Buffer / Uint8Array.
 *
 * @param {Buffer|Uint8Array} buffer
 * @returns {Promise<{text:string, fileType:'rtf', extraFindings:Array}>}
 */
export async function parseRtfBuffer(buffer) {
  const extraFindings = [];

  // Coerce to Uint8Array.
  const u8 =
    buffer instanceof Uint8Array
      ? buffer
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  // Defensive cap.
  let scanU8 = u8;
  if (u8.byteLength > RTF_MAX_BYTES) {
    scanU8 = u8.subarray(0, RTF_MAX_BYTES);
  }

  // RTF is ASCII-only at the document-syntax level (Unicode is escaped via
  // `\uN?`), so latin1 decoding is safe for lexing. We never echo decoded
  // user text — only control-word names and detector-controlled meta.
  const src = Buffer.from(scanU8).toString("latin1");

  const counts = Object.create(null);
  function bump(kebab) {
    counts[kebab] = (counts[kebab] || 0) + 1;
    return counts[kebab] <= PER_KEBAB_CAP;
  }

  // ---------- Lexer: track group depth + control-word stream ----------
  // We make ONE linear pass and dispatch on each control word. The lexer
  // recognizes:
  //   `\` followed by a..z letters    -> control word (optional digits arg)
  //   `\` followed by a non-letter    -> control symbol (e.g. `\*`, `\\`, `\{`)
  //   `{` `}`                          -> group push/pop
  //   `;`                              -> destination terminator (info groups)
  //   anything else                    -> literal text
  //
  // We do NOT decode `\uN?` Unicode escapes — we never surface decoded text.
  const len = src.length;
  let i = 0;
  let groupDepth = 0;
  // Stack to track the current destination name for `\*` lookups.
  const destStack = [];

  // For text-body detection (rtf-hidden-text-v): once we see `\v` (and not
  // `\v0`), buffer characters until we see a control word that resets the
  // hidden flag or a group close. We only count bytes — the body itself is
  // never echoed.
  let hiddenVisible = false;
  let hiddenCharCount = 0;
  // For field-hyperlink: \field { \*\fldinst { HYPERLINK "..." } { \*\fldrslt
  // ... } } — we scan for the literal `HYPERLINK "URL"` pattern inside the
  // current group after seeing `\field`. Simpler than trying to fully parse
  // the field nesting.
  // For OLE object: \object \objemb (or \objlink / \objautlink) — we look for
  // \objclass {classname} to extract the meta. \objdata is a binary blob — we
  // don't echo any of it.
  let inObject = false;
  let objClassPending = false;

  while (i < len) {
    const ch = src.charCodeAt(i);

    if (ch === 0x5c /* \ */) {
      // Lookahead for control word or control symbol.
      let j = i + 1;
      if (j >= len) {
        i = j;
        continue;
      }
      const next = src.charCodeAt(j);
      // Control symbol: `\*`, `\\`, `\{`, `\}`, `\~`, `\-`, `\_`, `\:`,
      // `\'XX` (hex), `\<newline>` etc.
      const isLetter = (next >= 0x41 && next <= 0x5a) || (next >= 0x61 && next <= 0x7a);
      if (!isLetter) {
        // `\*` = next control word is an unknown-destination marker. We
        // record the position and let the following control word check it.
        if (next === 0x2a /* * */) {
          // Peek ahead past optional space for the destination control word.
          let k = j + 1;
          // Allow space separator after `\*`.
          while (k < len && (src.charCodeAt(k) === 0x20)) k++;
          if (k < len && src.charCodeAt(k) === 0x5c) {
            let m = k + 1;
            const start = m;
            while (m < len) {
              const c = src.charCodeAt(m);
              if (!((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a))) break;
              m++;
            }
            const destName = src.slice(start, m);
            if (destName) {
              const dn = _normDest(destName);
              if (!KNOWN_DESTINATIONS.has(dn)) {
                if (bump("rtf-unknown-destination")) {
                  extraFindings.push({
                    element: "RTF \\* destination",
                    technique: "rtf-unknown-destination",
                    content: escapeForDisplay(dn.slice(0, META_STR_CAP)),
                    severity: "warning",
                    category: "suspiciousPatterns",
                    contextLocation: "RTF > \\* destination",
                    meta: { destination: _cap(dn) },
                  });
                }
              }
            }
          }
        }
        // `\'XX` = hex escape — skip the two hex digits to avoid mis-counting.
        if (next === 0x27 /* ' */) {
          i = j + 3;
          continue;
        }
        // Generic single-char control symbol — advance past it.
        i = j + 1;
        continue;
      }

      // Control word: collect letters then optional numeric argument.
      let k = j;
      while (k < len) {
        const c = src.charCodeAt(k);
        if (!((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a))) break;
        k++;
      }
      const word = src.slice(j, k);
      // Optional numeric argument (signed integer).
      let argStart = k;
      let argEnd = argStart;
      if (argEnd < len && (src.charCodeAt(argEnd) === 0x2d /* - */ || (src.charCodeAt(argEnd) >= 0x30 && src.charCodeAt(argEnd) <= 0x39))) {
        argEnd++;
        while (argEnd < len) {
          const c = src.charCodeAt(argEnd);
          if (!(c >= 0x30 && c <= 0x39)) break;
          argEnd++;
        }
      }
      const argStr = argEnd > argStart ? src.slice(argStart, argEnd) : null;
      const argNum = argStr === null ? null : parseInt(argStr, 10);

      // Delimiter: a single space terminates the control word but is consumed.
      let cursor = argEnd;
      if (cursor < len && src.charCodeAt(cursor) === 0x20) cursor++;

      // ---- Dispatch on control word ----
      const wlc = word.toLowerCase();

      if (wlc === "bin" && Number.isInteger(argNum) && argNum >= 0) {
        // \binN — N raw bytes follow the delimiter. Skip them.
        const skipN = argNum;
        if (skipN >= MIN_BINARY_BLOCK_BYTES) {
          if (bump("rtf-binary-block")) {
            extraFindings.push({
              element: "RTF \\bin block",
              technique: "rtf-binary-block",
              content: escapeForDisplay(String(skipN)),
              severity: "warning",
              category: "suspiciousPatterns",
              contextLocation: "RTF > \\bin",
              meta: { byteCount: skipN },
            });
          }
        }
        cursor += skipN;
        i = cursor;
        continue;
      }

      if (wlc === "objdata" || wlc === "objclass") {
        // \objdata is the embedded OLE binary blob. \objclass {Word.Document.8}
        // names the OLE class. Either alone is sufficient to flag the OLE
        // object surface.
        if (wlc === "objclass") {
          objClassPending = true;
        } else {
          if (bump("rtf-ole-object")) {
            extraFindings.push({
              element: "RTF OLE object",
              technique: "rtf-ole-object",
              content: escapeForDisplay("objdata"),
              severity: "danger",
              category: "suspiciousPatterns",
              contextLocation: "RTF > OLE object",
              meta: { objclass: null },
            });
          }
        }
        i = cursor;
        continue;
      }

      if (wlc === "object" || wlc === "objemb" || wlc === "objlink" || wlc === "objautlink" || wlc === "objupdate") {
        inObject = true;
        i = cursor;
        continue;
      }

      // \v / \v0 toggles hidden-text destination. RTF spec: `\v0` (or end of
      // group) disables. Any non-empty body while hiddenVisible=true counts.
      if (wlc === "v") {
        if (argNum === 0) {
          if (hiddenVisible && hiddenCharCount > 0) {
            if (bump("rtf-hidden-text-v")) {
              extraFindings.push({
                element: "RTF \\v hidden text",
                technique: "rtf-hidden-text-v",
                content: escapeForDisplay(String(hiddenCharCount)),
                severity: "warning",
                category: "suspiciousPatterns",
                contextLocation: "RTF > \\v",
                meta: { charCount: hiddenCharCount },
              });
            }
          }
          hiddenVisible = false;
          hiddenCharCount = 0;
        } else {
          hiddenVisible = true;
          hiddenCharCount = 0;
        }
        i = cursor;
        continue;
      }

      // Microscopic font: \fsN where N is in half-points and <= 8 (i.e. <=4pt).
      if (wlc === "fs" && Number.isInteger(argNum) && argNum > 0 && argNum <= MICROSCOPIC_HALF_POINTS) {
        if (bump("rtf-microscopic-font")) {
          const pt = argNum / 2;
          extraFindings.push({
            element: "RTF \\fs run",
            technique: "rtf-microscopic-font",
            content: escapeForDisplay(`${pt}pt`),
            severity: "warning",
            category: "suspiciousPatterns",
            contextLocation: "RTF > \\fs",
            meta: { fontSize: pt },
          });
        }
        i = cursor;
        continue;
      }

      // \field { \*\fldinst { HYPERLINK "URL" } ... } — once we see the
      // `\field` start we look ahead for HYPERLINK token inside the same
      // group bound (cheap scan up to 4 KB).
      if (wlc === "field") {
        const SCAN = Math.min(len, cursor + 4096);
        const slice = src.slice(cursor, SCAN);
        const m = /HYPERLINK\s+"([^"]+)"/i.exec(slice);
        if (m) {
          const url = _sanitizeFieldUrl(m[1]);
          if (url && bump("rtf-field-hyperlink")) {
            extraFindings.push({
              element: "RTF \\field hyperlink",
              technique: "rtf-field-hyperlink",
              content: escapeForDisplay(url),
              severity: "warning",
              category: "suspiciousPatterns",
              contextLocation: "RTF > \\field",
              meta: { url },
            });
          }
        }
        i = cursor;
        continue;
      }

      i = cursor;
      continue;
    }

    if (ch === 0x7b /* { */) {
      groupDepth++;
      destStack.push(null);
      i++;
      continue;
    }
    if (ch === 0x7d /* } */) {
      if (groupDepth > 0) groupDepth--;
      destStack.pop();
      // Closing the group cancels the hidden-text scope.
      if (hiddenVisible && hiddenCharCount > 0) {
        if (bump("rtf-hidden-text-v")) {
          extraFindings.push({
            element: "RTF \\v hidden text",
            technique: "rtf-hidden-text-v",
            content: escapeForDisplay(String(hiddenCharCount)),
            severity: "warning",
            category: "suspiciousPatterns",
            contextLocation: "RTF > \\v",
            meta: { charCount: hiddenCharCount },
          });
        }
        hiddenVisible = false;
        hiddenCharCount = 0;
      }
      if (inObject) inObject = false;
      i++;
      continue;
    }

    // Literal text byte. If hidden destination is active, count it.
    if (hiddenVisible && ch !== 0x0a && ch !== 0x0d && ch !== 0x20) {
      hiddenCharCount++;
    }
    if (objClassPending && ch !== 0x0a && ch !== 0x0d) {
      // Capture up to META_STR_CAP bytes of the next literal run.
      let m = i;
      const buf = [];
      while (m < len && buf.length < META_STR_CAP) {
        const c = src.charCodeAt(m);
        if (c === 0x5c || c === 0x7b || c === 0x7d) break;
        if (c !== 0x20 || buf.length > 0) buf.push(c);
        m++;
      }
      const classname = String.fromCharCode(...buf).trim();
      if (classname) {
        if (bump("rtf-ole-object")) {
          extraFindings.push({
            element: "RTF OLE object",
            technique: "rtf-ole-object",
            content: escapeForDisplay(classname.slice(0, META_STR_CAP)),
            severity: "danger",
            category: "suspiciousPatterns",
            contextLocation: "RTF > OLE object",
            meta: { objclass: _cap(classname) },
          });
        }
        objClassPending = false;
        i = m;
        continue;
      }
      objClassPending = false;
    }
    i++;
  }

  // Closing the document cancels a still-open hidden-text scope.
  if (hiddenVisible && hiddenCharCount > 0) {
    if (bump("rtf-hidden-text-v")) {
      extraFindings.push({
        element: "RTF \\v hidden text",
        technique: "rtf-hidden-text-v",
        content: escapeForDisplay(String(hiddenCharCount)),
        severity: "warning",
        category: "suspiciousPatterns",
        contextLocation: "RTF > \\v",
        meta: { charCount: hiddenCharCount },
      });
    }
  }

  // Body text channel: RTF body is bound to the analyze() pipeline only as a
  // scaffolding placeholder — we never echo decoded RTF user text, so the
  // text channel is empty. The detector still runs on the empty string with
  // fileType='rtf' (no-op).
  return {
    text: "",
    fileType: "rtf",
    extraFindings,
  };
}
