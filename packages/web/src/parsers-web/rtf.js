// v1.19.0 B2 — RTF parser (Web mirror of packages/mcp/server/parsers/rtf.js).
//
// Byte-identical (extraFindings -> hiddenFindings) parity contract: same
// kebab ids, same severity, same category, same meta keys, same threshold
// constants. R22 narrow-fingerprint parity holds because RTF_FIXTURES use the
// normalized (category, severity, technique) triple compare.
//
// R12: no raw RTF text re-surfaced. Detector-controlled meta only.
// R13: every finding folds into 'suspiciousPatterns'.
// R14: no new dependency — same hand-rolled lexer as MCP.

import { escapeForDisplay } from '@shield-scanner/core';

const RTF_MAX_BYTES = 10 * 1024 * 1024;
const META_STR_CAP = 200;
const MIN_BINARY_BLOCK_BYTES = 8;
const MICROSCOPIC_HALF_POINTS = 8;
const PER_KEBAB_CAP = 50;

const KNOWN_DESTINATIONS = new Set([
  'fonttbl', 'colortbl', 'stylesheet', 'info', 'title', 'author', 'operator',
  'company', 'category', 'keywords', 'subject', 'comment', 'doccomm',
  'generator', 'creatim', 'revtim', 'version', 'vern', 'edmins', 'nofpages',
  'nofwords', 'nofchars', 'nofcharsws', 'id', 'rsidtbl', 'rsidroot',
  'themedata', 'colorschememapping', 'latentstyles', 'lsdlockedexcept',
  'datastore', 'userprops', 'propname', 'staticval', 'listtable',
  'listoverridetable', 'list', 'listlevel', 'listoverride', 'listname',
  'listrestarthdn', 'listtemplateid', 'listsimple', 'listhybrid', 'leveltext',
  'levelnumbers', 'fldinst', 'fldrslt', 'shppict', 'nonshppict',
  'panose', 'falt', 'shp', 'shpinst', 'shptxt', 'shppict', 'headerl',
  'headerr', 'headerf', 'footerl', 'footerr', 'footerf', 'header', 'footer',
  'headery', 'footery', 'pict', 'pntext', 'pntxta', 'pntxtb',
  'atnauthor', 'atndate', 'atnid', 'atnref', 'atrfstart', 'atrfend',
  'annotation',
]);

function _normDest(s) {
  return String(s || '').toLowerCase();
}

function _cap(s) {
  if (typeof s !== 'string') return null;
  const slice = s.length > META_STR_CAP ? s.slice(0, META_STR_CAP) : s;
  return escapeForDisplay(slice);
}

function _sanitizeFieldUrl(rawUrl) {
  if (typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;
  const stripped = trimmed.replace(/^["']|["']$/g, '');
  try {
    const u = new URL(stripped);
    const safe = `${u.protocol}//${u.host}`;
    return _cap(safe);
  } catch {
    return _cap(stripped);
  }
}

/**
 * Decode a Uint8Array as latin1 to a JS string. Same byte-for-byte trick the
 * MCP side uses — RTF is ASCII at the syntax level so latin1 covers every
 * byte. We never echo decoded text.
 */
function _decodeLatin1(u8) {
  // Avoid String.fromCharCode.apply with very large arrays (call-stack risk).
  let out = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) {
    const slice = u8.subarray(i, Math.min(i + CHUNK, u8.length));
    out += String.fromCharCode.apply(null, slice);
  }
  return out;
}

/**
 * Parse an RTF document from a Buffer / Uint8Array / ArrayBuffer.
 *
 * @param {Buffer|Uint8Array|ArrayBuffer} buffer
 * @returns {Promise<{text:string, fileType:'rtf', hiddenFindings:Array}>}
 */
export async function parseRtf(buffer) {
  let u8;
  if (buffer instanceof Uint8Array) {
    u8 = buffer;
  } else if (buffer instanceof ArrayBuffer) {
    u8 = new Uint8Array(buffer);
  } else if (buffer && typeof buffer.byteLength === 'number' && buffer.buffer) {
    u8 = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  } else {
    u8 = new Uint8Array(buffer);
  }

  const hiddenFindings = [];

  let scanU8 = u8;
  if (u8.byteLength > RTF_MAX_BYTES) {
    scanU8 = u8.subarray(0, RTF_MAX_BYTES);
  }

  const src = _decodeLatin1(scanU8);

  const counts = Object.create(null);
  function bump(kebab) {
    counts[kebab] = (counts[kebab] || 0) + 1;
    return counts[kebab] <= PER_KEBAB_CAP;
  }

  const len = src.length;
  let i = 0;
  let groupDepth = 0;
  const destStack = [];

  let hiddenVisible = false;
  let hiddenCharCount = 0;
  let inObject = false;
  let objClassPending = false;

  while (i < len) {
    const ch = src.charCodeAt(i);

    if (ch === 0x5c /* \ */) {
      let j = i + 1;
      if (j >= len) {
        i = j;
        continue;
      }
      const next = src.charCodeAt(j);
      const isLetter = (next >= 0x41 && next <= 0x5a) || (next >= 0x61 && next <= 0x7a);
      if (!isLetter) {
        if (next === 0x2a /* * */) {
          let k = j + 1;
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
                if (bump('rtf-unknown-destination')) {
                  hiddenFindings.push({
                    element: 'RTF \\* destination',
                    technique: 'rtf-unknown-destination',
                    content: escapeForDisplay(dn.slice(0, META_STR_CAP)),
                    severity: 'warning',
                    category: 'suspiciousPatterns',
                    contextLocation: 'RTF > \\* destination',
                    meta: { destination: _cap(dn) },
                  });
                }
              }
            }
          }
        }
        if (next === 0x27 /* ' */) {
          i = j + 3;
          continue;
        }
        i = j + 1;
        continue;
      }

      let k = j;
      while (k < len) {
        const c = src.charCodeAt(k);
        if (!((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a))) break;
        k++;
      }
      const word = src.slice(j, k);
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

      let cursor = argEnd;
      if (cursor < len && src.charCodeAt(cursor) === 0x20) cursor++;

      const wlc = word.toLowerCase();

      if (wlc === 'bin' && Number.isInteger(argNum) && argNum >= 0) {
        const skipN = argNum;
        if (skipN >= MIN_BINARY_BLOCK_BYTES) {
          if (bump('rtf-binary-block')) {
            hiddenFindings.push({
              element: 'RTF \\bin block',
              technique: 'rtf-binary-block',
              content: escapeForDisplay(String(skipN)),
              severity: 'warning',
              category: 'suspiciousPatterns',
              contextLocation: 'RTF > \\bin',
              meta: { byteCount: skipN },
            });
          }
        }
        cursor += skipN;
        i = cursor;
        continue;
      }

      if (wlc === 'objdata' || wlc === 'objclass') {
        if (wlc === 'objclass') {
          objClassPending = true;
        } else {
          if (bump('rtf-ole-object')) {
            hiddenFindings.push({
              element: 'RTF OLE object',
              technique: 'rtf-ole-object',
              content: escapeForDisplay('objdata'),
              severity: 'danger',
              category: 'suspiciousPatterns',
              contextLocation: 'RTF > OLE object',
              meta: { objclass: null },
            });
          }
        }
        i = cursor;
        continue;
      }

      if (wlc === 'object' || wlc === 'objemb' || wlc === 'objlink' || wlc === 'objautlink' || wlc === 'objupdate') {
        inObject = true;
        i = cursor;
        continue;
      }

      if (wlc === 'v') {
        if (argNum === 0) {
          if (hiddenVisible && hiddenCharCount > 0) {
            if (bump('rtf-hidden-text-v')) {
              hiddenFindings.push({
                element: 'RTF \\v hidden text',
                technique: 'rtf-hidden-text-v',
                content: escapeForDisplay(String(hiddenCharCount)),
                severity: 'warning',
                category: 'suspiciousPatterns',
                contextLocation: 'RTF > \\v',
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

      if (wlc === 'fs' && Number.isInteger(argNum) && argNum > 0 && argNum <= MICROSCOPIC_HALF_POINTS) {
        if (bump('rtf-microscopic-font')) {
          const pt = argNum / 2;
          hiddenFindings.push({
            element: 'RTF \\fs run',
            technique: 'rtf-microscopic-font',
            content: escapeForDisplay(`${pt}pt`),
            severity: 'warning',
            category: 'suspiciousPatterns',
            contextLocation: 'RTF > \\fs',
            meta: { fontSize: pt },
          });
        }
        i = cursor;
        continue;
      }

      if (wlc === 'field') {
        const SCAN = Math.min(len, cursor + 4096);
        const slice = src.slice(cursor, SCAN);
        const m = /HYPERLINK\s+"([^"]+)"/i.exec(slice);
        if (m) {
          const url = _sanitizeFieldUrl(m[1]);
          if (url && bump('rtf-field-hyperlink')) {
            hiddenFindings.push({
              element: 'RTF \\field hyperlink',
              technique: 'rtf-field-hyperlink',
              content: escapeForDisplay(url),
              severity: 'warning',
              category: 'suspiciousPatterns',
              contextLocation: 'RTF > \\field',
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
      if (hiddenVisible && hiddenCharCount > 0) {
        if (bump('rtf-hidden-text-v')) {
          hiddenFindings.push({
            element: 'RTF \\v hidden text',
            technique: 'rtf-hidden-text-v',
            content: escapeForDisplay(String(hiddenCharCount)),
            severity: 'warning',
            category: 'suspiciousPatterns',
            contextLocation: 'RTF > \\v',
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

    if (hiddenVisible && ch !== 0x0a && ch !== 0x0d && ch !== 0x20) {
      hiddenCharCount++;
    }
    if (objClassPending && ch !== 0x0a && ch !== 0x0d) {
      let m = i;
      const buf = [];
      while (m < len && buf.length < META_STR_CAP) {
        const c = src.charCodeAt(m);
        if (c === 0x5c || c === 0x7b || c === 0x7d) break;
        if (c !== 0x20 || buf.length > 0) buf.push(c);
        m++;
      }
      const classname = String.fromCharCode.apply(null, buf).trim();
      if (classname) {
        if (bump('rtf-ole-object')) {
          hiddenFindings.push({
            element: 'RTF OLE object',
            technique: 'rtf-ole-object',
            content: escapeForDisplay(classname.slice(0, META_STR_CAP)),
            severity: 'danger',
            category: 'suspiciousPatterns',
            contextLocation: 'RTF > OLE object',
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

  if (hiddenVisible && hiddenCharCount > 0) {
    if (bump('rtf-hidden-text-v')) {
      hiddenFindings.push({
        element: 'RTF \\v hidden text',
        technique: 'rtf-hidden-text-v',
        content: escapeForDisplay(String(hiddenCharCount)),
        severity: 'warning',
        category: 'suspiciousPatterns',
        contextLocation: 'RTF > \\v',
        meta: { charCount: hiddenCharCount },
      });
    }
  }

  return {
    text: '',
    fileType: 'rtf',
    hiddenFindings,
  };
}
