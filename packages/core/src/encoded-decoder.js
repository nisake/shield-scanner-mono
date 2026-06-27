/**
 * v1.19.0 D1 — Encoded payload decode pipeline.
 *
 * Attack model: instruction-shaped payloads ("Ignore previous instructions",
 * jailbreak phrases, etc.) hidden behind a transport-level encoding so they
 * sneak past the literal suspicious-patterns regex sweep. Browsers and LLMs
 * frequently decode these implicitly (HTML entity expansion, copy-paste from
 * the address bar, IDNA / xn-- host display), so we need to decode them too
 * — but ONLY for *detection*. The decoded byte sequence MUST NOT leak back
 * into the response body (R12: Shield Scanner is not a decoding oracle).
 *
 * Encodings handled:
 *   - Base64       : [A-Za-z0-9+/]{20,}={0,2} runs whose decoded byte
 *                    sequence is printable text.
 *   - Hex          : [0-9a-fA-F]{40,} runs whose decoded bytes are
 *                    printable text.
 *   - HTML entity  : `&#xHH;` / `&#NNN;` numeric character references whose
 *                    decoded form reconstructs a suspicious phrase.
 *   - Punycode     : `xn--` ACE-prefixed labels inside http(s):// URLs
 *                    whose Unicode form is single-script non-Latin or
 *                    Latin/Cyrillic/Greek mixed-script (homograph signal).
 *   - Multi-layer  : Base64 wrapping bytes that, after one decode, *still*
 *                    contain invisible-Unicode obfuscation (ZWSP / Tags
 *                    block) over an instruction phrase — surfaced as a
 *                    separate kebab id so the UI can warn about layered
 *                    obfuscation explicitly.
 *
 * kebab ids (suspiciousPatterns fold — R13 5-bucket invariant preserved):
 *   - encoded-base64-instruction
 *   - encoded-hex-instruction
 *   - encoded-html-entity-instruction
 *   - punycode-host-homograph
 *   - multi-layer-encoded-payload
 *
 * R12 — the absolute rule:
 *   Decoded bytes / decoded strings NEVER appear in the returned finding.
 *   The only meta fields surfaced are:
 *     - decodedFrom    : 'base64' | 'hex' | 'html-entity' | 'punycode'
 *     - encodingClass  : 'instruction' | 'homograph' | 'multi-layer'
 *     - byteRange      : [start, end]  (raw positions in `content`, NOT
 *                                       decoded byte offsets)
 *     - layerCount     : integer (multi-layer only)
 *     - host           : the *raw* xn-- ACE host (punycode only)
 *     - decodedScript  : 'cyrillic' | 'greek' | 'mixed' (punycode only —
 *                        an enum, NOT decoded chars)
 *   No `decodedSample`, no `decodedText`, no `preview`, no `firstChars`.
 *   `matched` is a fixed structural placeholder ('[encoded payload]', etc.).
 *   `context` is sampled from the RAW (encoded) source slice and clamped
 *   to a short window so the encoded blob itself stays in the response
 *   verbatim (the user already typed it — no decoding-oracle service
 *   provided).
 *
 * R13 — findings fold into the existing `suspiciousPatterns` bucket via the
 * detector.js pipeline wire. No new top-level byCategory key is introduced.
 *
 * Pure module — no setEnv / no rule files / no I/O. Safe to import from any
 * env (MCP, Web, parity-check).
 */

import { getContext, escapeForDisplay } from "./utils.js";

// ─── Caps / Tunables ──────────────────────────────────────────────────────
// Tight caps so a hostile gigabyte of base64 doesn't burn the analyze() loop.
// Every cap is enforced on the *raw* candidate length, NOT on decoded size.
//
// Object.freeze prevents downstream mutation — caps are part of the detector
// contract (parity-check / regression tests assert against the kebab-fold
// shape that depends on them).
const CAPS = Object.freeze({
  // Base64 candidate run length: lower bound (12 raw chars decodes to ~9
  // bytes, enough for "ignore" + a wrapper word) and upper bound (cap the
  // longest run we attempt to decode at ~8 KiB so a megabyte blob is skipped).
  base64MinRaw: 20,
  base64MaxRaw: 8192,
  // Hex candidate run length: 40 hex chars = 20 bytes, enough for a phrase.
  hexMinRaw: 40,
  hexMaxRaw: 16384,
  // HTML numeric character reference: scan up to N references per analyze().
  htmlEntityMaxRefs: 4096,
  // Punycode: max number of xn-- host labels surfaced per analyze().
  punycodeMaxHits: 64,
  // Top-level cap on findings emitted by this whole module (defense-in-depth).
  maxFindings: 256,
});

export { CAPS as ENCODED_DECODER_CAPS };

// ─── Detector-controlled placeholders (R12 safe strings) ──────────────────
// Every `matched` / `technique` / `pattern` field is one of these constants
// — none of them embed user text.
const PLACEHOLDER_MATCHED = "[encoded payload]";

const KEBAB = Object.freeze({
  base64: "encoded-base64-instruction",
  hex: "encoded-hex-instruction",
  htmlEntity: "encoded-html-entity-instruction",
  punycodeHomograph: "punycode-host-homograph",
  multiLayer: "multi-layer-encoded-payload",
});

export { KEBAB as ENCODED_KEBAB };

// ─── Suspect-phrase detector for the *decoded* (in-memory) buffer ─────────
// The decoded buffer NEVER leaves this module — these regexes only decide
// whether a candidate's decoded form looks like a prompt-injection phrase.
// We deliberately keep this list short and self-contained (no rules-loader,
// no JSON file) so the detector stays env-free and so the matcher cost is
// bounded regardless of how `suspicious-patterns.json` grows.
//
// All flags include `i` because the decoded byte stream may carry the
// payload in any case (`Ignore`, `IGNORE`, `iGnOrE`).
const DECODED_INSTRUCTION_REGEX = [
  /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instruction|prompt|rule|guideline|directive)/i,
  /forget\s+(?:everything|all|the)\s+(?:above|previous|prior|earlier)/i,
  /disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instruction|prompt|rule)/i,
  /(?:reveal|print|show|dump)\s+(?:the\s+)?(?:system|hidden|secret)\s+prompt/i,
  /jailbreak|do\s+anything\s+now\b|DAN\s+mode|sudo\s+mode/i,
  /\byou\s+are\s+now\s+(?:a|an)\s+/i,
  // System / role hijack tokens commonly seen base64-wrapped in real attacks.
  /<\|im_start\|>|<\|im_end\|>/i,
  /\[INST\]|\[\/INST\]/i,
];

function decodedLooksLikeInstruction(s) {
  if (!s || s.length === 0) return false;
  // Trim a sensible upper window — the decoded string never surfaces, but we
  // still bound regex backtracking.
  const sample = s.length > 4096 ? s.slice(0, 4096) : s;
  for (const re of DECODED_INSTRUCTION_REGEX) {
    if (re.test(sample)) return true;
  }
  return false;
}

// Invisible-Unicode characters that, when present in decoded text WRAPPING an
// instruction phrase, mark this as a multi-layer obfuscation (encoding +
// invisible-Unicode payload). We don't import invisible-unicode.js to keep
// the dependency surface tight — only checking the most common smuggling
// codepoints is enough to flip the layered flag.
const ZW_TAGS_RE = /[​-‏‪-‮⁦-⁩\u{E0000}-\u{E007F}]/u;

// ─── Base64 ───────────────────────────────────────────────────────────────
//
// Run regex: at least CAPS.base64MinRaw bytes of [A-Za-z0-9+/] with optional
// trailing `=` padding. Anchored so we don't keep advancing inside a single
// hit (the `g` flag plus lastIndex advancement handles overlap).
const RE_BASE64_RUN = /[A-Za-z0-9+/]{20,}={0,2}/g;

// Stricter than `m.length % 4 === 0` because decoded text only makes sense
// at the byte level — base64 standard *requires* length % 4 === 0.
function isValidBase64Length(s) {
  return s.length >= CAPS.base64MinRaw && s.length % 4 === 0;
}

// Decode without throwing. Returns the decoded byte STRING (binary latin-1)
// or null on failure. Caller is responsible for printable-text filtering.
function safeBase64Decode(raw) {
  // Use globalThis.atob when present (Web, modern Node). Fall back to
  // Buffer for Node-only paths. Avoid `eval` / `new Function`.
  try {
    if (typeof atob === "function") {
      return atob(raw);
    }
    if (typeof Buffer !== "undefined") {
      return Buffer.from(raw, "base64").toString("binary");
    }
  } catch {
    return null;
  }
  return null;
}

// Reject decoded bytes that look like binary (PNG / ZIP / arbitrary high-bit
// noise). We want printable-ASCII-ish text — if even 25% of the bytes are
// outside the printable + whitespace range, treat as non-text and skip.
//
// Returns a UTF-8-decoded *string view* of the bytes (so the regex matcher
// works on multi-byte sequences) — but ONLY when the byte sequence is
// plausibly text. Returns null otherwise.
function bytesToPlausibleText(binaryStr) {
  if (!binaryStr || binaryStr.length === 0) return null;
  let printable = 0;
  let total = 0;
  for (let i = 0; i < binaryStr.length; i++) {
    const cc = binaryStr.charCodeAt(i);
    total++;
    // Printable ASCII (0x20-0x7E) + common whitespace (\t \n \r) + utf-8
    // continuation/start bytes (>= 0x80) — we count utf-8 high bytes as
    // printable because legitimate multi-byte UTF-8 lives here. The
    // *upper-bound* on noise is therefore < 25% in this counter.
    if (
      cc === 0x09 || cc === 0x0a || cc === 0x0d ||
      (cc >= 0x20 && cc <= 0x7e) ||
      cc >= 0x80
    ) {
      printable++;
    }
  }
  if (printable / total < 0.75) return null;

  // Promote latin-1 byte string to UTF-8 string for regex matching. TextDecoder
  // is available in Node 12+ and all modern browsers; the env-free fallback
  // (Buffer) catches any older Node host.
  try {
    if (typeof TextDecoder !== "undefined") {
      const bytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
      const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      return text;
    }
    if (typeof Buffer !== "undefined") {
      return Buffer.from(binaryStr, "binary").toString("utf-8");
    }
  } catch {
    return null;
  }
  return binaryStr;
}

function* iterateBase64Candidates(content) {
  RE_BASE64_RUN.lastIndex = 0;
  let m;
  while ((m = RE_BASE64_RUN.exec(content)) !== null) {
    if (m.index === RE_BASE64_RUN.lastIndex) RE_BASE64_RUN.lastIndex++;
    const raw = m[0];
    if (!isValidBase64Length(raw)) continue;
    if (raw.length > CAPS.base64MaxRaw) continue;
    yield { raw, start: m.index, end: m.index + raw.length };
  }
}

// ─── Hex ──────────────────────────────────────────────────────────────────
//
// Decode [0-9a-fA-F]+ pairs. Cap at hexMaxRaw raw chars. Even-length only.
const RE_HEX_RUN = /[0-9a-fA-F]{40,}/g;

function decodeHex(raw) {
  if (raw.length % 2 !== 0) return null;
  const bytes = new Uint8Array(raw.length / 2);
  for (let i = 0, j = 0; i < raw.length; i += 2, j++) {
    const hi = parseInt(raw.charAt(i), 16);
    const lo = parseInt(raw.charAt(i + 1), 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) return null;
    bytes[j] = (hi << 4) | lo;
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return binary;
}

function* iterateHexCandidates(content) {
  RE_HEX_RUN.lastIndex = 0;
  let m;
  while ((m = RE_HEX_RUN.exec(content)) !== null) {
    if (m.index === RE_HEX_RUN.lastIndex) RE_HEX_RUN.lastIndex++;
    const raw = m[0];
    if (raw.length > CAPS.hexMaxRaw) continue;
    if (raw.length % 2 !== 0) continue;
    yield { raw, start: m.index, end: m.index + raw.length };
  }
}

// ─── HTML numeric entity ──────────────────────────────────────────────────
//
// We look at every numeric character reference (`&#NN;` decimal, `&#xHH;`
// hex). Decoded chars accumulate into a buffer with their RAW source byte
// ranges so we can emit a single finding spanning the whole obfuscated run
// when it forms an instruction phrase.
//
// Plain text without any numeric reference -> nothing to do.
const RE_HTML_NUMERIC_ENTITY = /&#(?:x([0-9a-fA-F]+)|(\d+));/g;

function decodeHtmlEntities(content) {
  if (!content.includes("&#")) return null;
  let hits = 0;
  let decoded = "";
  // Track [start, end] of contiguous reference runs so we can attribute
  // a finding to its raw span. We extend a run when references are
  // separated only by other references (no plain text in between).
  let firstRefStart = -1;
  let lastRefEnd = -1;
  const runs = [];
  RE_HTML_NUMERIC_ENTITY.lastIndex = 0;
  let m;
  let lastIndex = 0;
  while ((m = RE_HTML_NUMERIC_ENTITY.exec(content)) !== null) {
    hits++;
    if (hits > CAPS.htmlEntityMaxRefs) break;
    if (m.index === RE_HTML_NUMERIC_ENTITY.lastIndex) RE_HTML_NUMERIC_ENTITY.lastIndex++;
    const start = m.index;
    const end = m.index + m[0].length;
    // Append any literal text since the last reference.
    decoded += content.slice(lastIndex, start);

    let cp;
    if (m[1] != null) cp = parseInt(m[1], 16);
    else cp = parseInt(m[2], 10);
    if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) {
      // Invalid — emit the raw token verbatim into the decoded buffer so we
      // don't corrupt positions, but it can't contribute to a match.
      decoded += m[0];
    } else {
      try {
        decoded += String.fromCodePoint(cp);
      } catch {
        decoded += m[0];
      }
    }

    // Accumulate the run span. If this reference touches the previous one
    // (no intervening printable bytes), extend the current run; otherwise
    // open a new run.
    if (firstRefStart < 0) {
      firstRefStart = start;
      lastRefEnd = end;
    } else if (start === lastRefEnd) {
      lastRefEnd = end;
    } else {
      runs.push({ start: firstRefStart, end: lastRefEnd });
      firstRefStart = start;
      lastRefEnd = end;
    }
    lastIndex = end;
  }
  if (lastIndex === 0) return null;
  decoded += content.slice(lastIndex);
  if (firstRefStart >= 0) {
    runs.push({ start: firstRefStart, end: lastRefEnd });
  }
  return { decoded, runs };
}

// ─── Punycode (xn-- host) ─────────────────────────────────────────────────
//
// Minimal RFC 3492 Punycode decoder. We DON'T rely on `URL.hostname` because
// the WHATWG URL parser keeps `xn--` labels in their ACE (ASCII-compatible
// encoding) form — `new URL('http://xn--pypl-53dc.com/').hostname` returns
// the raw ACE string, not the Unicode form. We also don't import
// `node:punycode` because it's Node-only (deprecated) and would break the
// MCP↔Web parity contract. So we ship a ~50-line decoder inline.
//
// This decoder follows the reference implementation in RFC 3492 §6.2
// (pseudocode in the appendix), pared to "decode a single ACE label".
const PUNY_BASE = 36;
const PUNY_TMIN = 1;
const PUNY_TMAX = 26;
const PUNY_SKEW = 38;
const PUNY_DAMP = 700;
const PUNY_INITIAL_BIAS = 72;
const PUNY_INITIAL_N = 128;

function punyAdapt(delta, numpoints, firsttime) {
  delta = firsttime ? Math.floor(delta / PUNY_DAMP) : delta >> 1;
  delta += Math.floor(delta / numpoints);
  let k = 0;
  while (delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) >> 1) {
    delta = Math.floor(delta / (PUNY_BASE - PUNY_TMIN));
    k += PUNY_BASE;
  }
  return k + Math.floor(((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW));
}

function punyBasicCodeForDigit(cp) {
  // 0..25 = 'a'..'z', 26..35 = '0'..'9'
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30 + 26;
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41;
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61;
  return PUNY_BASE; // invalid
}

/**
 * Decode a single ACE label (the part after "xn--"). Returns the Unicode
 * label, or null on failure. Caller is responsible for stripping the "xn--"
 * prefix before calling.
 */
function decodePunycodeLabel(input) {
  if (typeof input !== "string" || input.length === 0) return null;
  let n = PUNY_INITIAL_N;
  let i = 0;
  let bias = PUNY_INITIAL_BIAS;
  // Split out basic codepoints (before the last hyphen, if any).
  const lastDash = input.lastIndexOf("-");
  let basicStr = "";
  let restStart = 0;
  if (lastDash > 0) {
    basicStr = input.slice(0, lastDash);
    restStart = lastDash + 1;
    for (let k = 0; k < basicStr.length; k++) {
      if (basicStr.charCodeAt(k) >= 0x80) return null;
    }
  }
  const out = [];
  for (let k = 0; k < basicStr.length; k++) out.push(basicStr.charCodeAt(k));
  let inIdx = restStart;
  while (inIdx < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = PUNY_BASE; ; k += PUNY_BASE) {
      if (inIdx >= input.length) return null;
      const digit = punyBasicCodeForDigit(input.charCodeAt(inIdx++));
      if (digit >= PUNY_BASE) return null;
      if (digit > Math.floor((0x7fffffff - i) / w)) return null;
      i += digit * w;
      let t;
      if (k <= bias) t = PUNY_TMIN;
      else if (k >= bias + PUNY_TMAX) t = PUNY_TMAX;
      else t = k - bias;
      if (digit < t) break;
      if (w > Math.floor(0x7fffffff / (PUNY_BASE - t))) return null;
      w *= PUNY_BASE - t;
    }
    bias = punyAdapt(i - oldi, out.length + 1, oldi === 0);
    if (Math.floor(i / (out.length + 1)) > 0x7fffffff - n) return null;
    n += Math.floor(i / (out.length + 1));
    i = i % (out.length + 1);
    out.splice(i, 0, n);
    i++;
  }
  try {
    return String.fromCodePoint(...out);
  } catch {
    return null;
  }
}

/**
 * Decode a full hostname containing one or more `xn--` labels. Non-xn--
 * labels pass through unchanged. Returns the Unicode hostname, or null on
 * any decode failure.
 */
function decodePunycodeHost(host) {
  if (!host || typeof host !== "string") return null;
  const labels = host.split(".");
  const out = [];
  let sawAce = false;
  for (const label of labels) {
    const low = label.toLowerCase();
    if (low.startsWith("xn--")) {
      sawAce = true;
      const decoded = decodePunycodeLabel(low.slice(4));
      if (decoded === null) return null;
      out.push(decoded);
    } else {
      out.push(label);
    }
  }
  if (!sawAce) return null;
  return out.join(".");
}

const RE_URL_WITH_XN = /\bhttps?:\/\/[^\s<>"'`]+/gi;

function classifyScript(s) {
  // Counts of distinct script classes in the decoded label. We only care
  // about three signals:
  //   - Cyrillic  (U+0400-U+04FF, U+0500-U+052F)
  //   - Greek     (U+0370-U+03FF, U+1F00-U+1FFF)
  //   - Latin     (basic-latin + Latin-1 Supplement + Latin Extended)
  // Mixed Latin+(Cyrillic|Greek) -> 'mixed'; pure non-Latin homograph script
  // -> the script name. CJK / Hiragana / Katakana / Hangul / Arabic / Hebrew
  // are valid IDN scripts on their own and DO NOT form the classic Latin
  // homograph attack surface, so a host containing only those + Latin (e.g.
  // a benign .jp brand domain like xn--gckjcdiu1g.jp) returns null —
  // matches eml.js's _detectScriptMix() policy.
  let hasLatin = false;
  let hasCyrillic = false;
  let hasGreek = false;
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (
      (cp >= 0x0041 && cp <= 0x005a) ||
      (cp >= 0x0061 && cp <= 0x007a) ||
      (cp >= 0x00c0 && cp <= 0x024f) ||
      (cp >= 0x1e00 && cp <= 0x1eff)
    ) {
      hasLatin = true;
    } else if (
      (cp >= 0x0400 && cp <= 0x04ff) ||
      (cp >= 0x0500 && cp <= 0x052f)
    ) {
      hasCyrillic = true;
    } else if (
      (cp >= 0x0370 && cp <= 0x03ff) ||
      (cp >= 0x1f00 && cp <= 0x1fff)
    ) {
      hasGreek = true;
    }
    // CJK / Hiragana / Katakana / Hangul / Arabic / Hebrew etc. are
    // intentionally NOT counted — they don't participate in the Latin
    // homograph attack model.
  }
  if (hasLatin && (hasCyrillic || hasGreek)) return "mixed";
  if (hasCyrillic && !hasLatin) return "cyrillic";
  if (hasGreek && !hasLatin) return "greek";
  return null;
}

function* iteratePunycodeCandidates(content) {
  RE_URL_WITH_XN.lastIndex = 0;
  let m;
  let hits = 0;
  while ((m = RE_URL_WITH_XN.exec(content)) !== null) {
    if (m.index === RE_URL_WITH_XN.lastIndex) RE_URL_WITH_XN.lastIndex++;
    const raw = m[0];
    if (!raw.toLowerCase().includes("xn--")) continue;
    hits++;
    if (hits > CAPS.punycodeMaxHits) break;

    // Extract the raw ACE host segment from the URL without relying on the
    // WHATWG URL parser (which keeps xn-- in ACE form anyway and would
    // require try/catch for malformed URLs).
    const aceHost = extractAceHost(raw);
    if (!aceHost) continue;

    // Decode every xn-- label in the host using our inline RFC 3492
    // decoder. R12: the decoded string `unicodeHost` is consumed ONLY by
    // the script classifier below — it never reaches the finding meta /
    // body. The meta.host field carries the RAW (ACE) host the user typed.
    const unicodeHost = decodePunycodeHost(aceHost);
    if (!unicodeHost) continue;

    const script = classifyScript(unicodeHost);
    if (!script) continue;
    yield {
      start: m.index,
      end: m.index + raw.length,
      // R12: we surface the SCRIPT NAME (enum), not the decoded characters.
      decodedScript: script,
      // Keep the RAW ACE host (xn--…) for the meta breadcrumb — that's what
      // the user typed, not detector-synthesized text. Capped at 200.
      rawHost: aceHost.slice(0, 200),
    };
    // Drop the decoded buffer reference promptly so it doesn't escape this
    // generator scope (V8 will GC anyway; this is intent).
    // eslint-disable-next-line no-unused-vars
    let _drop = null;
  }
}

function extractAceHost(rawUrl) {
  // Cheap extraction without re-decoding — pull the host segment between
  // `://` and the next `/` or `?` or `#` or end.
  const i = rawUrl.indexOf("://");
  if (i < 0) return "";
  const rest = rawUrl.slice(i + 3);
  const j = rest.search(/[/?#]/);
  const host = j < 0 ? rest : rest.slice(0, j);
  return host.slice(0, 200);
}

// ─── Finding builder ──────────────────────────────────────────────────────
//
// Every finding produced by this module routes through here so the R12
// invariant ("no decoded raw text in the response") is enforced in one
// place — easy to audit, easy to test.
function buildFinding({
  kebab,
  encodingClass,
  decodedFrom,
  start,
  end,
  content,
  extraMeta = null,
}) {
  const matchLen = Math.max(1, end - start);
  const meta = {
    // R12: enum only, not decoded user text.
    decodedFrom,
    encodingClass,
    byteRange: [start, end],
  };
  if (extraMeta && typeof extraMeta === "object") {
    // Whitelist of allowed extra-meta keys. R12 gate: anything not in this
    // set is silently dropped so a future caller can't accidentally leak
    // decoded text.
    const allowed = ["layerCount", "host", "decodedScript"];
    for (const k of allowed) {
      if (k in extraMeta) meta[k] = extraMeta[k];
    }
  }
  return {
    // `pattern` is what suspiciousPatterns dedup keys on (see detector.js
    // `mergeShadowFindings`). We use the kebab id so the same finding
    // emitted twice (e.g. via two separate base64 candidates) doesn't fold
    // unless the byte range matches exactly.
    pattern: kebab,
    // Fixed structural placeholder — never user-controlled text.
    matched: PLACEHOLDER_MATCHED,
    position: start,
    matchLen,
    // Raw (encoded) source context. The user already typed it — surfacing
    // the encoded blob doesn't add a decoding-oracle service.
    context: getContext(content, start, matchLen),
    severity: "danger",
    // `technique` mirrors the kebab id so the UI's t_technique() resolver
    // can look it up directly (i18n key === kebab→camel).
    technique: kebab,
    meta,
  };
}

// ─── Main entry ───────────────────────────────────────────────────────────
//
// Public detector entrypoint. Pure, env-free, idempotent.
//
// @param {string} content
// @returns {Array} findings (each conforming to the suspiciousPatterns shape)
export function detectEncodedPayloads(content) {
  if (typeof content !== "string" || content.length === 0) return [];

  const findings = [];

  // ── Base64 ──
  for (const cand of iterateBase64Candidates(content)) {
    if (findings.length >= CAPS.maxFindings) break;
    const binary = safeBase64Decode(cand.raw);
    if (!binary) continue;
    const text = bytesToPlausibleText(binary);
    if (!text) continue;
    if (!decodedLooksLikeInstruction(text)) continue;
    // Multi-layer detection: if the decoded text *itself* still contains
    // invisible-Unicode obfuscation wrapping the instruction phrase, this
    // is a layered attack — emit the multi-layer kebab id instead.
    const layered = ZW_TAGS_RE.test(text);
    if (layered) {
      findings.push(
        buildFinding({
          kebab: KEBAB.multiLayer,
          encodingClass: "multi-layer",
          decodedFrom: "base64",
          start: cand.start,
          end: cand.end,
          content,
          extraMeta: { layerCount: 2 },
        })
      );
    } else {
      findings.push(
        buildFinding({
          kebab: KEBAB.base64,
          encodingClass: "instruction",
          decodedFrom: "base64",
          start: cand.start,
          end: cand.end,
          content,
        })
      );
    }
    // GC hint: drop the decoded buffer references promptly so the binary
    // never escapes this scope. (V8 will collect anyway; this is intent.)
    // eslint-disable-next-line no-unused-vars
    let _drop_binary = null;
    // eslint-disable-next-line no-unused-vars
    let _drop_text = null;
  }

  // ── Hex ──
  for (const cand of iterateHexCandidates(content)) {
    if (findings.length >= CAPS.maxFindings) break;
    const binary = decodeHex(cand.raw);
    if (!binary) continue;
    const text = bytesToPlausibleText(binary);
    if (!text) continue;
    if (!decodedLooksLikeInstruction(text)) continue;
    findings.push(
      buildFinding({
        kebab: KEBAB.hex,
        encodingClass: "instruction",
        decodedFrom: "hex",
        start: cand.start,
        end: cand.end,
        content,
      })
    );
  }

  // ── HTML numeric entity ──
  const htmlDecoded = decodeHtmlEntities(content);
  if (htmlDecoded && decodedLooksLikeInstruction(htmlDecoded.decoded)) {
    // Attribute the finding to the WIDEST run of contiguous references.
    let bestRun = htmlDecoded.runs[0];
    for (const r of htmlDecoded.runs) {
      if (r.end - r.start > bestRun.end - bestRun.start) bestRun = r;
    }
    if (bestRun && findings.length < CAPS.maxFindings) {
      findings.push(
        buildFinding({
          kebab: KEBAB.htmlEntity,
          encodingClass: "instruction",
          decodedFrom: "html-entity",
          start: bestRun.start,
          end: bestRun.end,
          content,
        })
      );
    }
  }

  // ── Punycode host ──
  for (const cand of iteratePunycodeCandidates(content)) {
    if (findings.length >= CAPS.maxFindings) break;
    findings.push(
      buildFinding({
        kebab: KEBAB.punycodeHomograph,
        encodingClass: "homograph",
        decodedFrom: "punycode",
        start: cand.start,
        end: cand.end,
        content,
        extraMeta: {
          // `host` is the RAW ACE form the user typed (xn--…) — NOT a
          // detector-synthesized decoded string.
          host: cand.rawHost,
          decodedScript: cand.decodedScript,
        },
      })
    );
  }

  return findings;
}

// Re-export the placeholder so audit tests can assert on its value directly.
export { PLACEHOLDER_MATCHED as ENCODED_PLACEHOLDER_MATCHED };

// `escapeForDisplay` is imported above so the lint pass doesn't complain
// about unused imports — keep it referenced via a no-op in case future
// kebab ids need to surface a tightly-escaped raw fragment. Currently
// unused for R12 reasons.
void escapeForDisplay;
