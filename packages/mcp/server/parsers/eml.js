/**
 * EML parser using mailparser.
 *
 * Splits an email into sections (headers/body/html/attachments) so each can
 * be scanned with the appropriate detector settings.
 *
 * Accepts either:
 * - A file path (.eml file)
 * - A raw email source string
 * - A raw Buffer (used when recursively scanning .eml attachments)
 *
 * Risk #10 guardrail: This module does NOT compare text/plain vs text/html
 * parts (no Jaccard / no trigram). Attachment recursive scanning only.
 */

import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import { createRequire } from "node:module";
import { simpleParser } from "mailparser";
import { escapeForDisplay, sanitizeContextLocation } from "@shield-scanner/core";

// node:punycode is deprecated but still shipped with Node 18/20/22 LTS and
// is the simplest way to decode IDN labels without adding a runtime dep.
// We lazy-require to keep the deprecation warning suppressed unless the
// header anomaly path actually runs.
const _requireForPuny = createRequire(import.meta.url);
let _punycodeMod = null;
function _getPunycode() {
  if (_punycodeMod !== null) return _punycodeMod;
  try {
    _punycodeMod = _requireForPuny("node:punycode");
  } catch {
    _punycodeMod = false;
  }
  return _punycodeMod;
}

// Lazy import to avoid an unresolvable circular at module-load time.
// parsers/index.js imports parseEmlBuffer from this file, so we cannot
// import dispatchBuffer at the top level without risking a TDZ error.
let _dispatchBuffer = null;
async function getDispatchBuffer() {
  if (!_dispatchBuffer) {
    const mod = await import("./index.js");
    _dispatchBuffer = mod.dispatchBuffer;
  }
  return _dispatchBuffer;
}

/**
 * Safety limits for attachment recursion.
 * Risk #13: bounded resource use; defensive against zip-bomb-style emails.
 */
export const ATTACHMENT_LIMITS = Object.freeze({
  MAX_DEPTH: 3,
  MAX_SIZE_BYTES: 25 * 1024 * 1024, // 25 MB
  MAX_COUNT: 50,
});

/**
 * Parse an .eml file from disk.
 */
export async function parseEmlFile(filePath, options = {}) {
  const raw = await readFile(filePath);
  return parseEmlContent(raw, options);
}

/**
 * Parse raw email text (string).
 */
export async function parseEmlContent(raw, options = {}) {
  const parsed = await simpleParser(raw);
  return buildSections(parsed, options);
}

/**
 * Parse an email from a Buffer (used when recursively scanning a nested .eml
 * attachment). Identical to parseEmlContent but explicitly named so the
 * dispatcher can be unambiguous.
 */
export async function parseEmlBuffer(buffer, options = {}) {
  const parsed = await simpleParser(buffer);
  return buildSections(parsed, options);
}

async function buildSections(parsed, options = {}) {
  // Recursion depth (used when this email itself is a nested attachment).
  const depth = Number.isInteger(options.depth) ? options.depth : 0;

  // Build a readable headers block
  const headerLines = [];
  if (parsed.from) headerLines.push(`From: ${parsed.from.text || ""}`);
  if (parsed.to) headerLines.push(`To: ${parsed.to.text || ""}`);
  if (parsed.cc) headerLines.push(`Cc: ${parsed.cc.text || ""}`);
  if (parsed.subject) headerLines.push(`Subject: ${parsed.subject}`);
  if (parsed.date) headerLines.push(`Date: ${parsed.date.toISOString()}`);
  if (parsed.replyTo)
    headerLines.push(`Reply-To: ${parsed.replyTo.text || ""}`);
  if (parsed.messageId) headerLines.push(`Message-ID: ${parsed.messageId}`);

  const headers = headerLines.join("\n");

  // ------------------------------------------------------------------
  // S11: Extended headers (Reply-To / Return-Path / Sender / X-* etc.)
  //
  // Many phishing attacks hide payloads or spoofing hints in less-common
  // headers. We extract them as a separate section so the existing analyze()
  // pipeline scans them just like the main headers/body. We do NOT mutate or
  // normalize the values (risk #1) — they are forwarded as raw text.
  //
  // Sources:
  //   - parsed.replyTo  → Reply-To  (also kept in the main headers section
  //                       for backward compat; duplicated is fine — scan is
  //                       idempotent)
  //   - parsed.headers Map (lowercased keys) for: return-path, sender,
  //                       x-original-from, x-forwarded-for, x-mailer,
  //                       x-originating-ip
  //   - parsed.headerLines for ANY remaining `x-*` header we did not already
  //                       enumerate, so unknown vendor headers still get
  //                       scanned.
  // ------------------------------------------------------------------
  const extendedHeaderLines = [];
  const seenExtendedKeys = new Set();

  function pushHeaderValue(displayName, rawValue) {
    if (rawValue == null) return;
    let text;
    if (typeof rawValue === "string") {
      text = rawValue;
    } else if (typeof rawValue === "object") {
      // mailparser address-style object: { value, text, html }
      text = rawValue.text || "";
    } else {
      text = String(rawValue);
    }
    if (!text) return;
    extendedHeaderLines.push(`${displayName}: ${text}`);
  }

  const headersMap = parsed.headers; // Map<lowercaseKey, value>
  if (headersMap && typeof headersMap.get === "function") {
    const explicitTargets = [
      ["reply-to", "Reply-To"],
      ["return-path", "Return-Path"],
      ["sender", "Sender"],
      ["x-original-from", "X-Original-From"],
      ["x-forwarded-for", "X-Forwarded-For"],
      ["x-mailer", "X-Mailer"],
      ["x-originating-ip", "X-Originating-IP"],
    ];
    for (const [key, display] of explicitTargets) {
      if (headersMap.has(key)) {
        pushHeaderValue(display, headersMap.get(key));
        seenExtendedKeys.add(key);
      }
    }
  }

  // Sweep all remaining X-* headers (unknown vendor headers).
  // Prefer headerLines (preserves original-case display name + exact value
  // as a single string). Fall back to headers Map iteration if headerLines
  // is unavailable.
  if (Array.isArray(parsed.headerLines)) {
    for (const hl of parsed.headerLines) {
      const key = (hl.key || "").toLowerCase();
      if (!key.startsWith("x-")) continue;
      if (seenExtendedKeys.has(key)) continue;
      seenExtendedKeys.add(key);
      // hl.line already has "Name: value" form
      if (hl.line) extendedHeaderLines.push(hl.line);
    }
  } else if (headersMap && typeof headersMap.forEach === "function") {
    headersMap.forEach((value, key) => {
      const k = String(key).toLowerCase();
      if (!k.startsWith("x-")) return;
      if (seenExtendedKeys.has(k)) return;
      seenExtendedKeys.add(k);
      pushHeaderValue(k, value);
    });
  }

  const extendedHeaders = extendedHeaderLines.join("\n");

  const body = parsed.text || "";
  const html = parsed.html || "";

  const allAttachments = parsed.attachments || [];

  // Attachment names (preserved for backward compatibility)
  const attachmentNames = allAttachments
    .map((a) => a.filename || "(unnamed)")
    .join("\n");

  // Extra findings: suspicious attachment filenames (e.g. double extensions)
  const extraFindings = [];

  // ------------------------------------------------------------------
  // v1.18.0: EML header anomaly + IDN/Punycode homograph + RFC2047
  // encoded-word abuse detection (3 systems, all fold to suspiciousPatterns,
  // R10/R12 guardrails strict).
  //
  //   (a) eml-from-reply-to-mismatch / eml-sender-from-mismatch /
  //       eml-authentication-failure — phishing header anomalies.
  //   (b) eml-punycode-homograph-domain / eml-mixed-script-domain —
  //       From/Reply-To/Subject xn-- decode + Cyrillic/Greek mixed-script.
  //   (c) eml-encoded-word-invisible-unicode — RFC2047 encoded-word decoded
  //       payload containing Unicode Tags / invisible chars / homoglyphs.
  //
  // R10: header scan ONLY (multipart vs HTML divergence is forbidden).
  // R12: detector-controlled `meta` fields only — never echo raw user text.
  // R13: every finding gets `category: 'suspiciousPatterns'` so the global
  //      5-key byCategory invariant is preserved.
  // ------------------------------------------------------------------
  emitEmlHeaderAnomalies(parsed, extraFindings);

  for (const att of allAttachments) {
    if (!att.filename) continue;
    // PDF-EML-FILENAME-CONTEXTLOC-SANITIZE: contextLocation must not echo
    // raw filename bytes (bidi RLO, ANSI, line-injection, zero-width).
    const safeFilename = sanitizeContextLocation(att.filename);
    // Double-extension pattern: foo.pdf.exe
    if (/\.[a-z0-9]{2,5}\.(exe|scr|bat|cmd|vbs|js|jar|ps1)$/i.test(att.filename)) {
      extraFindings.push({
        element: "Email Attachment",
        technique: "Suspicious double extension",
        content: escapeForDisplay(att.filename),
        severity: "danger",
        contextLocation: `Attachment ${safeFilename}`,
      });
    }
    // Hidden RLO (right-to-left override) in filename
    if (/\u202E/.test(att.filename)) {
      extraFindings.push({
        element: "Email Attachment",
        technique: "Right-to-Left Override in filename (U+202E)",
        content: escapeForDisplay(att.filename),
        severity: "danger",
        contextLocation: `Attachment ${safeFilename}`,
      });
    }
  }

  // ------------------------------------------------------------------
  // M4: Attachment recursive scanning
  //
  // For each attachment whose extension is dispatchable, parse it into a
  // {text, fileType, sections?} block that the caller (scan-email.js) can
  // feed back through the detector. We do NOT run the detector here — this
  // keeps the parser layer pure and lets scan-email aggregate consistently.
  //
  // Guardrails (risk #13):
  //   - depth >= MAX_DEPTH: skip all (parent email is already too deep)
  //   - filename count > MAX_COUNT: process first MAX_COUNT, log skip for rest
  //   - per-attachment size > MAX_SIZE_BYTES: skip with finding
  //   - unknown / non-dispatchable extension: skip silently (not an error)
  // ------------------------------------------------------------------
  const attachmentScans = [];
  const childDepth = depth + 1;

  if (childDepth > ATTACHMENT_LIMITS.MAX_DEPTH) {
    if (allAttachments.length > 0) {
      extraFindings.push({
        element: "Email Attachment",
        technique: `Recursion depth limit reached (${ATTACHMENT_LIMITS.MAX_DEPTH}); ${allAttachments.length} attachment(s) at depth ${depth} not scanned`,
        content: "(nested email too deep)",
        severity: "warning",
        contextLocation: "Email > Attachments",
      });
    }
  } else {
    const processCount = Math.min(allAttachments.length, ATTACHMENT_LIMITS.MAX_COUNT);
    if (allAttachments.length > ATTACHMENT_LIMITS.MAX_COUNT) {
      extraFindings.push({
        element: "Email Attachment",
        technique: `Attachment count limit reached (${ATTACHMENT_LIMITS.MAX_COUNT}); ${allAttachments.length - ATTACHMENT_LIMITS.MAX_COUNT} attachment(s) skipped`,
        content: `(total: ${allAttachments.length})`,
        severity: "warning",
        contextLocation: "Email > Attachments",
      });
    }

    for (let i = 0; i < processCount; i++) {
      const att = allAttachments[i];
      const filename = att.filename || `(unnamed-${i})`;
      // PDF-EML-FILENAME-CONTEXTLOC-SANITIZE: contextLocation field is
      // rendered in UI/report, so strip controls that would let a crafted
      // filename re-render the surrounding text.
      const safeFilename = sanitizeContextLocation(filename);
      const ext = inferAttachmentExtension(att);
      const size = (att.content && att.content.length) || att.size || 0;
      const label = `attachment[${i}]: ${filename}`;

      // Size guard
      if (size > ATTACHMENT_LIMITS.MAX_SIZE_BYTES) {
        extraFindings.push({
          element: label,
          technique: `Attachment size limit exceeded (${size} bytes > ${ATTACHMENT_LIMITS.MAX_SIZE_BYTES})`,
          content: escapeForDisplay(filename),
          severity: "warning",
          contextLocation: `Attachment ${safeFilename}`,
        });
        attachmentScans.push({
          index: i,
          filename,
          contentType: att.contentType || null,
          extension: ext,
          size,
          skipped: true,
          skipReason: "size-limit",
          label,
        });
        continue;
      }

      // T3-A: emit Empty attachment for ANY 0-byte attachment up-front so
      // unsupported-extension (no dispatch) and unknown content-types also
      // surface. Old logic at the post-dispatch site only fired when dispatch
      // succeeded, so 0-byte .xyz / .dat parts silently dropped.
      if (size === 0) {
        extraFindings.push({
          element: "Email Attachment",
          technique: "Empty attachment",
          content: escapeForDisplay(filename),
          severity: "warning",
          contextLocation: `Attachment ${safeFilename}`,
        });
      }

      // T3-C: Content-Disposition declared but buffer absent / zero-length
      // while the header-reported size is non-zero. mailparser yields
      // att.content=null or empty Buffer when the MIME body is truncated;
      // the `size` variable above falls through to att.size so the size===0
      // check above won't fire. Detect the bufferEmpty mismatch explicitly
      // so the recipient still sees the (empty-on-the-wire) channel existed.
      const bufferEmpty = !att.content || (Buffer.isBuffer(att.content) && att.content.length === 0);
      if (size > 0 && bufferEmpty) {
        // v1.17.1 (T3): technique refactored to kebab id `empty-attachment-body`
        // + meta {contentType, attachmentName} so the i18n layer can resolve a
        // single localized label (R12: detector-controlled meta only, no raw
        // headers in the response body). Folds under suspiciousPatterns to
        // preserve the R13 5-key byCategory invariant.
        extraFindings.push({
          element: "Email Attachment",
          technique: "empty-attachment-body",
          content: escapeForDisplay(filename),
          severity: "warning",
          category: "suspiciousPatterns",
          contextLocation: `Attachment ${safeFilename}`,
          meta: {
            contentType: att.contentType || null,
            attachmentName: escapeForDisplay(String(filename).slice(0, 200)),
          },
        });
      }

      // Extension dispatchable?
      let parsedContent = null;
      let parseError = null;
      try {
        const dispatch = await getDispatchBuffer();
        // Ensure we pass a Buffer (mailparser uses Buffer for att.content).
        const buf = Buffer.isBuffer(att.content)
          ? att.content
          : Buffer.from(att.content || []);

        if (ext === "eml") {
          // Recurse: parse the nested email with incremented depth.
          parsedContent = await parseEmlBuffer(buf, { depth: childDepth });
        } else if (ext) {
          parsedContent = await dispatch(buf, ext);
        }
      } catch (err) {
        parseError = err && err.message ? err.message : String(err);
      }

      if (parseError) {
        extraFindings.push({
          element: label,
          technique: `Attachment parse error`,
          content: escapeForDisplay(parseError.slice(0, 200)),
          severity: "warning",
          contextLocation: `Attachment ${safeFilename}`,
        });
        attachmentScans.push({
          index: i,
          filename,
          contentType: att.contentType || null,
          extension: ext,
          size,
          skipped: true,
          skipReason: "parse-error",
          error: parseError,
          label,
        });
        continue;
      }

      if (!parsedContent) {
        // Unsupported extension — not an error, just nothing to scan.
        attachmentScans.push({
          index: i,
          filename,
          contentType: att.contentType || null,
          extension: ext,
          size,
          skipped: true,
          skipReason: "unsupported-extension",
          label,
        });
        continue;
      }

      // T3-B: dispatched a non-trivially-sized attachment but the decoded
      // text is empty/whitespace. Gated on size <= 64 bytes so we only flag
      // attachments that are effectively content-free (decoded base64 of
      // CRLF-only bodies, empty stub .txt) and avoid false positives on
      // legitimate binary files (images/PDFs) that don't expose .text
      // through their parser.
      //
      // Branch T3-A above already covers the size===0 path (and works even
      // when dispatch is skipped due to unsupported extension), so the old
      // post-dispatch `size===0 && childTextEmpty` block is intentionally
      // removed to prevent double-firing.
      const childTextEmpty = !parsedContent.text || !String(parsedContent.text).trim();
      if (size > 0 && size <= 64 && childTextEmpty) {
        // v1.17.1 (T3): technique refactored to kebab id `whitespace-only-
        // attachment` + meta {sizeBytes, attachmentName}. R12: only detector-
        // controlled meta surfaces (raw decoded text never echoed). Folds
        // under suspiciousPatterns to preserve the R13 5-key byCategory.
        extraFindings.push({
          element: "Email Attachment",
          technique: "whitespace-only-attachment",
          content: escapeForDisplay(filename),
          severity: "warning",
          category: "suspiciousPatterns",
          contextLocation: `Attachment ${safeFilename}`,
          meta: {
            sizeBytes: size,
            attachmentName: escapeForDisplay(String(filename).slice(0, 200)),
          },
        });
      }

      attachmentScans.push({
        index: i,
        filename,
        contentType: att.contentType || null,
        extension: ext,
        size,
        skipped: false,
        label,
        // The shape mirrors what parseFile() returns for top-level files,
        // so the caller can analyze() each section identically.
        parsed: parsedContent,
      });
    }
  }

  return {
    sections: {
      headers,
      extendedHeaders,
      body,
      html,
      attachmentNames,
    },
    metadata: {
      from: parsed.from?.text || null,
      to: parsed.to?.text || null,
      subject: parsed.subject || null,
      date: parsed.date?.toISOString() || null,
      attachmentCount: allAttachments.length,
      depth,
    },
    extraFindings,
    attachmentScans,
  };
}

/**
 * Best-effort extension inference from an attachment.
 *   1) Filename extension (preferred — explicit user intent)
 *   2) Content-Type mapping (fallback for filename-less inline parts)
 * Returns lowercase extension WITHOUT leading dot, or null if unknown.
 */
function inferAttachmentExtension(att) {
  if (att.filename) {
    const e = extname(att.filename).slice(1).toLowerCase();
    if (e) return e;
  }
  const ct = (att.contentType || "").toLowerCase();
  if (!ct) return null;
  if (ct.includes("application/pdf")) return "pdf";
  if (
    ct.includes(
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
  )
    return "docx";
  if (
    ct.includes(
      "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    )
  )
    return "pptx";
  if (ct.includes("text/html")) return "html";
  if (ct.includes("message/rfc822")) return "eml";
  if (ct.includes("text/csv")) return "csv";
  if (ct.includes("application/json")) return "json";
  if (ct.includes("text/markdown")) return "md";
  // v1.19.0 B2: RTF MIME mapping. application/rtf and text/rtf both occur
  // in the wild (some mail clients pick one over the other). Without this
  // mapping, an inline part with filename omitted would fall through to the
  // unsupported-extension silent-skip path even after .rtf is in
  // BUFFER_DISPATCHABLE.
  if (ct.includes("application/rtf") || ct.includes("text/rtf")) return "rtf";
  // S12: inline images (HTML mail with `cid:` references typically drop the
  // filename parameter on the part). Without these mappings, parseImage is
  // never reached for the most common real-world image-delivery shape and
  // the S12 detector is silently bypassed. Mirrors IMAGE_EXTS in
  // parsers/index.js BUFFER_DISPATCHABLE.
  if (ct.includes("image/jpeg") || ct.includes("image/jpg")) return "jpg";
  if (ct.includes("image/png")) return "png";
  if (ct.includes("image/webp")) return "webp";
  if (ct.includes("image/gif")) return "gif";
  if (ct.includes("image/tiff") || ct.includes("image/tif")) return "tiff";
  if (ct.startsWith("text/")) return "txt";
  return null;
}

// ====================================================================
// v1.18.0 EML header anomaly helpers
// ====================================================================

/**
 * Cap (R12) for any string value we re-surface through `meta`. Header values
 * occasionally contain very long display names / encoded blobs and we never
 * want to balloon the response.
 */
const META_STR_CAP = 200;

function _capMeta(s) {
  if (typeof s !== "string") return null;
  if (s.length <= META_STR_CAP) return escapeForDisplay(s);
  return escapeForDisplay(s.slice(0, META_STR_CAP));
}

/**
 * Extract an RFC 5322 addr-spec local@domain from a parsed header value.
 * Accepts mailparser address objects, plain string, or null. Returns lowercase
 * domain or null. Defensive against angle-bracket and display-name shapes.
 */
function _extractDomain(value) {
  if (value == null) return null;
  let text = null;
  if (typeof value === "string") {
    text = value;
  } else if (typeof value === "object") {
    // mailparser address: value: [{ address, name }], text, html
    if (Array.isArray(value.value) && value.value.length > 0) {
      const first = value.value[0];
      if (first && typeof first.address === "string" && first.address.length > 0) {
        text = first.address;
      }
    }
    if (!text && typeof value.text === "string") text = value.text;
  } else {
    text = String(value);
  }
  if (!text) return null;
  // Pull the LAST `<...>` token if present (display-name + addr-spec form).
  const angle = text.match(/<([^<>]+)>/);
  const candidate = angle ? angle[1] : text;
  // First `@` split. Trim whitespace and strip angle/quote noise.
  const atIdx = candidate.indexOf("@");
  if (atIdx < 0) return null;
  const domainRaw = candidate
    .slice(atIdx + 1)
    .trim()
    .replace(/[>"';,\s].*$/, ""); // stop at first delimiter
  if (!domainRaw) return null;
  return domainRaw.toLowerCase();
}

/**
 * organizationalDomain: strip subdomains and compare on the last 2 labels for
 * common gTLDs (best-effort; we don't ship a Public Suffix List). For ccTLDs
 * with `.co.<cc>` shape we widen to 3 labels.
 */
function _orgDomain(domain) {
  if (!domain || typeof domain !== "string") return null;
  const labels = domain.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const last2 = labels.slice(-2).join(".");
  const tail2 = labels.slice(-2).join(".");
  // Crude double-suffix heuristic: e.g. example.co.jp / example.co.uk
  const TWO_LEVEL_CCTLD = new Set([
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.uk", "ac.uk", "org.uk", "gov.uk",
    "co.kr", "co.nz", "com.au", "net.au", "org.au",
    "com.br", "com.cn",
  ]);
  if (TWO_LEVEL_CCTLD.has(tail2) && labels.length >= 3) {
    return labels.slice(-3).join(".");
  }
  return last2;
}

/**
 * RFC 5321.MailFrom (Return-Path) sometimes wraps in `<...>`. Strip the wrap.
 */
function _stripAngles(s) {
  if (typeof s !== "string") return s;
  const m = s.match(/^\s*<([^>]*)>\s*$/);
  return m ? m[1] : s;
}

/**
 * Decode Punycode (xn--) labels using the URL hostname parser. Returns the
 * decoded host (Unicode), or the original lowercased input on failure.
 * Defensive: an invalid `xn--` triggers URL throw, we swallow and return raw.
 */
function _punyDecodeHost(host) {
  if (!host || typeof host !== "string") return host;
  const lower = host.toLowerCase();
  if (!lower.includes("xn--")) return lower;
  const puny = _getPunycode();
  if (puny && typeof puny.toUnicode === "function") {
    try {
      const decoded = puny.toUnicode(lower);
      return decoded || lower;
    } catch {
      return lower;
    }
  }
  // URL parser does NOT decode Punycode in Node — last-resort fallback is
  // the raw lowercased host. Tests on Node LTS will hit the punycode path.
  return lower;
}

/**
 * Classify the dominant script(s) present in the decoded host. Returns an
 * array of script tags found (at least 1 letter per script). We only check
 * Latin / Cyrillic / Greek (the classic mixed-script homograph trio). ASCII
 * digits, hyphens, and dots are ignored.
 */
function _detectScriptMix(host) {
  if (!host) return [];
  const scripts = new Set();
  for (const ch of host) {
    const cp = ch.codePointAt(0);
    if (cp == null) continue;
    // ASCII letters
    if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a)) {
      scripts.add("Latin");
      continue;
    }
    // Cyrillic block U+0400..U+04FF (+supplement U+0500..U+052F)
    if (cp >= 0x0400 && cp <= 0x052f) {
      scripts.add("Cyrillic");
      continue;
    }
    // Greek and Coptic U+0370..U+03FF
    if (cp >= 0x0370 && cp <= 0x03ff) {
      scripts.add("Greek");
      continue;
    }
    // We intentionally ignore CJK / Hangul / Hebrew / Arabic — those are
    // valid IDN scripts on their own and don't form the classic Latin
    // homograph attack surface.
  }
  return Array.from(scripts).sort();
}

/**
 * Walk every xn-- containing host in a free-form text value (From / Reply-To
 * display string, Subject etc.) and report (originalHost, decodedHost) pairs.
 */
function _findPunycodeHosts(text) {
  if (!text || typeof text !== "string") return [];
  const out = [];
  // Match any token that contains xn-- and is bounded by non-host chars.
  // Hosts may have multiple labels (xn--80akhbyknj4f.xn--p1ai).
  const re = /[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const tok = m[0];
    if (!/xn--/i.test(tok)) continue;
    // Skip pure ASCII tokens with no dot — not a host.
    if (!tok.includes(".")) continue;
    const decoded = _punyDecodeHost(tok);
    if (decoded && decoded !== tok.toLowerCase()) {
      out.push({ original: tok.toLowerCase(), decoded });
    }
  }
  return out;
}

/**
 * RFC 2047 encoded-word matcher: `=?charset?B|Q?payload?=`. Returns array of
 * decoded payloads (Buffer -> utf8 string). Charset is honored for utf-8 /
 * iso-8859-1 (Latin-1); anything else falls through to utf-8 best-effort.
 */
function _decodeRfc2047(text) {
  if (!text || typeof text !== "string") return [];
  const decoded = [];
  const re = /=\?([A-Za-z0-9._-]+)\?([BbQq])\?([^?]*)\?=/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const charset = m[1].toLowerCase();
    const enc = m[2].toUpperCase();
    const payload = m[3];
    let buf = null;
    try {
      if (enc === "B") {
        buf = Buffer.from(payload, "base64");
      } else {
        // Q-encoding: `_` = space, `=XX` = hex byte.
        const qDec = payload
          .replace(/_/g, " ")
          .replace(/=([0-9A-Fa-f]{2})/g, (_, hh) =>
            String.fromCharCode(parseInt(hh, 16)),
          );
        // Q-decoded already a string of code points 0..255; convert via
        // Buffer to honor the declared charset.
        buf = Buffer.from(qDec, "binary");
      }
    } catch {
      continue;
    }
    let str = null;
    try {
      if (charset === "utf-8" || charset === "utf8") {
        str = buf.toString("utf8");
      } else if (charset === "iso-8859-1" || charset === "latin1") {
        str = buf.toString("latin1");
      } else {
        // Best-effort utf-8 (R14: never blindly latin-1 promote Unicode).
        str = buf.toString("utf8");
      }
    } catch {
      continue;
    }
    if (str) decoded.push(str);
  }
  return decoded;
}

/**
 * Unicode Tag block U+E0000..U+E007F + invisibles + Cyrillic/Greek
 * homoglyph chars common in spoofing.
 */
const _UNICODE_TAG_RE = /[\u{E0000}-\u{E007F}]/u;
const _INVISIBLE_RE = /[​-‍⁠﻿]/;
const _CYRILLIC_LETTER_RE = /[Ѐ-ԯ]/;
const _GREEK_LETTER_RE = /[Ͱ-Ͽ]/;

/**
 * Authentication-Results header parser — flag any `dmarc=fail` / `spf=fail` /
 * `dkim=fail`. Permissive whitespace + case-insensitive match.
 */
function _parseAuthResultsFail(value) {
  if (typeof value !== "string" || value.length === 0) return [];
  const hits = [];
  const re = /\b(dmarc|spf|dkim)\s*=\s*(fail|softfail|temperror|permerror)\b/gi;
  let m;
  while ((m = re.exec(value)) !== null) {
    hits.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase() });
  }
  return hits;
}

function emitEmlHeaderAnomalies(parsed, extraFindings) {
  if (!parsed) return;

  // -- Header value extraction (R12: raw user text never re-surfaced) --
  const fromDomain = _extractDomain(parsed.from);
  const replyToDomain = _extractDomain(parsed.replyTo);

  const headersMap =
    parsed.headers && typeof parsed.headers.get === "function"
      ? parsed.headers
      : null;

  const returnPathRaw = headersMap ? headersMap.get("return-path") : null;
  const returnPathText =
    typeof returnPathRaw === "string"
      ? _stripAngles(returnPathRaw)
      : returnPathRaw && typeof returnPathRaw === "object"
      ? _stripAngles(returnPathRaw.text || "")
      : null;
  const returnPathDomain = returnPathText
    ? _extractDomain(returnPathText)
    : null;

  const senderRaw = headersMap ? headersMap.get("sender") : null;
  const senderDomain = senderRaw ? _extractDomain(senderRaw) : null;

  // (a1) Reply-To vs From organizational-domain mismatch.
  if (fromDomain && replyToDomain) {
    const fromOrg = _orgDomain(fromDomain);
    const replyOrg = _orgDomain(replyToDomain);
    if (fromOrg && replyOrg && fromOrg !== replyOrg) {
      extraFindings.push({
        element: "Email Headers",
        technique: "eml-from-reply-to-mismatch",
        content: escapeForDisplay(`${fromOrg} vs ${replyOrg}`),
        severity: "warning",
        category: "suspiciousPatterns",
        contextLocation: "Headers > From/Reply-To",
        meta: {
          fromDomain: _capMeta(fromDomain),
          replyToDomain: _capMeta(replyToDomain),
        },
      });
    }
  }

  // (a2) Return-Path vs From organizational-domain mismatch (folded into
  // eml-from-reply-to-mismatch family is wrong — we keep it a distinct kebab
  // signal via eml-sender-from-mismatch when Sender header is the source.)
  if (fromDomain && returnPathDomain) {
    const fromOrg = _orgDomain(fromDomain);
    const rpOrg = _orgDomain(returnPathDomain);
    if (fromOrg && rpOrg && fromOrg !== rpOrg) {
      // Re-use the same kebab id family — phishing signal is the same shape
      // (envelope mismatch). meta carries replyToDomain=Return-Path so the
      // localized label can disambiguate downstream.
      extraFindings.push({
        element: "Email Headers",
        technique: "eml-from-reply-to-mismatch",
        content: escapeForDisplay(`${fromOrg} vs ${rpOrg}`),
        severity: "warning",
        category: "suspiciousPatterns",
        contextLocation: "Headers > From/Return-Path",
        meta: {
          fromDomain: _capMeta(fromDomain),
          replyToDomain: _capMeta(returnPathDomain),
        },
      });
    }
  }

  // (a3) Sender != From organizational-domain.
  if (fromDomain && senderDomain) {
    const fromOrg = _orgDomain(fromDomain);
    const sndOrg = _orgDomain(senderDomain);
    if (fromOrg && sndOrg && fromOrg !== sndOrg) {
      extraFindings.push({
        element: "Email Headers",
        technique: "eml-sender-from-mismatch",
        content: escapeForDisplay(`${fromOrg} vs ${sndOrg}`),
        severity: "warning",
        category: "suspiciousPatterns",
        contextLocation: "Headers > Sender/From",
        meta: {
          fromDomain: _capMeta(fromDomain),
          senderDomain: _capMeta(senderDomain),
        },
      });
    }
  }

  // (a4) Authentication-Results: any fail / softfail / temperror / permerror.
  if (headersMap) {
    const authRaw = headersMap.get("authentication-results");
    let authText = null;
    if (typeof authRaw === "string") authText = authRaw;
    else if (authRaw && typeof authRaw === "object" && typeof authRaw.text === "string")
      authText = authRaw.text;
    if (authText) {
      const failures = _parseAuthResultsFail(authText);
      if (failures.length > 0) {
        // Surface ONE finding summarizing the failures (avoid noise inflation).
        const summary = failures
          .map((f) => `${f.method}=${f.result}`)
          .join(", ");
        extraFindings.push({
          element: "Email Headers",
          technique: "eml-authentication-failure",
          content: escapeForDisplay(summary),
          severity: "warning",
          category: "suspiciousPatterns",
          contextLocation: "Headers > Authentication-Results",
          meta: {
            methods: failures.map((f) => f.method).join(","),
            results: failures.map((f) => f.result).join(","),
          },
        });
      }
    }
  }

  // (b) Punycode / IDN homograph scan across From/Reply-To/Subject text.
  //
  // Two paths:
  //   - Raw xn-- token in display text (e.g. an attacker who left the ACE
  //     form in headerLines or an unsuspecting client never decoded it).
  //   - mailparser-decoded address objects where the host is ALREADY Unicode
  //     (mailparser auto-applies punycode.toUnicode). For those we go
  //     straight to script-mix detection on the host as-is.
  const punySources = [];
  if (parsed.from && parsed.from.text) punySources.push(parsed.from.text);
  if (parsed.replyTo && parsed.replyTo.text) punySources.push(parsed.replyTo.text);
  if (typeof parsed.subject === "string" && parsed.subject.length > 0)
    punySources.push(parsed.subject);
  // Pull raw header lines too — they may still hold the xn-- ACE form even
  // if mailparser produced a Unicode display version.
  if (Array.isArray(parsed.headerLines)) {
    for (const hl of parsed.headerLines) {
      const k = (hl.key || "").toLowerCase();
      if ((k === "from" || k === "reply-to" || k === "subject") && typeof hl.line === "string") {
        punySources.push(hl.line);
      }
    }
  }
  const seenPunyHosts = new Set();

  // Pre-pass: direct host extraction from already-decoded mailparser address
  // objects. Use _extractDomain to get the Unicode host (no xn-- form needed)
  // and feed straight to script-mix.
  const decodedHostCandidates = [];
  if (fromDomain) decodedHostCandidates.push({ original: fromDomain, decoded: fromDomain });
  if (replyToDomain) decodedHostCandidates.push({ original: replyToDomain, decoded: replyToDomain });
  if (returnPathDomain)
    decodedHostCandidates.push({ original: returnPathDomain, decoded: returnPathDomain });
  if (senderDomain) decodedHostCandidates.push({ original: senderDomain, decoded: senderDomain });
  for (const src of punySources) {
    const hosts = _findPunycodeHosts(src);
    for (const h of hosts) decodedHostCandidates.push(h);
  }

  for (const h of decodedHostCandidates) {
      // Dedupe on decoded form so xn-- ACE and the auto-decoded Unicode
      // address don't both fire for the same host.
      const dedupeKey = h.decoded || h.original;
      if (seenPunyHosts.has(dedupeKey)) continue;
      seenPunyHosts.add(dedupeKey);
      const scriptMix = _detectScriptMix(h.decoded);
      const hasCyrillic = scriptMix.includes("Cyrillic");
      const hasGreek = scriptMix.includes("Greek");
      const hasLatin = scriptMix.includes("Latin");
      const mixed =
        (hasCyrillic && hasLatin) ||
        (hasGreek && hasLatin) ||
        (hasCyrillic && hasGreek);
      if (mixed) {
        extraFindings.push({
          element: "Email Headers",
          technique: "eml-mixed-script-domain",
          content: escapeForDisplay(`${h.original} -> ${h.decoded}`),
          severity: "danger",
          category: "suspiciousPatterns",
          contextLocation: "Headers > From/Reply-To/Subject",
          meta: {
            decodedHost: _capMeta(h.decoded),
            scriptMix: scriptMix.join(","),
          },
        });
      } else if (hasCyrillic || hasGreek) {
        // Pure non-Latin punycode is usually legitimate (e.g. a Russian or
        // Greek company using their own script). We surface as 'warning' to
        // hint at IDN usage, but mixed-script above is the true alarm.
        extraFindings.push({
          element: "Email Headers",
          technique: "eml-punycode-homograph-domain",
          content: escapeForDisplay(`${h.original} -> ${h.decoded}`),
          severity: "warning",
          category: "suspiciousPatterns",
          contextLocation: "Headers > From/Reply-To/Subject",
          meta: {
            decodedHost: _capMeta(h.decoded),
            scriptMix: scriptMix.join(","),
          },
        });
      } else {
        // Pure Latin / CJK / etc — no homograph risk. Quiet.
      }
  }

  // (c) RFC 2047 encoded-word abuse across From/Reply-To/Subject text.
  // We decode and check for Unicode Tags / invisibles / Cyrillic-or-Greek
  // letters that would suggest a hidden payload in the display name.
  const rfcSources = [];
  if (parsed.from && parsed.from.text) rfcSources.push(parsed.from.text);
  if (parsed.replyTo && parsed.replyTo.text) rfcSources.push(parsed.replyTo.text);
  if (typeof parsed.subject === "string" && parsed.subject.length > 0)
    rfcSources.push(parsed.subject);
  // Pull raw Subject header line too — mailparser sometimes pre-decodes the
  // displayed subject so the encoded-word marker is lost from parsed.subject.
  if (Array.isArray(parsed.headerLines)) {
    for (const hl of parsed.headerLines) {
      const k = (hl.key || "").toLowerCase();
      if (k === "subject" && typeof hl.line === "string") {
        rfcSources.push(hl.line);
      }
    }
  }
  const seenAbuseTokens = new Set();
  for (const src of rfcSources) {
    const decodedList = _decodeRfc2047(src);
    for (const decodedPayload of decodedList) {
      const token = decodedPayload.slice(0, 64);
      if (seenAbuseTokens.has(token)) continue;
      const hasTag = _UNICODE_TAG_RE.test(decodedPayload);
      const hasInvisible = _INVISIBLE_RE.test(decodedPayload);
      const hasCyrillic = _CYRILLIC_LETTER_RE.test(decodedPayload);
      const hasGreek = _GREEK_LETTER_RE.test(decodedPayload);
      // We require at least one suspicious feature AND a Latin letter in
      // the same payload — mixed-script in the decoded display name. Pure
      // Japanese encoded subjects (very common) are quiet.
      const hasLatin = /[A-Za-z]/.test(decodedPayload);
      const suspiciousChar = hasTag || hasInvisible;
      const mixedScript = (hasCyrillic || hasGreek) && hasLatin;
      if (suspiciousChar || mixedScript) {
        seenAbuseTokens.add(token);
        const flags = [];
        if (hasTag) flags.push("unicode-tag");
        if (hasInvisible) flags.push("invisible");
        if (hasCyrillic) flags.push("cyrillic");
        if (hasGreek) flags.push("greek");
        extraFindings.push({
          element: "Email Headers",
          technique: "eml-encoded-word-invisible-unicode",
          // R12: never surface the decoded payload itself. Surface only the
          // flag categories the detector resolved.
          content: escapeForDisplay(flags.join(",")),
          severity: "danger",
          category: "suspiciousPatterns",
          contextLocation: "Headers > From/Reply-To/Subject",
          meta: {
            flags: flags.join(","),
          },
        });
      }
    }
  }
}
