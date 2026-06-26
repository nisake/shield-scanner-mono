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
import { simpleParser } from "mailparser";
import { escapeForDisplay, sanitizeContextLocation } from "@shield-scanner/core";

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

      // PDF-EML-EMPTY-ATTACHMENT-CHANNEL: dispatchBuffer succeeded but yielded
      // no text AND the input was 0 bytes — surface the channel anyway so the
      // recipient sees the (empty) attachment existed.
      const childTextEmpty = !parsedContent.text || !String(parsedContent.text).trim();
      if (size === 0 && childTextEmpty) {
        extraFindings.push({
          element: "Email Attachment",
          technique: "Empty attachment",
          content: escapeForDisplay(filename),
          severity: "warning",
          contextLocation: `Attachment ${safeFilename}`,
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
