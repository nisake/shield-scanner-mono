/**
 * v1.20.0 T3-ODP — OpenDocument Presentation (.odp) parser.
 *
 * Mirrors the PPTX parser surface for the OpenDocument equivalent:
 *
 *   - content.xml — slide bodies, speaker notes (<presentation:notes>),
 *     master-slide instructions (<style:master-page>), embedded frames
 *     (<draw:frame>) and slide transitions (<presentation:transition>).
 *   - settings.xml — embedded OLE / external object references that the
 *     viewer fetches on open.
 *   - Pictures/* — embedded image binaries, scanned through parseImageBuffer
 *     with the same OFFICE_MEDIA_MAX_BYTES / OFFICE_MEDIA_MAX_COUNT caps.
 *   - Object<N> folder entries — embedded OLE / sub-document objects.
 *
 * The 4 new kebab ids are:
 *   - odp-notes-prompt-injection         (speaker-note instruction body)
 *   - odp-slide-transition-macro         (transition with script / macro link)
 *   - odp-embedded-object-external       (external OLE / sub-document reference)
 *   - odp-master-slide-instruction       (master-page instruction body)
 *
 * R12: every finding content flows through escapeForDisplay, never raw
 * source text in the kebab id or meta keys. R13: all 4 ids fold into
 * `category: 'suspiciousPatterns'`. R18: no rule-load at module-load (only
 * pure helpers imported from core).
 */

import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import JSZip from "jszip";
import { escapeForDisplay, looksLikeInstruction } from "@shield-scanner/core";
import { parseImageBuffer } from "./image.js";

// Shared caps with the other Office parsers (docx / pptx / xlsx).
const OFFICE_IMAGE_EXTS = new Set(["jpg", "jpeg", "png", "webp", "gif", "tiff", "tif"]);
const OFFICE_MEDIA_MAX_BYTES = 5 * 1024 * 1024;
const OFFICE_MEDIA_MAX_COUNT = 50;

// Remote URL allow-list: ODF objects with xlink:href pointing at one of these
// schemes / patterns are external references the viewer fetches on open.
const REMOTE_URL_PREFIX_RE = /^(?:https?:|file:|ftp:|\\\\|\.\.\/)/i;

function decodeXmlEntities(s) {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

/**
 * Pull every <text:p>...</text:p> body. ODF stores slide / notes text inside
 * nested <text:span> runs; we flatten on the OPEN tag boundary so any nested
 * markup is stripped. Returns array of decoded text fragments.
 */
function extractTextParagraphs(xml) {
  const out = [];
  const re = /<text:p\b[^>]*>([\s\S]*?)<\/text:p>/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const inner = m[1].replace(/<[^>]+>/g, "");
    const decoded = decodeXmlEntities(inner).trim();
    if (decoded) out.push(decoded);
  }
  return out;
}

/**
 * Pull <draw:page draw:name="...">…</draw:page> blocks. Each block contains
 * one slide. Returns an array of { name, body }.
 */
function extractDrawPages(xml) {
  const out = [];
  const re = /<draw:page\b([^>]*)>([\s\S]*?)<\/draw:page>/g;
  let m;
  let idx = 0;
  while ((m = re.exec(xml)) !== null) {
    const attrs = m[1];
    const body = m[2];
    const nameMatch = attrs.match(/\bdraw:name\s*=\s*"([^"]*)"/);
    idx += 1;
    out.push({
      index: idx,
      name: nameMatch ? decodeXmlEntities(nameMatch[1]) : `page${idx}`,
      body,
    });
  }
  return out;
}

export async function parseOdp(filePath) {
  const buffer = await readFile(filePath);
  return parseOdpBuffer(buffer);
}

/**
 * Parse ODP from a Buffer (also used for recursive attachment scanning).
 */
export async function parseOdpBuffer(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const texts = [];
  const extraFindings = [];

  // --- content.xml: slide pages + notes + transitions + frames ---
  const contentEntry = zip.file("content.xml");
  if (contentEntry) {
    const xml = await contentEntry.async("string");
    const pages = extractDrawPages(xml);

    for (const page of pages) {
      const slideLabel = `Slide ${page.index} (${page.name})`;

      // Slide body text (paragraphs inside <draw:text-box>, etc.)
      const bodyParas = extractTextParagraphs(page.body);
      if (bodyParas.length > 0) {
        texts.push(`[${slideLabel}] ` + bodyParas.join(" "));
      }

      // --- Speaker notes (<presentation:notes>) ---
      const notesRe =
        /<presentation:notes\b[^>]*>([\s\S]*?)<\/presentation:notes>/g;
      let nm;
      while ((nm = notesRe.exec(page.body)) !== null) {
        const noteParas = extractTextParagraphs(nm[1]);
        const noteText = noteParas.join(" ");
        if (noteText.trim()) {
          texts.push(`[${slideLabel} Notes] ` + noteText);
          if (looksLikeInstruction(noteText)) {
            extraFindings.push({
              element: `Speaker Note (${slideLabel})`,
              technique: "odp-notes-prompt-injection",
              content: escapeForDisplay(noteText.slice(0, 200)),
              severity: "danger",
              category: "suspiciousPatterns",
              contextLocation: `${slideLabel} > Notes`,
              meta: { slideIndex: page.index },
            });
          }
        }
      }

      // --- Slide transitions with macro / script links ---
      // <presentation:event-listener script:event-name="dom:load" xlink:href="...">
      // <presentation:sound xlink:href="...vnd.sun.star.script:..." />
      const evRe =
        /<presentation:event-listener\b([^>]*)>|<presentation:sound\b([^>]*)\/?\s*>/g;
      let em;
      while ((em = evRe.exec(page.body)) !== null) {
        const attrs = em[1] || em[2] || "";
        const hrefMatch = attrs.match(/\bxlink:href\s*=\s*"([^"]*)"/);
        if (!hrefMatch) continue;
        const href = decodeXmlEntities(hrefMatch[1]);
        // Macro / script schemes: vnd.sun.star.script: or javascript:
        if (/^(?:vnd\.sun\.star\.script:|javascript:|macro:)/i.test(href)) {
          extraFindings.push({
            element: slideLabel,
            technique: "odp-slide-transition-macro",
            content: escapeForDisplay(href.slice(0, 200)),
            severity: "danger",
            category: "suspiciousPatterns",
            contextLocation: `${slideLabel} > transition`,
            meta: { scriptHref: escapeForDisplay(href.slice(0, 500)) },
          });
        }
      }

      // --- Embedded external objects in <draw:frame> ---
      // <draw:object xlink:href="..." xlink:type="simple" xlink:show="embed"/>
      // or <draw:object-ole> with external link.
      const objRe =
        /<draw:object(?:-ole)?\b([^>]*?)\/?\s*>/g;
      let om;
      while ((om = objRe.exec(page.body)) !== null) {
        const attrs = om[1] || "";
        const hrefMatch = attrs.match(/\bxlink:href\s*=\s*"([^"]*)"/);
        if (!hrefMatch) continue;
        const href = decodeXmlEntities(hrefMatch[1]);
        if (!REMOTE_URL_PREFIX_RE.test(href)) continue;
        extraFindings.push({
          element: slideLabel,
          technique: "odp-embedded-object-external",
          content: escapeForDisplay(href.slice(0, 200)),
          severity: "warning",
          category: "suspiciousPatterns",
          contextLocation: `${slideLabel} > draw:object`,
          meta: { objectHref: escapeForDisplay(href.slice(0, 500)) },
        });
      }
    }
  }

  // --- styles.xml: master pages (<style:master-page>) ---
  // Mirrors PPTX slideMasters/* — body text never rendered to user but reaches
  // LLM ingestion. Only instruction-shaped bodies surface a finding.
  const stylesEntry = zip.file("styles.xml");
  if (stylesEntry) {
    const sxml = await stylesEntry.async("string");
    const masterRe =
      /<style:master-page\b([^>]*)>([\s\S]*?)<\/style:master-page>/g;
    let mm;
    let masterIdx = 0;
    while ((mm = masterRe.exec(sxml)) !== null) {
      masterIdx += 1;
      const attrs = mm[1];
      const body = mm[2];
      const nameMatch = attrs.match(/\bstyle:name\s*=\s*"([^"]*)"/);
      const masterName = nameMatch
        ? decodeXmlEntities(nameMatch[1])
        : `master${masterIdx}`;
      const paras = extractTextParagraphs(body);
      const masterText = paras.join(" ");
      if (!masterText.trim()) continue;
      texts.push(`[Master ${masterIdx} (${masterName})] ` + masterText);
      if (looksLikeInstruction(masterText)) {
        extraFindings.push({
          element: `Master Page (${masterName})`,
          technique: "odp-master-slide-instruction",
          content: escapeForDisplay(masterText.slice(0, 200)),
          severity: "warning",
          category: "suspiciousPatterns",
          contextLocation: `Master ${masterIdx} (${masterName})`,
          meta: { masterIndex: masterIdx, masterName: escapeForDisplay(masterName.slice(0, 100)) },
        });
      }
    }
  }

  // --- settings.xml: external OLE / config-item-set references ---
  // OpenOffice/LibreOffice can stash xlink:href values pointing at remote
  // resources in <config:config-item ...> blocks. Surface external schemes.
  const settingsEntry = zip.file("settings.xml");
  if (settingsEntry) {
    const stext = await settingsEntry.async("string");
    const hrefRe = /\bxlink:href\s*=\s*"([^"]*)"/g;
    let sm;
    while ((sm = hrefRe.exec(stext)) !== null) {
      const href = decodeXmlEntities(sm[1]);
      if (!REMOTE_URL_PREFIX_RE.test(href)) continue;
      extraFindings.push({
        element: "ODP settings.xml",
        technique: "odp-embedded-object-external",
        content: escapeForDisplay(href.slice(0, 200)),
        severity: "warning",
        category: "suspiciousPatterns",
        contextLocation: "settings.xml",
        meta: { objectHref: escapeForDisplay(href.slice(0, 500)) },
      });
    }
  }

  // --- Pictures/* embedded image scan (mirrors PPTX ppt/media/*) ---
  const mediaFiles = Object.keys(zip.files).filter((f) =>
    /^Pictures\/[^/]+$/.test(f)
  );
  let mediaProcessed = 0;
  for (const mediaPath of mediaFiles) {
    if (mediaProcessed >= OFFICE_MEDIA_MAX_COUNT) break;
    const ext = extname(mediaPath).slice(1).toLowerCase();
    if (!OFFICE_IMAGE_EXTS.has(ext)) continue;
    const entry = zip.file(mediaPath);
    if (!entry) continue;
    const mediaName = mediaPath.replace(/^Pictures\//, "");
    let buf;
    try {
      buf = await entry.async("nodebuffer");
    } catch {
      continue;
    }
    if (buf.length === 0) {
      extraFindings.push({
        element: "ODP Embedded Image",
        technique: "empty-embedded-image",
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: "warning",
        contextLocation: `ODP Pictures:${mediaName}`,
      });
      mediaProcessed++;
      continue;
    }
    if (buf.length > OFFICE_MEDIA_MAX_BYTES) {
      extraFindings.push({
        element: "ODP Embedded Image",
        technique: "oversize-embedded-image",
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: "warning",
        contextLocation: `ODP Pictures:${mediaName}`,
        meta: { maxBytes: OFFICE_MEDIA_MAX_BYTES },
      });
      mediaProcessed++;
      continue;
    }
    let sub;
    try {
      sub = await parseImageBuffer(buf, ext);
    } catch {
      mediaProcessed++;
      continue;
    }
    mediaProcessed++;
    if (!sub) continue;
    if (sub.text && sub.text.trim()) {
      texts.push(`[ODP Pictures:${mediaName}]`);
      texts.push(sub.text);
    }
    if (Array.isArray(sub.extraFindings)) {
      for (const f of sub.extraFindings) {
        const existing =
          typeof f.contextLocation === "string" ? f.contextLocation : "";
        extraFindings.push({
          ...f,
          contextLocation: existing
            ? `ODP Pictures:${mediaName} > ${existing}`
            : `ODP Pictures:${mediaName}`,
        });
      }
    }
  }

  return {
    text: texts.join("\n"),
    fileType: "text",
    extraFindings,
  };
}
