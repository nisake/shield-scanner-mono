// v1.20.0 T3-ODP — OpenDocument Presentation (.odp) parser (Web mirror).
//
// Byte-identical kebab id / severity / meta shape with
// packages/mcp/server/parsers/odp.js. Returns the canonical Web envelope
// `{text, fileType: 'text', hiddenFindings}`.
//
// Depends on global: JSZip (loaded by index.html via CDN script tag, same as
// pptx.js / xlsx.js / archive.js — no static import for the bundler).
// Depends on core: escapeForDisplay, looksLikeInstruction.

import { escapeForDisplay, looksLikeInstruction } from '@shield-scanner/core';
import { parseImage } from './image.js';
import { _extOf, _PDF_IMAGE_EXTS } from './pdf.js';

const _OFFICE_MEDIA_MAX_BYTES = 5 * 1024 * 1024;
const _OFFICE_MEDIA_MAX_COUNT = 50;
const _REMOTE_URL_PREFIX_RE = /^(?:https?:|file:|ftp:|\\\\|\.\.\/)/i;

function decodeXmlEntities(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function extractTextParagraphs(xml) {
  const out = [];
  const re = /<text:p\b[^>]*>([\s\S]*?)<\/text:p>/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const inner = m[1].replace(/<[^>]+>/g, '');
    const decoded = decodeXmlEntities(inner).trim();
    if (decoded) out.push(decoded);
  }
  return out;
}

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

async function parseOdp(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const texts = [];
  const hiddenFindings = [];

  // --- content.xml ---
  const contentEntry = zip.file('content.xml');
  if (contentEntry) {
    const xml = await contentEntry.async('string');
    const pages = extractDrawPages(xml);
    for (const page of pages) {
      const slideLabel = `Slide ${page.index} (${page.name})`;
      const bodyParas = extractTextParagraphs(page.body);
      if (bodyParas.length > 0) {
        texts.push(`[${slideLabel}] ` + bodyParas.join(' '));
      }

      // Speaker notes
      const notesRe = /<presentation:notes\b[^>]*>([\s\S]*?)<\/presentation:notes>/g;
      let nm;
      while ((nm = notesRe.exec(page.body)) !== null) {
        const noteParas = extractTextParagraphs(nm[1]);
        const noteText = noteParas.join(' ');
        if (noteText.trim()) {
          texts.push(`[${slideLabel} Notes] ` + noteText);
          if (looksLikeInstruction(noteText)) {
            hiddenFindings.push({
              element: `Speaker Note (${slideLabel})`,
              technique: 'odp-notes-prompt-injection',
              content: escapeForDisplay(noteText.slice(0, 200)),
              severity: 'danger',
              category: 'suspiciousPatterns',
              contextLocation: `${slideLabel} > Notes`,
              meta: { slideIndex: page.index },
            });
          }
        }
      }

      // Transitions: macro/script-linked event listeners or sound
      const evRe = /<presentation:event-listener\b([^>]*)>|<presentation:sound\b([^>]*)\/?\s*>/g;
      let em;
      while ((em = evRe.exec(page.body)) !== null) {
        const attrs = em[1] || em[2] || '';
        const hrefMatch = attrs.match(/\bxlink:href\s*=\s*"([^"]*)"/);
        if (!hrefMatch) continue;
        const href = decodeXmlEntities(hrefMatch[1]);
        if (/^(?:vnd\.sun\.star\.script:|javascript:|macro:)/i.test(href)) {
          hiddenFindings.push({
            element: slideLabel,
            technique: 'odp-slide-transition-macro',
            content: escapeForDisplay(href.slice(0, 200)),
            severity: 'danger',
            category: 'suspiciousPatterns',
            contextLocation: `${slideLabel} > transition`,
            meta: { scriptHref: escapeForDisplay(href.slice(0, 500)) },
          });
        }
      }

      // Embedded external draw:object
      const objRe = /<draw:object(?:-ole)?\b([^>]*?)\/?\s*>/g;
      let om;
      while ((om = objRe.exec(page.body)) !== null) {
        const attrs = om[1] || '';
        const hrefMatch = attrs.match(/\bxlink:href\s*=\s*"([^"]*)"/);
        if (!hrefMatch) continue;
        const href = decodeXmlEntities(hrefMatch[1]);
        if (!_REMOTE_URL_PREFIX_RE.test(href)) continue;
        hiddenFindings.push({
          element: slideLabel,
          technique: 'odp-embedded-object-external',
          content: escapeForDisplay(href.slice(0, 200)),
          severity: 'warning',
          category: 'suspiciousPatterns',
          contextLocation: `${slideLabel} > draw:object`,
          meta: { objectHref: escapeForDisplay(href.slice(0, 500)) },
        });
      }
    }
  }

  // --- styles.xml master pages ---
  const stylesEntry = zip.file('styles.xml');
  if (stylesEntry) {
    const sxml = await stylesEntry.async('string');
    const masterRe = /<style:master-page\b([^>]*)>([\s\S]*?)<\/style:master-page>/g;
    let mm;
    let masterIdx = 0;
    while ((mm = masterRe.exec(sxml)) !== null) {
      masterIdx += 1;
      const attrs = mm[1];
      const body = mm[2];
      const nameMatch = attrs.match(/\bstyle:name\s*=\s*"([^"]*)"/);
      const masterName = nameMatch ? decodeXmlEntities(nameMatch[1]) : `master${masterIdx}`;
      const paras = extractTextParagraphs(body);
      const masterText = paras.join(' ');
      if (!masterText.trim()) continue;
      texts.push(`[Master ${masterIdx} (${masterName})] ` + masterText);
      if (looksLikeInstruction(masterText)) {
        hiddenFindings.push({
          element: `Master Page (${masterName})`,
          technique: 'odp-master-slide-instruction',
          content: escapeForDisplay(masterText.slice(0, 200)),
          severity: 'warning',
          category: 'suspiciousPatterns',
          contextLocation: `Master ${masterIdx} (${masterName})`,
          meta: { masterIndex: masterIdx, masterName: escapeForDisplay(masterName.slice(0, 100)) },
        });
      }
    }
  }

  // --- settings.xml: external xlink:href surface ---
  const settingsEntry = zip.file('settings.xml');
  if (settingsEntry) {
    const stext = await settingsEntry.async('string');
    const hrefRe = /\bxlink:href\s*=\s*"([^"]*)"/g;
    let sm;
    while ((sm = hrefRe.exec(stext)) !== null) {
      const href = decodeXmlEntities(sm[1]);
      if (!_REMOTE_URL_PREFIX_RE.test(href)) continue;
      hiddenFindings.push({
        element: 'ODP settings.xml',
        technique: 'odp-embedded-object-external',
        content: escapeForDisplay(href.slice(0, 200)),
        severity: 'warning',
        category: 'suspiciousPatterns',
        contextLocation: 'settings.xml',
        meta: { objectHref: escapeForDisplay(href.slice(0, 500)) },
      });
    }
  }

  // --- Pictures/* embedded image scan ---
  const mediaFiles = Object.keys(zip.files).filter(f => /^Pictures\/[^/]+$/.test(f));
  let mediaProcessed = 0;
  for (const mediaPath of mediaFiles) {
    if (mediaProcessed >= _OFFICE_MEDIA_MAX_COUNT) break;
    const ext = _extOf(mediaPath.replace(/^Pictures\//, ''));
    if (!_PDF_IMAGE_EXTS.has(ext)) continue;
    const entry = zip.file(mediaPath);
    if (!entry) continue;
    const mediaName = mediaPath.replace(/^Pictures\//, '');
    let buf;
    try { buf = await entry.async('uint8array'); } catch { continue; }
    if (buf.byteLength === 0) {
      hiddenFindings.push({
        element: 'ODP Embedded Image',
        technique: 'empty-embedded-image',
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: 'warning',
        contextLocation: `ODP Pictures:${mediaName}`,
      });
      mediaProcessed++;
      continue;
    }
    if (buf.byteLength > _OFFICE_MEDIA_MAX_BYTES) {
      hiddenFindings.push({
        element: 'ODP Embedded Image',
        technique: 'oversize-embedded-image',
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: 'warning',
        contextLocation: `ODP Pictures:${mediaName}`,
        meta: { maxBytes: _OFFICE_MEDIA_MAX_BYTES },
      });
      mediaProcessed++;
      continue;
    }
    let sub;
    try { sub = await parseImage(buf, ext); } catch { mediaProcessed++; continue; }
    mediaProcessed++;
    if (!sub) continue;
    if (sub.text && sub.text.trim()) {
      texts.push(`[ODP Pictures:${mediaName}]`);
      texts.push(sub.text);
    }
    if (Array.isArray(sub.hiddenFindings)) {
      for (const f of sub.hiddenFindings) {
        const existing = typeof f.contextLocation === 'string' ? f.contextLocation : '';
        hiddenFindings.push({
          ...f,
          contextLocation: existing
            ? `ODP Pictures:${mediaName} > ${existing}`
            : `ODP Pictures:${mediaName}`,
        });
      }
    }
  }

  return { text: texts.join('\n'), fileType: 'text', hiddenFindings };
}

export { parseOdp };
