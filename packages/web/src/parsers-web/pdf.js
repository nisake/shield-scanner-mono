// PDF parser - extracted from index.html L1937-L2173
// Depends on global: pdfjsLib (CDN)
// Depends on core: escapeForDisplay, sanitizeContextLocation
import {
  escapeForDisplay,
  sanitizeContextLocation,
  walkStructTree,
  sanitizeStructKey,
} from '@shield-scanner/core';
import { parseDocx } from './docx.js';
import { parsePptx } from './pptx.js';
import { parseImage } from './image.js';

// S7 Stage A: extract page text + annotations (Highlight/FreeText/Popup/
// Squiggly/Stamp/Link) + AcroForm field values + XMP/info metadata; append
// each with a `[PDF k1=v1 k2=v2] ` header so the central pattern detector
// covers them uniformly.
// S7 Stage B: recursively scan EMBEDDED FILE attachments (text-family
// extensions only — pdf/docx/pptx/html/md/txt/json/csv/xml/svg). EML is
// MCP-only because the web bundle has no MIME parser; EML attachments
// surface as a filename-only warning so users still see the channel.
// Depth bound: _PDF_RECURSION_LIMIT = 2. Findings from a recursive scan
// are hoisted into the parent's hiddenFindings list, location-tagged with
// `Attachment <filename>` (prefixed in front of any existing contextLocation).
// S20: extraFindings carry `contextLocation: "Page N"`.
// PDF-DEEP-04 (Web mirror): Widget + FileAttachment annotations added.
// Mirrors the MCP-side set so parity-check drift stays 0. Widget dedupes
// against the AcroForm fieldName registry; FileAttachment dedupes against
// the catalog getAttachments key.
const _PDF_ANN_SUBTYPES = new Set([
  'Highlight','FreeText','Popup','Squiggly','Stamp','Link',
  'Widget','FileAttachment',
]);
const _PDF_RECURSION_LIMIT = 2;
// Kept in sync with the MCP server's RECURSIVE_EXTS (parsers/pdf.js).
// Adding an extension on one side without echoing it on the other silently
// drops matching PDF attachments at Stage B.
// S12 fix (S12-XR-01): image extensions added so PDF-embedded JPEG/PNG/WebP/
// GIF/TIFF attachments are routed through _dispatchAttachmentBuffer →
// parseImage, surfacing EXIF/XMP/IPTC/zTXt/iTXt prompt-injection that
// previously slipped through. The existing 5MB byteLength cap below applies
// uniformly to image attachments.
const _PDF_RECURSIVE_TEXT_EXTS = new Set([
  'txt','md','mdc','cursorrules',
  'html','htm','xml','svg',
  'pdf','docx','pptx',
  'json','csv',
  // S12: image attachments — parsed via _dispatchAttachmentBuffer → parseImage.
  'jpg','jpeg','png','webp','gif','tiff','tif',
]);
const _PDF_IMAGE_EXTS = new Set(['jpg','jpeg','png','webp','gif','tiff','tif']);
function _sanitizePdfKey(s) { return String(s).replace(/[\s\[\]]+/g, '_').slice(0, 64); }
// Mirrors Node's path.extname() so the Web Stage B dispatcher matches the
// MCP server's `extname(filename).slice(1).toLowerCase()` exactly. The naive
// `split('.').pop()` drifts on dotfiles (`.cursorrules` -> 'cursorrules'),
// extensionless names (`README` -> 'README'), and trailing dots (`foo.` ->
// ''/'foo'), which would either dispatch to the wrong parser or emit a
// spurious binary-attachment warning. Contract: leading-dot-only, no dot,
// or trailing-dot returns ''. Lowercased so callers don't have to.
function _extOf(filename) {
  const s = String(filename == null ? '' : filename);
  const i = s.lastIndexOf('.');
  if (i <= 0) return '';            // no dot, or dotfile (.cursorrules)
  if (i === s.length - 1) return '';// trailing dot (foo.)
  return s.slice(i + 1).toLowerCase();
}
// Cap on attachment buffer size before any decode / nested parse. A 500MB
// embedded .txt would OOM the tab; we surface a single warning and skip.
const _PDF_MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
function _utf8Decode(buffer) {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(
      buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
    );
  } catch { return ''; }
}
// Web-side mirror of MCP's dispatchBuffer (parsers/index.js). Only the
// extensions in _PDF_RECURSIVE_TEXT_EXTS are routed; everything else
// returns null so the caller can fall back to a filename-only finding.
// `depth` is forwarded to nested parsePdf so the recursion limit holds
// across PDF-in-PDF chains.
async function _dispatchAttachmentBuffer(buffer, ext, depth) {
  const e = (ext || '').toLowerCase();
  if (!_PDF_RECURSIVE_TEXT_EXTS.has(e)) return null;
  if (e === 'pdf') return parsePdf(buffer, { depth });
  if (e === 'docx') return parseDocx(buffer);
  if (e === 'pptx') return parsePptx(buffer);
  // S12 fix (S12-XR-01): image attachments — parseImage takes (buffer, ext)
  // and returns { text, hiddenFindings } with the same shape, so the caller's
  // text-hoist + finding-prefix logic works without any further branching.
  if (_PDF_IMAGE_EXTS.has(e)) return parseImage(buffer, e);
  const text = _utf8Decode(buffer);
  if (e === 'md' || e === 'mdc' || e === 'cursorrules') {
    return { text, hiddenFindings: [], fileType: 'markdown' };
  }
  if (e === 'html' || e === 'htm' || e === 'xml' || e === 'svg') {
    return { text, hiddenFindings: [], fileType: 'html' };
  }
  // txt / csv / json — plain text.
  return { text, hiddenFindings: [], fileType: 'text' };
}
async function parsePdf(buffer, options) {
  const depth = options && Number.isInteger(options.depth) ? options.depth : 0;
  const uint8 = new Uint8Array(buffer);
  const pdf = await pdfjsLib.getDocument({ data: uint8 }).promise;
  const texts = [];
  const hiddenFindings = [];

  // PDF-DEEP-05 (Web mirror): emit struct-tree-cap-exceeded at most once.
  let structTreeCapExceeded = false;

  // PDF-DEEP-04 (Web mirror): dedup sets shared across per-page + catalog.
  // Pre-seed AcroForm fieldNames so Widget annotations on earlier pages
  // skip a name AcroForm will emit later (MCP parity).
  const seenFieldNames = new Set();
  const seenAttachKey = new Set();
  try {
    if (typeof pdf.getFieldObjects === 'function') {
      const fields = await pdf.getFieldObjects();
      if (fields && typeof fields === 'object') {
        for (const name of Object.keys(fields)) {
          seenFieldNames.add(String(name));
        }
      }
    }
  } catch (e) { /* ignore */ }

  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const textContent = await page.getTextContent();
    const pageText = textContent.items.map(item => item.str).join(' ');
    if (pageText.trim()) texts.push(pageText);

    // Microscopic / invisible text per item.
    textContent.items.forEach(item => {
      if (item.str && item.str.trim()) {
        if (item.height !== undefined && item.height < 1 && item.height > 0) {
          hiddenFindings.push({
            element: `PDF Page ${i}`,
            technique: 'microscopic-text',
            meta: { height: item.height },
            content: escapeForDisplay(item.str.slice(0, 200)),
            severity: 'danger',
            contextLocation: `Page ${i}`,
          });
        }
      }
    });

    // S7 Stage A: annotations.
    try {
      const annots = await page.getAnnotations();
      for (const a of (annots || [])) {
        if (!a || !a.subtype || !_PDF_ANN_SUBTYPES.has(a.subtype)) continue;
        const contents = (a.contents || (a.contentsObj && a.contentsObj.str) || '').trim();
        const url = (a.url || '').trim();
        if (contents) texts.push(`[PDF page=${i} kind=annotation subtype=${a.subtype}] ${contents}`);
        if (url) texts.push(`[PDF page=${i} kind=annotation subtype=${a.subtype} url] ${url}`);

        // PDF-DEEP-04 (Web mirror): Widget annotation (AcroForm UI surface).
        if (a.subtype === 'Widget') {
          const fname = typeof a.fieldName === 'string' ? a.fieldName : '';
          if (!fname || !seenFieldNames.has(fname)) {
            if (fname) seenFieldNames.add(fname);
            const fvalue = typeof a.fieldValue === 'string' ? a.fieldValue : '';
            const alt = typeof a.alternativeText === 'string' ? a.alternativeText : '';
            if (fname && fvalue.trim()) {
              texts.push(`[PDF page=${i} kind=widget field=${_sanitizePdfKey(fname)}] ${fvalue}`);
            }
            if (alt.trim()) {
              texts.push(`[PDF page=${i} kind=widget-alt field=${_sanitizePdfKey(fname || '_')}] ${alt}`);
            }
            if (a.actions && typeof a.actions === 'object') {
              for (const [act, bodies] of Object.entries(a.actions)) {
                if (!Array.isArray(bodies)) continue;
                for (const body of bodies) {
                  if (typeof body === 'string' && body.trim()) {
                    texts.push(`[PDF page=${i} kind=widget-action field=${_sanitizePdfKey(fname || '_')} act=${_sanitizePdfKey(act)}] ${body}`);
                  }
                }
              }
            }
          }
        }

        // PDF-DEEP-04 (Web mirror): FileAttachment annotation.
        if (a.subtype === 'FileAttachment') {
          const fl = a.file || {};
          const afname = (typeof fl.filename === 'string' && fl.filename) ||
            (typeof a.attachmentDest === 'string' && a.attachmentDest) || '';
          const key = afname || `_page${i}_${a.id || ''}`;
          if (!seenAttachKey.has(key)) {
            seenAttachKey.add(key);
            if (afname) {
              texts.push(`[PDF page=${i} kind=fileattachment filename=${_sanitizePdfKey(afname)}]`);
            }
          }
        }
      }
    } catch (e) { /* annotation errors non-fatal */ }

    // PDF-DEEP-05 (Web mirror): structure-tree /Alt /ActualText (per page).
    try {
      if (typeof page.getStructTree === 'function') {
        const tree = await page.getStructTree();
        if (tree && typeof tree === 'object') {
          const { records, capExceeded } = walkStructTree(tree);
          for (const rec of records) {
            // R12: alt / actualText are attacker-controlled. texts.push wraps
            // the body for the central detectors; contextLocation uses only the
            // role enum + fixed field name.
            if (rec.alt) {
              texts.push(`[PDF page=${i} kind=structtree role=${sanitizeStructKey(rec.role)} field=Alt] ${rec.alt}`);
            }
            if (rec.actualText) {
              texts.push(`[PDF page=${i} kind=structtree role=${sanitizeStructKey(rec.role)} field=ActualText] ${rec.actualText}`);
            }
          }
          if (capExceeded && !structTreeCapExceeded) {
            structTreeCapExceeded = true;
            hiddenFindings.push({
              element: 'PDF Catalog',
              technique: 'struct-tree-cap-exceeded',
              content: '(structure tree walk halted at cap)',
              severity: 'warning',
              contextLocation: 'Catalog',
            });
          }
        }
      }
    } catch (e) { /* struct-tree errors non-fatal — many PDFs lack one */ }
  }

  // S7 Stage A: AcroForm field values.
  try {
    if (typeof pdf.getFieldObjects === 'function') {
      const fields = await pdf.getFieldObjects();
      if (fields && typeof fields === 'object') {
        for (const [name, entries] of Object.entries(fields)) {
          // PDF-DEEP-04: register all field names so Widget annotations
          // don't double-emit them.
          seenFieldNames.add(String(name));
          if (!Array.isArray(entries)) continue;
          for (const entry of entries) {
            const value = entry && entry.value;
            if (typeof value === 'string' && value.trim()) {
              texts.push(`[PDF kind=acroform field=${_sanitizePdfKey(name)}] ${value}`);
            }
          }
        }
      }
    }
  } catch (e) { /* ignore */ }

  // S7 Stage A: PDF Info dict + XMP raw metadata.
  try {
    const metadata = await pdf.getMetadata();
    if (metadata) {
      if (metadata.info && typeof metadata.info === 'object') {
        for (const [key, value] of Object.entries(metadata.info)) {
          if (typeof value === 'string' && value.trim()) {
            texts.push(`[PDF kind=info key=${_sanitizePdfKey(key)}] ${value}`);
          }
        }
      }
      if (metadata.metadata) {
        try {
          const all = typeof metadata.metadata.getAll === 'function'
            ? metadata.metadata.getAll() : null;
          if (all && typeof all === 'object') {
            for (const [key, value] of Object.entries(all)) {
              if (typeof value === 'string' && value.trim()) {
                texts.push(`[PDF kind=xmp key=${_sanitizePdfKey(key)}] ${value}`);
              }
            }
          }
        } catch (e) { /* ignore */ }
      }
    }
  } catch (e) { /* ignore metadata errors */ }

  // PDF-DEEP-01 (Web mirror): catalog-level JavaScript actions.
  try {
    if (typeof pdf.getJSActions === 'function') {
      const jsActions = await pdf.getJSActions();
      if (jsActions && typeof jsActions === 'object') {
        let hadAny = false;
        for (const [name, bodies] of Object.entries(jsActions)) {
          if (!Array.isArray(bodies)) continue;
          for (const body of bodies) {
            if (typeof body === 'string' && body.trim()) {
              hadAny = true;
              texts.push(`[PDF kind=jsaction name=${_sanitizePdfKey(name)}] ${body}`);
            }
          }
        }
        if (hadAny) {
          hiddenFindings.push({
            element: 'PDF Catalog',
            technique: 'PDF embeds JavaScript actions',
            content: '(see jsaction body in scan text)',
            severity: 'warning',
            contextLocation: 'Catalog',
          });
        }
      }
    }
  } catch (e) { /* ignore */ }

  // PDF-DEEP-02 (Web mirror): catalog /OpenAction (auto-launch).
  try {
    if (typeof pdf.getOpenAction === 'function') {
      const oa = await pdf.getOpenAction();
      if (oa && typeof oa === 'object') {
        let stringified = '';
        try { stringified = JSON.stringify(oa); } catch (e) { stringified = String(oa); }
        if (stringified && stringified !== '{}' && stringified !== 'null') {
          texts.push(`[PDF kind=openaction] ${stringified}`);
        }
      }
    }
  } catch (e) { /* ignore */ }

  // PDF-DEEP-03 (Web mirror): catalog /Outlines (bookmarks).
  try {
    if (typeof pdf.getOutline === 'function') {
      const outline = await pdf.getOutline();
      if (Array.isArray(outline) && outline.length) {
        const MAX_DEPTH = 5;
        const MAX_NODES = 256;
        let nodeCount = 0;
        const walk = (nodes, d) => {
          if (!Array.isArray(nodes)) return;
          if (d > MAX_DEPTH) return;
          for (const n of nodes) {
            if (nodeCount >= MAX_NODES) return;
            nodeCount++;
            if (n && typeof n === 'object') {
              const title = typeof n.title === 'string' ? n.title : '';
              const u = typeof n.unsafeUrl === 'string' ? n.unsafeUrl : '';
              if (title.trim()) texts.push(`[PDF kind=outline depth=${d}] ${title}`);
              if (u.trim()) texts.push(`[PDF kind=outline-url depth=${d}] ${u}`);
              if (Array.isArray(n.items) && n.items.length) {
                walk(n.items, d + 1);
              }
            }
          }
        };
        walk(outline, 0);
      }
    }
  } catch (e) { /* ignore */ }

  // S7 Stage B: recurse into embedded file attachments. PDF.js's
  // `pdf.getAttachments()` returns a `{ key: { filename, content, ... } }`
  // map; we filter by extension to text-family files only (binaries are
  // skipped to keep memory bounded). The depth bound stops PDF-in-PDF
  // bombs from blowing up the scan.
  if (depth < _PDF_RECURSION_LIMIT) {
    let attachments = null;
    try { attachments = await pdf.getAttachments(); }
    catch { attachments = null; }
    if (attachments && typeof attachments === 'object') {
      for (const [key, att] of Object.entries(attachments)) {
        const filename = (att && att.filename) || key;
        const content = att && att.content;
        if (!content || !filename) continue;
        // PDF-DEEP-04: register catalog attachment so per-page FileAttachment
        // annotations carrying the same filename don't double-count.
        seenAttachKey.add(String(filename));
        // PDF-EML-FILENAME-CONTEXTLOC-SANITIZE: sanitize before threading
        // filename into contextLocation.
        const safeFilename = sanitizeContextLocation(filename);
        // Size short-circuit: before any decode or nested parse, drop
        // attachments larger than _PDF_MAX_ATTACHMENT_BYTES with a single
        // hoisted warning. Keeps the tab alive against 500MB embeds.
        const byteLen = (content && typeof content.byteLength === 'number') ? content.byteLength : 0;
        if (byteLen > _PDF_MAX_ATTACHMENT_BYTES) {
          hiddenFindings.push({
            element: 'PDF Attachment',
            technique: 'Oversize attachment skipped (> 5MB)',
            content: escapeForDisplay(filename.slice(0, 200)),
            severity: 'warning',
            contextLocation: `Attachment ${safeFilename}`,
          });
          continue;
        }
        const ext = _extOf(filename);
        // MCP parity: extname returns '' for dotfiles (`.cursorrules`),
        // extensionless names (`README`, `Makefile`), and trailing dots.
        // MCP silently continues in that case, so we mirror — no warning.
        if (ext === '') continue;
        if (!_PDF_RECURSIVE_TEXT_EXTS.has(ext)) {
          // Non-text/binary attachment: surface its presence so reviewers
          // know the channel exists, but don't try to parse it.
          hiddenFindings.push({
            element: 'PDF Attachment',
            technique: 'Embedded binary attachment',
            content: escapeForDisplay(filename.slice(0, 200)),
            severity: 'warning',
            contextLocation: `Attachment ${safeFilename}`,
          });
          continue;
        }
        try {
          const sub = await _dispatchAttachmentBuffer(content, ext, depth + 1);
          if (!sub) continue;
          // PDF-EML-EMPTY-ATTACHMENT-CHANNEL: 0-byte attachment surfaced as
          // warning even with no text body.
          const childTextEmpty = !sub.text || !String(sub.text).trim();
          if (byteLen === 0 && childTextEmpty) {
            hiddenFindings.push({
              element: 'PDF Attachment',
              technique: 'Empty attachment',
              content: escapeForDisplay(filename.slice(0, 200)),
              severity: 'warning',
              contextLocation: `Attachment ${safeFilename}`,
            });
          }
          if (sub.text && sub.text.trim()) {
            texts.push(`[PDF kind=attachment filename=${_sanitizePdfKey(filename)}]`);
            texts.push(sub.text);
          }
          if (Array.isArray(sub.hiddenFindings)) {
            for (const f of sub.hiddenFindings) {
              const existing = typeof f.contextLocation === 'string' ? f.contextLocation : '';
              hiddenFindings.push({
                ...f,
                contextLocation: existing
                  ? `Attachment ${safeFilename} > ${existing}`
                  : `Attachment ${safeFilename}`,
              });
            }
          }
        } catch { /* malformed attachment — skip silently */ }
      }
    }
  }

  return { text: texts.join('\n'), hiddenFindings };
}

export { parsePdf, _extOf, _PDF_IMAGE_EXTS, _sanitizePdfKey, _utf8Decode, _dispatchAttachmentBuffer, _PDF_RECURSIVE_TEXT_EXTS, _PDF_RECURSION_LIMIT };
