// DOCX parser - extracted from index.html L1707-L1935
// Depends on global: JSZip (CDN), parseImage (for embedded media), _extOf, _PDF_IMAGE_EXTS
// Depends on core: escapeForDisplay, looksLikeInstruction
import { escapeForDisplay, looksLikeInstruction } from '@shield-scanner/core';
import { parseImage } from './image.js';
import { _extOf, _PDF_IMAGE_EXTS } from './pdf.js';

async function parseDocx(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const texts = [];
  const hiddenFindings = [];

  // Main document body
  const docXml = zip.file('word/document.xml');
  if (docXml) {
    const xml = await docXml.async('string');
    // Extract text from <w:t> tags
    const textMatches = xml.match(/<w:t[^>]*>([^<]*)<\/w:t>/gi) || [];
    textMatches.forEach(m => {
      const inner = m.replace(/<[^>]+>/g, '');
      if (inner) texts.push(inner);
    });

    // Detect hidden text: <w:vanish/> or <w:vanish w:val="true"/>
    const vanishRegex = /<w:rPr>[^]*?<w:vanish(?:\s[^/]*)?\/?>[^]*?<\/w:rPr>[^]*?<w:t[^>]*>([^<]*)<\/w:t>/gi;
    let vm;
    while ((vm = vanishRegex.exec(xml)) !== null) {
      if (vm[1] && vm[1].trim()) {
        hiddenFindings.push({
          element: 'w:r (Word run)',
          technique: 'Hidden text (w:vanish)',
          content: escapeForDisplay(vm[1].slice(0, 200)),
          severity: 'danger',
        });
      }
    }

    // Detect white/transparent font color hiding
    const colorHideRegex = /<w:rPr>[^]*?<w:color\s+w:val="(?:FFFFFF|ffffff)"[^/]*\/>[^]*?<\/w:rPr>[^]*?<w:t[^>]*>([^<]*)<\/w:t>/gi;
    let cm;
    while ((cm = colorHideRegex.exec(xml)) !== null) {
      if (cm[1] && cm[1].trim()) {
        hiddenFindings.push({
          element: 'w:r (Word run)',
          technique: 'White font color (#FFFFFF)',
          content: escapeForDisplay(cm[1].slice(0, 200)),
          severity: 'danger',
        });
      }
    }

    // Detect extremely small font size (< 4pt = w:sz val < 8 half-points)
    // v1.13.0 Theme docx-microscopic: kebab-case technique id + meta.fontSize
    // (Number, point value). Mirrors MCP parser + PDF Theme A microscopic-text
    // pattern — R12 invariant (no dynamic numeric value in technique label).
    // UI formats via formatTechniqueWithMeta in app.js → i18n placeholder.
    const tinyFontRegex = /<w:rPr>[^]*?<w:sz\s+w:val="([0-3])"[^/]*\/>[^]*?<\/w:rPr>[^]*?<w:t[^>]*>([^<]*)<\/w:t>/gi;
    let tf;
    while ((tf = tinyFontRegex.exec(xml)) !== null) {
      if (tf[2] && tf[2].trim()) {
        hiddenFindings.push({
          element: 'w:r (Word run)',
          technique: 'microscopic-font-size',
          meta: { fontSize: parseInt(tf[1], 10) / 2 },
          content: escapeForDisplay(tf[2].slice(0, 200)),
          severity: 'danger',
        });
      }
    }

    // v1.14.0 ext-2 (DOCX shape textbox microscopic): wps:txbxContent is the
    // WordprocessingShape textbox payload (xmlns:wps=
    // "http://schemas.microsoft.com/office/word/2010/wordprocessingShape").
    // Mirrors MCP parser byte-identical — re-scan only the shape blocks with
    // the same regex and rewrite the element label to
    // 'w:r (Word run, shape textbox)' so consumers can trace shape provenance.
    // Replaces any already-emitted plain 'w:r (Word run)' finding whose
    // content+meta matches a shape-textbox hit to avoid double-counting.
    const shapeBlockRegex = /<wps:txbxContent\b[^>]*>([\s\S]*?)<\/wps:txbxContent>/gi;
    let sb;
    while ((sb = shapeBlockRegex.exec(xml)) !== null) {
      const inner = sb[1];
      if (!inner) continue;
      const shapeTinyRegex = /<w:rPr>[^]*?<w:sz\s+w:val="([0-3])"[^/]*\/>[^]*?<\/w:rPr>[^]*?<w:t[^>]*>([^<]*)<\/w:t>/gi;
      let stf;
      while ((stf = shapeTinyRegex.exec(inner)) !== null) {
        if (!stf[2] || !stf[2].trim()) continue;
        const displayContent = escapeForDisplay(stf[2].slice(0, 200));
        const fontSize = parseInt(stf[1], 10) / 2;
        const dupIdx = hiddenFindings.findIndex(
          (f) =>
            f.technique === 'microscopic-font-size' &&
            f.element === 'w:r (Word run)' &&
            f.content === displayContent &&
            f.meta &&
            f.meta.fontSize === fontSize,
        );
        if (dupIdx >= 0) {
          hiddenFindings[dupIdx] = {
            ...hiddenFindings[dupIdx],
            element: 'w:r (Word run, shape textbox)',
          };
        } else {
          hiddenFindings.push({
            element: 'w:r (Word run, shape textbox)',
            technique: 'microscopic-font-size',
            meta: { fontSize },
            content: displayContent,
            severity: 'danger',
          });
        }
      }
    }

    // S8 (Web mirror): Tracked-change deletion residue (<w:del> / <w:delText>).
    // Mirrors shield-scanner-mcp/server/parsers/docx.js. Severity warning by
    // default (legitimate during review); upgraded to danger when the
    // residue text looksLikeInstruction.
    const delRegex = /<w:delText[^>]*>([^<]*)<\/w:delText>/gi;
    let dm;
    while ((dm = delRegex.exec(xml)) !== null) {
      const inner = dm[1];
      if (!inner || !inner.trim()) continue;
      const severity = looksLikeInstruction(inner) ? 'danger' : 'warning';
      hiddenFindings.push({
        element: 'w:del (Tracked-change deletion)',
        technique: 'Tracked-change deletion residue (w:del/w:delText)',
        content: escapeForDisplay(inner.slice(0, 200)),
        severity,
      });
    }

    // S8 (Web mirror): Word field instructions (<w:instrText>). HYPERLINK /
    // MERGEFIELD / INCLUDETEXT etc. can carry attack URLs or include
    // external content invisible at first read. Benign field codes filtered.
    const BENIGN_FIELD_HEAD =
      /^(PAGE|NUMPAGES|TIME|DATE|TOC|REF|PAGEREF|NOTEREF|STYLEREF|SEQ|SET|IF|LISTNUM|FORMTEXT|FORMCHECKBOX|FORMDROPDOWN|SYMBOL|NUMERIC|FILLIN)(\s|$)/i;
    const instrRegex = /<w:instrText[^>]*>([^<]*)<\/w:instrText>/gi;
    let im;
    while ((im = instrRegex.exec(xml)) !== null) {
      const inner = im[1];
      if (!inner || !inner.trim()) continue;
      const trimmed = inner.trim();
      // S8-DOCX-001 fix: SET/IF/FILLIN take user-controlled string arguments
      // so a head-only whitelist would let attack URLs and prompt-injection
      // payloads slip through. Always run the URL / instruction-shape checks
      // first; only suppress when the head is benign AND no danger signal
      // is present in the args.
      const hasUrl = /(?:https?|javascript|data|file|vbscript):/i.test(inner);
      const looksInst = looksLikeInstruction(inner);
      if (BENIGN_FIELD_HEAD.test(trimmed) && !hasUrl && !looksInst) continue;
      // HYPERLINK / INCLUDETEXT with URL = danger; instruction-shaped also
      // danger; otherwise warning so unusual fields still surface.
      let severity = 'warning';
      if (hasUrl || looksInst) severity = 'danger';
      hiddenFindings.push({
        element: 'w:instrText (Word field)',
        technique: 'Field instruction (HYPERLINK / MERGEFIELD / etc.)',
        content: escapeForDisplay(inner.slice(0, 200)),
        severity,
      });
    }
  }

  // S8 (Web mirror): Custom document properties (docProps/custom.xml). Only
  // surface string-valued props (vt:lpwstr / vt:lpstr) that looksLikeInstruction.
  // Category: suspiciousPatterns (text-pattern based, not structural).
  const customXmlEntry = zip.file('docProps/custom.xml');
  if (customXmlEntry) {
    const cxml = await customXmlEntry.async('string');
    // S8-DOCX-002 fix: two-stage scan so vt:vector and multiple sibling
    // vt:lpwstr / vt:lpstr children inside one <property> are all enumerated.
    // The previous single-regex approach captured only the first string-typed
    // child per <property>, silently dropping later vector elements (the
    // typical attacker shape).
    const propBlockRegex =
      /<property\b[^>]*\bname="([^"]+)"[^>]*>([\s\S]*?)<\/property>/gi;
    const stringChildRegex =
      /<vt:(lpwstr|lpstr)\b[^>]*>([\s\S]*?)<\/vt:\1>/gi;
    let pm;
    while ((pm = propBlockRegex.exec(cxml)) !== null) {
      const name = pm[1];
      const propInner = pm[2];
      stringChildRegex.lastIndex = 0;
      let sm;
      while ((sm = stringChildRegex.exec(propInner)) !== null) {
        const value = sm[2];
        if (!value || !value.trim()) continue;
        if (!looksLikeInstruction(value)) continue;
        hiddenFindings.push({
          element: `docProps custom:${escapeForDisplay(name)}`,
          technique: 'Custom property with instruction-like text',
          content: escapeForDisplay(value.slice(0, 200)),
          severity: 'warning',
          category: 'suspiciousPatterns',
        });
      }
    }
  }

  // Check comments (word/comments.xml)
  const commentsXml = zip.file('word/comments.xml');
  if (commentsXml) {
    const cxml = await commentsXml.async('string');
    const commentTexts = cxml.match(/<w:t[^>]*>([^<]*)<\/w:t>/gi) || [];
    const commentContent = commentTexts.map(m => m.replace(/<[^>]+>/g, '')).join(' ');
    if (commentContent.trim() && looksLikeInstruction(commentContent)) {
      hiddenFindings.push({
        element: 'Word Comment',
        technique: 'Comment with instruction-like text',
        content: escapeForDisplay(commentContent.slice(0, 200)),
        severity: 'warning',
      });
    }
    texts.push('[COMMENT] ' + commentContent);
  }

  // Check headers/footers
  const headerFooterFiles = Object.keys(zip.files).filter(f =>
    f.match(/^word\/(header|footer)\d*\.xml$/)
  );
  for (const hf of headerFooterFiles) {
    const hfXml = await zip.file(hf).async('string');
    const hfTexts = hfXml.match(/<w:t[^>]*>([^<]*)<\/w:t>/gi) || [];
    hfTexts.forEach(m => {
      const inner = m.replace(/<[^>]+>/g, '');
      if (inner) texts.push(inner);
    });
  }

  // S12-XR-02: embedded images in word/media/* must be scanned for EXIF/XMP/
  // IPTC/zTXt/iTXt prompt-injection. Same envelope as PDF S12-XR-01:
  // - per-image 5 MB cap, per-archive 50 media-count cap (zip-bomb guard)
  // - extension allow-list mirrors _PDF_IMAGE_EXTS
  // - extracted text appended; image hiddenFindings hoisted with
  //   contextLocation prefix `DOCX media:<filename>`.
  const _OFFICE_MEDIA_MAX_BYTES = 5 * 1024 * 1024;
  const _OFFICE_MEDIA_MAX_COUNT = 50;
  const mediaFiles = Object.keys(zip.files).filter(f => /^word\/media\/[^/]+$/.test(f));
  let mediaProcessed = 0;
  for (const mediaPath of mediaFiles) {
    if (mediaProcessed >= _OFFICE_MEDIA_MAX_COUNT) break;
    const ext = _extOf(mediaPath.replace(/^word\/media\//, ''));
    if (!_PDF_IMAGE_EXTS.has(ext)) continue;
    const entry = zip.file(mediaPath);
    if (!entry) continue;
    const mediaName = mediaPath.replace(/^word\/media\//, '');
    let buf;
    try {
      buf = await entry.async('uint8array');
    } catch { continue; }
    if (buf.byteLength > _OFFICE_MEDIA_MAX_BYTES) {
      hiddenFindings.push({
        element: 'DOCX Embedded Image',
        technique: `Oversize embedded image skipped (> ${_OFFICE_MEDIA_MAX_BYTES} bytes)`,
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: 'warning',
        contextLocation: `DOCX media:${mediaName}`,
      });
      mediaProcessed++;
      continue;
    }
    let sub;
    try { sub = await parseImage(buf, ext); } catch { mediaProcessed++; continue; }
    mediaProcessed++;
    if (!sub) continue;
    if (sub.text && sub.text.trim()) {
      texts.push(`[DOCX media:${mediaName}]`);
      texts.push(sub.text);
    }
    if (Array.isArray(sub.hiddenFindings)) {
      for (const f of sub.hiddenFindings) {
        const existing = typeof f.contextLocation === 'string' ? f.contextLocation : '';
        hiddenFindings.push({
          ...f,
          contextLocation: existing
            ? `DOCX media:${mediaName} > ${existing}`
            : `DOCX media:${mediaName}`,
        });
      }
    }
  }

  return { text: texts.join('\n'), hiddenFindings };
}

export { parseDocx };
