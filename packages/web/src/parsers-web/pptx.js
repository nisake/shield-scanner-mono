// PPTX parser - extracted from index.html L3258-L3514
// Depends on global: JSZip (CDN)
// Depends on core: escapeForDisplay, looksLikeInstruction
import { escapeForDisplay, looksLikeInstruction } from '@shield-scanner/core';
import { parseImage } from './image.js';
import { _extOf, _PDF_IMAGE_EXTS } from './pdf.js';

function decodeXmlEntities(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}
// Pull every <p:cNvPr ...> descr / title attribute value, in document order.
function extractCNvPrAltText(xml) {
  const out = [];
  const tagRe = /<p:cNvPr\b([^>]*)>/g;
  let m;
  while ((m = tagRe.exec(xml)) !== null) {
    const attrs = m[1];
    const descrMatch = attrs.match(/\bdescr\s*=\s*"([^"]*)"|\bdescr\s*=\s*'([^']*)'/);
    const titleMatch = attrs.match(/\btitle\s*=\s*"([^"]*)"|\btitle\s*=\s*'([^']*)'/);
    if (descrMatch) {
      const v = decodeXmlEntities((descrMatch[1] != null ? descrMatch[1] : descrMatch[2]) || '').trim();
      if (v) out.push({ kind: 'descr', value: v });
    }
    if (titleMatch) {
      const v = decodeXmlEntities((titleMatch[1] != null ? titleMatch[1] : titleMatch[2]) || '').trim();
      if (v) out.push({ kind: 'title', value: v });
    }
  }
  return out;
}
// Push alt-text entries into the shared `texts` blob; only surface
// `instruction-looking` ones as hidden findings (alt text is a known
// smuggling surface but most alt text is legit accessibility metadata).
function collectAltText(xml, sectionLabel, elementLabel, texts, hiddenFindings) {
  const entries = extractCNvPrAltText(xml);
  if (entries.length === 0) return;
  texts.push(`[${sectionLabel} alt text] ` + entries.map(e => e.value).join(' '));
  for (const e of entries) {
    if (looksLikeInstruction(e.value)) {
      hiddenFindings.push({
        element: elementLabel,
        technique: `Alt text (${e.kind}=) with instruction-like content`,
        content: escapeForDisplay(e.value.slice(0, 200)),
        severity: 'warning',
      });
    }
  }
}

async function parsePptx(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const texts = [];
  const hiddenFindings = [];

  // Get all slide files
  const slideFiles = Object.keys(zip.files)
    .filter(f => f.match(/^ppt\/slides\/slide\d+\.xml$/))
    .sort((a, b) => {
      const na = parseInt(a.match(/slide(\d+)/)[1]);
      const nb = parseInt(b.match(/slide(\d+)/)[1]);
      return na - nb;
    });

  for (const slideFile of slideFiles) {
    const xml = await zip.file(slideFile).async('string');
    const slideNum = slideFile.match(/slide(\d+)/)[1];

    // Extract text from <a:t> tags
    const textMatches = xml.match(/<a:t>([^<]*)<\/a:t>/gi) || [];
    const slideTexts = textMatches.map(m => m.replace(/<[^>]+>/g, ''));
    if (slideTexts.length > 0) {
      texts.push(`[Slide ${slideNum}] ` + slideTexts.join(' '));
    }

    // QW4: alt text from <p:cNvPr descr="..." title="..."> on this slide.
    // Only instruction-looking entries become hidden-findings, so harmless
    // accessibility metadata won't change baseline test results.
    collectAltText(xml, `slide${slideNum}`, `Slide ${slideNum}`, texts, hiddenFindings);

    // Check for hidden/invisible text in slides
    // Visibility: <p:cNvPr ... hidden="1"/>
    if (xml.includes('hidden="1"')) {
      const hiddenTextMatches = xml.match(/<a:t>([^<]*)<\/a:t>/gi) || [];
      const hiddenText = hiddenTextMatches.map(m => m.replace(/<[^>]+>/g, '')).join(' ');
      if (hiddenText.trim()) {
        hiddenFindings.push({
          element: `Slide ${slideNum}`,
          technique: 'Hidden shape (hidden="1")',
          content: escapeForDisplay(hiddenText.slice(0, 200)),
          severity: 'warning',
        });
      }
    }

    // Check for off-screen positioned elements
    const offScreenRegex = /<a:off\s+x="(-?\d+)"\s+y="(-?\d+)"/g;
    let offM;
    while ((offM = offScreenRegex.exec(xml)) !== null) {
      const x = parseInt(offM[1]);
      const y = parseInt(offM[2]);
      // EMU: 1 inch = 914400 EMU. Typical slide ~12192000 x 6858000
      if (x < -914400 || y < -914400 || x > 15000000 || y > 10000000) {
        // Find nearby text
        const nearbyText = xml.slice(offM.index, offM.index + 500);
        const nearbyT = nearbyText.match(/<a:t>([^<]*)<\/a:t>/gi) || [];
        const tContent = nearbyT.map(m => m.replace(/<[^>]+>/g, '')).join(' ');
        if (tContent.trim()) {
          hiddenFindings.push({
            element: `Slide ${slideNum}`,
            technique: `Off-screen element (x:${x}, y:${y})`,
            content: escapeForDisplay(tContent.slice(0, 200)),
            severity: 'danger',
          });
        }
      }
    }

    // Transparent/white text: <a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill>
    if (/val="(?:FFFFFF|ffffff)"/.test(xml)) {
      hiddenFindings.push({
        element: `Slide ${slideNum}`,
        technique: 'White font color (#FFFFFF) detected',
        content: '(May contain invisible text on white background)',
        severity: 'warning',
      });
    }
  }

  // QW4: Slide Masters — viewers never render this text directly,
  // making it a known smuggling surface. Body <a:t> goes into the text
  // blob (analyzed by suspicious-pattern + unicode detectors), and any
  // <p:cNvPr> alt text is checked for instruction-like content.
  const masterFiles = Object.keys(zip.files)
    .filter(f => f.match(/^ppt\/slideMasters\/slideMaster\d+\.xml$/))
    .sort((a, b) => {
      const na = parseInt(a.match(/slideMaster(\d+)/)[1]);
      const nb = parseInt(b.match(/slideMaster(\d+)/)[1]);
      return na - nb;
    });
  for (const mf of masterFiles) {
    const xml = await zip.file(mf).async('string');
    const num = mf.match(/slideMaster(\d+)/)[1];
    const bodyMatches = xml.match(/<a:t>([^<]*)<\/a:t>/gi) || [];
    const bodyTexts = bodyMatches.map(m => decodeXmlEntities(m.replace(/<[^>]+>/g, '')));
    if (bodyTexts.length > 0) {
      texts.push(`[slideMaster${num}] ` + bodyTexts.join(' '));
    }
    collectAltText(xml, `slideMaster${num}`, `SlideMaster ${num}`, texts, hiddenFindings);
  }

  // QW4: Slide Layouts
  const layoutFiles = Object.keys(zip.files)
    .filter(f => f.match(/^ppt\/slideLayouts\/slideLayout\d+\.xml$/))
    .sort((a, b) => {
      const na = parseInt(a.match(/slideLayout(\d+)/)[1]);
      const nb = parseInt(b.match(/slideLayout(\d+)/)[1]);
      return na - nb;
    });
  for (const lf of layoutFiles) {
    const xml = await zip.file(lf).async('string');
    const num = lf.match(/slideLayout(\d+)/)[1];
    const bodyMatches = xml.match(/<a:t>([^<]*)<\/a:t>/gi) || [];
    const bodyTexts = bodyMatches.map(m => decodeXmlEntities(m.replace(/<[^>]+>/g, '')));
    if (bodyTexts.length > 0) {
      texts.push(`[slideLayout${num}] ` + bodyTexts.join(' '));
    }
    collectAltText(xml, `slideLayout${num}`, `SlideLayout ${num}`, texts, hiddenFindings);
  }

  // Check speaker notes
  const noteFiles = Object.keys(zip.files)
    .filter(f => f.match(/^ppt\/notesSlides\/notesSlide\d+\.xml$/));

  for (const noteFile of noteFiles) {
    const xml = await zip.file(noteFile).async('string');
    const noteNum = noteFile.match(/notesSlide(\d+)/)[1];
    const textMatches = xml.match(/<a:t>([^<]*)<\/a:t>/gi) || [];
    const noteText = textMatches.map(m => m.replace(/<[^>]+>/g, '')).join(' ');
    if (noteText.trim()) {
      texts.push(`[Note ${noteNum}] ` + noteText);
      if (looksLikeInstruction(noteText)) {
        hiddenFindings.push({
          element: `Speaker Note (Slide ${noteNum})`,
          technique: 'Speaker note with instruction-like text',
          content: escapeForDisplay(noteText.slice(0, 200)),
          severity: 'warning',
        });
      }
    }
  }

  // Check for hidden slides in presentation.xml
  const presXml = zip.file('ppt/presentation.xml');
  if (presXml) {
    const pxml = await presXml.async('string');
    const hiddenSlideRegex = /show="0"/g;
    if (hiddenSlideRegex.test(pxml)) {
      hiddenFindings.push({
        element: 'Presentation',
        technique: 'Hidden slide(s) detected (show="0")',
        content: '(Slides set to be hidden during presentation)',
        severity: 'warning',
      });
    }
  }

  // S12-XR-02: embedded images in ppt/media/* — same blind spot as DOCX
  // before this fix. Caps mirror docx.js / PDF S12-XR-01.
  const _OFFICE_MEDIA_MAX_BYTES = 5 * 1024 * 1024;
  const _OFFICE_MEDIA_MAX_COUNT = 50;
  const pptxMediaFiles = Object.keys(zip.files).filter(f => /^ppt\/media\/[^/]+$/.test(f));
  let pptxMediaProcessed = 0;
  for (const mediaPath of pptxMediaFiles) {
    if (pptxMediaProcessed >= _OFFICE_MEDIA_MAX_COUNT) break;
    const ext = _extOf(mediaPath.replace(/^ppt\/media\//, ''));
    if (!_PDF_IMAGE_EXTS.has(ext)) continue;
    const entry = zip.file(mediaPath);
    if (!entry) continue;
    const mediaName = mediaPath.replace(/^ppt\/media\//, '');
    let buf;
    try {
      buf = await entry.async('uint8array');
    } catch { continue; }
    if (buf.byteLength > _OFFICE_MEDIA_MAX_BYTES) {
      hiddenFindings.push({
        element: 'PPTX Embedded Image',
        technique: `Oversize embedded image skipped (> ${_OFFICE_MEDIA_MAX_BYTES} bytes)`,
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: 'warning',
        contextLocation: `PPTX media:${mediaName}`,
      });
      pptxMediaProcessed++;
      continue;
    }
    let sub;
    try { sub = await parseImage(buf, ext); } catch { pptxMediaProcessed++; continue; }
    pptxMediaProcessed++;
    if (!sub) continue;
    if (sub.text && sub.text.trim()) {
      texts.push(`[PPTX media:${mediaName}]`);
      texts.push(sub.text);
    }
    if (Array.isArray(sub.hiddenFindings)) {
      for (const f of sub.hiddenFindings) {
        const existing = typeof f.contextLocation === 'string' ? f.contextLocation : '';
        hiddenFindings.push({
          ...f,
          contextLocation: existing
            ? `PPTX media:${mediaName} > ${existing}`
            : `PPTX media:${mediaName}`,
        });
      }
    }
  }

  return { text: texts.join('\n'), hiddenFindings };
}

// --- Scanning Engine ---

export { parsePptx, decodeXmlEntities, extractCNvPrAltText, collectAltText };
