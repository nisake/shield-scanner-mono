/**
 * PPTX parser using JSZip.
 *
 * Extracts text from slides and detects:
 * - Hidden shapes (hidden="1")
 * - Off-screen positioned elements
 * - White text
 * - Suspicious speaker notes
 * - Hidden slides (show="0")
 *
 * Additional scan surface (QW4):
 * - Slide Masters    (ppt/slideMasters/slideMaster*.xml)  → <a:t> body
 * - Slide Layouts    (ppt/slideLayouts/slideLayout*.xml)  → <a:t> body
 * - Alt text         (<p:cNvPr descr="..." title="...">)  across all slides
 *
 * Output strategy: new content is appended to the same `texts` blob that
 * existing slide / note text uses, with a clear section prefix so downstream
 * detectors run the same way on it. Alt text becomes an extraFinding only
 * when it reads like an instruction (looksLikeInstruction) — alt text is a
 * known smuggling surface.
 */

import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import JSZip from "jszip";
import { escapeForDisplay, looksLikeInstruction } from "@shield-scanner/core";
import { parseImageBuffer } from "./image.js";

/**
 * S12-XR-02 fix: embedded image scan caps (mirrors docx.js).
 *
 * 5 MB per attachment / 50 attachments per archive — same envelope as PDF
 * S12-XR-01 and the EML attachment recursion limits. Without these caps,
 * the freshly-added ppt/media/* recursion would open a zip-bomb shape.
 */
const OFFICE_IMAGE_EXTS = new Set(["jpg", "jpeg", "png", "webp", "gif", "tiff", "tif"]);
const OFFICE_MEDIA_MAX_BYTES = 5 * 1024 * 1024;
const OFFICE_MEDIA_MAX_COUNT = 50;

// v1.18.0 Follina: Office Compound File Binary (CFB) magic. Shared with
// docx.js / xlsx.js — duplicated locally to avoid cross-parser coupling.
const CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

// v1.18.0 Follina: Remote-URL prefix allow-list, mirrors docx.js.
const REMOTE_URL_PREFIX_RE = /^(?:https?:|file:|\\\\)/i;

// v1.18.0 Follina: relationship types whose Target+TargetMode=External
// represent a remote template-style fetch on presentation open. Notes
// masters and slide-masters with external targets are the PPTX equivalent
// of word/attachedTemplate.
const REMOTE_TEMPLATE_REL_TYPES = [
  "slideMaster",
  "notesMaster",
  "handoutMaster",
  "theme",
  "presProps",
  "attachedTemplate",
];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/**
 * Extract <a:t>...</a:t> body text from a DrawingML XML string.
 * Returns an array of text fragments (XML entities decoded).
 */
function extractDrawingMLText(xml) {
  const matches = xml.match(/<a:t>([^<]*)<\/a:t>/gi) || [];
  return matches.map((m) => decodeXmlEntities(m.replace(/<[^>]+>/g, "")));
}

/**
 * Decode the five XML predefined entities. Sufficient for OOXML <a:t>
 * payloads and <p:cNvPr> attribute values.
 */
function decodeXmlEntities(s) {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

/**
 * Extract descr= and title= attributes from every <p:cNvPr ...> tag.
 * Returns an array of { kind: 'descr'|'title', value: string } in document
 * order. Empty / whitespace-only values are skipped.
 *
 * Note: matches the OPEN tag (self-closing or not). <p:cNvPr> children are
 * <a:extLst> entries, never <a:t> — so we only care about its attributes.
 */
function extractCNvPrAltText(xml) {
  const out = [];
  const tagRe = /<p:cNvPr\b([^>]*)>/g;
  let m;
  while ((m = tagRe.exec(xml)) !== null) {
    const attrs = m[1];
    const descrMatch = attrs.match(/\bdescr\s*=\s*"([^"]*)"|\bdescr\s*=\s*'([^']*)'/);
    const titleMatch = attrs.match(/\btitle\s*=\s*"([^"]*)"|\btitle\s*=\s*'([^']*)'/);
    if (descrMatch) {
      const v = decodeXmlEntities(descrMatch[1] ?? descrMatch[2] ?? "").trim();
      if (v) out.push({ kind: "descr", value: v });
    }
    if (titleMatch) {
      const v = decodeXmlEntities(titleMatch[1] ?? titleMatch[2] ?? "").trim();
      if (v) out.push({ kind: "title", value: v });
    }
  }
  return out;
}

/**
 * Sort a list of part filenames by their trailing numeric index, with a
 * deterministic fallback to lexicographic order.
 */
function sortByTrailingNumber(files, regex) {
  return files.slice().sort((a, b) => {
    const ma = a.match(regex);
    const mb = b.match(regex);
    const na = ma ? parseInt(ma[1], 10) : NaN;
    const nb = mb ? parseInt(mb[1], 10) : NaN;
    if (Number.isNaN(na) || Number.isNaN(nb)) return a.localeCompare(b);
    return na - nb;
  });
}

/**
 * Push alt-text entries into the shared texts blob and surface
 * instruction-looking ones as extraFindings.
 */
function collectAltText(xml, sectionLabel, elementLabel, texts, extraFindings) {
  const altEntries = extractCNvPrAltText(xml);
  if (altEntries.length === 0) return;
  texts.push(
    `[${sectionLabel} alt text] ` + altEntries.map((e) => e.value).join(" ")
  );
  for (const entry of altEntries) {
    if (looksLikeInstruction(entry.value)) {
      extraFindings.push({
        element: elementLabel,
        technique: `Alt text (${entry.kind}=) with instruction-like content`,
        content: escapeForDisplay(entry.value.slice(0, 200)),
        severity: "warning",
        contextLocation: elementLabel,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

export async function parsePptx(filePath) {
  const buffer = await readFile(filePath);
  return parsePptxBuffer(buffer);
}

/**
 * Parse PPTX from a Buffer (used for recursive attachment scanning).
 */
export async function parsePptxBuffer(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const texts = [];
  const extraFindings = [];

  // --- Slide files (sorted by number) ---
  const slideFiles = sortByTrailingNumber(
    Object.keys(zip.files).filter((f) =>
      f.match(/^ppt\/slides\/slide\d+\.xml$/)
    ),
    /slide(\d+)/
  );

  for (const slideFile of slideFiles) {
    const xml = await zip.file(slideFile).async("string");
    const slideNum = slideFile.match(/slide(\d+)/)[1];

    // Extract <a:t> text
    const slideTexts = extractDrawingMLText(xml);
    if (slideTexts.length > 0) {
      texts.push(`[Slide ${slideNum}] ` + slideTexts.join(" "));
    }

    // Alt text (descr / title on <p:cNvPr>) — QW4
    collectAltText(
      xml,
      `slide${slideNum}`,
      `Slide ${slideNum}`,
      texts,
      extraFindings
    );

    // Hidden shapes (hidden="1")
    if (xml.includes('hidden="1"')) {
      const hiddenText = slideTexts.join(" ");
      if (hiddenText.trim()) {
        extraFindings.push({
          element: `Slide ${slideNum}`,
          technique: 'Hidden shape (hidden="1")',
          content: escapeForDisplay(hiddenText.slice(0, 200)),
          severity: "warning",
          contextLocation: `Slide ${slideNum}`,
        });
      }
    }

    // Off-screen positioned elements
    const offScreenRegex = /<a:off\s+x="(-?\d+)"\s+y="(-?\d+)"/g;
    let offM;
    while ((offM = offScreenRegex.exec(xml)) !== null) {
      const x = parseInt(offM[1], 10);
      const y = parseInt(offM[2], 10);
      // EMU: 1 inch = 914400 EMU
      if (x < -914400 || y < -914400 || x > 15000000 || y > 10000000) {
        const nearbySlice = xml.slice(offM.index, offM.index + 500);
        const nearbyMatches = nearbySlice.match(/<a:t>([^<]*)<\/a:t>/gi) || [];
        const nearbyContent = nearbyMatches
          .map((m) => m.replace(/<[^>]+>/g, ""))
          .join(" ");
        if (nearbyContent.trim()) {
          extraFindings.push({
            element: `Slide ${slideNum}`,
            technique: `Off-screen element (x:${x}, y:${y})`,
            content: escapeForDisplay(nearbyContent.slice(0, 200)),
            severity: "danger",
            contextLocation: `Slide ${slideNum}`,
          });
        }
      }
    }

    // White font color
    if (/val="(?:FFFFFF|ffffff)"/.test(xml)) {
      extraFindings.push({
        element: `Slide ${slideNum}`,
        technique: "White font color (#FFFFFF) detected",
        content: "(May contain invisible text on white background)",
        severity: "warning",
        contextLocation: `Slide ${slideNum}`,
      });
    }
  }

  // --- Slide Masters (QW4) ---
  // Masters carry boilerplate placeholder text ("Click to edit Master title
  // style", etc.) — usually harmless, but a known smuggling surface because
  // viewers never render this text directly.
  const masterFiles = sortByTrailingNumber(
    Object.keys(zip.files).filter((f) =>
      f.match(/^ppt\/slideMasters\/slideMaster\d+\.xml$/)
    ),
    /slideMaster(\d+)/
  );
  for (const masterFile of masterFiles) {
    const xml = await zip.file(masterFile).async("string");
    const num = masterFile.match(/slideMaster(\d+)/)[1];
    const bodyTexts = extractDrawingMLText(xml);
    if (bodyTexts.length > 0) {
      texts.push(`[slideMaster${num}] ` + bodyTexts.join(" "));
    }
    collectAltText(
      xml,
      `slideMaster${num}`,
      `SlideMaster ${num}`,
      texts,
      extraFindings
    );
  }

  // --- Slide Layouts (QW4) ---
  const layoutFiles = sortByTrailingNumber(
    Object.keys(zip.files).filter((f) =>
      f.match(/^ppt\/slideLayouts\/slideLayout\d+\.xml$/)
    ),
    /slideLayout(\d+)/
  );
  for (const layoutFile of layoutFiles) {
    const xml = await zip.file(layoutFile).async("string");
    const num = layoutFile.match(/slideLayout(\d+)/)[1];
    const bodyTexts = extractDrawingMLText(xml);
    if (bodyTexts.length > 0) {
      texts.push(`[slideLayout${num}] ` + bodyTexts.join(" "));
    }
    collectAltText(
      xml,
      `slideLayout${num}`,
      `SlideLayout ${num}`,
      texts,
      extraFindings
    );
  }

  // --- Speaker notes ---
  const noteFiles = Object.keys(zip.files).filter((f) =>
    f.match(/^ppt\/notesSlides\/notesSlide\d+\.xml$/)
  );
  for (const noteFile of noteFiles) {
    const xml = await zip.file(noteFile).async("string");
    const noteNum = noteFile.match(/notesSlide(\d+)/)[1];
    const textMatches = xml.match(/<a:t>([^<]*)<\/a:t>/gi) || [];
    const noteText = textMatches
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join(" ");
    if (noteText.trim()) {
      texts.push(`[Note ${noteNum}] ` + noteText);
      if (looksLikeInstruction(noteText)) {
        extraFindings.push({
          element: `Speaker Note (Slide ${noteNum})`,
          technique: "Speaker note with instruction-like text",
          content: escapeForDisplay(noteText.slice(0, 200)),
          severity: "warning",
          contextLocation: `Slide ${noteNum} > Notes`,
        });
      }
    }
  }

  // --- Hidden slides ---
  const presXml = zip.file("ppt/presentation.xml");
  if (presXml) {
    const pxml = await presXml.async("string");
    if (/show="0"/.test(pxml)) {
      extraFindings.push({
        element: "Presentation",
        technique: 'Hidden slide(s) detected (show="0")',
        content: "(Slides set to be hidden during presentation)",
        severity: "warning",
        contextLocation: "Presentation",
      });
    }
  }

  // --- Embedded images (S12-XR-02) ---
  // ppt/media/* holds slide picture inserts. Same blind spot as DOCX before
  // the fix — slide-embedded EXIF/XMP/IPTC injection slipped past S12.
  // Cap bytes per image (5 MB) and count per archive (50) to keep the
  // zip-bomb amplification surface bounded. ContextLocation prefix-joins so
  // consumers can trace findings back through the carrier.
  const mediaFiles = Object.keys(zip.files).filter((f) =>
    /^ppt\/media\/[^/]+$/.test(f)
  );
  let mediaProcessed = 0;
  for (const mediaPath of mediaFiles) {
    if (mediaProcessed >= OFFICE_MEDIA_MAX_COUNT) break;
    const ext = extname(mediaPath).slice(1).toLowerCase();
    if (!OFFICE_IMAGE_EXTS.has(ext)) continue;
    const entry = zip.file(mediaPath);
    if (!entry) continue;
    const mediaName = mediaPath.replace(/^ppt\/media\//, "");
    let buf;
    try {
      buf = await entry.async("nodebuffer");
    } catch {
      continue;
    }
    if (buf.length === 0) {
      extraFindings.push({
        element: "PPTX Embedded Image",
        technique: "empty-embedded-image",
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: "warning",
        contextLocation: `PPTX media:${mediaName}`,
      });
      mediaProcessed++;
      continue;
    }
    if (buf.length > OFFICE_MEDIA_MAX_BYTES) {
      extraFindings.push({
        element: "PPTX Embedded Image",
        technique: "oversize-embedded-image",
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: "warning",
        contextLocation: `PPTX media:${mediaName}`,
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
      texts.push(`[PPTX media:${mediaName}]`);
      texts.push(sub.text);
    }
    if (Array.isArray(sub.extraFindings)) {
      for (const f of sub.extraFindings) {
        const existing =
          typeof f.contextLocation === "string" ? f.contextLocation : "";
        extraFindings.push({
          ...f,
          contextLocation: existing
            ? `PPTX media:${mediaName} > ${existing}`
            : `PPTX media:${mediaName}`,
        });
      }
    }
  }

  // --- v1.18.0 Follina: ppt/_rels/presentation.xml.rels external template ---
  // The PPTX equivalent of word/attachedTemplate is an OPC relationship from
  // ppt/presentation.xml whose Target+TargetMode=External points at a remote
  // .potx / .thmx / .xml that the viewer fetches on open. We surface every
  // such relationship whose Type matches a known template-style category and
  // whose Target uses a remote scheme (http(s)/file/UNC).
  const presRelsEntry = zip.file("ppt/_rels/presentation.xml.rels");
  if (presRelsEntry) {
    const relsXml = await presRelsEntry.async("string");
    const relRe =
      /<Relationship\b[^>]*\bType\s*=\s*"([^"]+)"[^>]*\bTarget\s*=\s*"([^"]+)"([^>]*)>/gi;
    let rm;
    while ((rm = relRe.exec(relsXml)) !== null) {
      const type = rm[1];
      const target = rm[2];
      const rest = rm[3] || "";
      if (!REMOTE_URL_PREFIX_RE.test(target)) continue;
      // require TargetMode="External" so internal relative targets do not FP.
      if (!/\bTargetMode\s*=\s*"External"/i.test(rest)) continue;
      const matchesTemplateType = REMOTE_TEMPLATE_REL_TYPES.some((kind) =>
        type.toLowerCase().endsWith("/" + kind.toLowerCase()),
      );
      if (!matchesTemplateType) continue;
      // v1.18.0 Follina: kebab ID + meta-only URL (R12 invariant).
      extraFindings.push({
        element: "ppt rel (presentation.xml.rels)",
        technique: "pptx-attached-template-remote",
        content: escapeForDisplay(target.slice(0, 200)),
        severity: "danger",
        category: "suspiciousPatterns",
        meta: { templateUrl: escapeForDisplay(target.slice(0, 500)) },
      });
    }
  }

  // --- v1.18.0 Follina: ppt/embeddings/*.bin CFB OLE detection ---
  // Shared kebab id 'office-embedded-ole-cfb' with DOCX/XLSX surface.
  const embeddingFiles = Object.keys(zip.files).filter((f) =>
    /^ppt\/embeddings\/[^/]+\.bin$/i.test(f),
  );
  for (const ef of embeddingFiles) {
    const entry = zip.file(ef);
    if (!entry) continue;
    let buf;
    try {
      buf = await entry.async("nodebuffer");
    } catch {
      continue;
    }
    if (buf.length > OFFICE_MEDIA_MAX_BYTES) continue;
    let hasCfbMagic = false;
    if (buf.length >= 8) {
      hasCfbMagic = true;
      for (let i = 0; i < 8; i++) {
        if (buf[i] !== CFB_MAGIC[i]) {
          hasCfbMagic = false;
          break;
        }
      }
    }
    if (!hasCfbMagic) continue;
    extraFindings.push({
      element: "PPTX Embedded OLE",
      technique: "office-embedded-ole-cfb",
      content: escapeForDisplay(ef.slice(0, 200)),
      severity: "warning",
      category: "suspiciousPatterns",
      contextLocation: ef,
      meta: { embeddingPath: ef, hasCfbMagic: true },
    });
  }

  return {
    text: texts.join("\n"),
    fileType: "text",
    extraFindings,
  };
}
