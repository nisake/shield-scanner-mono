/**
 * DOCX parser using JSZip.
 *
 * Extracts visible text and detects hidden content:
 * - w:vanish (hidden text)
 * - White font color (#FFFFFF)
 * - Microscopic font size (< 4pt)
 * - Suspicious comments, headers, footers
 */

import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import JSZip from "jszip";
import { escapeForDisplay, looksLikeInstruction } from "@shield-scanner/core";
import { parseImageBuffer } from "./image.js";

/**
 * S12-XR-02 fix: embedded image scan caps.
 *
 * Matches the PDF S12-XR-01 contract (5 MB per attachment, sourced from
 * PDF_MAX_ATTACHMENT_BYTES). Per-archive media-count cap is the EML
 * ATTACHMENT_LIMITS.MAX_COUNT value (50). Without these caps, fixing the
 * blind spot opens a zip-bomb amplification surface on these formats too.
 */
const OFFICE_IMAGE_EXTS = new Set(["jpg", "jpeg", "png", "webp", "gif", "tiff", "tif"]);
const OFFICE_MEDIA_MAX_BYTES = 5 * 1024 * 1024;
const OFFICE_MEDIA_MAX_COUNT = 50;

export async function parseDocx(filePath) {
  const buffer = await readFile(filePath);
  return parseDocxBuffer(buffer);
}

/**
 * Parse DOCX from a Buffer (used for recursive attachment scanning).
 */
export async function parseDocxBuffer(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const texts = [];
  const extraFindings = [];

  // --- Main document body ---
  const docXml = zip.file("word/document.xml");
  if (docXml) {
    const xml = await docXml.async("string");

    // Extract <w:t> text
    const textMatches = xml.match(/<w:t[^>]*>([^<]*)<\/w:t>/gi) || [];
    textMatches.forEach((m) => {
      const inner = m.replace(/<[^>]+>/g, "");
      if (inner) texts.push(inner);
    });

    // Hidden text: <w:vanish/>
    const vanishRegex =
      /<w:rPr>[^]*?<w:vanish(?:\s[^/]*)?\/?>[^]*?<\/w:rPr>[^]*?<w:t[^>]*>([^<]*)<\/w:t>/gi;
    let vm;
    while ((vm = vanishRegex.exec(xml)) !== null) {
      if (vm[1] && vm[1].trim()) {
        extraFindings.push({
          element: "w:r (Word run)",
          technique: "Hidden text (w:vanish)",
          content: escapeForDisplay(vm[1].slice(0, 200)),
          severity: "danger",
        });
      }
    }

    // White font color hiding
    const colorHideRegex =
      /<w:rPr>[^]*?<w:color\s+w:val="(?:FFFFFF|ffffff)"[^/]*\/>[^]*?<\/w:rPr>[^]*?<w:t[^>]*>([^<]*)<\/w:t>/gi;
    let cm;
    while ((cm = colorHideRegex.exec(xml)) !== null) {
      if (cm[1] && cm[1].trim()) {
        extraFindings.push({
          element: "w:r (Word run)",
          technique: "White font color (#FFFFFF)",
          content: escapeForDisplay(cm[1].slice(0, 200)),
          severity: "danger",
        });
      }
    }

    // Microscopic font (w:sz val < 8 half-points = < 4pt)
    // v1.13.0 Theme docx-microscopic: kebab-case technique id + meta.fontSize
    // (Number, point value). Mirrors PDF Theme A (v1.12.0) microscopic-text
    // pattern — keeps R12 invariant (no dynamic numeric value baked into the
    // technique label). UI formats via i18n placeholder {fontSize}.toFixed(2)
    // through formatTechniqueWithMeta in app.js.
    const tinyFontRegex =
      /<w:rPr>[^]*?<w:sz\s+w:val="([0-3])"[^/]*\/>[^]*?<\/w:rPr>[^]*?<w:t[^>]*>([^<]*)<\/w:t>/gi;
    let tf;
    while ((tf = tinyFontRegex.exec(xml)) !== null) {
      if (tf[2] && tf[2].trim()) {
        extraFindings.push({
          element: "w:r (Word run)",
          technique: "microscopic-font-size",
          meta: { fontSize: parseInt(tf[1], 10) / 2 },
          content: escapeForDisplay(tf[2].slice(0, 200)),
          severity: "danger",
        });
      }
    }

    // v1.14.0 ext-2 (DOCX shape textbox microscopic): wps:txbxContent is the
    // WordprocessingShape textbox payload (xmlns:wps=
    // "http://schemas.microsoft.com/office/word/2010/wordprocessingShape").
    // Word lets authors stuff regular w:p / w:r structures inside a shape's
    // textbox, which the regular-run scanner above does match through (the
    // /[^]*?/ greedy permits namespace nesting). However, the element-name
    // 'w:r (Word run)' loses the shape provenance, making forensics harder.
    // We re-scan only the wps:txbxContent blocks with the same regex and
    // rewrite the element label to 'w:r (Word run, shape textbox)' to give
    // the consumer that context. To avoid double-counting we replace any
    // already-emitted plain 'w:r (Word run)' finding whose content+meta
    // matches a shape-textbox hit.
    const shapeBlockRegex =
      /<wps:txbxContent\b[^>]*>([\s\S]*?)<\/wps:txbxContent>/gi;
    let sb;
    while ((sb = shapeBlockRegex.exec(xml)) !== null) {
      const inner = sb[1];
      if (!inner) continue;
      const shapeTinyRegex =
        /<w:rPr>[^]*?<w:sz\s+w:val="([0-3])"[^/]*\/>[^]*?<\/w:rPr>[^]*?<w:t[^>]*>([^<]*)<\/w:t>/gi;
      let stf;
      while ((stf = shapeTinyRegex.exec(inner)) !== null) {
        if (!stf[2] || !stf[2].trim()) continue;
        const displayContent = escapeForDisplay(stf[2].slice(0, 200));
        const fontSize = parseInt(stf[1], 10) / 2;
        const dupIdx = extraFindings.findIndex(
          (f) =>
            f.technique === "microscopic-font-size" &&
            f.element === "w:r (Word run)" &&
            f.content === displayContent &&
            f.meta &&
            f.meta.fontSize === fontSize,
        );
        if (dupIdx >= 0) {
          extraFindings[dupIdx] = {
            ...extraFindings[dupIdx],
            element: "w:r (Word run, shape textbox)",
          };
        } else {
          extraFindings.push({
            element: "w:r (Word run, shape textbox)",
            technique: "microscopic-font-size",
            meta: { fontSize },
            content: displayContent,
            severity: "danger",
          });
        }
      }
    }

    // S8: Tracked-change deletion residue (<w:del> / <w:delText>).
    // Track-changes preserves deleted text in the document so reviewers can
    // accept/reject the edit. An attacker can plant an attack as a
    // "deletion" — the file still contains the bytes but readers see only
    // the post-edit view. Severity warning by default (legitimate during
    // review); upgraded to danger when the residue text looksLikeInstruction.
    const delRegex = /<w:delText[^>]*>([^<]*)<\/w:delText>/gi;
    let dm;
    while ((dm = delRegex.exec(xml)) !== null) {
      const inner = dm[1];
      if (!inner || !inner.trim()) continue;
      const severity = looksLikeInstruction(inner) ? "danger" : "warning";
      extraFindings.push({
        element: "w:del (Tracked-change deletion)",
        technique: "Tracked-change deletion residue (w:del/w:delText)",
        content: escapeForDisplay(inner.slice(0, 200)),
        severity,
      });
    }

    // S8: Word field instructions (<w:instrText>) — HYPERLINK / MERGEFIELD
    // / INCLUDETEXT etc. can carry attack URLs or include external content
    // that's invisible at first read. Benign field codes (PAGE, NUMPAGES,
    // TOC, REF, FORMTEXT…) are filtered up-front to suppress FP.
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
      let severity = "warning";
      if (hasUrl || looksInst) severity = "danger";
      extraFindings.push({
        element: "w:instrText (Word field)",
        technique: "Field instruction (HYPERLINK / MERGEFIELD / etc.)",
        content: escapeForDisplay(inner.slice(0, 200)),
        severity,
      });
    }
  }

  // S8: Custom document properties (docProps/custom.xml) — user-defined
  // metadata that the Word UI keeps under File > Info > Properties >
  // Advanced. Not rendered in the body, so it's a quiet carrier for
  // instructions. Only surface string-valued props (vt:lpwstr / vt:lpstr)
  // that looksLikeInstruction (bools / ints / dates carry no payload).
  // Category: suspiciousPatterns (text-pattern based, not structural).
  const customXml = zip.file("docProps/custom.xml");
  if (customXml) {
    const cxml = await customXml.async("string");
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
        extraFindings.push({
          element: `docProps custom:${escapeForDisplay(name)}`,
          technique: "Custom property with instruction-like text",
          content: escapeForDisplay(value.slice(0, 200)),
          severity: "warning",
          category: "suspiciousPatterns",
        });
      }
    }
  }

  // --- Comments ---
  const commentsXml = zip.file("word/comments.xml");
  if (commentsXml) {
    const cxml = await commentsXml.async("string");
    const commentTexts = cxml.match(/<w:t[^>]*>([^<]*)<\/w:t>/gi) || [];
    const commentContent = commentTexts
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join(" ");
    if (commentContent.trim() && looksLikeInstruction(commentContent)) {
      extraFindings.push({
        element: "Word Comment",
        technique: "Comment with instruction-like text",
        content: escapeForDisplay(commentContent.slice(0, 200)),
        severity: "warning",
      });
    }
    if (commentContent.trim()) {
      texts.push("[COMMENT] " + commentContent);
    }
  }

  // --- Headers / Footers ---
  const headerFooterFiles = Object.keys(zip.files).filter((f) =>
    f.match(/^word\/(header|footer)\d*\.xml$/)
  );
  for (const hf of headerFooterFiles) {
    const hfXml = await zip.file(hf).async("string");
    const hfTexts = hfXml.match(/<w:t[^>]*>([^<]*)<\/w:t>/gi) || [];
    hfTexts.forEach((m) => {
      const inner = m.replace(/<[^>]+>/g, "");
      if (inner) texts.push(inner);
    });
  }

  // --- Embedded images (S12-XR-02) ---
  // word/media/* is the standard carrier for Insert > Picture. Without this
  // pass, EXIF/XMP/IPTC/zTXt/iTXt prompt-injection in an embedded image
  // completely bypasses the S12 detector (DOCX is the dominant Office
  // attachment shape — see image-attacks fixtures #2..#15). Mirrors the PDF
  // S12-XR-01 recursion pattern: filter by extension, cap bytes per image
  // (5 MB) and count per archive (50), prefix-join contextLocation so
  // consumers can trace the finding back through the carrier.
  const mediaFiles = Object.keys(zip.files).filter((f) =>
    /^word\/media\/[^/]+$/.test(f)
  );
  let mediaProcessed = 0;
  for (const mediaPath of mediaFiles) {
    if (mediaProcessed >= OFFICE_MEDIA_MAX_COUNT) break;
    const ext = extname(mediaPath).slice(1).toLowerCase();
    if (!OFFICE_IMAGE_EXTS.has(ext)) continue;
    const entry = zip.file(mediaPath);
    if (!entry) continue;
    const mediaName = mediaPath.replace(/^word\/media\//, "");
    let buf;
    try {
      buf = await entry.async("nodebuffer");
    } catch {
      continue;
    }
    if (buf.length > OFFICE_MEDIA_MAX_BYTES) {
      extraFindings.push({
        element: "DOCX Embedded Image",
        technique: `Oversize embedded image skipped (> ${OFFICE_MEDIA_MAX_BYTES} bytes)`,
        content: escapeForDisplay(mediaName.slice(0, 200)),
        severity: "warning",
        contextLocation: `DOCX media:${mediaName}`,
      });
      mediaProcessed++;
      continue;
    }
    let sub;
    try {
      sub = await parseImageBuffer(buf, ext);
    } catch {
      // parseImageBuffer is contractually non-throwing, but belt-and-braces.
      mediaProcessed++;
      continue;
    }
    mediaProcessed++;
    if (!sub) continue;
    if (sub.text && sub.text.trim()) {
      texts.push(`[DOCX media:${mediaName}]`);
      texts.push(sub.text);
    }
    if (Array.isArray(sub.extraFindings)) {
      for (const f of sub.extraFindings) {
        const existing =
          typeof f.contextLocation === "string" ? f.contextLocation : "";
        extraFindings.push({
          ...f,
          contextLocation: existing
            ? `DOCX media:${mediaName} > ${existing}`
            : `DOCX media:${mediaName}`,
        });
      }
    }
  }

  return {
    text: texts.join("\n"),
    fileType: "text", // extracted text; XML-level findings go in extraFindings
    extraFindings,
  };
}
