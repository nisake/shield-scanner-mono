/**
 * PDF parser using pdfjs-dist (legacy build for Node.js).
 *
 * S7 Stage A: extracts text from page contents + annotations (Highlight /
 *             FreeText / Popup / Squiggly / Stamp / Link), XMP metadata, and
 *             AcroForm field values. Extracted blobs are appended to the
 *             scan text with a uniform `[PDF k1=v1 k2=v2] ` header so the
 *             central suspicious-patterns detector covers them like any
 *             other text. Headers are pure key=value tokens so they never
 *             trip the natural-language detectors themselves.
 *
 * S7 Stage B: recursively scans EMBEDDED FILE attachments (text-family
 *             extensions only — pdf/docx/eml/pptx/html/md/txt). Depth bound:
 *             PDF_RECURSION_LIMIT = 2. Findings from a recursive scan are
 *             surfaced as ONE summary extraFinding when dangerCount > 0.
 *
 * S20: every extraFinding carries `contextLocation = "Page N"` (or
 *      "Attachment <filename>" for recursive children). Microscopic-text
 *      findings additionally carry a `position` field relative to the
 *      concatenated page text.
 *
 * Guardrail R12: extracted values are escaped via escapeForDisplay before
 *                surfacing as content; raw shadow / VS-decoded strings are
 *                never injected here.
 */

import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import {
  escapeForDisplay,
  sanitizeContextLocation,
  walkStructTree,
  sanitizeStructKey,
} from "@shield-scanner/core";

// pdfjs-dist v4+: use legacy build for Node.js compatibility
let pdfjsLib;
async function getPdfjs() {
  if (!pdfjsLib) {
    pdfjsLib = await import("pdfjs-dist/legacy/build/pdf.mjs");
  }
  return pdfjsLib;
}

export const PDF_RECURSION_LIMIT = 2;
export const PDF_MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024; // 5 MB cap
// Must stay in sync with BUFFER_DISPATCHABLE in parsers/index.js. Adding a
// text-family OR image extension there without echoing it here would silently
// drop matching PDF attachments at Stage B, defeating the recursion. We mirror
// the set explicitly (rather than importing) to avoid a circular import between
// pdf.js and parsers/index.js (parsers/index.js already imports pdf.js).
//
// S12 fix (S12-XR-01): image extensions added so PDF-embedded JPEG/PNG/WebP/
// GIF/TIFF attachments are routed through dispatchBuffer → parseImageBuffer,
// surfacing EXIF/XMP/IPTC/zTXt/iTXt prompt-injection that previously slipped
// through as a {status:"safe"} false-negative. The existing 5MB attachment
// byteLength cap below applies uniformly to image attachments as well.
const RECURSIVE_EXTS = new Set([
  "txt", "md", "mdc", "cursorrules",
  "html", "htm", "xml", "svg",
  "pdf", "docx", "eml", "pptx",
  "json", "csv",
  // S12: image attachments — parsed via dispatchBuffer → parseImageBuffer.
  "jpg", "jpeg", "png", "webp", "gif", "tiff", "tif",
]);

// Annotation subtypes worth surfacing into the scan text. Link gets URL
// extraction too.
// PDF-DEEP-04: Widget (AcroForm field UI) and FileAttachment (per-page attach
// surface) are now extracted to close a known bypass — payloads in Widget
// /TU tooltips and per-page FileAttachment annotations were previously
// silent. Widget dedupes against AcroForm fieldName via seenFieldNames,
// FileAttachment dedupes against catalog getAttachments via seenAttachKey.
const ANNOTATION_SUBTYPES = new Set([
  "Highlight", "FreeText", "Popup", "Squiggly", "Stamp", "Link",
  "Widget", "FileAttachment",
]);

export async function parsePdf(filePath) {
  const buffer = await readFile(filePath);
  return parsePdfBuffer(buffer);
}

/**
 * Parse PDF from a Buffer (used for recursive attachment scanning).
 *
 * @param {Buffer|Uint8Array} buffer
 * @param {object} [options]
 * @param {number} [options.depth=0] — current recursion depth (Stage B)
 */
export async function parsePdfBuffer(buffer, options = {}) {
  const depth = Number.isInteger(options.depth) ? options.depth : 0;
  const uint8 = new Uint8Array(buffer);

  const pdfjs = await getPdfjs();

  const loadingTask = pdfjs.getDocument({
    data: uint8,
    useSystemFonts: true,
    disableFontFace: true,
  });
  const pdf = await loadingTask.promise;

  const texts = [];
  const extraFindings = [];
  // Track the cumulative offset into `texts.join("\n")` so per-item positions
  // are consistent with the final scan text.
  let accumOffset = 0;

  function pushText(line) {
    texts.push(line);
    accumOffset += line.length + 1; // +1 for the \n that join() inserts
  }

  // PDF-DEEP-05: emit struct-tree-cap-exceeded at most once per document even
  // if multiple pages individually exceed the walker cap (the central detector
  // only needs to know "the channel was truncated", not which page hit first).
  let structTreeCapExceeded = false;

  // PDF-DEEP-04: dedup sets shared across per-page and catalog passes.
  // - seenFieldNames: pre-seeded from AcroForm before the page loop so Widget
  //   annotations carrying the same fieldName skip a field that the AcroForm
  //   path is going to emit. The AcroForm body-emission still happens later
  //   (Stage A block); we only pre-register the *keys* here.
  // - seenAttachKey: getAttachments() pass populates first; per-page
  //   FileAttachment annotations skip duplicates surfaced from the catalog.
  const seenFieldNames = new Set();
  const seenAttachKey = new Set();
  try {
    if (typeof pdf.getFieldObjects === "function") {
      const fields = await pdf.getFieldObjects();
      if (fields && typeof fields === "object") {
        for (const name of Object.keys(fields)) {
          seenFieldNames.add(String(name));
        }
      }
    }
  } catch {
    // ignore — best-effort pre-seed
  }

  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const textContent = await page.getTextContent();
    const pageText = textContent.items.map((item) => item.str).join(" ");
    const pageStartOffset = accumOffset;
    if (pageText.trim()) pushText(pageText);

    // ---- Microscopic text (existing behavior, now with position) ----
    let itemOffset = pageStartOffset;
    for (const item of textContent.items) {
      const str = item.str || "";
      if (str.trim()) {
        if (item.height !== undefined && item.height < 1 && item.height > 0) {
          extraFindings.push({
            element: `PDF Page ${i}`,
            technique: "microscopic-text",
            meta: { height: item.height },
            content: escapeForDisplay(str.slice(0, 200)),
            severity: "danger",
            position: itemOffset,
            matchLen: str.length,
            contextLocation: `Page ${i}`,
          });
        }
      }
      itemOffset += str.length + 1; // +1 for the " " join separator
    }

    // ---- Stage A: annotations ----
    try {
      const annots = await page.getAnnotations();
      for (const a of annots || []) {
        if (!a || !a.subtype) continue;
        if (!ANNOTATION_SUBTYPES.has(a.subtype)) continue;
        const contents = (a.contents || a.contentsObj?.str || "").trim();
        const url = (a.url || "").trim();
        if (contents) {
          // Use a symbol-only header so suspicious-patterns can't accidentally
          // misread the header itself as a natural-language hit.
          pushText(`[PDF page=${i} kind=annotation subtype=${a.subtype}] ${contents}`);
        }
        if (url) {
          pushText(`[PDF page=${i} kind=annotation subtype=${a.subtype} url] ${url}`);
        }

        // ---- PDF-DEEP-04: Widget (AcroForm UI annotation) ----
        // Widget annotations carry the field-level UI metadata that is NOT
        // emitted by getFieldObjects (TU tooltip, alt text, page-specific
        // actions). We dedup by fieldName so a payload already surfaced via
        // the AcroForm path isn't double-counted.
        if (a.subtype === "Widget") {
          const fname = typeof a.fieldName === "string" ? a.fieldName : "";
          if (!fname || !seenFieldNames.has(fname)) {
            if (fname) seenFieldNames.add(fname);
            const fvalue = typeof a.fieldValue === "string" ? a.fieldValue : "";
            const alt = typeof a.alternativeText === "string" ? a.alternativeText : "";
            if (fname && fvalue.trim()) {
              pushText(`[PDF page=${i} kind=widget field=${sanitizeKey(fname)}] ${fvalue}`);
            }
            if (alt.trim()) {
              pushText(`[PDF page=${i} kind=widget-alt field=${sanitizeKey(fname || "_")}] ${alt}`);
            }
            // Actions: pdf.js exposes { onclick: ['body'], ... } shaped maps.
            if (a.actions && typeof a.actions === "object") {
              for (const [act, bodies] of Object.entries(a.actions)) {
                if (!Array.isArray(bodies)) continue;
                for (const body of bodies) {
                  if (typeof body === "string" && body.trim()) {
                    pushText(
                      `[PDF page=${i} kind=widget-action field=${sanitizeKey(fname || "_")} act=${sanitizeKey(act)}] ${body}`,
                    );
                  }
                }
              }
            }
          }
        }

        // ---- PDF-DEEP-04: FileAttachment annotation ----
        // The catalog-level getAttachments() pass below covers most attachment
        // payloads, but per-page FileAttachment annotations can carry an
        // additional /Contents human-language note plus their own filename.
        // Dedup against the catalog pass using filename as the key.
        if (a.subtype === "FileAttachment") {
          const fl = a.file || {};
          const afname = (typeof fl.filename === "string" && fl.filename) ||
            (typeof a.attachmentDest === "string" && a.attachmentDest) || "";
          const key = afname || `_page${i}_${a.id || ""}`;
          if (!seenAttachKey.has(key)) {
            seenAttachKey.add(key);
            if (afname) {
              pushText(`[PDF page=${i} kind=fileattachment filename=${sanitizeKey(afname)}]`);
            }
            // /Contents on FileAttachment carries the attached-file description.
            // Already emitted above via the generic `contents` branch — no
            // duplicate here. The dedup-key registration is the work.
          }
        }
      }
    } catch {
      // Annotation errors are non-fatal.
    }

    // ---- PDF-DEEP-05: structure-tree /Alt /ActualText (per page) ----
    // pdf.js exposes a serialized struct tree per page (Figure / Formula / Form
    // role nodes carry /Alt or /ActualText payloads from image XObjects). The
    // bodies are attacker-controlled — surfacing them here lets the central
    // suspicious-patterns + instruction detectors cover the screen-reader
    // metadata channel that previously slipped past as a {status:"safe"}
    // false-negative.
    try {
      if (typeof page.getStructTree === "function") {
        const tree = await page.getStructTree();
        if (tree && typeof tree === "object") {
          const { records, capExceeded } = walkStructTree(tree);
          for (const rec of records) {
            // R12: alt / actualText are attacker-controlled. pushText wraps the
            // body for the central detectors; contextLocation uses only the
            // role enum + fixed field name (no raw alt slice).
            if (rec.alt) {
              pushText(`[PDF page=${i} kind=structtree role=${sanitizeStructKey(rec.role)} field=Alt] ${rec.alt}`);
            }
            if (rec.actualText) {
              pushText(`[PDF page=${i} kind=structtree role=${sanitizeStructKey(rec.role)} field=ActualText] ${rec.actualText}`);
            }
          }
          if (capExceeded && !structTreeCapExceeded) {
            structTreeCapExceeded = true;
            extraFindings.push({
              element: "PDF Catalog",
              technique: "struct-tree-cap-exceeded",
              content: "(structure tree walk halted at cap)",
              severity: "warning",
              contextLocation: "Catalog",
            });
          }
        }
      }
    } catch {
      // Struct-tree errors are non-fatal — many PDFs lack a struct tree
      // entirely (un-tagged), and pdf.js may throw on malformed StructTreeRoot.
    }
  }

  // ---- Stage A: AcroForm field values ----
  try {
    if (typeof pdf.getFieldObjects === "function") {
      const fields = await pdf.getFieldObjects();
      if (fields && typeof fields === "object") {
        for (const [name, entries] of Object.entries(fields)) {
          // PDF-DEEP-04: even when entries is empty/non-array, AcroForm has
          // already claimed this field name — Widget dedup uses the registry.
          seenFieldNames.add(String(name));
          if (!Array.isArray(entries)) continue;
          for (const entry of entries) {
            const value = entry && entry.value;
            if (typeof value === "string" && value.trim()) {
              pushText(`[PDF kind=acroform field=${sanitizeKey(name)}] ${value}`);
            }
          }
        }
      }
    }
  } catch {
    // ignore
  }

  // ---- Stage A: metadata (info + XMP) ----
  try {
    const metadata = await pdf.getMetadata();
    if (metadata) {
      // PDF Info dict (Title / Author / Subject / Keywords / Producer / Creator)
      if (metadata.info && typeof metadata.info === "object") {
        for (const [key, value] of Object.entries(metadata.info)) {
          if (typeof value === "string" && value.trim()) {
            pushText(`[PDF kind=info key=${sanitizeKey(key)}] ${value}`);
          }
        }
      }
      // XMP raw metadata: prefer .getAll() if available.
      if (metadata.metadata) {
        try {
          const all =
            typeof metadata.metadata.getAll === "function"
              ? metadata.metadata.getAll()
              : null;
          if (all && typeof all === "object") {
            for (const [key, value] of Object.entries(all)) {
              if (typeof value === "string" && value.trim()) {
                pushText(`[PDF kind=xmp key=${sanitizeKey(key)}] ${value}`);
              }
            }
          }
        } catch {
          // ignore
        }
      }
    }
  } catch {
    // ignore
  }

  // ---- PDF-DEEP-01: catalog-level JavaScript actions ----
  // /OpenAction /AA can hold raw JS that auto-executes on document open.
  // Even if pdf.js can't safely run it, surfacing the body lets the central
  // suspicious-patterns detector cover it like any other text.
  try {
    if (typeof pdf.getJSActions === "function") {
      const jsActions = await pdf.getJSActions();
      if (jsActions && typeof jsActions === "object") {
        let hadAny = false;
        for (const [name, bodies] of Object.entries(jsActions)) {
          if (!Array.isArray(bodies)) continue;
          for (const body of bodies) {
            if (typeof body === "string" && body.trim()) {
              hadAny = true;
              pushText(`[PDF kind=jsaction name=${sanitizeKey(name)}] ${body}`);
            }
          }
        }
        if (hadAny) {
          extraFindings.push({
            element: "PDF Catalog",
            technique: "PDF embeds JavaScript actions",
            content: "(see jsaction body in scan text)",
            severity: "warning",
            contextLocation: "Catalog",
          });
        }
      }
    }
  } catch {
    // ignore — getJSActions is best-effort
  }

  // ---- PDF-DEEP-02: catalog /OpenAction (auto-launch URL or destination) ----
  // pdf.js getOpenAction() returns a shape that varies by action type:
  //   { action: 'Print' } | { url: 'http://...' } | { dest: [...] }
  // JSON.stringify keeps it scannable as a single line; the central detector
  // covers the resulting URL / instruction-text payload.
  try {
    if (typeof pdf.getOpenAction === "function") {
      const oa = await pdf.getOpenAction();
      if (oa && typeof oa === "object") {
        let stringified = "";
        try {
          stringified = JSON.stringify(oa);
        } catch {
          stringified = String(oa);
        }
        if (stringified && stringified !== "{}" && stringified !== "null") {
          pushText(`[PDF kind=openaction] ${stringified}`);
        }
      }
    }
  } catch {
    // ignore
  }

  // ---- PDF-DEEP-03: catalog /Outlines (bookmark titles + unsafeUrl) ----
  // Bookmarks can carry attacker-controlled titles and URL/destination links.
  // Walk depth-first with hard caps so a self-referential outline (cycle) or
  // a deeply-nested decoy tree can't pin the parser.
  try {
    if (typeof pdf.getOutline === "function") {
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
            if (n && typeof n === "object") {
              const title = typeof n.title === "string" ? n.title : "";
              const u = typeof n.unsafeUrl === "string" ? n.unsafeUrl : "";
              if (title.trim()) {
                pushText(`[PDF kind=outline depth=${d}] ${title}`);
              }
              if (u.trim()) {
                pushText(`[PDF kind=outline-url depth=${d}] ${u}`);
              }
              if (Array.isArray(n.items) && n.items.length) {
                walk(n.items, d + 1);
              }
            }
          }
        };
        walk(outline, 0);
      }
    }
  } catch {
    // ignore
  }

  // ---- Stage B: attachment recursion ----
  if (depth < PDF_RECURSION_LIMIT) {
    let attachments = null;
    try {
      attachments = await pdf.getAttachments();
    } catch {
      attachments = null;
    }
    if (attachments && typeof attachments === "object") {
      // Lazy-load to avoid circular import.
      const { dispatchBuffer } = await import("./index.js");
      for (const [key, att] of Object.entries(attachments)) {
        const filename = (att && att.filename) || key;
        const content = att && att.content;
        if (!content || !filename) continue;
        // PDF-DEEP-04: register catalog attachment so per-page FileAttachment
        // annotations carrying the same filename don't double-count.
        seenAttachKey.add(String(filename));
        // PDF-EML-FILENAME-CONTEXTLOC-SANITIZE: every contextLocation derived
        // from a raw attachment filename is sanitized to strip ANSI / bidi /
        // line-injection / zero-width controls before being threaded through
        // to scan output. Display-side `content` still uses escapeForDisplay
        // so the two surfaces have independent guardrails.
        const safeFilename = sanitizeContextLocation(filename);
        const ext = extname(filename).slice(1).toLowerCase();
        if (!RECURSIVE_EXTS.has(ext)) continue; // ignore unsupported binaries
        if (content.byteLength > PDF_MAX_ATTACHMENT_BYTES) {
          extraFindings.push({
            element: 'PDF Attachment',
            technique: 'Oversize attachment skipped (> 5MB)',
            content: escapeForDisplay(filename.slice(0, 200)),
            severity: 'warning',
            contextLocation: `Attachment ${safeFilename}`,
          });
          continue;
        }
        try {
          let sub;
          if (ext === "pdf") {
            sub = await parsePdfBuffer(Buffer.from(content), {
              depth: depth + 1,
            });
          } else {
            sub = await dispatchBuffer(Buffer.from(content), ext);
          }
          if (!sub) continue;
          // PDF-EML-EMPTY-ATTACHMENT-CHANNEL: 0-byte attachment surfaces as
          // a warning even though there's no body text — the channel exists
          // and should be visible to reviewers.
          const childByteLen = (content && typeof content.byteLength === "number") ? content.byteLength : 0;
          const childTextEmpty = !sub.text || !String(sub.text).trim();
          if (childByteLen === 0 && childTextEmpty) {
            extraFindings.push({
              element: "PDF Attachment",
              technique: "Empty attachment",
              content: escapeForDisplay(filename.slice(0, 200)),
              severity: "warning",
              contextLocation: `Attachment ${safeFilename}`,
            });
          }
          // Append child text into our text blob so detectors see it.
          if (sub.text && sub.text.trim()) {
            pushText(`[PDF kind=attachment filename=${sanitizeKey(filename)}]`);
            pushText(sub.text);
          }
          // Hoist child extraFindings into ours, location-tagged.
          if (Array.isArray(sub.extraFindings)) {
            for (const f of sub.extraFindings) {
              const existing =
                typeof f.contextLocation === "string" ? f.contextLocation : "";
              extraFindings.push({
                ...f,
                contextLocation: existing
                  ? `Attachment ${safeFilename} > ${existing}`
                  : `Attachment ${safeFilename}`,
              });
            }
          }
        } catch {
          // Skip malformed attachments quietly.
        }
      }
    }
  }

  return {
    text: texts.join("\n"),
    fileType: "text",
    extraFindings,
  };
}

/**
 * Make a value safe inside a [PDF k=v] header: strip spaces and brackets so
 * the header is always a single token that downstream regex won't confuse
 * with the value payload.
 */
function sanitizeKey(s) {
  return String(s).replace(/[\s\[\]]+/g, "_").slice(0, 64);
}
