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
// v1.18.0 S16: RichMedia / 3D / Sound / Movie subtypes added so the parser
// surfaces a kebab signal (`pdf-richmedia-embed` / `pdf-3d-embed` /
// `pdf-sound-action` / `pdf-movie-action`) per document. These pdf.js
// "unimplemented" annotation types previously fell through to the base
// annotation path silently — even though OWASP/CISA 2025 list RichMedia /
// 3D as active CVE channels. Body is bounded (annotation name only) so R12
// invariant holds; signal is hoisted ONCE per document like
// pdf-widget-action.
const ANNOTATION_SUBTYPES = new Set([
  "Highlight", "FreeText", "Popup", "Squiggly", "Stamp", "Link",
  "Widget", "FileAttachment",
  "RichMedia", "3D", "Sound", "Movie",
]);

// v1.18.0 S16: PDF non-JS high-risk action types we detect via Widget /A
// or /AA action.S enum (plus Link annotation /A action where pdf.js
// surfaces it via a.url). PDF spec ISO 32000-1 §12.6.4 enumerates these
// action types. SubmitForm exfils form data to a URL; GoToR redirects to
// an external PDF (often hosted at attacker domain). pdf.js v4 hands these
// to us through `a.actions` map keys (mock-friendly contract) or via the
// link's /A action subtype on parser inspection.
const PDF_NON_JS_HIGH_RISK_ACTION_TYPES = new Set([
  "SubmitForm", "GoToR",
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

  // S15 (T2): pdf-widget-action signal — emit at most once per document.
  // Collect distinct action-type enum tokens (PDF spec fixed names like K/F/V/
  // C/Fo/Bl/PO/PC/PV/PI) into a bounded Set so the body of the action stays
  // in scan text (where the central detector covers it) while the signal-level
  // extraFinding carries only the type enum list as meta (R12: type names are
  // PDF spec enum, NOT attacker-controlled body).
  let widgetActionFound = false;
  const widgetActionTypes = new Set();
  const WIDGET_ACTION_TYPES_CAP = 8;

  // v1.18.0 S16: PDF non-JS high-risk action signals — emit at most ONCE per
  // document each, mirroring the widgetActionFound 1-per-doc invariant from
  // S15. Each tracks a kebab id, and the meta.targetUrl / meta.target /
  // meta.subtype payload is set from detector-controlled sanitized fields.
  // RichMedia / 3D / Sound / Movie are simple subtype flags. SubmitForm /
  // GoToR may be reachable through a.actions map (Widget /AA) when pdf.js
  // surfaces the action enum, OR via Link a.url (GoToR /F path that pdf.js
  // exposes as a URL).
  let submitFormSeen = false;
  let submitFormTargetUrl = "";
  let gotoRemoteSeen = false;
  let gotoRemoteTarget = "";
  let richMediaSeen = false;
  let threeDSeen = false;
  let soundSeen = false;
  let movieSeen = false;

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
                // S15 (T2): collect action-type enum (PDF spec fixed names)
                // for the pdf-widget-action signal extraFinding. We dedup
                // into widgetActionTypes Set (cap 8) and flip widgetActionFound
                // true on the FIRST non-empty body to signal that a widget
                // action carries actual JS — empty maps don't count.
                let hasNonEmptyBody = false;
                for (const body of bodies) {
                  if (typeof body === "string" && body.trim()) {
                    hasNonEmptyBody = true;
                    pushText(
                      `[PDF page=${i} kind=widget-action field=${sanitizeKey(fname || "_")} act=${sanitizeKey(act)}] ${body}`,
                    );
                  }
                }
                if (hasNonEmptyBody) {
                  widgetActionFound = true;
                  if (widgetActionTypes.size < WIDGET_ACTION_TYPES_CAP) {
                    widgetActionTypes.add(sanitizeKey(act));
                  }
                }
              }
            }
          }
        }

        // ---- v1.18.0 S16: non-JS high-risk action / multimedia subtypes ----
        // RichMedia / 3D / Sound / Movie carry CVE-tracked rendering paths
        // (especially RichMedia + Flash and 3D + U3D). pdf.js logs an
        // "unimplemented annotation type" warning and falls through to the
        // base annotation; we surface a kebab signal so reviewers see the
        // channel exists. Meta carries only the PDF spec subtype enum
        // (R12 safe — fixed PDF enum, not attacker body).
        if (a.subtype === "RichMedia") richMediaSeen = true;
        if (a.subtype === "3D") threeDSeen = true;
        if (a.subtype === "Sound") soundSeen = true;
        if (a.subtype === "Movie") movieSeen = true;

        // SubmitForm + GoToR detection.
        //   1. Through `a.actions` map (pdf.js exposes Widget /AA action sub-
        //      dicts whose `.S` is SubmitForm / GoToR — same channel as the
        //      v1.17.0 widget JavaScript actions).
        //   2. Through Link annotation `a.url` (pdf.js inlines a GoToR /A
        //      action's /F into the url field when the host file is a URL).
        //   3. Through `a.action` legacy single-action field.
        // Whichever path fires first wins; the 1-per-doc invariant collapses
        // duplicates. meta.targetUrl / meta.target are SANITIZED (sanitizeKey
        // strips spaces and brackets, truncates 64 chars) so raw attacker
        // strings never reach the response body — even though pdf.js may
        // hand us %-encoded fragments. R12 guard holds.
        if (a.actions && typeof a.actions === "object") {
          for (const actName of Object.keys(a.actions)) {
            if (actName === "SubmitForm" && !submitFormSeen) {
              submitFormSeen = true;
              const bodies = Array.isArray(a.actions[actName]) ? a.actions[actName] : [];
              for (const b of bodies) {
                if (typeof b === "string" && b.trim()) {
                  submitFormTargetUrl = sanitizeKey(b);
                  break;
                }
              }
            }
            if (actName === "GoToR" && !gotoRemoteSeen) {
              gotoRemoteSeen = true;
              const bodies = Array.isArray(a.actions[actName]) ? a.actions[actName] : [];
              for (const b of bodies) {
                if (typeof b === "string" && b.trim()) {
                  gotoRemoteTarget = sanitizeKey(b);
                  break;
                }
              }
            }
          }
        }
        // Link with /A SubmitForm: pdf.js doesn't expose SubmitForm action
        // body through high-level API. We look at a.action (if exposed)
        // and a.actionType (if pdf.js exposes the action type tag at all).
        // When neither is available we still fire on direct `a.actions`.
        if (a.subtype === "Link" && typeof a.url === "string" && a.url.trim()) {
          // pdf.js encodes GoToR destination as <url>#<dest> on the Link's
          // a.url field. We treat the presence of an external URL on a Link
          // (where the action type is GoToR) as a GoToR signal IF the
          // action enum is exposed via a.actionType / a.action.
          const actionTag = (typeof a.actionType === "string" && a.actionType) ||
            (typeof a.action === "string" && a.action) || "";
          if (actionTag === "GoToR" && !gotoRemoteSeen) {
            gotoRemoteSeen = true;
            gotoRemoteTarget = sanitizeKey(a.url);
          }
          if (actionTag === "SubmitForm" && !submitFormSeen) {
            submitFormSeen = true;
            submitFormTargetUrl = sanitizeKey(a.url);
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
  // v1.17.0 (T2): technique refactored to kebab id `pdf-embeds-javascript-
  // actions` + meta.count (number of distinct action names with non-empty
  // body). R12: meta is detector-controlled module constant + int, NOT
  // attacker body. i18n resolves via existing `pdfEmbedsJavaScriptActions`
  // dict key (kebab→camel path 2).
  try {
    if (typeof pdf.getJSActions === "function") {
      const jsActions = await pdf.getJSActions();
      if (jsActions && typeof jsActions === "object") {
        let actionCount = 0;
        for (const [name, bodies] of Object.entries(jsActions)) {
          if (!Array.isArray(bodies)) continue;
          let nameHadBody = false;
          for (const body of bodies) {
            if (typeof body === "string" && body.trim()) {
              nameHadBody = true;
              pushText(`[PDF kind=jsaction name=${sanitizeKey(name)}] ${body}`);
            }
          }
          if (nameHadBody) actionCount++;
        }
        if (actionCount > 0) {
          extraFindings.push({
            element: "PDF Catalog",
            technique: "pdf-embeds-javascript-actions",
            meta: { count: actionCount },
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

  // ---- v1.17.0 (T2): S15 pdf-widget-action signal extraFinding ----
  // Hoisted ONCE per document if any Widget annotation carried non-empty
  // /AA additional actions. Body already surfaced via per-page pushText
  // (kind=widget-action header). meta.actionTypes is a bounded list (≤8) of
  // PDF spec action-type enum tokens — R12 safe (fixed enum, not attacker
  // body). contextLocation is fixed 'Catalog' (1 emit per doc, mirrors
  // struct-tree-cap-exceeded pattern).
  if (widgetActionFound) {
    extraFindings.push({
      element: "PDF Catalog",
      technique: "pdf-widget-action",
      meta: { actionTypes: Array.from(widgetActionTypes) },
      content: "(see widget-action body in scan text)",
      severity: "warning",
      contextLocation: "Catalog",
    });
  }

  // ---- v1.18.0 S16: non-JS high-risk action / multimedia signals ----
  // Each signal is hoisted ONCE per document (1-per-doc invariant matches
  // pdf-widget-action). Meta carries only detector-controlled sanitized
  // URLs or PDF spec subtype enums — never raw attacker text.
  if (submitFormSeen) {
    extraFindings.push({
      element: "PDF Catalog",
      technique: "pdf-submit-form-action",
      meta: { targetUrl: submitFormTargetUrl || "(unknown)" },
      content: "(see submit-form action target in scan text)",
      severity: "warning",
      contextLocation: "Catalog",
    });
  }
  if (gotoRemoteSeen) {
    extraFindings.push({
      element: "PDF Catalog",
      technique: "pdf-goto-remote-action",
      meta: { target: gotoRemoteTarget || "(unknown)" },
      content: "(see go-to-remote action target in scan text)",
      severity: "warning",
      contextLocation: "Catalog",
    });
  }
  if (richMediaSeen) {
    extraFindings.push({
      element: "PDF Catalog",
      technique: "pdf-richmedia-embed",
      meta: { subtype: "RichMedia" },
      content: "(RichMedia annotation present)",
      severity: "warning",
      contextLocation: "Catalog",
    });
  }
  if (threeDSeen) {
    extraFindings.push({
      element: "PDF Catalog",
      technique: "pdf-3d-embed",
      meta: { subtype: "3D" },
      content: "(3D annotation present)",
      severity: "warning",
      contextLocation: "Catalog",
    });
  }
  if (soundSeen) {
    extraFindings.push({
      element: "PDF Catalog",
      technique: "pdf-sound-action",
      meta: { subtype: "Sound" },
      content: "(Sound annotation present)",
      severity: "warning",
      contextLocation: "Catalog",
    });
  }
  if (movieSeen) {
    extraFindings.push({
      element: "PDF Catalog",
      technique: "pdf-movie-action",
      meta: { subtype: "Movie" },
      content: "(Movie annotation present)",
      severity: "warning",
      contextLocation: "Catalog",
    });
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
        let ext = extname(filename).slice(1).toLowerCase();
        // v1.17.0 (T2): S15 pdf-embedded-html — MIME-typed embedded file
        // (e.g. /Subtype=/text#2Fhtml with non-html filename) was previously
        // silent-dropped because RECURSIVE_EXTS only knew about extensions.
        // pdf.js v4 may expose att.subtype on supported PDFs; we guard on
        // typeof string and (a) emit the kebab signal AND (b) force ext='html'
        // so the existing Stage B dispatch routes the body through the HTML
        // path. If att.subtype is absent (typical), the extension-based
        // dispatch below is unchanged (silent fallback — R23 byte-identical).
        let embeddedHtmlEmit = false;
        if (typeof att.subtype === "string") {
          const subLow = att.subtype.toLowerCase();
          if (subLow === "text/html" || subLow === "application/xhtml+xml") {
            embeddedHtmlEmit = true;
            ext = "html";
          }
        }
        if (!RECURSIVE_EXTS.has(ext)) continue; // ignore unsupported binaries
        if (content.byteLength > PDF_MAX_ATTACHMENT_BYTES) {
          extraFindings.push({
            element: 'PDF Attachment',
            technique: 'pdf-oversize-attachment',
            meta: { maxBytes: PDF_MAX_ATTACHMENT_BYTES, actualBytes: content.byteLength },
            content: escapeForDisplay(filename.slice(0, 200)),
            severity: 'warning',
            contextLocation: `Attachment ${safeFilename}`,
          });
          continue;
        }
        // S15 (T2): emit pdf-embedded-html before dispatch (signal-only —
        // does NOT replace the body dispatch which still runs the html
        // parser path below).
        if (embeddedHtmlEmit) {
          extraFindings.push({
            element: "PDF Attachment",
            technique: "pdf-embedded-html",
            meta: { subtype: "text/html" },
            content: escapeForDisplay(filename.slice(0, 200)),
            severity: "warning",
            contextLocation: `Attachment ${safeFilename}`,
          });
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
              technique: "pdf-empty-attachment",
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
