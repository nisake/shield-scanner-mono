/**
 * S12 cross-format regression: image metadata injection arriving via container
 * formats (EML attachments, PDF embedded files).
 *
 * Adversarial #9 (spec/finalScope): an EML carrying evil.jpg whose EXIF
 * UserComment field contains an INJECT string MUST produce at least one
 * finding whose `contextLocation` matches /^Attachment .* > IMG exif:UserComment$/.
 * This proves the location prefix-join works end-to-end (eml.js dispatches the
 * image via dispatchBuffer → parseImageBuffer → emits an extraFinding with
 * `contextLocation: "IMG exif:UserComment"`; scan-email then prefixes that
 * with the attachment label via enrichFindingsLocation).
 *
 * S12-XR-01 (high, fixed): the parallel image-in-PDF scenario. PDF Stage B's
 * RECURSIVE_EXTS was originally narrower than parsers/index.js's
 * BUFFER_DISPATCHABLE — every image extension was silently dropped before
 * dispatch, making a PDF-wrapped JPEG with an EXIF UserComment injection a
 * one-line bypass of the new S12 detector. Adversarial verification flagged
 * this as a confirmed false-negative (3/3 verifier agreement, confidence 10).
 * The fix widens RECURSIVE_EXTS to include jpg/jpeg/png/webp/gif/tiff/tif so
 * the PDF→image path mirrors the EML→image path. The PDF-suite below pins
 * that fix: image attachments now surface IMG-typed findings with the same
 * "Attachment <name> > IMG <field>" location-prefix the EML suite uses.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import JSZip from "jszip";
import { scanEmail } from "../../server/tools/scan-email.js";
import { parsePdfBuffer } from "../../server/parsers/pdf.js";
import { parseDocxBuffer } from "../../server/parsers/docx.js";
import { parsePptxBuffer } from "../../server/parsers/pptx.js";
import { analyze } from "@shield-scanner/core";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "..", "fixtures");

// Reuse the canonical EXIF UserComment fixture so this test stays byte-faithful
// with image-metadata.test.js and the generator output (no risk of drift
// between an inline-built JPEG and the on-disk fixture).
const JPEG_PATH = join(
  FIXTURES_DIR,
  "image-attacks",
  "02-jpeg-exif-usercomment.jpg"
);

/**
 * Build a minimal multipart/mixed RFC 5322 message with a base64-encoded JPEG
 * attachment. Returns the raw email source as a string — suitable for
 * `scanEmail({ raw_text })`.
 *
 * No new dependency: we hand-roll the headers and the base64 body so the
 * fixture is reproducible from this file alone.
 */
function buildEmlWithJpeg(jpegBuffer, attachmentName = "evil.jpg") {
  const boundary = "----shield-scanner-s12-boundary";
  // Wrap base64 at 76 chars per RFC 2045.
  const b64 = jpegBuffer.toString("base64").replace(/.{76}/g, (m) => m + "\r\n");
  return [
    `From: attacker@example.com`,
    `To: victim@example.com`,
    `Subject: photo`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    ``,
    `--${boundary}`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    `See attached photo.`,
    ``,
    `--${boundary}`,
    `Content-Type: image/jpeg; name="${attachmentName}"`,
    `Content-Transfer-Encoding: base64`,
    `Content-Disposition: attachment; filename="${attachmentName}"`,
    ``,
    b64,
    `--${boundary}--`,
    ``,
  ].join("\r\n");
}

describe("S12 cross-format: EML carrying image with EXIF UserComment injection", () => {
  const jpeg = readFileSync(JPEG_PATH);
  const eml = buildEmlWithJpeg(jpeg, "evil.jpg");

  it("scanEmail surfaces the image attachment as a non-skipped scan", async () => {
    const res = await scanEmail({ raw_text: eml });
    expect(Array.isArray(res.attachment_scans)).toBe(true);
    const evilScan = res.attachment_scans.find(
      (a) => a.filename === "evil.jpg"
    );
    expect(evilScan, "evil.jpg attachment scan should be present").toBeTruthy();
    expect(evilScan.extension).toBe("jpg");
    expect(evilScan.skipped).toBe(false);
  });

  it("byCategory.suspiciousPatterns >= 1 (image-metadata injection reaches detector)", async () => {
    const res = await scanEmail({ raw_text: eml });
    // The image attachment's joined text is run through analyze() inside
    // scan-email's scanParsedContent, so suspiciousPatterns must register at
    // least one hit across the aggregate summary.
    expect(res.summary.dangerCount + res.summary.warningCount).toBeGreaterThanOrEqual(1);
    // Drill into the attachment's per-section findings: the image leaf is
    // exposed under `content` (see scanParsedContent leaf branch).
    const evilScan = res.attachment_scans.find((a) => a.filename === "evil.jpg");
    const sectionFindings = evilScan?.threats_by_section?.content;
    expect(sectionFindings, "evil.jpg content section findings").toBeTruthy();
    const susp = sectionFindings.suspiciousPatterns || [];
    expect(susp.length).toBeGreaterThanOrEqual(1);
  });

  it("at least one finding's contextLocation matches /^Attachment .* > IMG exif:UserComment$/", async () => {
    // Adversarial #9 contract — the prefix-join MUST land so consumers can
    // trace the IMG metadata finding back through the carrier attachment.
    const res = await scanEmail({ raw_text: eml });
    const evilScan = res.attachment_scans.find((a) => a.filename === "evil.jpg");
    expect(evilScan).toBeTruthy();

    // Gather every contextLocation visible on the attachment:
    //   - structural extraFindings (parseImage's per-field labels)
    //   - per-section findings (analyze() output on the joined image text)
    const locations = [];
    for (const f of evilScan.structural || []) {
      if (f.contextLocation) locations.push(f.contextLocation);
    }
    for (const sec of Object.values(evilScan.threats_by_section || {})) {
      for (const cat of Object.values(sec || {})) {
        if (!Array.isArray(cat)) continue;
        for (const f of cat) {
          if (f.contextLocation) locations.push(f.contextLocation);
        }
      }
    }

    const pattern = /^Attachment .* > IMG exif:UserComment$/;
    const matched = locations.some((loc) => pattern.test(loc));
    expect(
      matched,
      `expected at least one contextLocation matching /^Attachment .* > IMG exif:UserComment$/, got:\n${locations.join("\n")}`
    ).toBe(true);
  });

  it("baseline byCategory shape stays intact (5-key invariant, no imageMetadata key)", async () => {
    const res = await scanEmail({ raw_text: eml });
    // scan-email's combinedSummary does not include byCategory at the top
    // level, but every analyze() result inside attachment_scans should.
    const evilScan = res.attachment_scans.find((a) => a.filename === "evil.jpg");
    expect(evilScan).toBeTruthy();
    // The leaf section's analyze() result is reachable indirectly via the
    // findings shape — assert no unexpected category keys appear.
    const sectionFindings = evilScan?.threats_by_section?.content || {};
    const keys = Object.keys(sectionFindings).sort();
    // findings keys (note: 5 categories, no "imageMetadata")
    const allowed = new Set([
      "controlChars",
      "hiddenHtml",
      "homoglyphs",
      "invisibleUnicode",
      "suspiciousPatterns",
    ]);
    for (const k of keys) {
      expect(allowed.has(k), `unexpected finding category "${k}"`).toBe(true);
    }
  });
});

/**
 * S12-XR-03 regression: inline image with NO filename (Content-Type only).
 *
 * Real HTML mail emitted by Outlook / Apple Mail / Thunderbird routinely uses
 * `multipart/related` + `Content-ID: <...>` + `Content-Disposition: inline`
 * for images referenced via `cid:` in the HTML body, and frequently omits the
 * `name=` / `filename=` parameters entirely. Before the fix,
 * `inferAttachmentExtension` had no `image/*` Content-Type mappings, so such
 * a part fell through to `return null` → `skipReason: 'unsupported-extension'`
 * and parseImage was never reached. The S12 detector was 100% bypassed for
 * this shape — a silent false-negative in a security tool.
 */
function buildEmlWithInlineImageNoFilename(jpegBuffer) {
  const boundary = "----shield-scanner-s12-xr03-boundary";
  const b64 = jpegBuffer.toString("base64").replace(/.{76}/g, (m) => m + "\r\n");
  return [
    `From: attacker@example.com`,
    `To: victim@example.com`,
    `Subject: inline image without filename`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/related; boundary="${boundary}"`,
    ``,
    `--${boundary}`,
    `Content-Type: text/html; charset=utf-8`,
    ``,
    `<html><body><img src="cid:img1"></body></html>`,
    ``,
    `--${boundary}`,
    // NO name= parameter, NO filename= — only the Content-Type carries the
    // hint that this part is a JPEG.
    `Content-Type: image/jpeg`,
    `Content-Transfer-Encoding: base64`,
    `Content-Disposition: inline`,
    `Content-ID: <img1>`,
    ``,
    b64,
    `--${boundary}--`,
    ``,
  ].join("\r\n");
}

describe("S12-XR-03: inline image with no filename (image/* Content-Type only) reaches parseImage", () => {
  const jpeg = readFileSync(JPEG_PATH);
  const eml = buildEmlWithInlineImageNoFilename(jpeg);

  it("inferAttachmentExtension maps image/jpeg → 'jpg' even when filename is absent", async () => {
    const res = await scanEmail({ raw_text: eml });
    expect(Array.isArray(res.attachment_scans)).toBe(true);
    // There's exactly one filename-less image attachment in the fixture.
    // Filename-less inline parts surface as `(unnamed-N)` per eml.js
    // attachmentScans bookkeeping (line ~244). Find by that synthetic name
    // since we cannot rely on a filename hint.
    const imageScan = res.attachment_scans.find(
      (a) => a.filename === "(unnamed-0)"
    );
    expect(imageScan, "image/jpeg attachment scan should be present").toBeTruthy();
    expect(imageScan.extension).toBe("jpg");
    expect(imageScan.skipped).toBe(false);
    expect(imageScan.skipReason).toBeFalsy();
  });

  it("S12 detector fires on the inline image even without a filename", async () => {
    const res = await scanEmail({ raw_text: eml });
    // The EXIF UserComment carries an INJECT string, so the overall scan
    // must surface at least one finding (was 0 / 'safe' before the fix).
    expect(res.summary.dangerCount + res.summary.warningCount).toBeGreaterThanOrEqual(1);

    // Filename-less inline parts surface as `(unnamed-N)` per eml.js
    // attachmentScans bookkeeping (line ~244). Find by that synthetic name
    // since we cannot rely on a filename hint.
    const imageScan = res.attachment_scans.find(
      (a) => a.filename === "(unnamed-0)"
    );
    expect(imageScan).toBeTruthy();

    // Same contract as the named-attachment case: at least one
    // contextLocation must pinpoint the EXIF UserComment field through the
    // carrier attachment, with filename rendered as `(unnamed-N)`.
    const locations = [];
    for (const f of imageScan.structural || []) {
      if (f.contextLocation) locations.push(f.contextLocation);
    }
    for (const sec of Object.values(imageScan.threats_by_section || {})) {
      for (const cat of Object.values(sec || {})) {
        if (!Array.isArray(cat)) continue;
        for (const f of cat) {
          if (f.contextLocation) locations.push(f.contextLocation);
        }
      }
    }
    const pattern = /^Attachment .* > IMG exif:UserComment$/;
    const matched = locations.some((loc) => pattern.test(loc));
    expect(
      matched,
      `expected at least one contextLocation matching /^Attachment .* > IMG exif:UserComment$/, got:\n${locations.join("\n")}`
    ).toBe(true);
  });
});

describe("S12-XR-01: PDF DOES recurse into image attachments (parity with EML)", () => {
  // S12-XR-01 (high, confirmed by 3 verifiers): PDF Stage B's RECURSIVE_EXTS
  // (formerly RECURSIVE_TEXT_EXTS) was authored before S12 and silently dropped
  // every image attachment — making a single PDF-wrapped JPEG with an EXIF
  // UserComment injection a one-line bypass of the new S12 detector. The fix
  // widens RECURSIVE_EXTS to include jpg/jpeg/png/webp/gif/tiff/tif so the
  // PDF→image path mirrors the EML→image path that already worked.
  //
  // These tests hand-craft a minimal PDF that embeds the canonical EXIF
  // UserComment fixture as an /EmbeddedFile attachment named photo.jpg, then
  // assert the injection surfaces with the EML-parity contextLocation
  // /^Attachment .* > IMG exif:UserComment$/.

  /**
   * Build a minimal-but-valid PDF that embeds the given image bytes as an
   * /EmbeddedFile attachment. Same construction as the reproducer script the
   * verifiers used (offsets matter — we build the xref table by hand to match
   * pdf.js's parser).
   */
  function buildPdfWithJpegAttachment(jpegBytes, attachmentName = "photo.jpg") {
    const objs = [];
    function obj(n, body) { objs.push({ n, body }); }

    obj(1, '<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 6 0 R >> >>');
    obj(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
    obj(3, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources <<>> >>');
    const content = 'BT /F1 12 Tf 100 700 Td (Hello PDF) Tj ET';
    obj(4, `<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
    obj(5, `<< /Type /EmbeddedFile /Subtype /image#2Fjpeg /Length ${jpegBytes.length} >>\nstream\n${Buffer.from(jpegBytes).toString('binary')}\nendstream`);
    obj(6, `<< /Names [(${attachmentName}) 7 0 R] >>`);
    obj(7, `<< /Type /Filespec /F (${attachmentName}) /UF (${attachmentName}) /EF << /F 5 0 R >> >>`);

    let pdf = '%PDF-1.5\n%\xff\xff\xff\xff\n';
    const offsets = [0];
    for (const { n, body } of objs) {
      offsets[n] = pdf.length;
      pdf += `${n} 0 obj\n${body}\nendobj\n`;
    }
    const xrefStart = pdf.length;
    pdf += `xref\n0 ${objs.length + 1}\n`;
    pdf += '0000000000 65535 f \n';
    for (let i = 1; i <= objs.length; i++) {
      pdf += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
    }
    pdf += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
    return Buffer.from(pdf, 'binary');
  }

  it("parsePdfBuffer surfaces IMG exif:UserComment via Attachment prefix (PDF/EML parity)", async () => {
    const jpeg = readFileSync(JPEG_PATH);
    const pdfBuf = buildPdfWithJpegAttachment(jpeg, "photo.jpg");
    const r = await parsePdfBuffer(pdfBuf, { depth: 0 });
    expect(r).toBeTruthy();
    expect(Array.isArray(r.extraFindings)).toBe(true);

    // The image extraFinding from parseImageBuffer must be hoisted with the
    // "Attachment <name> > " prefix — mirroring how scanEmail prefixes its
    // attachment findings.
    const pattern = /^Attachment .* > IMG exif:UserComment$/;
    const locations = r.extraFindings
      .map((f) => f.contextLocation)
      .filter((s) => typeof s === "string");
    const matched = locations.some((loc) => pattern.test(loc));
    expect(
      matched,
      `expected at least one extraFinding with contextLocation matching ${pattern}, got:\n${locations.join("\n")}`
    ).toBe(true);
  });

  it("parsePdfBuffer hoists the image's decoded text into the joined blob (detector reaches it)", async () => {
    // Without this hoist, analyze() running on parsed.text would still miss
    // the injection even if extraFindings included an IMG entry. We assert
    // both the attachment header AND the [IMG ...] decoded value land.
    const jpeg = readFileSync(JPEG_PATH);
    const pdfBuf = buildPdfWithJpegAttachment(jpeg, "photo.jpg");
    const r = await parsePdfBuffer(pdfBuf, { depth: 0 });
    expect(typeof r.text).toBe("string");
    expect(r.text).toContain("[PDF kind=attachment filename=photo.jpg]");
    expect(r.text).toContain("[IMG exif:UserComment]");
  });

  it("oversize image attachment still hits the 5MB cap (DoS guardrail preserved)", async () => {
    // Build a fake JPEG body just over the 5 MB cap. parsePdfBuffer must
    // short-circuit BEFORE invoking parseImageBuffer — otherwise the cap is
    // a paper tiger. We assert the oversize-warning extraFinding lands and
    // no IMG-typed finding is emitted (parser was never called).
    const oversize = Buffer.alloc(5 * 1024 * 1024 + 16, 0x00);
    // Minimal JPEG SOI so the bytes look plausible even though the size check
    // fires first.
    oversize[0] = 0xff; oversize[1] = 0xd8;
    const pdfBuf = buildPdfWithJpegAttachment(oversize, "huge.jpg");
    const r = await parsePdfBuffer(pdfBuf, { depth: 0 });
    const oversizeFinding = r.extraFindings.find(
      (f) => f.technique === "pdf-oversize-attachment"
    );
    expect(oversizeFinding, "5MB cap should fire a warning extraFinding").toBeTruthy();
    expect(oversizeFinding.contextLocation).toBe("Attachment huge.jpg");
    const imgFindings = r.extraFindings.filter(
      (f) => typeof f.contextLocation === "string" && /\bIMG\b/.test(f.contextLocation)
    );
    expect(imgFindings.length, "no IMG findings on oversize-skipped attachment").toBe(0);
  });
});

// ---------------------------------------------------------------------------
// S12-XR-02: DOCX / PPTX must recurse into embedded images (word/media,
// ppt/media). Before this fix both parsers ignored those entries and an
// EXIF-poisoned screenshot inside a Word doc or PowerPoint slide bypassed
// the freshly-shipped S12 detector entirely — architecturally identical to
// S12-XR-01 (PDF embedded images). The DOCX/PPTX case is arguably worse
// because Word's Insert > Picture and PowerPoint media inserts are the
// dominant Office attachment shape in real-world corporate workflows.
// ---------------------------------------------------------------------------

/**
 * Build a minimal Word .docx whose word/media/<mediaName> is the given
 * bytes. Body text is a fixed "Body text." so tests assert the
 * media-recursion contribution, not the body.
 */
async function buildDocxWithImage(jpegBuffer, mediaName = "image1.jpeg") {
  const z = new JSZip();
  z.file(
    "[Content_Types].xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="jpeg" ContentType="image/jpeg"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`
  );
  z.file(
    "_rels/.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`
  );
  z.file(
    "word/document.xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>Body text.</w:t></w:r></w:p></w:body></w:document>`
  );
  z.file(`word/media/${mediaName}`, jpegBuffer);
  return await z.generateAsync({ type: "nodebuffer" });
}

/**
 * Build a minimal PowerPoint .pptx whose ppt/media/<mediaName> is the given
 * bytes. Slide 1 contains "Slide body." so tests isolate media contribution.
 */
async function buildPptxWithImage(jpegBuffer, mediaName = "image1.jpeg") {
  const z = new JSZip();
  z.file(
    "[Content_Types].xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="jpeg" ContentType="image/jpeg"/>
<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
</Types>`
  );
  z.file(
    "_rels/.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>`
  );
  z.file(
    "ppt/presentation.xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>`
  );
  z.file(
    "ppt/slides/slide1.xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
       xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Slide body.</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`
  );
  z.file(`ppt/media/${mediaName}`, jpegBuffer);
  return await z.generateAsync({ type: "nodebuffer" });
}

describe("S12-XR-02 cross-format: DOCX/PPTX recurse into embedded images", () => {
  const jpeg = readFileSync(JPEG_PATH); // EXIF UserComment = injection string

  describe("DOCX (word/media/*)", () => {
    it("parseDocxBuffer hoists IMG findings with prefix-joined contextLocation", async () => {
      const buf = await buildDocxWithImage(jpeg);
      const res = await parseDocxBuffer(buf);
      // Body text still present
      expect(res.text).toContain("Body text.");
      // Image extraction surfaced — joined text carries the IMG header
      expect(res.text).toContain("[DOCX media:image1.jpeg]");
      expect(res.text).toContain("[IMG exif:UserComment]");
      // extraFinding from parseImage is hoisted with the media-prefix
      const imgFindings = res.extraFindings.filter(
        (f) =>
          typeof f.contextLocation === "string" &&
          f.contextLocation === "DOCX media:image1.jpeg > IMG exif:UserComment"
      );
      expect(imgFindings.length).toBeGreaterThanOrEqual(1);
    });

    it("analyze() on the parsed DOCX text now flips from safe to danger", async () => {
      const buf = await buildDocxWithImage(jpeg);
      const res = await parseDocxBuffer(buf);
      const a = analyze(res.text, { fileType: res.fileType });
      expect(a.summary.status).toBe("danger");
      expect(a.summary.total).toBeGreaterThanOrEqual(1);
    });

    it("baseline 5-key invariant preserved on the analyze() result", async () => {
      const buf = await buildDocxWithImage(jpeg);
      const res = await parseDocxBuffer(buf);
      const a = analyze(res.text, { fileType: res.fileType });
      // The 5-key gate applies to summary.byCategory (the public detector
      // shape). No `imageMetadata` key is allowed even when image-borne
      // findings have routed through here via DOCX media recursion.
      expect(Object.keys(a.summary.byCategory).sort()).toEqual([
        "controlChars",
        "hiddenHtml",
        "homoglyphs",
        "invisibleUnicode",
        "suspiciousPatterns",
      ]);
    });

    it("per-image 5MB byte cap fires a structural warning, no payload echo", async () => {
      // Build a DOCX whose word/media entry is > 5 MB. The cap is enforced
      // BEFORE parseImageBuffer is called, so we never decode the bytes.
      const big = Buffer.alloc(5 * 1024 * 1024 + 16, 0xff);
      const buf = await buildDocxWithImage(big, "huge.jpeg");
      const res = await parseDocxBuffer(buf);
      const oversize = res.extraFindings.find(
        (f) => f.technique === "oversize-embedded-image"
      );
      expect(oversize).toBeTruthy();
      expect(oversize.contextLocation).toBe("DOCX media:huge.jpeg");
      // No IMG-typed findings should land for the skipped entry.
      const hugeImg = res.extraFindings.filter(
        (f) =>
          typeof f.contextLocation === "string" &&
          f.contextLocation.startsWith("DOCX media:huge.jpeg > IMG ")
      );
      expect(hugeImg.length).toBe(0);
    });

    it("per-archive 50-media cap bounds work (zip-bomb amplification guard)", async () => {
      // 60 small image entries — only first 50 should be processed; we
      // assert the 51st+ produce no findings (no oversize warning, no IMG
      // finding, no parse-error). Distinct contextLocations are counted.
      const z = new JSZip();
      z.file(
        "[Content_Types].xml",
        `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="jpeg" ContentType="image/jpeg"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`
      );
      z.file(
        "_rels/.rels",
        `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`
      );
      z.file(
        "word/document.xml",
        `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>`
      );
      for (let i = 1; i <= 60; i++) {
        z.file(`word/media/image${i}.jpeg`, jpeg);
      }
      const buf = await z.generateAsync({ type: "nodebuffer" });
      const res = await parseDocxBuffer(buf);
      const locs = new Set();
      for (const f of res.extraFindings) {
        if (typeof f.contextLocation === "string") {
          const m = f.contextLocation.match(/^DOCX media:(image\d+\.jpeg)/);
          if (m) locs.add(m[1]);
        }
      }
      expect(locs.size).toBeLessThanOrEqual(50);
      expect(locs.has("image51.jpeg")).toBe(false);
    });
  });

  describe("PPTX (ppt/media/*)", () => {
    it("parsePptxBuffer hoists IMG findings with prefix-joined contextLocation", async () => {
      const buf = await buildPptxWithImage(jpeg);
      const res = await parsePptxBuffer(buf);
      expect(res.text).toContain("Slide body.");
      expect(res.text).toContain("[PPTX media:image1.jpeg]");
      expect(res.text).toContain("[IMG exif:UserComment]");
      const imgFindings = res.extraFindings.filter(
        (f) =>
          typeof f.contextLocation === "string" &&
          f.contextLocation === "PPTX media:image1.jpeg > IMG exif:UserComment"
      );
      expect(imgFindings.length).toBeGreaterThanOrEqual(1);
    });

    it("analyze() on the parsed PPTX text flips from safe to danger", async () => {
      const buf = await buildPptxWithImage(jpeg);
      const res = await parsePptxBuffer(buf);
      const a = analyze(res.text, { fileType: res.fileType });
      expect(a.summary.status).toBe("danger");
      expect(a.summary.total).toBeGreaterThanOrEqual(1);
    });
  });
});

/**
 * S12-XR-05 regression: nested-EML attachment chain breadcrumb on structural
 * findings.
 *
 * Before the fix, `scanParsedContent` recursed for nested-EML attachments via
 * `scanParsedContent(sub.parsed, sub.label)` without forwarding any location
 * prefix. The inner `pushStructural` therefore had `attachmentPrefix === null`,
 * so structural findings bubbled up either bare or carrying only the literal
 * `"Email > Attachments"` string set by eml.js's depth-guard — operators had
 * no breadcrumb to trace which nested attachment a finding came from.
 *
 * The fix passes a full `locationPrefix` (parent chain + sub.label) into the
 * recursive call, so depth-N findings inherit the whole chain.
 */
describe("S12-XR-05: nested-EML structural findings carry the full chain breadcrumb", () => {
  function makeEmlXR05(subject, mime, name, b64) {
    const boundary = "----shield-scanner-s12-xr05-" + Math.random().toString(36).slice(2, 8);
    return [
      `From: a@example.com`,
      `To: b@example.org`,
      `Subject: ${subject}`,
      `MIME-Version: 1.0`,
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      ``,
      `--${boundary}`,
      `Content-Type: text/plain; charset=utf-8`,
      ``,
      `hello`,
      ``,
      `--${boundary}`,
      `Content-Type: ${mime}; name="${name}"`,
      `Content-Transfer-Encoding: base64`,
      `Content-Disposition: attachment; filename="${name}"`,
      ``,
      b64,
      ``,
      `--${boundary}--`,
      ``,
    ].join("\r\n");
  }
  function b64wrapXR05(buf) {
    return buf.toString("base64").match(/.{1,76}/g).join("\r\n");
  }

  it("4-deep EML: depth-limit warning's contextLocation carries the full chain prefix", async () => {
    const jpeg = readFileSync(JPEG_PATH);
    // L4 (innermost) carries the image; L3 carries L4; L2 carries L3; L1 (top) carries L2.
    // MAX_DEPTH = 3, so L4 fires the depth-guard when it tries to recurse into
    // its image attachment.
    const l4 = makeEmlXR05("L4", "image/jpeg", "photo.jpg", b64wrapXR05(jpeg));
    const l3 = makeEmlXR05("L3", "message/rfc822", "L4.eml", b64wrapXR05(Buffer.from(l4, "utf8")));
    const l2 = makeEmlXR05("L2", "message/rfc822", "L3.eml", b64wrapXR05(Buffer.from(l3, "utf8")));
    const l1 = makeEmlXR05("L1 top", "message/rfc822", "L2.eml", b64wrapXR05(Buffer.from(l2, "utf8")));

    const res = await scanEmail({ raw_text: l1 });
    const top = res.attachment_scans.find((a) => a.filename === "L2.eml");
    expect(top, "L2.eml attachment scan should be present").toBeTruthy();

    const depthWarning = (top.structural || []).find((f) =>
      /Recursion depth limit reached/.test(f.technique || "")
    );
    expect(depthWarning, "depth-limit structural warning should bubble up").toBeTruthy();

    // Pre-fix: literal "Email > Attachments" with no breadcrumb.
    // Post-fix: chain prepended → "Attachment L2.eml > attachment[0]: L3.eml > attachment[0]: L4.eml > Email > Attachments"
    expect(depthWarning.contextLocation).toMatch(
      /^Attachment L2\.eml > attachment\[0\]: L3\.eml > attachment\[0\]: L4\.eml > /
    );
  });

  it("1-level nested image: IMG extraFinding carries Attachment + sub-attachment chain prefix", async () => {
    const jpeg = readFileSync(JPEG_PATH);
    // L2 (inner) carries the image; L1 (top) carries L2. Image at depth 2 is
    // within MAX_DEPTH, so it parses fully.
    const l2 = makeEmlXR05("L2", "image/jpeg", "photo.jpg", b64wrapXR05(jpeg));
    const l1 = makeEmlXR05("L1 top", "message/rfc822", "L2.eml", b64wrapXR05(Buffer.from(l2, "utf8")));

    const res = await scanEmail({ raw_text: l1 });
    const top = res.attachment_scans.find((a) => a.filename === "L2.eml");
    expect(top, "L2.eml attachment scan should be present").toBeTruthy();

    // The image's IMG extraFinding bubbles through the L2 EML wrapper into
    // L2's structural[]. Its contextLocation MUST be the full chain — before
    // the fix it surfaced as just "IMG exif:UserComment".
    const imgFinding = (top.structural || []).find(
      (f) => typeof f.contextLocation === "string" && /\bIMG exif:UserComment$/.test(f.contextLocation)
    );
    expect(
      imgFinding,
      `expected one structural finding ending in 'IMG exif:UserComment', got:\n${JSON.stringify(top.structural, null, 2)}`
    ).toBeTruthy();
    expect(imgFinding.contextLocation).toBe(
      "Attachment L2.eml > attachment[0]: photo.jpg > IMG exif:UserComment"
    );
  });
});
