/**
 * v1.15.0 Theme A embedded-binary-surface (PPTX) regression
 *
 * Mirrors docx-empty-image.test.js for the PPTX `ppt/media/*` carrier:
 *   - 0-byte buffer: technique:'empty-embedded-image', severity:'warning',
 *     contextLocation starts 'PPTX media:empty.jpg', element:'PPTX Embedded Image'
 *   - > OFFICE_MEDIA_MAX_BYTES: technique:'oversize-embedded-image',
 *     meta.maxBytes === 5242880, severity:'warning'
 *
 * R23 mirror invariant: MCP parsers MUST emit byte-identical finding shapes
 * to the Web parsers (sans the `category:'hiddenHtml'` field, which is XLSX
 * Web-only and out of scope for DOCX/PPTX).
 */

import { describe, it, expect } from "vitest";
import JSZip from "jszip";
import { parsePptxBuffer } from "../../server/parsers/pptx.js";

const P_NS = `xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"`;
const A_NS = `xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"`;

async function buildEmptyImagePptx() {
  const zip = new JSZip();
  zip.file(
    "[Content_Types].xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/></Types>`,
  );
  zip.file(
    "_rels/.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/></Relationships>`,
  );
  zip.file(
    "ppt/presentation.xml",
    `<?xml version="1.0" encoding="UTF-8"?><p:presentation ${P_NS}><p:sldIdLst><p:sldId id="256" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></p:sldIdLst></p:presentation>`,
  );
  zip.file(
    "ppt/slides/slide1.xml",
    `<?xml version="1.0" encoding="UTF-8"?><p:sld ${P_NS} ${A_NS}><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>hi</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`,
  );
  zip.file("ppt/media/empty.jpg", Buffer.alloc(0));
  return await zip.generateAsync({ type: "nodebuffer" });
}

async function buildOversizeImagePptx() {
  const zip = new JSZip();
  zip.file(
    "[Content_Types].xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/></Types>`,
  );
  zip.file(
    "_rels/.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/></Relationships>`,
  );
  zip.file(
    "ppt/presentation.xml",
    `<?xml version="1.0" encoding="UTF-8"?><p:presentation ${P_NS}><p:sldIdLst><p:sldId id="256" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></p:sldIdLst></p:presentation>`,
  );
  zip.file(
    "ppt/slides/slide1.xml",
    `<?xml version="1.0" encoding="UTF-8"?><p:sld ${P_NS} ${A_NS}><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>hi</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`,
  );
  zip.file("ppt/media/big.jpg", Buffer.alloc(6 * 1024 * 1024));
  return await zip.generateAsync({ type: "nodebuffer" });
}

describe("v1.15.0 Theme A embedded-binary-surface: PPTX", () => {
  it("0-byte ppt/media/empty.jpg emits technique='empty-embedded-image' + severity='warning' + contextLocation prefix 'PPTX media:empty.jpg'", async () => {
    const buf = await buildEmptyImagePptx();
    const r = await parsePptxBuffer(buf);
    const empties = (r.extraFindings || []).filter(
      (f) => f.technique === "empty-embedded-image",
    );
    expect(empties.length).toBe(1);
    expect(empties[0].technique).toBe("empty-embedded-image");
    expect(empties[0].severity).toBe("warning");
    expect(empties[0].element).toBe("PPTX Embedded Image");
    expect(typeof empties[0].contextLocation).toBe("string");
    expect(empties[0].contextLocation.startsWith("PPTX media:empty.jpg")).toBe(
      true,
    );
    const legacy = (r.extraFindings || []).filter(
      (f) =>
        typeof f.technique === "string" &&
        /^Oversize embedded image skipped \(>/.test(f.technique),
    );
    expect(legacy.length).toBe(0);
  });

  it("oversize 6 MB ppt/media/big.jpg emits technique='oversize-embedded-image' + meta.maxBytes===5242880", async () => {
    const buf = await buildOversizeImagePptx();
    const r = await parsePptxBuffer(buf);
    const oversize = (r.extraFindings || []).filter(
      (f) => f.technique === "oversize-embedded-image",
    );
    expect(oversize.length).toBe(1);
    expect(oversize[0].technique).toBe("oversize-embedded-image");
    expect(oversize[0].severity).toBe("warning");
    expect(oversize[0].element).toBe("PPTX Embedded Image");
    expect(oversize[0].meta).toBeDefined();
    expect(oversize[0].meta.maxBytes).toBe(5 * 1024 * 1024);
    expect(typeof oversize[0].meta.maxBytes).toBe("number");
    expect(oversize[0].technique).not.toMatch(/5242880/);
    expect(oversize[0].technique).not.toMatch(/bytes/);
  });
});
