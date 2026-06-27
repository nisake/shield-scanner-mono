/**
 * v1.15.0 Theme A embedded-binary-surface (XLSX) regression
 *
 * Mirrors docx/pptx-empty-image.test.js for the XLSX `xl/media/*` carrier.
 * Note: the MCP XLSX scanMedia oversize emit does NOT include
 * `category:'hiddenHtml'` (only the Web mirror does, to align with the
 * adjacent Embedded OLE block in the same file). We follow the existing MCP
 * shape — adding a category here would be a parser-shape drift.
 *
 * Pins:
 *   - 0-byte buffer: technique:'empty-embedded-image', severity:'warning',
 *     contextLocation starts 'XLSX media:empty.jpg', element:'XLSX Embedded Image'
 *   - > OFFICE_MEDIA_MAX_BYTES: technique:'oversize-embedded-image',
 *     meta.maxBytes === 5242880, severity:'warning'
 */

import { describe, it, expect } from "vitest";
import JSZip from "jszip";
import { parseXlsxBuffer } from "../../server/parsers/xlsx.js";

async function buildEmptyImageXlsx() {
  const zip = new JSZip();
  zip.file(
    "[Content_Types].xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`,
  );
  zip.file(
    "_rels/.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
  );
  zip.file(
    "xl/workbook.xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`,
  );
  zip.file(
    "xl/_rels/workbook.xml.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`,
  );
  zip.file(
    "xl/worksheets/sheet1.xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>hi</t></is></c></row></sheetData></worksheet>`,
  );
  zip.file("xl/media/empty.jpg", Buffer.alloc(0));
  return await zip.generateAsync({ type: "nodebuffer" });
}

async function buildOversizeImageXlsx() {
  const zip = new JSZip();
  zip.file(
    "[Content_Types].xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`,
  );
  zip.file(
    "_rels/.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
  );
  zip.file(
    "xl/workbook.xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`,
  );
  zip.file(
    "xl/_rels/workbook.xml.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`,
  );
  zip.file(
    "xl/worksheets/sheet1.xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>hi</t></is></c></row></sheetData></worksheet>`,
  );
  zip.file("xl/media/big.jpg", Buffer.alloc(6 * 1024 * 1024));
  return await zip.generateAsync({ type: "nodebuffer" });
}

describe("v1.15.0 Theme A embedded-binary-surface: XLSX", () => {
  it("0-byte xl/media/empty.jpg emits technique='empty-embedded-image' + severity='warning' + contextLocation prefix 'XLSX media:empty.jpg'", async () => {
    const buf = await buildEmptyImageXlsx();
    const r = await parseXlsxBuffer(buf);
    const empties = (r.extraFindings || []).filter(
      (f) => f.technique === "empty-embedded-image",
    );
    expect(empties.length).toBe(1);
    expect(empties[0].technique).toBe("empty-embedded-image");
    expect(empties[0].severity).toBe("warning");
    expect(empties[0].element).toBe("XLSX Embedded Image");
    expect(typeof empties[0].contextLocation).toBe("string");
    expect(empties[0].contextLocation.startsWith("XLSX media:empty.jpg")).toBe(
      true,
    );
    const legacy = (r.extraFindings || []).filter(
      (f) =>
        typeof f.technique === "string" &&
        /^Oversize embedded image skipped \(>/.test(f.technique),
    );
    expect(legacy.length).toBe(0);
  });

  it("oversize 6 MB xl/media/big.jpg emits technique='oversize-embedded-image' + meta.maxBytes===5242880", async () => {
    const buf = await buildOversizeImageXlsx();
    const r = await parseXlsxBuffer(buf);
    const oversize = (r.extraFindings || []).filter(
      (f) => f.technique === "oversize-embedded-image",
    );
    expect(oversize.length).toBe(1);
    expect(oversize[0].technique).toBe("oversize-embedded-image");
    expect(oversize[0].severity).toBe("warning");
    expect(oversize[0].element).toBe("XLSX Embedded Image");
    expect(oversize[0].meta).toBeDefined();
    expect(oversize[0].meta.maxBytes).toBe(5 * 1024 * 1024);
    expect(typeof oversize[0].meta.maxBytes).toBe("number");
    expect(oversize[0].technique).not.toMatch(/5242880/);
    expect(oversize[0].technique).not.toMatch(/bytes/);
  });
});
