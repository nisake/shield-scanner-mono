/**
 * v1.15.0 Theme A embedded-binary-surface (DOCX) regression
 *
 * Pins the DOCX `word/media/*` 0-byte detection and the kebab-id refactor
 * for the oversize emit:
 *   - 0-byte buffer: technique:'empty-embedded-image', severity:'warning',
 *     contextLocation starts 'DOCX media:empty.jpg', element:'DOCX Embedded Image'
 *   - > OFFICE_MEDIA_MAX_BYTES (5 MB): technique:'oversize-embedded-image',
 *     meta.maxBytes === 5242880 (numeric, from module constant), severity:'warning'
 *
 * Invariants:
 *   - R12: both ids are fixed kebab strings — no user/attacker content path
 *     into the technique field. meta.maxBytes is a module constant.
 *   - 0-byte detection short-circuits BEFORE parseImageBuffer dispatch — the
 *     finding surfaces and the per-archive count cap (50) is decremented to
 *     keep zip-bomb amplification bounded.
 *   - The legacy template-literal label `Oversize embedded image skipped
 *     (> 5242880 bytes)` is NEVER emitted (R12 spirit + dict lookup contract
 *     hand-off to i18n.t_technique).
 */

import { describe, it, expect } from "vitest";
import JSZip from "jszip";
import { parseDocxBuffer } from "../../server/parsers/docx.js";

const W_NS = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`;

async function buildEmptyImageDocx() {
  const zip = new JSZip();
  zip.file(
    "[Content_Types].xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
  );
  zip.file(
    "_rels/.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
  );
  zip.file(
    "word/document.xml",
    `<?xml version="1.0" encoding="UTF-8"?><w:document ${W_NS}><w:body><w:p><w:r><w:t>hi</w:t></w:r></w:p></w:body></w:document>`,
  );
  zip.file("word/media/empty.jpg", Buffer.alloc(0));
  return await zip.generateAsync({ type: "nodebuffer" });
}

async function buildOversizeImageDocx() {
  const zip = new JSZip();
  zip.file(
    "[Content_Types].xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
  );
  zip.file(
    "_rels/.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
  );
  zip.file(
    "word/document.xml",
    `<?xml version="1.0" encoding="UTF-8"?><w:document ${W_NS}><w:body><w:p><w:r><w:t>hi</w:t></w:r></w:p></w:body></w:document>`,
  );
  // 6 MB payload — beyond the 5 MB cap. Content is benign 0x00 so the
  // oversize short-circuit fires before any image parser ever sees the
  // bytes (and never gets a chance to misclassify them).
  zip.file("word/media/big.jpg", Buffer.alloc(6 * 1024 * 1024));
  return await zip.generateAsync({ type: "nodebuffer" });
}

describe("v1.15.0 Theme A embedded-binary-surface: DOCX", () => {
  it("0-byte word/media/empty.jpg emits technique='empty-embedded-image' + severity='warning' + contextLocation prefix 'DOCX media:empty.jpg'", async () => {
    const buf = await buildEmptyImageDocx();
    const r = await parseDocxBuffer(buf);
    const empties = (r.extraFindings || []).filter(
      (f) => f.technique === "empty-embedded-image",
    );
    expect(empties.length).toBe(1);
    expect(empties[0].technique).toBe("empty-embedded-image");
    expect(empties[0].severity).toBe("warning");
    expect(empties[0].element).toBe("DOCX Embedded Image");
    expect(typeof empties[0].contextLocation).toBe("string");
    expect(empties[0].contextLocation.startsWith("DOCX media:empty.jpg")).toBe(
      true,
    );
    // R12: no template placeholders / legacy longform leaked.
    const legacy = (r.extraFindings || []).filter(
      (f) =>
        typeof f.technique === "string" &&
        /^Oversize embedded image skipped \(>/.test(f.technique),
    );
    expect(legacy.length).toBe(0);
  });

  it("oversize 6 MB word/media/big.jpg emits technique='oversize-embedded-image' + meta.maxBytes===5242880", async () => {
    const buf = await buildOversizeImageDocx();
    const r = await parseDocxBuffer(buf);
    const oversize = (r.extraFindings || []).filter(
      (f) => f.technique === "oversize-embedded-image",
    );
    expect(oversize.length).toBe(1);
    expect(oversize[0].technique).toBe("oversize-embedded-image");
    expect(oversize[0].severity).toBe("warning");
    expect(oversize[0].element).toBe("DOCX Embedded Image");
    expect(oversize[0].meta).toBeDefined();
    expect(oversize[0].meta.maxBytes).toBe(5 * 1024 * 1024);
    expect(typeof oversize[0].meta.maxBytes).toBe("number");
    // R12: ensure the dynamic byte count is NOT baked into the technique id
    // (it lives in meta only).
    expect(oversize[0].technique).not.toMatch(/5242880/);
    expect(oversize[0].technique).not.toMatch(/bytes/);
  });
});
