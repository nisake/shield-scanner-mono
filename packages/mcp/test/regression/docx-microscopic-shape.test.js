/**
 * v1.14.0 ext-2 Theme docx-microscopic-shape-extension regression
 *
 * Pins the DOCX shape/textbox (wps:txbxContent) extension of v1.13.0 Theme
 * docx-microscopic:
 *   - technique: 'microscopic-font-size' (kebab-case, fixed string; same as
 *     regular w:r)
 *   - meta: { fontSize: Number } (point value, dynamic numeric)
 *   - severity: 'danger'
 *   - element: 'w:r (Word run, shape textbox)' (contextual provenance vs
 *     regular 'w:r (Word run)')
 *
 * Invariants:
 *   - R12: technique label remains the fixed kebab string; element is also a
 *     fixed string (no dynamic numeric / no raw user text in either field).
 *     The numeric is isolated in meta.fontSize.
 *   - R13: byCategory 5-key shape preserved (no new category introduced —
 *     shape findings fold into the same default hiddenHtml bucket).
 *   - The shape walker is additive: regular run findings are still emitted
 *     for non-shape runs and shape runs are surfaced with the contextual
 *     element label (de-dup pass replaces a plain w:r finding when the same
 *     run reaches both walkers).
 */

import { describe, it, expect } from "vitest";
import JSZip from "jszip";
import { parseDocxBuffer } from "../../server/parsers/docx.js";

const W_NS = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`;
const WPS_NS = `xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape"`;
const WP_NS = `xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"`;
const A_NS = `xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"`;

async function buildShapeDocx({ documentXml }) {
  const zip = new JSZip();
  zip.file(
    "[Content_Types].xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
  );
  zip.file(
    "_rels/.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
  );
  zip.file("word/document.xml", documentXml);
  return await zip.generateAsync({ type: "nodebuffer" });
}

function shapeRun({ szVal, text }) {
  return (
    `<wps:txbxContent>` +
    `<w:p>` +
    `<w:r><w:rPr><w:sz w:val="${szVal}"/></w:rPr><w:t>${text}</w:t></w:r>` +
    `</w:p>` +
    `</wps:txbxContent>`
  );
}

describe("v1.14.0 ext-2 Theme docx-microscopic-shape-extension: positive grid", () => {
  it("wps:txbxContent with microscopic run val=2 (1pt) emits finding with element 'w:r (Word run, shape textbox)'", async () => {
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS} ${WP_NS} ${A_NS}><w:body>` +
        `<w:p>` +
        shapeRun({ szVal: "2", text: "shape textbox payload one point" }) +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const micros = (r.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(micros.length).toBe(1);
    expect(micros[0].element).toBe("w:r (Word run, shape textbox)");
    expect(micros[0].meta).toBeDefined();
    expect(micros[0].meta.fontSize).toBe(1);
    expect(typeof micros[0].meta.fontSize).toBe("number");
    expect(micros[0].severity).toBe("danger");
    expect(micros[0].content).toContain("shape textbox payload one point");
    expect(micros[0].category).toBeUndefined();
  });

  it("multiple wps:txbxContent blocks in same paragraph each emit shape-textbox findings", async () => {
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS} ${WP_NS} ${A_NS}><w:body>` +
        `<w:p>` +
        shapeRun({ szVal: "2", text: "first shape micro payload" }) +
        shapeRun({ szVal: "1", text: "second shape micro payload" }) +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const micros = (r.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(micros.length).toBe(2);
    for (const m of micros) {
      expect(m.element).toBe("w:r (Word run, shape textbox)");
    }
    const sizes = micros.map((m) => m.meta.fontSize).sort();
    expect(sizes).toEqual([0.5, 1]);
  });

  it("nested w:p inside wps:txbxContent surfaces with shape-textbox element label", async () => {
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS} ${WP_NS} ${A_NS}><w:body>` +
        `<w:p>` +
        `<wps:txbxContent>` +
        `<w:p><w:r><w:rPr><w:sz w:val="1"/></w:rPr><w:t>tiny in shape paragraph</w:t></w:r></w:p>` +
        `</wps:txbxContent>` +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const micros = (r.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(micros.length).toBe(1);
    expect(micros[0].element).toBe("w:r (Word run, shape textbox)");
    expect(micros[0].meta.fontSize).toBe(0.5);
    expect(micros[0].content).toContain("tiny in shape paragraph");
  });

  it("mixed: regular w:r microscopic + shape textbox w:r microscopic in same document emit two findings with distinct elements", async () => {
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS} ${WP_NS} ${A_NS}><w:body>` +
        `<w:p>` +
        `<w:r><w:rPr><w:sz w:val="2"/></w:rPr><w:t>regular run micro one</w:t></w:r>` +
        shapeRun({ szVal: "1", text: "shape run micro distinct" }) +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const micros = (r.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(micros.length).toBe(2);
    const regular = micros.filter((m) => m.element === "w:r (Word run)");
    const shape = micros.filter(
      (m) => m.element === "w:r (Word run, shape textbox)",
    );
    expect(regular.length).toBe(1);
    expect(shape.length).toBe(1);
    expect(regular[0].content).toContain("regular run micro one");
    expect(shape[0].content).toContain("shape run micro distinct");
  });

  it("wps:txbxContent with val=0 sentinel + non-whitespace text emits with meta.fontSize=0", async () => {
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS} ${WP_NS} ${A_NS}><w:body>` +
        `<w:p>` +
        shapeRun({ szVal: "0", text: "zero point shape payload" }) +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const micros = (r.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(micros.length).toBe(1);
    expect(micros[0].element).toBe("w:r (Word run, shape textbox)");
    expect(micros[0].meta.fontSize).toBe(0);
    expect(typeof micros[0].meta.fontSize).toBe("number");
    expect(micros[0].content).toContain("zero point shape payload");
  });

  it("R12 pin: shape-textbox finding never emits the legacy 'Microscopic font size (Npt)' label", async () => {
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS} ${WP_NS} ${A_NS}><w:body>` +
        `<w:p>` +
        shapeRun({ szVal: "3", text: "shape another tiny payload" }) +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const legacy = (r.extraFindings || []).filter(
      (f) =>
        typeof f.technique === "string" &&
        /^Microscopic font size \(/.test(f.technique),
    );
    expect(legacy.length).toBe(0);
  });
});

describe("v1.14.0 ext-2 Theme docx-microscopic-shape-extension: negative grid", () => {
  it("wps:txbxContent with microscopic sz but whitespace-only text is skipped", async () => {
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS} ${WP_NS} ${A_NS}><w:body>` +
        `<w:p>` +
        shapeRun({ szVal: "2", text: "   " }) +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const micros = (r.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(micros.length).toBe(0);
  });

  it("wps:txbxContent with normal font size (val=4, 2pt) generates no finding", async () => {
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS} ${WP_NS} ${A_NS}><w:body>` +
        `<w:p>` +
        `<wps:txbxContent><w:p><w:r><w:rPr><w:sz w:val="4"/></w:rPr><w:t>normal sized shape text</w:t></w:r></w:p></wps:txbxContent>` +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const micros = (r.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(micros.length).toBe(0);
  });

  it("empty wps:txbxContent (no w:r children) generates no finding", async () => {
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS} ${WP_NS} ${A_NS}><w:body>` +
        `<w:p>` +
        `<wps:txbxContent></wps:txbxContent>` +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const micros = (r.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(micros.length).toBe(0);
  });
});

describe("v1.14.0 ext-2 Theme docx-microscopic-shape-extension: tracked-change residue inside shape textbox", () => {
  // The w:delText walker is XML-position agnostic — it matches any w:delText
  // node anywhere in word/document.xml, including nested under a shape
  // textbox. Pin that the same severity/element surface holds for residue
  // hidden inside a shape so reviewers can't be fooled by the shape wrapper.
  it("w:delText nested inside wps:txbxContent surfaces with the same warning/element as a top-level deletion", async () => {
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS}><w:body>` +
        `<w:p>` +
        `<wps:txbxContent>` +
        `<w:p>` +
        `<w:del w:id="9" w:author="x" w:date="2026-06-26T00:00:00Z">` +
        `<w:r><w:delText>shape textbox deletion residue text</w:delText></w:r>` +
        `</w:del>` +
        `</w:p>` +
        `</wps:txbxContent>` +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const dels = (r.extraFindings || []).filter(
      (f) => f.technique && f.technique.includes("tracked-change"),
    );
    expect(dels.length).toBe(1);
    expect(dels[0].severity).toBe("warning");
    expect(dels[0].element).toBe("w:del (Tracked-change deletion)");
    expect(dels[0].content).toContain("shape textbox deletion residue text");
    expect(dels[0].category).toBeUndefined();
  });
});

describe("v1.14.0 ext-2 Theme docx-microscopic-shape-extension: R12 raw text leak guard", () => {
  it("shape-textbox finding's technique + element fields are fixed strings (no raw user text injection)", async () => {
    const ATTACK = "ATTACK__PAYLOAD__MARKER";
    const buf = await buildShapeDocx({
      documentXml:
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<w:document ${W_NS} ${WPS_NS} ${WP_NS} ${A_NS}><w:body>` +
        `<w:p>` +
        shapeRun({ szVal: "1", text: ATTACK }) +
        `</w:p>` +
        `</w:body></w:document>`,
    });
    const r = await parseDocxBuffer(buf);
    const micros = (r.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(micros.length).toBe(1);
    // technique/element are fixed strings, ATTACK is allowed in content only.
    expect(micros[0].technique).toBe("microscopic-font-size");
    expect(micros[0].element).toBe("w:r (Word run, shape textbox)");
    expect(micros[0].technique.includes(ATTACK)).toBe(false);
    expect(micros[0].element.includes(ATTACK)).toBe(false);
    // content legitimately echoes the user-controlled string.
    expect(micros[0].content).toContain(ATTACK);
  });
});
