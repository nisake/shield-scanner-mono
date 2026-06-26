/**
 * v1.13.0 Theme docx-microscopic regression
 *
 * Pins the DOCX equivalent of PDF Theme A microscopic-text (v1.12.0):
 *   - technique: 'microscopic-font-size' (kebab-case, fixed string)
 *   - meta: { fontSize: Number } (point value, dynamic numeric)
 *   - severity: 'danger'
 *   - element: 'w:r (Word run)'
 *
 * Invariants:
 *   - R12: the old format-string label `Microscopic font size (Npt)` is
 *     never emitted by the parser (no raw / dynamic numeric in the technique
 *     id). The numeric is isolated in meta.fontSize for the UI to format.
 *   - The detection envelope (w:sz val 0-3 half-points = 0-1.5pt) is unchanged
 *     from v1.12.0; only the surface shape moved.
 *   - val='0' (0pt sentinel) matches the regex but a whitespace-only text run
 *     is skipped (tf[2].trim() filter).
 */

import { describe, it, expect } from "vitest";
import JSZip from "jszip";
import { parseDocxBuffer } from "../../server/parsers/docx.js";

const W_NS = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`;

async function buildMicroscopicDocx({ szVal, text }) {
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
    `<?xml version="1.0" encoding="UTF-8"?>` +
      `<w:document ${W_NS}><w:body>` +
      `<w:p>` +
      `<w:r><w:t>visible text</w:t></w:r>` +
      `<w:r><w:rPr><w:sz w:val="${szVal}"/></w:rPr><w:t>${text}</w:t></w:r>` +
      `</w:p>` +
      `</w:body></w:document>`,
  );
  return await zip.generateAsync({ type: "nodebuffer" });
}

describe("v1.13.0 Theme docx-microscopic: technique surface", () => {
  it("emits kebab technique 'microscopic-font-size' + meta.fontSize===1 (Number) for w:sz val=2 (1pt)", async () => {
    const buf = await buildMicroscopicDocx({
      szVal: "2",
      text: "hidden one point payload",
    });
    const r = await parseDocxBuffer(buf);
    const micros = (r.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(micros.length).toBe(1);
    expect(micros[0].technique).toBe("microscopic-font-size");
    expect(micros[0].meta).toBeDefined();
    expect(micros[0].meta.fontSize).toBe(1);
    expect(typeof micros[0].meta.fontSize).toBe("number");
    expect(micros[0].severity).toBe("danger");
    expect(micros[0].element).toBe("w:r (Word run)");
    expect(micros[0].content).toContain("hidden one point payload");
    // category not set → default hiddenHtml bucket (R13 5-key shape preserved)
    expect(micros[0].category).toBeUndefined();
  });

  it("R12 regression pin: the old format-string label 'Microscopic font size (Npt)' is NEVER emitted", async () => {
    // v1.12.0 and earlier emitted `Microscopic font size (${pt}pt)` — a
    // dynamic numeric value baked into the technique id (R12 violation).
    // v1.13.0 Theme docx-microscopic moves the numeric into meta.fontSize
    // and uses a fixed kebab-case id. This test guards against an accidental
    // revert: any finding whose technique string matches the legacy pattern
    // fails the build immediately.
    const buf = await buildMicroscopicDocx({
      szVal: "3",
      text: "another tiny payload",
    });
    const r = await parseDocxBuffer(buf);
    const legacyShaped = (r.extraFindings || []).filter(
      (f) => typeof f.technique === "string" &&
             /^Microscopic font size \(/.test(f.technique),
    );
    expect(legacyShaped.length).toBe(0);
  });

  it("meta.fontSize carries the correct point value across val='1' (0.5pt) and val='3' (1.5pt)", async () => {
    // val=1 → 0.5pt
    const bufHalf = await buildMicroscopicDocx({
      szVal: "1",
      text: "half point text",
    });
    const rHalf = await parseDocxBuffer(bufHalf);
    const microsHalf = (rHalf.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(microsHalf.length).toBe(1);
    expect(microsHalf[0].meta.fontSize).toBe(0.5);
    expect(typeof microsHalf[0].meta.fontSize).toBe("number");

    // val=3 → 1.5pt
    const bufOneHalf = await buildMicroscopicDocx({
      szVal: "3",
      text: "one and a half point text",
    });
    const rOneHalf = await parseDocxBuffer(bufOneHalf);
    const microsOneHalf = (rOneHalf.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(microsOneHalf.length).toBe(1);
    expect(microsOneHalf[0].meta.fontSize).toBe(1.5);
    expect(typeof microsOneHalf[0].meta.fontSize).toBe("number");
  });

  it("val='0' (0pt sentinel) regex matches but a whitespace-only text run is skipped", async () => {
    // val=0 is within the [0-3] regex class. The parser's `tf[2].trim()`
    // guard MUST skip whitespace-only payloads so a benign zero-sized
    // placeholder doesn't generate a finding.
    const bufWhitespace = await buildMicroscopicDocx({
      szVal: "0",
      text: "   ",
    });
    const rWhitespace = await parseDocxBuffer(bufWhitespace);
    const microsWhitespace = (rWhitespace.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(microsWhitespace.length).toBe(0);

    // Sanity check: same val=0 with non-whitespace text DOES surface, so the
    // skip is targeted at empty/whitespace payloads, not at val=0 itself.
    const bufActual = await buildMicroscopicDocx({
      szVal: "0",
      text: "zero point payload",
    });
    const rActual = await parseDocxBuffer(bufActual);
    const microsActual = (rActual.extraFindings || []).filter(
      (f) => f.technique === "microscopic-font-size",
    );
    expect(microsActual.length).toBe(1);
    expect(microsActual[0].meta.fontSize).toBe(0);
    expect(typeof microsActual[0].meta.fontSize).toBe("number");
  });
});
