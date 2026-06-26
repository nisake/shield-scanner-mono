/**
 * PDF-DEEP-02 regression: catalog-level pdf.getOpenAction() coverage.
 *
 * Pins:
 *   - When the catalog exposes an /OpenAction map (e.g. auto-launch URL),
 *     the JSON-stringified body lands in the scan text under
 *     `[PDF kind=openaction] ...` so the central detector covers it.
 *   - When getOpenAction returns null / {} / "null", nothing is emitted.
 *   - Best-effort stringification: even non-stringifiable shapes don't crash
 *     the parser.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

let nextDoc = null;
vi.mock("pdfjs-dist/legacy/build/pdf.mjs", () => ({
  getDocument: () => ({ promise: Promise.resolve(nextDoc) }),
}));

const { parsePdfBuffer } = await import("../../server/parsers/pdf.js");

function makeDoc(overrides = {}) {
  return {
    numPages: 1,
    async getPage() {
      return {
        async getTextContent() { return { items: [] }; },
        async getAnnotations() { return []; },
      };
    },
    async getAttachments() { return null; },
    async getMetadata() { return { info: {}, metadata: null }; },
    async getFieldObjects() { return null; },
    async getJSActions() { return null; },
    async getOpenAction() { return null; },
    async getOutline() { return null; },
    ...overrides,
  };
}

describe("PDF-DEEP-02: catalog getOpenAction()", () => {
  beforeEach(() => { nextDoc = null; });

  it("emits [PDF kind=openaction] JSON when /OpenAction carries a URL", async () => {
    nextDoc = makeDoc({
      async getOpenAction() {
        return { url: "http://attacker.example/payload?ignore=previous" };
      },
    });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(out.text).toContain("[PDF kind=openaction]");
    expect(out.text).toContain("attacker.example");
  });

  it("emits the OpenAction body even for action: Print", async () => {
    nextDoc = makeDoc({
      async getOpenAction() { return { action: "Print" }; },
    });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(out.text).toContain("[PDF kind=openaction]");
    expect(out.text).toContain('"action":"Print"');
  });

  it("does not emit when getOpenAction returns null", async () => {
    nextDoc = makeDoc({ async getOpenAction() { return null; } });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(out.text).not.toContain("kind=openaction");
  });

  it("does not emit when getOpenAction returns an empty object", async () => {
    nextDoc = makeDoc({ async getOpenAction() { return {}; } });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(out.text).not.toContain("kind=openaction");
  });

  it("survives getOpenAction throwing", async () => {
    nextDoc = makeDoc({
      async getOpenAction() { throw new Error("bad OpenAction"); },
    });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(typeof out.text).toBe("string");
  });

  it("falls back to String() if JSON.stringify fails (circular ref)", async () => {
    nextDoc = makeDoc({
      async getOpenAction() {
        const o = { kind: "circular" };
        o.self = o; // JSON.stringify throws on this
        return o;
      },
    });
    // Parser must not throw — `stringified` defaults to String(o).
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(typeof out.text).toBe("string");
  });
});
