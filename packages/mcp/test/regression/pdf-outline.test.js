/**
 * PDF-DEEP-03 regression: catalog-level pdf.getOutline() coverage.
 *
 * Pins:
 *   - Each outline node's title lands as `[PDF kind=outline depth=D] <title>`.
 *   - Each unsafeUrl lands as `[PDF kind=outline-url depth=D] <url>`.
 *   - Recursive items[] are walked depth-first; depth is incremented.
 *   - Hard caps: walker stops at depth > 5 or after 256 total nodes so a
 *     cyclic / decoy-tree outline cannot pin the parser.
 *   - getOutline === null is silently skipped.
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

describe("PDF-DEEP-03: catalog getOutline()", () => {
  beforeEach(() => { nextDoc = null; });

  it("emits depth-tagged title for top-level bookmark", async () => {
    nextDoc = makeDoc({
      async getOutline() {
        return [{ title: "Chapter One", unsafeUrl: null, items: [] }];
      },
    });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(out.text).toContain("[PDF kind=outline depth=0] Chapter One");
  });

  it("emits unsafeUrl alongside title", async () => {
    nextDoc = makeDoc({
      async getOutline() {
        return [{
          title: "Click me",
          unsafeUrl: "http://malicious.example/x",
          items: [],
        }];
      },
    });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(out.text).toContain("[PDF kind=outline depth=0] Click me");
    expect(out.text).toContain("[PDF kind=outline-url depth=0] http://malicious.example/x");
  });

  it("walks nested items with increasing depth", async () => {
    nextDoc = makeDoc({
      async getOutline() {
        return [{
          title: "Top",
          items: [
            { title: "Sub", items: [{ title: "Leaf", items: [] }] },
          ],
        }];
      },
    });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(out.text).toContain("[PDF kind=outline depth=0] Top");
    expect(out.text).toContain("[PDF kind=outline depth=1] Sub");
    expect(out.text).toContain("[PDF kind=outline depth=2] Leaf");
  });

  it("stops at the depth cap (depth > 5 ignored)", async () => {
    // Build a chain of length 8: depth 0..7. The 4-level cap is 5, so
    // depth=6 and depth=7 must NOT appear.
    const make = (n, label) => n === 0 ? [] : [{ title: `${label}-${n}`, items: make(n - 1, label) }];
    nextDoc = makeDoc({ async getOutline() { return make(8, "L"); } });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(out.text).toContain("[PDF kind=outline depth=5] L-3");
    expect(out.text).not.toContain("depth=6");
    expect(out.text).not.toContain("depth=7");
  });

  it("stops at the 256-node cap (cycle-bomb protection)", async () => {
    // A sibling array of 300 entries at the root level — all depth 0 — must
    // be truncated at 256 emissions.
    const big = [];
    for (let k = 0; k < 300; k++) big.push({ title: `node-${k}`, items: [] });
    nextDoc = makeDoc({ async getOutline() { return big; } });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(out.text).toContain("node-255");
    expect(out.text).not.toContain("node-256");
    expect(out.text).not.toContain("node-299");
  });

  it("does nothing when getOutline returns null", async () => {
    nextDoc = makeDoc({ async getOutline() { return null; } });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(out.text).not.toContain("kind=outline");
  });

  it("survives getOutline throwing", async () => {
    nextDoc = makeDoc({ async getOutline() { throw new Error("bad"); } });
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    expect(typeof out.text).toBe("string");
  });
});
