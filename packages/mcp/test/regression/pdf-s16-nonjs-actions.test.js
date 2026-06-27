/**
 * v1.18.0 S16 regression: PDF non-JS high-risk action / multimedia signals.
 *
 * Pins six new kebab extraFinding ids that ride the per-page annotation loop:
 *   - pdf-submit-form-action        (SubmitForm via a.actions[SubmitForm])
 *   - pdf-goto-remote-action        (GoToR via a.actions[GoToR] or Link a.url
 *                                    with a.actionType === 'GoToR')
 *   - pdf-richmedia-embed           (Subtype === 'RichMedia')
 *   - pdf-3d-embed                  (Subtype === '3D')
 *   - pdf-sound-action              (Subtype === 'Sound')
 *   - pdf-movie-action              (Subtype === 'Movie')
 *
 * Contracts (each identical to the S15 widget signal):
 *   - element='PDF Catalog' / severity='warning' / contextLocation='Catalog'
 *   - exactly ONE per document (1-per-doc invariant)
 *   - R12 safe: meta carries only sanitized URL (sanitizeKey strips spaces/
 *     brackets, ≤64 chars) or PDF spec subtype enum — NEVER raw attacker text
 *   - benign FP guard: empty annotation list emits 0 of any new kebab id
 *   - R13 fold: every new finding stays inside the 5 baseline byCategory
 *     keys via the central detector — the test only asserts the kebab id
 *     contract surface; the byCategory pin lives in baseline.test.js.
 *
 * Strategy: vi.mock pdfjs-dist legacy build with a synthesized doc, same
 * pattern as pdf-s15-embedded-html-js.test.js.
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

const STUB_BYTES = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

describe("v1.18.0 S16: pdf-submit-form-action signal", () => {
  beforeEach(() => { nextDoc = null; });

  it("emits exactly ONE signal when a Widget /A SubmitForm is present", async () => {
    nextDoc = makeDoc({
      async getPage() {
        return {
          async getTextContent() { return { items: [] }; },
          async getAnnotations() {
            return [{
              subtype: "Widget",
              fieldName: "submitBtn",
              actions: {
                SubmitForm: ["https://evil.example/exfil"],
              },
            }];
          },
        };
      },
    });
    const out = await parsePdfBuffer(STUB_BYTES);
    const hits = out.extraFindings.filter((f) => f.technique === "pdf-submit-form-action");
    expect(hits.length).toBe(1);
    const hit = hits[0];
    expect(hit.element).toBe("PDF Catalog");
    expect(hit.severity).toBe("warning");
    expect(hit.contextLocation).toBe("Catalog");
    expect(hit.meta).toBeTruthy();
    expect(typeof hit.meta.targetUrl).toBe("string");
    // R12 audit: sanitized targetUrl drops brackets and is ≤64 chars
    expect(hit.meta.targetUrl.length).toBeLessThanOrEqual(64);
    expect(hit.meta.targetUrl).not.toMatch(/[\s\[\]]/);
  });

  it("collapses multiple SubmitForm actions across pages to ONE signal", async () => {
    nextDoc = makeDoc({
      numPages: 3,
      async getPage(i) {
        return {
          async getTextContent() { return { items: [] }; },
          async getAnnotations() {
            return [{
              subtype: "Widget",
              fieldName: `submit_${i}`,
              actions: { SubmitForm: [`https://e.example/p${i}`] },
            }];
          },
        };
      },
    });
    const out = await parsePdfBuffer(STUB_BYTES);
    const hits = out.extraFindings.filter((f) => f.technique === "pdf-submit-form-action");
    expect(hits.length).toBe(1);
  });

  it("does NOT emit when no SubmitForm action exists", async () => {
    nextDoc = makeDoc();
    const out = await parsePdfBuffer(STUB_BYTES);
    const hits = out.extraFindings.filter((f) => f.technique === "pdf-submit-form-action");
    expect(hits.length).toBe(0);
  });
});

describe("v1.18.0 S16: pdf-goto-remote-action signal", () => {
  beforeEach(() => { nextDoc = null; });

  it("emits ONE signal when a Widget /A GoToR is present", async () => {
    nextDoc = makeDoc({
      async getPage() {
        return {
          async getTextContent() { return { items: [] }; },
          async getAnnotations() {
            return [{
              subtype: "Widget",
              fieldName: "gotoBtn",
              actions: { GoToR: ["https://evil.example/other.pdf"] },
            }];
          },
        };
      },
    });
    const out = await parsePdfBuffer(STUB_BYTES);
    const hits = out.extraFindings.filter((f) => f.technique === "pdf-goto-remote-action");
    expect(hits.length).toBe(1);
    const hit = hits[0];
    expect(hit.element).toBe("PDF Catalog");
    expect(hit.severity).toBe("warning");
    expect(hit.contextLocation).toBe("Catalog");
    expect(hit.meta).toBeTruthy();
    expect(typeof hit.meta.target).toBe("string");
    expect(hit.meta.target).not.toMatch(/[\s\[\]]/);
  });

  it("emits via Link a.url when actionType === GoToR", async () => {
    nextDoc = makeDoc({
      async getPage() {
        return {
          async getTextContent() { return { items: [] }; },
          async getAnnotations() {
            return [{
              subtype: "Link",
              url: "https://evil.example/other.pdf",
              actionType: "GoToR",
            }];
          },
        };
      },
    });
    const out = await parsePdfBuffer(STUB_BYTES);
    const hits = out.extraFindings.filter((f) => f.technique === "pdf-goto-remote-action");
    expect(hits.length).toBe(1);
  });

  it("does NOT emit on plain external Link (no GoToR action tag)", async () => {
    nextDoc = makeDoc({
      async getPage() {
        return {
          async getTextContent() { return { items: [] }; },
          async getAnnotations() {
            return [{
              subtype: "Link",
              url: "https://benign.example/page",
              // no actionType / no actions
            }];
          },
        };
      },
    });
    const out = await parsePdfBuffer(STUB_BYTES);
    const hits = out.extraFindings.filter((f) => f.technique === "pdf-goto-remote-action");
    expect(hits.length).toBe(0);
  });
});

describe("v1.18.0 S16: pdf-richmedia-embed / pdf-3d-embed / pdf-sound-action / pdf-movie-action", () => {
  beforeEach(() => { nextDoc = null; });

  for (const [subtype, kebab] of [
    ["RichMedia", "pdf-richmedia-embed"],
    ["3D", "pdf-3d-embed"],
    ["Sound", "pdf-sound-action"],
    ["Movie", "pdf-movie-action"],
  ]) {
    it(`emits ONE ${kebab} when subtype=${subtype} annotation present`, async () => {
      nextDoc = makeDoc({
        async getPage() {
          return {
            async getTextContent() { return { items: [] }; },
            async getAnnotations() { return [{ subtype }]; },
          };
        },
      });
      const out = await parsePdfBuffer(STUB_BYTES);
      const hits = out.extraFindings.filter((f) => f.technique === kebab);
      expect(hits.length).toBe(1);
      const hit = hits[0];
      expect(hit.element).toBe("PDF Catalog");
      expect(hit.severity).toBe("warning");
      expect(hit.contextLocation).toBe("Catalog");
      expect(hit.meta).toBeTruthy();
      expect(hit.meta.subtype).toBe(subtype);
    });
  }

  it("collapses multiple RichMedia annotations across pages to ONE signal", async () => {
    nextDoc = makeDoc({
      numPages: 2,
      async getPage() {
        return {
          async getTextContent() { return { items: [] }; },
          async getAnnotations() {
            return [
              { subtype: "RichMedia" },
              { subtype: "RichMedia" },
            ];
          },
        };
      },
    });
    const out = await parsePdfBuffer(STUB_BYTES);
    const hits = out.extraFindings.filter((f) => f.technique === "pdf-richmedia-embed");
    expect(hits.length).toBe(1);
  });
});

describe("v1.18.0 S16: benign FP guard + multi-signal coexistence", () => {
  beforeEach(() => { nextDoc = null; });

  it("0 of the 6 new kebab ids emitted on a fully-empty PDF", async () => {
    nextDoc = makeDoc();
    const out = await parsePdfBuffer(STUB_BYTES);
    const kebabs = [
      "pdf-submit-form-action", "pdf-goto-remote-action",
      "pdf-richmedia-embed", "pdf-3d-embed",
      "pdf-sound-action", "pdf-movie-action",
    ];
    for (const k of kebabs) {
      expect(out.extraFindings.filter((f) => f.technique === k).length, k).toBe(0);
    }
  });

  it("multiple distinct subtypes coexist, each emitting their own ONE signal", async () => {
    nextDoc = makeDoc({
      async getPage() {
        return {
          async getTextContent() { return { items: [] }; },
          async getAnnotations() {
            return [
              { subtype: "RichMedia" },
              { subtype: "3D" },
              { subtype: "Sound" },
              { subtype: "Movie" },
              { subtype: "Widget", fieldName: "x", actions: { SubmitForm: ["https://a.example"] } },
              { subtype: "Widget", fieldName: "y", actions: { GoToR: ["https://b.example/y.pdf"] } },
            ];
          },
        };
      },
    });
    const out = await parsePdfBuffer(STUB_BYTES);
    expect(out.extraFindings.filter((f) => f.technique === "pdf-richmedia-embed").length).toBe(1);
    expect(out.extraFindings.filter((f) => f.technique === "pdf-3d-embed").length).toBe(1);
    expect(out.extraFindings.filter((f) => f.technique === "pdf-sound-action").length).toBe(1);
    expect(out.extraFindings.filter((f) => f.technique === "pdf-movie-action").length).toBe(1);
    expect(out.extraFindings.filter((f) => f.technique === "pdf-submit-form-action").length).toBe(1);
    expect(out.extraFindings.filter((f) => f.technique === "pdf-goto-remote-action").length).toBe(1);
  });
});
