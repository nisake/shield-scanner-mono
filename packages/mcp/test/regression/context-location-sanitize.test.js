/**
 * PDF-EML-FILENAME-CONTEXTLOC-SANITIZE regression.
 *
 * The filename portion of `contextLocation` (e.g. "Attachment <filename>")
 * MUST NOT contain raw bidi controls, ANSI escape sequences, zero-width
 * codepoints, or line-injection bytes. These would let a crafted attachment
 * filename re-render the surrounding UI / report (R12 risk extension).
 *
 * Covers both the helper (sanitizeContextLocation) and end-to-end through
 * EML and PDF parsers.
 */

import { describe, it, expect, vi } from "vitest";
import { sanitizeContextLocation } from "@shield-scanner/core";
import { parseEmlContent } from "../../server/parsers/eml.js";

let nextDoc = null;
vi.mock("pdfjs-dist/legacy/build/pdf.mjs", () => ({
  getDocument: () => ({ promise: Promise.resolve(nextDoc) }),
}));
const { parsePdfBuffer } = await import("../../server/parsers/pdf.js");

describe("sanitizeContextLocation helper", () => {
  it("strips bidi RLO (U+202E)", () => {
    expect(sanitizeContextLocation("evil‮fdp.docx")).toBe("evil?fdp.docx");
  });

  it("strips line-injection (\\r \\n \\t)", () => {
    expect(sanitizeContextLocation("a\rb")).toBe("a?b");
    expect(sanitizeContextLocation("a\nb")).toBe("a?b");
    expect(sanitizeContextLocation("a\tb")).toBe("a?b");
  });

  it("strips CSI ANSI sequence", () => {
    expect(sanitizeContextLocation("evil[31mred.txt")).toBe("evil?red.txt");
  });

  it("strips OSC ANSI sequence (ESC ] ... BEL)", () => {
    expect(sanitizeContextLocation("evil]0;titlefoo.txt")).toBe("evil?foo.txt");
  });

  it("strips zero-width codepoints (ZWSP)", () => {
    expect(sanitizeContextLocation("a​b")).toBe("a?b");
  });

  it("preserves legitimate square brackets", () => {
    expect(sanitizeContextLocation("dir [v1]/file.txt")).toBe("dir [v1]/file.txt");
  });

  it("returns '' on null / undefined", () => {
    expect(sanitizeContextLocation(null)).toBe("");
    expect(sanitizeContextLocation(undefined)).toBe("");
  });

  it("caps the result at 200 chars", () => {
    expect(sanitizeContextLocation("a".repeat(500)).length).toBe(200);
  });
});

describe("EML parser: sanitized filename in extraFinding contextLocation", () => {
  it("RLO in attachment filename is stripped before reaching contextLocation", async () => {
    const filename = "evil‮Fdp.docx";
    const boundary = "----shield-scanner-rlo-boundary";
    const raw = [
      "From: a@example.com",
      "To: b@example.com",
      "Subject: rlo filename",
      "MIME-Version: 1.0",
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      "",
      `--${boundary}`,
      "Content-Type: text/plain; charset=utf-8",
      "",
      "(body)",
      "",
      `--${boundary}`,
      "Content-Type: text/plain; charset=utf-8",
      `Content-Disposition: attachment; filename="${filename}"`,
      "Content-Transfer-Encoding: base64",
      "",
      Buffer.from("payload").toString("base64"),
      "",
      `--${boundary}--`,
      "",
    ].join("\r\n");
    const out = await parseEmlContent(raw);
    // Existing RLO-in-filename detector should fire AND its contextLocation
    // must be the sanitized form (no U+202E byte).
    const rloHit = (out.extraFindings || []).find(
      (f) => /Right-to-Left Override/.test(f.technique || ""),
    );
    expect(rloHit).toBeTruthy();
    expect(rloHit.contextLocation).not.toMatch(/‮/);
    expect(rloHit.contextLocation).toBe("Attachment evil?Fdp.docx");
  });
});

describe("PDF parser: sanitized filename in contextLocation", () => {
  it("oversize-attachment warning carries sanitized filename", async () => {
    const filename = "huge‮Fdp.txt";
    nextDoc = {
      numPages: 1,
      async getPage() {
        return {
          async getTextContent() { return { items: [] }; },
          async getAnnotations() { return []; },
        };
      },
      async getAttachments() {
        return {
          [filename]: {
            filename,
            content: new Uint8Array(6 * 1024 * 1024),
          },
        };
      },
      async getMetadata() { return { info: {}, metadata: null }; },
      async getFieldObjects() { return null; },
      async getJSActions() { return null; },
      async getOpenAction() { return null; },
      async getOutline() { return null; },
    };
    const out = await parsePdfBuffer(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
    const hit = (out.extraFindings || []).find(
      (f) => f.technique === "Oversize attachment skipped (> 5MB)",
    );
    expect(hit).toBeTruthy();
    expect(hit.contextLocation).not.toMatch(/‮/);
    expect(hit.contextLocation).toBe("Attachment huge?Fdp.txt");
  });
});
