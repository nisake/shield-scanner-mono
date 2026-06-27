/**
 * v1.20.0 T6 regression: PDF /EmbeddedFile /Subtype raw-bytes helper.
 *
 * Pins the contract of extractEmbeddedFileSubtypes / hasEmbeddedHtmlSubtype
 * in packages/mcp/server/parsers/pdf-attachment-subtype.js — the helper that
 * works around pdf.js v4's missing /Subtype propagation on getAttachments().
 *
 * Coverage:
 *   - hex-encoded `/text#2Fhtml` is decoded to `text/html` (real fixture)
 *   - plain `/text/html` Name form is also accepted (synthesized buffer)
 *   - application/xhtml+xml is recognised (hex-encoded form)
 *   - benign /Type /EmbeddedFile with `/Subtype /text#2Fplain` is NOT flagged
 *     as html (hasEmbeddedHtmlSubtype false)
 *   - PDF with no embedded file → empty list / false
 *   - multiple distinct subtypes are deduplicated and returned in order
 *   - /SubtypeSomething (boundary check) does NOT spoof a subtype hit
 *   - lookahead stops at endobj — a /Subtype in a sibling object does NOT
 *     leak into the EmbeddedFile entry
 *   - byte-cap defense: input under 8 bytes returns empty
 *   - R12: returned strings only contain canonical subtype text (no raw
 *     PDF bytes leak through)
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  extractEmbeddedFileSubtypes,
  hasEmbeddedHtmlSubtype,
  __test__,
} from "../../server/parsers/pdf-attachment-subtype.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(
  __dirname,
  "..",
  "fixtures",
  "attacks",
  "pdf_embedded_html_subtype.pdf",
);

function synthBuf(s) {
  return Buffer.from(s, "latin1");
}

describe("v1.20.0 T6: pdf-attachment-subtype helper", () => {
  it("decodes /text#2Fhtml from the real on-disk fixture", () => {
    const buf = readFileSync(FIXTURE);
    const subs = extractEmbeddedFileSubtypes(buf);
    expect(subs.length).toBe(1);
    expect(subs[0].subtype).toBe("text/html");
    expect(hasEmbeddedHtmlSubtype(buf)).toBe(true);
  });

  it("accepts the plain `/text/html` Name form too", () => {
    const buf = synthBuf(
      "1 0 obj\n<< /Type /EmbeddedFile /Subtype /text/html /Length 0 >>\nstream\n\nendstream\nendobj\n",
    );
    const subs = extractEmbeddedFileSubtypes(buf);
    expect(subs.length).toBe(1);
    expect(subs[0].subtype).toBe("text");
    // NOTE: the plain `/text/html` form parses as Name="text" because `/` is
    // a Name delimiter (ISO 32000-1 §7.3.5). The spec-compliant form is
    // `/text#2Fhtml`. We document this here so future readers don't expect
    // `text/html` from the un-escaped form.
    expect(hasEmbeddedHtmlSubtype(buf)).toBe(false);
  });

  it("recognises application/xhtml+xml (hex-encoded form)", () => {
    // /application#2Fxhtml+xml — `+` is a legal Name char (no escape needed)
    const buf = synthBuf(
      "1 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fxhtml+xml /Length 0 >>\nstream\n\nendstream\nendobj\n",
    );
    const subs = extractEmbeddedFileSubtypes(buf);
    expect(subs.length).toBe(1);
    expect(subs[0].subtype).toBe("application/xhtml+xml");
    expect(hasEmbeddedHtmlSubtype(buf)).toBe(true);
  });

  it("benign /text#2Fplain attachment is NOT flagged as html", () => {
    const buf = synthBuf(
      "1 0 obj\n<< /Type /EmbeddedFile /Subtype /text#2Fplain /Length 0 >>\nstream\n\nendstream\nendobj\n",
    );
    const subs = extractEmbeddedFileSubtypes(buf);
    expect(subs.length).toBe(1);
    expect(subs[0].subtype).toBe("text/plain");
    expect(hasEmbeddedHtmlSubtype(buf)).toBe(false);
  });

  it("returns empty for a PDF with no embedded file", () => {
    const buf = synthBuf(
      "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
    );
    expect(extractEmbeddedFileSubtypes(buf)).toEqual([]);
    expect(hasEmbeddedHtmlSubtype(buf)).toBe(false);
  });

  it("deduplicates and order-preserves multiple distinct subtypes", () => {
    const buf = synthBuf(
      "1 0 obj\n<< /Type /EmbeddedFile /Subtype /text#2Fhtml >>\nendobj\n" +
      "2 0 obj\n<< /Type /EmbeddedFile /Subtype /text#2Fplain >>\nendobj\n" +
      "3 0 obj\n<< /Type /EmbeddedFile /Subtype /text#2Fhtml >>\nendobj\n",
    );
    const subs = extractEmbeddedFileSubtypes(buf);
    expect(subs.map((s) => s.subtype)).toEqual(["text/html", "text/plain"]);
  });

  it("does not spoof a subtype from /SubtypeSomethingElse (boundary check)", () => {
    // /SubtypeQuirk is a single Name — there is no /Subtype entry in this
    // dict, so the helper must return nothing.
    const buf = synthBuf(
      "1 0 obj\n<< /Type /EmbeddedFile /SubtypeQuirk /text#2Fhtml >>\nendobj\n",
    );
    const subs = extractEmbeddedFileSubtypes(buf);
    expect(subs).toEqual([]);
  });

  it("stops lookahead at endobj — a sibling /Subtype does not leak", () => {
    // Object 1 = /EmbeddedFile with NO /Subtype; Object 2 (sibling) carries
    // /Subtype /text#2Fhtml. The helper must NOT attribute the sibling's
    // /Subtype to the EmbeddedFile entry.
    const buf = synthBuf(
      "1 0 obj\n<< /Type /EmbeddedFile /Length 0 >>\nstream\n\nendstream\nendobj\n" +
      "2 0 obj\n<< /Type /Annot /Subtype /text#2Fhtml >>\nendobj\n",
    );
    const subs = extractEmbeddedFileSubtypes(buf);
    expect(subs).toEqual([]);
  });

  it("handles empty / tiny inputs without throwing", () => {
    expect(extractEmbeddedFileSubtypes(null)).toEqual([]);
    expect(extractEmbeddedFileSubtypes(Buffer.alloc(0))).toEqual([]);
    expect(extractEmbeddedFileSubtypes(Buffer.from("%PDF"))).toEqual([]);
    expect(hasEmbeddedHtmlSubtype(Buffer.alloc(0))).toBe(false);
  });

  it("R12: returned subtype contains no raw PDF byte slices (printable ascii only)", () => {
    const buf = readFileSync(FIXTURE);
    const subs = extractEmbeddedFileSubtypes(buf);
    for (const s of subs) {
      // Reject any non-printable / non-ascii char — defensive against future
      // refactors that accidentally leak un-decoded bytes.
      expect(/^[\x20-\x7e]+$/.test(s.subtype)).toBe(true);
      // The subtype must NOT carry any obvious PDF structural tokens.
      expect(s.subtype.includes("<<")).toBe(false);
      expect(s.subtype.includes(">>")).toBe(false);
      expect(s.subtype.includes("stream")).toBe(false);
      expect(s.subtype.includes("endobj")).toBe(false);
    }
  });
});

describe("v1.20.0 T6: pdf-attachment-subtype internals", () => {
  it("decodePdfName handles #2F (slash) and #2E (dot)", () => {
    expect(__test__.decodePdfName("text#2Fhtml")).toBe("text/html");
    expect(__test__.decodePdfName("foo#2Ebar")).toBe("foo.bar");
    expect(__test__.decodePdfName("plain")).toBe("plain");
  });

  it("decodePdfName preserves non-hex `#` sequences as-is", () => {
    expect(__test__.decodePdfName("foo#ZZ")).toBe("foo#ZZ");
    expect(__test__.decodePdfName("foo#")).toBe("foo#");
  });

  it("readName stops at delimiters / whitespace", () => {
    const buf = synthBuf("name1 next");
    const { raw, end } = __test__.readName(buf, 0);
    expect(raw).toBe("name1");
    expect(end).toBe(5);
  });

  it("indexOfAscii is bounded by MAX_SCAN_BYTES (defensive)", () => {
    // The helper caps the scan at 5 MiB. Constructing a 6 MiB buffer that
    // hides the needle past the cap should yield -1.
    const big = Buffer.alloc(6 * 1024 * 1024, 0x20);
    big.write("/EmbeddedFile", 5.5 * 1024 * 1024, "latin1");
    expect(extractEmbeddedFileSubtypes(big)).toEqual([]);
  });
});
