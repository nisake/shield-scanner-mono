/**
 * PDF-EML-EMPTY-ATTACHMENT-CHANNEL regression.
 *
 * A 0-byte attachment that yields no body text is invisible to reviewers
 * unless we surface it as a finding. Pins the warning shape:
 *   element: "Email Attachment", technique: "Empty attachment",
 *   severity: "warning", contextLocation: "Attachment <safe-filename>"
 *
 * Independent from the existing per-attachment-size-limit / per-attachment-
 * recursion warnings (we don't want those firing alongside).
 */

import { describe, it, expect } from "vitest";
import { parseEmlContent } from "../../server/parsers/eml.js";

function buildEmlWith0ByteAttachment(filename = "empty.txt") {
  const boundary = "----shield-scanner-empty-boundary";
  return [
    "From: a@example.com",
    "To: b@example.com",
    "Subject: zero-byte channel",
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
    "",
    `--${boundary}--`,
    "",
  ].join("\r\n");
}

describe("EML 0-byte attachment channel", () => {
  it("surfaces a single warning finding for a 0-byte attachment", async () => {
    const raw = buildEmlWith0ByteAttachment("empty.txt");
    const out = await parseEmlContent(raw);
    const hits = (out.extraFindings || []).filter(
      (f) => f.technique === "Empty attachment",
    );
    expect(hits.length).toBe(1);
    const hit = hits[0];
    expect(hit.severity).toBe("warning");
    expect(hit.element).toBe("Email Attachment");
    expect(hit.contextLocation).toBe("Attachment empty.txt");
  });

  it("does NOT surface 'Empty attachment' when the attachment carries text", async () => {
    // Build an email with a small non-empty text/plain attachment.
    const boundary = "----shield-scanner-nonempty-boundary";
    const body = Buffer.from("hello body").toString("base64");
    const raw = [
      "From: a@example.com",
      "To: b@example.com",
      "Subject: non-empty channel",
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
      'Content-Disposition: attachment; filename="hello.txt"',
      "Content-Transfer-Encoding: base64",
      "",
      body,
      "",
      `--${boundary}--`,
      "",
    ].join("\r\n");
    const out = await parseEmlContent(raw);
    const hits = (out.extraFindings || []).filter(
      (f) => f.technique === "Empty attachment",
    );
    expect(hits.length).toBe(0);
  });
});
