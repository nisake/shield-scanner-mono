/**
 * v1.20.0 T6 — Minimal raw-bytes PDF generator that produces an EmbeddedFile
 * stream carrying `/Subtype /text#2Fhtml` (hex-encoded `/` as `#2F`).
 *
 * Why hand-built bytes (not pdf-lib): pdf-lib's high-level attach API does
 * set /Subtype on the EmbeddedFile stream but it uses the un-escaped Name
 * token `/text/html`, which is technically illegal (Names cannot contain
 * unescaped `/`) and which pdf.js v4 normalises into `text/html` only via
 * its Name parser. We want a fixture that exercises BOTH boundaries:
 *
 *   1. The hex-encoded `#2F` form (`/text#2Fhtml`) which the spec requires
 *      for `/` inside a Name. This is what real-world malware-style PDFs
 *      tend to emit because some generators always hex-escape special chars.
 *   2. The simple unescaped form (`/text/html`) as a control case in case
 *      future fixtures want it. We only emit the hex-encoded one here.
 *
 * The fixture is intentionally tiny (~700 bytes) and parses cleanly enough
 * for the raw-bytes helper. It does NOT need to be openable by pdfjs — the
 * v1.20.0 Theme only tests the helper, which works on the raw byte buffer.
 *
 * Output:
 *   packages/mcp/test/fixtures/attacks/pdf_embedded_html_subtype.pdf
 *
 * Run:
 *   node tools/_generate_pdf_subtype_html.js
 *
 * Idempotency: writes deterministic bytes — re-running produces a
 * bit-identical file. Verified by a sha256 round-trip self-check.
 */

import { writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..");
const ATTACKS_DIR = join(
  REPO_ROOT,
  "packages",
  "mcp",
  "test",
  "fixtures",
  "attacks",
);
mkdirSync(ATTACKS_DIR, { recursive: true });

const OUT_PATH = join(ATTACKS_DIR, "pdf_embedded_html_subtype.pdf");

// ─────────────────────────────────────────────────────────────────────────
// Hand-rolled PDF
// ─────────────────────────────────────────────────────────────────────────

// HTML payload embedded inside the EmbeddedFile stream. Kept short.
const HTML = "<!doctype html><html><body>note</body></html>\n";

function buildPdfBytes() {
  // Object 1: Catalog. References /Names (object 4) for embedded files.
  // Object 2: Pages (empty page tree — fixture doesn't render).
  // Object 3: EmbeddedFile stream, dict carries /Subtype /text#2Fhtml.
  // Object 4: Names tree pointing at the FileSpec (object 5).
  // Object 5: FileSpec — /F filename, /EF /F -> object 3.
  //
  // We build each object as an ASCII string, then assemble with a real
  // xref table + trailer so the bytes are spec-shaped (xref offsets must
  // be byte-accurate).

  const enc = (s) => Buffer.from(s, "latin1");

  // Use \r\n line endings inside stream content so the byte length is stable
  // (we count the HTML bytes literally).
  const streamBody = HTML;
  const streamBodyBuf = Buffer.from(streamBody, "utf8");
  const streamLen = streamBodyBuf.length;

  const objects = [];
  // index 0 is the free entry — slot it as null so indices match object numbers
  objects.push(null);

  // 1 — Catalog
  objects.push(
    "<< /Type /Catalog /Pages 2 0 R /Names 4 0 R >>",
  );
  // 2 — Pages (empty kids array)
  objects.push("<< /Type /Pages /Kids [] /Count 0 >>");
  // 3 — EmbeddedFile stream. Note the hex-encoded `#2F` for `/`.
  objects.push(
    `<< /Type /EmbeddedFile /Subtype /text#2Fhtml /Length ${streamLen} >>\nstream\n${streamBody}\nendstream`,
  );
  // 4 — Names dict pointing at /EmbeddedFiles name tree (5)
  objects.push("<< /EmbeddedFiles 5 0 R >>");
  // 5 — EmbeddedFiles name tree (single Names array)
  objects.push(
    "<< /Names [ (payload.html) 6 0 R ] >>",
  );
  // 6 — FileSpec dict referencing the EmbeddedFile stream (3)
  objects.push(
    "<< /Type /Filespec /F (payload.html) /UF (payload.html) /EF << /F 3 0 R /UF 3 0 R >> >>",
  );

  // Assemble body with byte-accurate offsets.
  let body = "%PDF-1.7\n%âãÏÓ\n"; // binary marker
  const offsets = new Array(objects.length).fill(0);

  // Helper to append a chunk and return bytes-written-so-far.
  let bodyBuf = Buffer.from(body, "latin1");
  for (let i = 1; i < objects.length; i++) {
    offsets[i] = bodyBuf.length;
    const header = `${i} 0 obj\n`;
    const footer = "\nendobj\n";
    bodyBuf = Buffer.concat([
      bodyBuf,
      Buffer.from(header, "latin1"),
      Buffer.from(objects[i], "latin1"),
      Buffer.from(footer, "latin1"),
    ]);
  }

  // xref table
  const xrefOffset = bodyBuf.length;
  let xref = `xref\n0 ${objects.length}\n`;
  // free entry
  xref += "0000000000 65535 f \n";
  for (let i = 1; i < objects.length; i++) {
    xref += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  }

  // trailer
  const trailer =
    `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\n` +
    `startxref\n${xrefOffset}\n%%EOF\n`;

  return Buffer.concat([
    bodyBuf,
    Buffer.from(xref, "latin1"),
    Buffer.from(trailer, "latin1"),
  ]);
}

const bytes = buildPdfBytes();
writeFileSync(OUT_PATH, bytes);
const sha = createHash("sha256").update(bytes).digest("hex").slice(0, 16);
console.log(`wrote ${OUT_PATH} (${bytes.length} bytes, sha256[0:16]=${sha})`);

// Idempotency self-check
const rebuilt = buildPdfBytes();
const onDisk = readFileSync(OUT_PATH);
const reHash = createHash("sha256").update(rebuilt).digest("hex");
const diskHash = createHash("sha256").update(onDisk).digest("hex");
if (reHash !== diskHash) {
  console.error("FAIL idempotency: rebuilt bytes differ from on-disk");
  process.exit(1);
}
console.log("OK idempotency: rebuilt bytes match on-disk");

// Quick sanity scan: ensure the fixture really contains the markers the
// helper will look for.
const buf = onDisk;
const hasEmb = buf.includes(Buffer.from("/EmbeddedFile", "latin1"));
const hasHex = buf.includes(Buffer.from("/text#2Fhtml", "latin1"));
if (!hasEmb) {
  console.error("FAIL: fixture is missing /EmbeddedFile marker");
  process.exit(1);
}
if (!hasHex) {
  console.error("FAIL: fixture is missing /text#2Fhtml marker");
  process.exit(1);
}
console.log("OK sanity: fixture contains /EmbeddedFile + /text#2Fhtml");

if (!existsSync(OUT_PATH)) {
  console.error("FAIL: output file not present after write");
  process.exit(1);
}
