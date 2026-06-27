/**
 * v1.20.0 — T8-XLSX-OLE: XLSX Embedded OLE scope-specific kebab regression.
 *
 * Pins the new standalone-helper contract added in v1.20.0:
 *   - xlsx-ole-oversize       : embedded blob > 5 MB (warning, hiddenHtml)
 *   - xlsx-ole-encrypted      : CFB carrying 'EncryptedPackage' stream
 *                               (warning, hiddenHtml)
 *   - xlsx-ole-macro-bearing  : CFB carrying '_VBA_PROJECT' / 'PROJECTwm'
 *                               stream (danger, suspiciousPatterns)
 *
 * The helper is NOT yet wired into packages/mcp/server/parsers/xlsx.js
 * (v1.20.x parser wiring follow-up). This regression therefore drives the
 * helper directly with synthesized OLE-shaped buffers + lightweight XLSX
 * archives that embed those buffers as xl/embeddings/oleObject.bin. The
 * archives are written to disk under fixtures/attacks/ so the contract
 * (file + helper export) is auditable from a fresh checkout.
 *
 * R12: meta carries only sizeBytes / scope / streamName / hasVbaProject /
 *      hasProjectWm — never the decoded OLE stream bytes.
 * R13: every finding's `category` is one of the canonical 5-key bucket names
 *      (hiddenHtml or suspiciousPatterns).
 * R14: no third-party CFB parser used by the helper (regex / byte-window
 *      scan only). The test setup uses JSZip purely to assemble the XLSX
 *      envelope (already a project dependency).
 */

import { describe, it, expect, beforeAll } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
import JSZip from "jszip";
import {
  scanXlsxOleScope,
  XLSX_OLE_OVERSIZE_THRESHOLD,
  XLSX_OLE_SCOPE_KEBABS,
} from "../../server/parsers/xlsx-ole-scope.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ATTACKS = join(__dirname, "..", "fixtures", "attacks");

// ---------------------------------------------------------------------------
// Minimal synthesized OLE-shaped buffers
// ---------------------------------------------------------------------------
//
// We don't need a structurally valid CFB — only the 8-byte magic header plus
// the UTF-16LE encoded stream names that scanXlsxOleScope keys off. This is
// the same shape the helper itself looks for, so the test exercises the real
// detection path without pulling in a CFB-writer dependency (R14).

const CFB_MAGIC = Uint8Array.from([
  0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1,
]);

function utf16le(s) {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    out[i * 2] = s.charCodeAt(i) & 0xff;
    out[i * 2 + 1] = (s.charCodeAt(i) >> 8) & 0xff;
  }
  return out;
}

function concatBuffers(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// Build a minimally-valid XLSX zip with a single sheet + the supplied OLE
// blob at xl/embeddings/oleObject1.bin. The sheet content is intentionally
// trivial — we only care about the embedded OLE payload for these tests.
async function buildXlsxWithOle(oleBytes) {
  const zip = new JSZip();
  zip.file(
    "[Content_Types].xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`,
  );
  zip.file(
    "_rels/.rels",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`,
  );
  zip.file(
    "xl/workbook.xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>
</workbook>`,
  );
  zip.file(
    "xl/worksheets/sheet1.xml",
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>`,
  );
  zip.file("xl/embeddings/oleObject1.bin", Buffer.from(oleBytes));
  return await zip.generateAsync({ type: "nodebuffer" });
}

// ---------------------------------------------------------------------------
// Fixture builders — synthesized OLE buffers
// ---------------------------------------------------------------------------

function makeOversizeBlob() {
  // 5 MB + 1 byte → strictly over the threshold. We don't need a valid CFB
  // header for the oversize path (helper returns early before magic check).
  const n = XLSX_OLE_OVERSIZE_THRESHOLD + 1;
  const buf = new Uint8Array(n);
  // Sprinkle the CFB magic at the head so the buffer is at least vaguely
  // shaped like an OLE blob — but the oversize gate fires first.
  buf.set(CFB_MAGIC, 0);
  return buf;
}

function makeEncryptedBlob() {
  // CFB magic + UTF-16LE 'EncryptedPackage' string somewhere in the middle.
  // 4 KiB total is far below the oversize threshold so only the encrypted
  // kebab should fire.
  const filler = new Uint8Array(2048);
  const tail = new Uint8Array(1024);
  return concatBuffers([CFB_MAGIC, filler, utf16le("EncryptedPackage"), tail]);
}

function makeMacroBearingBlob() {
  // CFB magic + UTF-16LE '_VBA_PROJECT' stream-name marker.
  const filler = new Uint8Array(1024);
  const tail = new Uint8Array(512);
  return concatBuffers([CFB_MAGIC, filler, utf16le("_VBA_PROJECT"), tail]);
}

function makeBenignBlob() {
  // CFB magic only — no encrypted / macro markers. Should produce zero
  // findings (R12 / R13 invariant: helper is silent on benign OLE blobs).
  const filler = new Uint8Array(512);
  return concatBuffers([CFB_MAGIC, filler]);
}

// ---------------------------------------------------------------------------
// Setup: write fixtures to disk so a fresh checkout can audit them
// ---------------------------------------------------------------------------

beforeAll(async () => {
  await mkdir(ATTACKS, { recursive: true });
  const oversize = await buildXlsxWithOle(makeOversizeBlob());
  const encrypted = await buildXlsxWithOle(makeEncryptedBlob());
  const macro = await buildXlsxWithOle(makeMacroBearingBlob());
  await writeFile(join(ATTACKS, "xlsx_ole_oversize.xlsx"), oversize);
  await writeFile(join(ATTACKS, "xlsx_ole_encrypted.xlsx"), encrypted);
  await writeFile(join(ATTACKS, "xlsx_ole_macro_bearing.xlsx"), macro);
});

// ---------------------------------------------------------------------------
// Helper-direct tests
// ---------------------------------------------------------------------------

describe("v1.20.0 T8-XLSX-OLE: scope-specific helper", () => {
  it("exports the documented kebab id set", () => {
    expect(Array.from(XLSX_OLE_SCOPE_KEBABS).sort()).toEqual([
      "xlsx-ole-encrypted",
      "xlsx-ole-macro-bearing",
      "xlsx-ole-oversize",
    ]);
  });

  it("xlsx-ole-oversize: warning + hiddenHtml + sizeBytes meta", () => {
    const f = scanXlsxOleScope(makeOversizeBlob(), {
      memberName: "xl/embeddings/oleObject1.bin",
    });
    expect(f.length).toBe(1);
    const hit = f[0];
    expect(hit.technique).toBe("xlsx-ole-oversize");
    expect(hit.severity).toBe("warning");
    expect(hit.category).toBe("hiddenHtml");
    expect(hit.meta.scope).toBe("embeddedOle");
    expect(hit.meta.maxBytes).toBe(XLSX_OLE_OVERSIZE_THRESHOLD);
    expect(hit.meta.sizeBytes).toBeGreaterThan(XLSX_OLE_OVERSIZE_THRESHOLD);
    expect(hit.contextLocation).toBe("xl/embeddings/oleObject1.bin");
  });

  it("xlsx-ole-encrypted: warning + hiddenHtml + EncryptedPackage stream name", () => {
    const f = scanXlsxOleScope(makeEncryptedBlob(), {
      memberName: "xl/embeddings/oleObject1.bin",
    });
    const hit = f.find((x) => x.technique === "xlsx-ole-encrypted");
    expect(hit, "no xlsx-ole-encrypted finding").toBeDefined();
    expect(hit.severity).toBe("warning");
    expect(hit.category).toBe("hiddenHtml");
    expect(hit.meta.streamName).toBe("EncryptedPackage");
    expect(hit.meta.scope).toBe("embeddedOle");
    // No macro-bearing finding (no _VBA_PROJECT in the buffer).
    expect(f.find((x) => x.technique === "xlsx-ole-macro-bearing")).toBeUndefined();
  });

  it("xlsx-ole-macro-bearing: danger + suspiciousPatterns + _VBA_PROJECT stream name", () => {
    const f = scanXlsxOleScope(makeMacroBearingBlob(), {
      memberName: "xl/embeddings/oleObject1.bin",
    });
    const hit = f.find((x) => x.technique === "xlsx-ole-macro-bearing");
    expect(hit, "no xlsx-ole-macro-bearing finding").toBeDefined();
    expect(hit.severity).toBe("danger");
    expect(hit.category).toBe("suspiciousPatterns");
    expect(hit.meta.streamName).toBe("_VBA_PROJECT");
    expect(hit.meta.hasVbaProject).toBe(true);
    expect(hit.meta.scope).toBe("embeddedOle");
    // No encrypted finding.
    expect(f.find((x) => x.technique === "xlsx-ole-encrypted")).toBeUndefined();
  });

  it("benign CFB blob (no markers) produces zero findings", () => {
    const f = scanXlsxOleScope(makeBenignBlob());
    expect(f).toEqual([]);
  });

  it("non-CFB blob (no magic) produces zero findings", () => {
    const f = scanXlsxOleScope(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0, 1, 2, 3, 4]));
    expect(f).toEqual([]);
  });

  it("oversize short-circuits before CFB magic check (no encrypted/macro emitted)", () => {
    // Oversize buffer is intentionally not a valid CFB stream-name container —
    // we just need to confirm the helper returns the oversize finding alone
    // and skips the more expensive scans.
    const f = scanXlsxOleScope(makeOversizeBlob());
    expect(f.length).toBe(1);
    expect(f[0].technique).toBe("xlsx-ole-oversize");
  });

  it("empty / undefined input returns []", () => {
    expect(scanXlsxOleScope(null)).toEqual([]);
    expect(scanXlsxOleScope(undefined)).toEqual([]);
    expect(scanXlsxOleScope(new Uint8Array(0))).toEqual([]);
  });

  it("R12: no decoded OLE stream bytes leak in serialized output", () => {
    const f = scanXlsxOleScope(makeMacroBearingBlob(), {
      memberName: "xl/embeddings/oleObject1.bin",
    });
    const json = JSON.stringify(f);
    // The raw CFB magic byte pattern (4-byte hex prefix) must not appear in
    // the serialized finding output — only structural metadata may.
    expect(json.includes("\\u00d0\\u00cf\\u0011\\u00e0")).toBe(false);
    // Decoded stream bodies / raw nodebuffer bytes never serialize.
    expect(/"raw|bytes|decoded/.test(json)).toBe(false);
  });
});
