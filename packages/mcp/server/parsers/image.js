/**
 * Image metadata parser (S12 spine).
 *
 * Surfaces text-bearing metadata fields from JPEG / PNG / WebP / GIF / TIFF
 * so the central detector can scan them for prompt-injection content the
 * same way it does PDF / DOCX / EML payloads.
 *
 * Design pillars:
 *
 * - ALLOW-list driven. Five module-scope Maps name the only EXIF tags, GPS
 *   tags, IPTC datasets and XMP fields we extract. Unknown fields are
 *   dropped on the floor — we do not surface binary blobs, GPS fixes,
 *   thumbnails, MakerNote payloads, etc.
 *
 * - TWO-layer instruction gate (closes split-payload bypass):
 *     LAYER 1: looksLikeInstruction is applied PER FIELD before we emit a
 *              per-field extraFinding. Suppresses false positives on benign
 *              metadata like "Canon EOS R6 Mark II".
 *     LAYER 2: ALL non-empty fields are unconditionally joined into the
 *              returned `text` (with a non-word SEPARATOR so per-field
 *              boundaries can't bridge regex matches). The central detector
 *              scans that joined blob, and we additionally emit an
 *              "aggregate" finding when looksLikeInstruction(joinedText)
 *              fires across multiple fields but no single field tripped it.
 *
 * - Guardrail R12: NO raw user text is echoed via extraFindings — only
 *   structural hints (`sourceField` / `length` / `encoding`).
 *
 * - Guardrail R1: NO NFKC. Raw decoded bytes are kept byte-faithful so the
 *   downstream sanitizer + suspicious-patterns detector see exactly what an
 *   attacker embedded.
 *
 * - Graceful: parseImage / parseImageBuffer NEVER throw. Any unexpected
 *   error inside a walker is caught and surfaced as a single
 *   `parseError` warning finding plus an empty `text`.
 *
 * - Zero new runtime deps. node:fs/promises + node:zlib only.
 *
 * The MCP copy of the constants here must remain byte-identical with the
 * Web index.html mirror inside parseImage() — image-parity.test.js pins
 * that contract.
 */

import { readFile } from "node:fs/promises";
import { createInflate, inflateSync } from "node:zlib";
import { looksLikeInstruction } from "@shield-scanner/core";

// ---------------------------------------------------------------------------
// Module-scope constants (kept byte-identical with the Web index.html copy).
// ---------------------------------------------------------------------------

export const SEPARATOR = "\n----- IMG_FIELD_BOUNDARY -----\n";
export const MAX_INFLATED_BYTES = 5 * 1024 * 1024; // 5 MB zTXt decompression cap

// S12-XR-04 amplification caps. The original spec hardened only against the
// zTXt zip-bomb (Risk #11) — compressed input -> huge inflated output. It did
// NOT cover the "legitimate-shape DoS" where an attacker pays the input bytes
// upfront with many small valid segments (e.g. 200 × 60 KB JPEG COM segments,
// each carrying a copy of an injection token). EML's per-attachment ceiling
// is 25 MB; without these caps a single image attachment can keep ~25 MB of
// joined text resident, blow scan latency to multi-second, and emit hundreds
// of `imageMetadataInjection` findings — alert-fatigue / response-amplification
// in a security tool. Caps land before the central detector runs so the work
// done downstream is bounded.
//
//  - IMG_MAX_BYTES                 input buffer hard cap; over -> single
//                                  `imageOversize` warning, no parse attempt.
//  - IMG_MAX_JOINED_TEXT_BYTES     joined text truncated at this length and
//                                  an `imageMetadataTruncated` warning emitted.
//  - IMG_MAX_PER_FIELD_FINDINGS    perFieldSurvivors collapsed to this count;
//                                  overflow replaced by one aggregate
//                                  `imageMetadataFieldFlood` warning.
export const IMG_MAX_BYTES = 5 * 1024 * 1024;
export const IMG_MAX_JOINED_TEXT_BYTES = 1 * 1024 * 1024;
export const IMG_MAX_PER_FIELD_FINDINGS = 64;

export const JPEG_TAG_ALLOW = new Map([
  [0x010d, "DocumentName"],
  [0x010e, "ImageDescription"],
  [0x010f, "Make"],
  [0x0110, "Model"],
  [0x0131, "Software"],
  [0x013b, "Artist"],
  [0x013c, "HostComputer"],
  [0x8298, "Copyright"],
  [0x9c9b, "XPTitle"],
  [0x9c9c, "XPComment"],
  [0x9c9d, "XPAuthor"],
  [0x9c9e, "XPKeywords"],
  [0x9c9f, "XPSubject"],
  [0x02bc, "__XMP_IN_TIFF"],
  [0x83bb, "__IPTC_IN_TIFF"],
  [0x8769, "__SUBIFD"],
  [0x8825, "__GPSIFD"],
]);

export const EXIF_SUBIFD_ALLOW = new Map([[0x9286, "UserComment"]]);

export const GPS_IFD_ALLOW = new Map([
  [0x001b, "GPSProcessingMethod"],
  [0x001c, "GPSAreaInformation"],
]);

export const IPTC_ALLOW = new Map([
  ["2:040", "SpecialInstructions"],
  ["2:080", "Byline"],
  ["2:105", "Headline"],
  ["2:116", "Copyright"],
  ["2:120", "Caption"],
  ["2:025", "Keywords"],
]);

export const XMP_FIELD_ALLOW = [
  // Dublin Core free-text fields
  "dc:description",
  "dc:title",
  "dc:subject",
  "dc:rights",
  "dc:creator",
  "dc:relation",
  "dc:contributor",
  "dc:publisher",
  // Adobe XMP basic
  "xmp:CreatorTool",
  // Photoshop legacy IPTC mirror
  "photoshop:Instructions",
  "photoshop:Headline",
  "photoshop:Credit",
  "photoshop:Source",
  "photoshop:SupplementalCategories",
  // BYPASS-03 — xmpRights / IPTC4XMP / Camera Raw / TIFF-XMP / MicrosoftPhoto
  // free-text fields that Adobe Lightroom, Bridge, Premiere, and Windows
  // Explorer write on every save. Without these the allowlist was a public
  // bypass surface — attackers simply parked the injection in any non-listed
  // namespace and parseImage returned text="" / extraFindings=[]. Keep this
  // enumerative (NOT a namespace wildcard) so structural fields like
  // crs:WhiteBalance or exif:GPSLatitude don't leak into the detector.
  "xmpRights:UsageTerms",
  "xmpRights:WebStatement",
  "Iptc4xmpCore:Location",
  "crs:Comments",
  "crs:RawFileName",
  "tiff:ImageDescription",
  "tiff:Artist",
  "tiff:Copyright",
  "MicrosoftPhoto:LastKeywordIPTC",
];

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/**
 * Parse an image file from disk. Reads bytes, dispatches by extension, never
 * throws — returns the empty-image shape on unknown extensions and a single
 * parseError finding on internal walker faults.
 *
 * @param {string} filePath
 */
export async function parseImage(filePath) {
  const buf = await readFile(filePath);
  const ext = String(filePath || "").split(".").pop();
  return parseImageBuffer(buf, ext);
}

/**
 * Same as parseImage but takes the bytes directly. This is the variant
 * exercised by attachment recursion / fuzz fixtures.
 *
 * @param {Buffer|Uint8Array} buffer
 * @param {string} ext
 */
export async function parseImageBuffer(buffer, ext) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer || []);

  // S12-XR-04 cap #1: input bytes. Reject anything over IMG_MAX_BYTES
  // upfront — emit a single structural `imageOversize` warning instead of
  // spending O(input) work walking the container. Defends against the
  // legitimate-shape DoS where an attacker uses many small valid segments
  // (e.g. 200 × 60 KB JPEG COM segments) to inflate scan latency and joined-
  // text memory. No raw bytes leak: only `bytes` (length) is structural.
  if (buf.length > IMG_MAX_BYTES) {
    return {
      text: "",
      fileType: "image",
      extraFindings: [
        {
          element: "Image",
          severity: "warning",
          category: "suspiciousPatterns",
          label: "imageOversize",
          technique: "image-metadata-oversize",
          contextLocation: "IMG",
          priority: 30,
          structural: { bytes: buf.length, cap: IMG_MAX_BYTES },
        },
      ],
      decodedRanges: [],
      sections: { imageMetadata: [] },
    };
  }

  let raw = [];
  try {
    const e = String(ext || "").toLowerCase().replace(/^\./, "");
    if (e === "jpg" || e === "jpeg") raw = _walkJpeg(buf);
    else if (e === "png") raw = await _walkPng(buf);
    else if (e === "webp") raw = _walkRiff(buf);
    else if (e === "gif") raw = _walkGif(buf);
    else if (e === "tif" || e === "tiff") raw = _readTiff(buf, "tiff");
    else {
      return {
        text: "",
        fileType: "image",
        extraFindings: [],
        decodedRanges: [],
        sections: { imageMetadata: [] },
      };
    }
  } catch (_err) {
    // Walker fault — surface as a single warning, no raw text echoed.
    return {
      text: "",
      fileType: "image",
      extraFindings: [
        {
          element: "Image",
          severity: "warning",
          category: "suspiciousPatterns",
          label: "parseError",
          technique: "image-metadata-parse-failed",
          contextLocation: "IMG",
          priority: 30,
          structural: { error: "parse_throw" },
        },
      ],
      decodedRanges: [],
      sections: { imageMetadata: [] },
    };
  }

  // Filter empties (whitespace-only fields contribute no signal).
  raw = raw.filter(
    (r) => r && typeof r.value === "string" && r.value.trim().length > 0
  );

  // LAYER 1 — per-field looksLikeInstruction gate. Only survivors become
  // per-field extraFindings.
  const perFieldSurvivors = raw.filter((r) => looksLikeInstruction(r.value));

  // S12-XR-04 cap #3: per-image finding count. When an attacker stuffs the
  // same injection into hundreds of small valid segments, perFieldSurvivors
  // explodes 1:1 into extraFindings — each finding is then double-amplified
  // by the central detector. Cap the per-field emission at
  // IMG_MAX_PER_FIELD_FINDINGS and collapse overflow into a single aggregate
  // `imageMetadataFieldFlood` warning. The joined-text gate (LAYER 2) still
  // sees the truncated text so genuine prompt-injection still routes to
  // suspiciousPatterns via the central detector.
  const survivorsKept = perFieldSurvivors.slice(0, IMG_MAX_PER_FIELD_FINDINGS);
  const survivorsOverflowed = perFieldSurvivors.length - survivorsKept.length;
  const extraFindings = survivorsKept.map((s) => ({
    element: "Image Metadata",
    severity: "warning",
    category: "suspiciousPatterns",
    label: "imageMetadataInjection",
    technique: "image-metadata-injection",
    contextLocation: `IMG ${s.location}`,
    priority: 55,
    structural: {
      sourceField: s.location,
      length: s.value.length,
      encoding: s.encoding,
    },
  }));
  if (survivorsOverflowed > 0) {
    extraFindings.push({
      element: "Image Metadata (flood)",
      severity: "warning",
      category: "suspiciousPatterns",
      label: "imageMetadataFieldFlood",
      technique: "image-metadata-field-flood",
      contextLocation: "IMG aggregate",
      priority: 40,
      structural: {
        total: perFieldSurvivors.length,
        kept: survivorsKept.length,
        suppressed: survivorsOverflowed,
        cap: IMG_MAX_PER_FIELD_FINDINGS,
      },
    });
  }

  // BYPASS-02 fix: emit one structural warning per zTXt/iTXt field that
  // streaming-inflate truncated at MAX_INFLATED_BYTES. Reuses the existing
  // `imageMetadataTruncated` label (the joined-text overflow uses it too)
  // but tags the decompression case via structural.decompression so the
  // call site can distinguish. The field's value is already in the joined
  // text and may have tripped LAYER 1 / LAYER 2 — this warning is an
  // additional breadcrumb, not a replacement for the injection finding.
  // R12-safe: structural fields are detector-controlled vocab only.
  for (const r of raw) {
    if (r && r.truncated === true) {
      extraFindings.push({
        element: "Image Metadata (truncated)",
        severity: "warning",
        category: "suspiciousPatterns",
        label: "imageMetadataTruncated",
        technique: "image-metadata-zlib-truncated",
        contextLocation: `IMG ${r.location}`,
        priority: 35,
        structural: {
          sourceField: r.location,
          decompression: "truncated",
          cap: MAX_INFLATED_BYTES,
        },
      });
    }
  }

  // LAYER 2 — unconditional joined text for the central detector. The
  // SEPARATOR is a long non-word run, so per-field boundaries cannot
  // accidentally bridge a regex match across two innocuous neighbours.
  //
  // R12 (S12 fix): while building the joined blob we also record the
  // character ranges of each VALUE that was synthesized by a decoder
  // (XML-entity expansion, UTF-16 transcode, zlib inflate, IPTC UTF-8
  // mode-switch). `decodedRanges` is consumed by the post-analyze
  // `redactDecodedFindings` helper so suspicious-pattern hits inside
  // decoder-synthesized text never echo their `matched` / `context`
  // strings back into the response body. This is the parser-level half
  // of the same guardrail that `scanShadowForSuspiciousPatterns` enforces
  // for NFKC / invisible-stripped shadows in the detector layer.
  // S12-XR-04 cap #2: joined-text length. Stop appending once we cross
  // IMG_MAX_JOINED_TEXT_BYTES and emit a structural `imageMetadataTruncated`
  // warning. The cursor stays in lockstep with the final joinedText string
  // because we account for SEPARATOR length BEFORE the cap check, so
  // decodedRanges entries emitted before the cap remain index-valid; entries
  // that would have fallen past the cap are dropped together with their text.
  // The central detector then processes <= ~1 MB per image rather than up to
  // ~25 MB (the EML per-attachment ceiling).
  const decodedRanges = [];
  const parts = [];
  let cursor = 0;
  let joinedTruncated = false;
  let fieldsKept = 0;
  for (let i = 0; i < raw.length; i++) {
    const r = raw[i];
    const prefix = `[IMG ${r.location}] `;
    const segment = prefix + r.value;
    const sepLen = parts.length > 0 ? SEPARATOR.length : 0;
    if (cursor + sepLen + segment.length > IMG_MAX_JOINED_TEXT_BYTES) {
      joinedTruncated = true;
      break;
    }
    cursor += sepLen;
    parts.push(segment);
    fieldsKept++;
    if (r.decoded === true) {
      const valStart = cursor + prefix.length;
      const valEnd = valStart + r.value.length;
      decodedRanges.push({
        start: valStart,
        end: valEnd,
        location: r.location,
        encoding: r.encoding,
      });
    }
    cursor += segment.length;
  }
  const joinedText = parts.join(SEPARATOR);
  // The truncation warning targets multi-field amplification: lots of
  // legitimate-shape segments piled up to inflate joined-text memory. A
  // single oversized field (e.g. a zTXt that the inflate cap already
  // truncated to 5 MB) is a different class — already covered by the
  // per-field inflate cap — and would also create a Web/MCP parity gap
  // (the Web inflate path drops the whole oversized field instead of
  // keeping the first MAX_INFLATED_BYTES bytes). Gate the warning on
  // `fieldsKept >= 1` so it fires only when we actually squeezed some
  // fields in and then ran out of room for subsequent ones.
  if (joinedTruncated && fieldsKept >= 1) {
    extraFindings.push({
      element: "Image Metadata (truncated)",
      severity: "warning",
      category: "suspiciousPatterns",
      label: "imageMetadataTruncated",
      technique: "image-metadata-truncated",
      contextLocation: "IMG aggregate",
      priority: 35,
      structural: {
        totalFields: raw.length,
        keptFields: fieldsKept,
        joinedTextLength: joinedText.length,
        cap: IMG_MAX_JOINED_TEXT_BYTES,
      },
    });
  }

  // Aggregate finding — fires only when the joined blob crosses the
  // instruction threshold AND no single field tripped LAYER 1 alone
  // (the split-payload case where each piece is sub-threshold).
  if (
    raw.length >= 2 &&
    looksLikeInstruction(joinedText) &&
    perFieldSurvivors.length < raw.length
  ) {
    extraFindings.push({
      element: "Image Metadata (aggregate)",
      severity: "danger",
      category: "suspiciousPatterns",
      label: "imageMetadataSplitPayload",
      technique: "image-metadata-split-payload",
      contextLocation: "IMG aggregate",
      priority: 70,
      structural: {
        fieldCount: raw.length,
        segments: raw.map((r) => r.location),
      },
    });
  }

  return {
    text: joinedText,
    fileType: "image",
    extraFindings,
    decodedRanges,
    sections: {
      imageMetadata: raw.map((r) => ({
        location: r.location,
        length: r.value.length,
        encoding: r.encoding,
      })),
    },
  };
}

export default { parseImage, parseImageBuffer };

// ---------------------------------------------------------------------------
// Container walkers — return Array<{location, value, encoding}>
// ---------------------------------------------------------------------------

/**
 * Walk a JPEG segment stream. Each segment after SOI is `0xFF marker [len_hi
 * len_lo payload]` (length-less standalone markers RSTn / SOI / EOI excepted).
 * SOS is the entropy-coded start — we stop there (after handling SOS itself,
 * since metadata segments always precede SOS in well-formed JPEGs).
 *
 * Emits COM (0xFE) comment text, plus dispatches APP1 (Exif/XMP) and APP13
 * (Photoshop/IPTC) to their format-specific readers.
 */
export function _walkJpeg(buf) {
  const out = [];
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return out; // No SOI
  let p = 2;
  while (p + 1 < buf.length) {
    // Resync past any fill 0xFF bytes between segments.
    if (buf[p] !== 0xff) {
      p++;
      continue;
    }
    while (p + 1 < buf.length && buf[p + 1] === 0xff) p++;
    const marker = buf[p + 1];
    p += 2;

    // Standalone markers — no length, no payload.
    if (marker === 0x00 || marker === 0xff) continue;
    if (marker === 0xd8 || marker === 0xd9) continue; // SOI / EOI
    if (marker >= 0xd0 && marker <= 0xd7) continue; // RSTn

    if (p + 1 >= buf.length) break; // No room for length
    const segLen = buf.readUInt16BE(p);
    if (segLen < 2 || p + segLen > buf.length) break;
    const segStart = p + 2;
    const segEnd = p + segLen;
    const seg = buf.subarray(segStart, segEnd);

    if (marker === 0xfe) {
      // COM
      const decoded = _decodeUtf8OrLatin1(seg);
      // R12: COM payloads are usually plain ASCII / Latin-1 / UTF-8 where the
      // bytes already render the literal text; we only flag `decoded: true`
      // for paths where a decoder synthesizes new plaintext (XML entities,
      // UTF-16, zlib, IPTC UTF-8 mode-switch). UTF-8 vs Latin-1 selection on
      // raw bytes does not synthesize plaintext for ASCII attack tokens.
      out.push({ location: "jpeg:COM", value: decoded, encoding: "auto", decoded: false });
    } else if (marker === 0xe1) {
      // APP1 — Exif or XMP
      if (
        seg.length >= 6 &&
        seg[0] === 0x45 && // E
        seg[1] === 0x78 && // x
        seg[2] === 0x69 && // i
        seg[3] === 0x66 && // f
        seg[4] === 0x00 &&
        seg[5] === 0x00
      ) {
        // Exif\0\0 — TIFF stream starts at seg[6]. srcLabel is the bare
        // "exif" namespace (per spec adversarial #1 — fields surface as
        // `IMG exif:UserComment`, not `IMG jpeg:exif:...`).
        const tiff = seg.subarray(6);
        const tiffOut = _readTiff(tiff, "exif");
        out.push(...tiffOut);
      } else {
        // XMP: 29-byte ASCII namespace prefix + NUL.
        // Spec Test 4 / Test 8: inline XMP-only containers (JPEG APP1 XMP
        // and PNG iTXt XML:com.adobe.xmp) surface as `IMG xmp:<field>` —
        // the container framing is unwrapped, leaving the bare `xmp:` prefix.
        const ns = "http://ns.adobe.com/xap/1.0/\0";
        if (seg.length >= ns.length && seg.slice(0, ns.length).toString("latin1") === ns) {
          const xmpBytes = seg.subarray(ns.length);
          out.push(..._extractXmpFields(_decodePacket(xmpBytes), ""));
        }
        // Extended XMP and unknown APP1 sub-formats: skip (we don't claim
        // round-trip XMP recombination — only inline single-packet XMP is in
        // S12 scope).
      }
    } else if (marker === 0xed) {
      // APP13 — Photoshop / IPTC
      out.push(..._readApp13(seg));
    }

    p = segEnd;

    if (marker === 0xda) {
      // SOS — entropy-coded data follows, no more metadata in scope.
      break;
    }
  }
  return out;
}

/**
 * Walk a PNG chunk stream. Each chunk is `length:u32be type:4ascii data:length
 * crc:u32be`. We surface tEXt, zTXt and iTXt; iTXt with key `XML:com.adobe.xmp`
 * is routed to the XMP extractor instead. eXIf chunks (PNG spec ext) get fed
 * to the TIFF reader.
 */
export async function _walkPng(buf) {
  const out = [];
  if (buf.length < 8) return out;
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  for (let i = 0; i < 8; i++) if (buf[i] !== sig[i]) return out;
  let p = 8;
  while (p + 8 <= buf.length) {
    const len = buf.readUInt32BE(p);
    const type = buf.slice(p + 4, p + 8).toString("latin1");
    const dataStart = p + 8;
    const dataEnd = dataStart + len;
    if (dataEnd + 4 > buf.length) break;
    const data = buf.subarray(dataStart, dataEnd);

    if (type === "tEXt") {
      const sep = data.indexOf(0);
      // PARSE-003 fix: accept sep===0 (empty key, spec-illegal but still
      // surfaced by many image toolchains and downstream LLMs). Without this,
      // a 1-byte NUL prefix lets an attacker bypass all PNG-tEXt detection.
      // Synthetic key '__empty' keeps the location string tokenic.
      if (sep >= 0) {
        const key = data.slice(0, sep).toString("latin1");
        // BYPASS-01 fix: spec says PNG tEXt is Latin-1, but real-world writers
        // (ExifTool, Pillow, etc.) routinely emit UTF-8 bytes here. UTF-8-first
        // preserves attacker-supplied Unicode (RLO, ZWSP, Cyrillic homoglyphs)
        // so downstream invisibleUnicode/homoglyph detectors can fire. ASCII-
        // only inputs round-trip unchanged.
        const value = _decodeUtf8OrLatin1(data.slice(sep + 1));
        out.push({
          location: `png:tEXt:${_safeKey(key) || "__empty"}`,
          value,
          encoding: "auto",
          decoded: false,
        });
      }
    } else if (type === "zTXt") {
      const sep = data.indexOf(0);
      // PARSE-003 fix: empty-key parity with tEXt. sep===0 + zlib body is
      // still parseable; only the keyword is missing.
      if (sep >= 0 && data.length >= sep + 2) {
        const key = data.slice(0, sep).toString("latin1");
        const method = data[sep + 1];
        if (method === 0) {
          // BYPASS-02 fix: streaming inflate. On overflow we keep the first
          // MAX_INFLATED_BYTES bytes and surface them (instead of dropping
          // the whole field, which silently erased any payload an attacker
          // stashed at the start of an oversized zTXt). The `truncated`
          // flag drives a structural warning in parseImageBuffer.
          const inflated = await _inflateBytesCapped(data.subarray(sep + 2));
          if (inflated) {
            out.push({
              location: `png:zTXt:${_safeKey(key) || "__empty"}`,
              // BYPASS-01 fix: see PNG tEXt comment above.
              value: _decodeUtf8OrLatin1(inflated.bytes),
              encoding: "auto",
              // R12 (S12 fix): zlib inflation synthesizes plaintext from the
              // compressed source bytes — the attack tokens do not appear
              // visibly in the .png on disk. Mark `decoded: true` so the
              // post-analyze redactor blanks matched/context for any
              // suspicious-pattern hit landing inside this field's value.
              decoded: true,
              truncated: inflated.truncated,
            });
          }
        }
      }
    } else if (type === "iTXt") {
      // key\0 compFlag compMethod langTag\0 transKey\0 text
      const sep1 = data.indexOf(0);
      // PARSE-003 fix: empty-key parity. sep1===0 still has a valid trailer
      // (compFlag/compMethod/lang/transKey/text), so we can decode the value.
      if (sep1 >= 0 && data.length >= sep1 + 4) {
        const key = data.slice(0, sep1).toString("latin1");
        const compFlag = data[sep1 + 1];
        const compMethod = data[sep1 + 2];
        let q = sep1 + 3;
        const sep2 = data.indexOf(0, q);
        if (sep2 < 0) {
          p = dataEnd + 4;
          continue;
        }
        q = sep2 + 1;
        const sep3 = data.indexOf(0, q);
        if (sep3 < 0) {
          p = dataEnd + 4;
          continue;
        }
        let textBytes = data.subarray(sep3 + 1);
        let iTxtInflated = false;
        let iTxtTruncated = false;
        if (compFlag === 1) {
          if (compMethod === 0) {
            const inflated = await _inflateBytesCapped(textBytes);
            if (!inflated) {
              p = dataEnd + 4;
              continue;
            }
            textBytes = inflated.bytes;
            iTxtInflated = true;
            iTxtTruncated = inflated.truncated;
          } else {
            p = dataEnd + 4;
            continue;
          }
        }
        if (key === "XML:com.adobe.xmp") {
          // Spec Test 8: PNG iTXt with `XML:com.adobe.xmp` is unwrapped —
          // the location is `IMG xmp:<field>`, not `IMG png:xmp:...`.
          const xmpFields = _extractXmpFields(_decodePacket(textBytes), "");
          // BYPASS-02 fix: propagate truncation onto the first surfaced
          // XMP field so parseImageBuffer can emit a single structural
          // warning even when the carrier iTXt was capped mid-packet.
          if (iTxtTruncated && xmpFields.length > 0) {
            xmpFields[0].truncated = true;
          }
          out.push(...xmpFields);
        } else {
          out.push({
            // PARSE-003 fix: `_safeKey('') === ''` so empty-key iTXt would
            // produce a dangling `png:iTXt:` location string — fall back to
            // `__empty` for parity with tEXt / zTXt.
            location: `png:iTXt:${_safeKey(key) || "__empty"}`,
            value: textBytes.toString("utf8"),
            encoding: "utf-8",
            // R12 (S12 fix): plaintext iTXt has bytes == value, but the
            // compressed form synthesizes plaintext from compressed bytes.
            decoded: iTxtInflated,
            truncated: iTxtTruncated,
          });
        }
      }
    } else if (type === "eXIf") {
      out.push(..._readTiff(data, "png:eXIf"));
    } else if (type === "IEND") {
      break;
    }

    p = dataEnd + 4; // skip CRC
  }
  return out;
}

/**
 * Walk a RIFF (WebP) chunk stream. Recognises EXIF and XMP  chunks; routes
 * everything else past silently (image-data chunks, ICCP, etc.).
 */
export function _walkRiff(buf) {
  const out = [];
  if (buf.length < 12) return out;
  if (buf.slice(0, 4).toString("latin1") !== "RIFF") return out;
  if (buf.slice(8, 12).toString("latin1") !== "WEBP") return out;
  // NOTE: bytes 4..7 hold the RIFF master chunk size. We deliberately ignore
  // it and walk to physical EOF, bounded only by the per-chunk size guard
  // (`payEnd > buf.length` below). This is anti-evasion, not a bug:
  //   - Tolerant decoders in the wild (libwebp / Chromium / Pillow) walk past
  //     a too-small master size and still render trailing XMP/EXIF chunks.
  //   - If we honored the master size as a hard outer bound, an attacker
  //     could set RIFF size = 1 and append a malicious XMP chunk past byte 9;
  //     strict parsers would stop and miss it, while downstream renderers
  //     would still see (and inject) the payload.
  //   - Some real-world encoders also mis-fill this field, so a strict clamp
  //     would create FN on benign inputs too.
  // The per-chunk `payEnd > buf.length` guard is the only bound that matters
  // for memory safety. Pinned by image-metadata.test.js
  // "WebP RIFF master size lie is ignored (anti-evasion)".
  let p = 12;
  while (p + 8 <= buf.length) {
    const fourCC = buf.slice(p, p + 4).toString("latin1");
    const size = buf.readUInt32LE(p + 4);
    const payStart = p + 8;
    const payEnd = payStart + size;
    if (payEnd > buf.length) break;
    const payload = buf.subarray(payStart, payEnd);

    if (fourCC === "EXIF") {
      out.push(..._readTiff(payload, "webp:exif"));
    } else if (fourCC === "XMP ") {
      out.push(..._extractXmpFields(_decodePacket(payload), "webp:"));
    }

    // Chunks are word-aligned: pad to even size.
    p = payEnd + (size & 1);
  }
  return out;
}

/**
 * Walk a GIF block stream. Surfaces Comment Extension (0x21 0xFE), Plain Text
 * Extension (0x21 0x01), and the Application Extension 'XMP DataXMP' variant
 * (concatenated sub-blocks with the 258-byte magic-trailer stripped).
 */
export function _walkGif(buf) {
  const out = [];
  if (buf.length < 13) return out;
  const sig = buf.slice(0, 6).toString("latin1");
  if (sig !== "GIF87a" && sig !== "GIF89a") return out;
  // Logical Screen Descriptor at [6..12], byte 10 has GCT flags.
  const packed = buf[10];
  const gctFlag = (packed >> 7) & 1;
  const gctSize = gctFlag ? 3 * (1 << ((packed & 0x07) + 1)) : 0;
  let p = 13 + gctSize;

  while (p < buf.length) {
    const tag = buf[p];
    if (tag === 0x3b) break; // Trailer
    if (tag === 0x21) {
      // Extension
      if (p + 2 > buf.length) break;
      const label = buf[p + 1];
      p += 2;
      if (label === 0xfe) {
        // Comment Extension — sub-block chain
        const { data, next } = _readGifSubBlocks(buf, p);
        out.push({
          location: "gif:Comment",
          value: _decodeUtf8OrLatin1(data),
          encoding: "auto",
          decoded: false,
        });
        p = next;
      } else if (label === 0xff) {
        // Application Extension: 1-byte block size (usually 0x0B), 8 AppID + 3 Auth
        if (p >= buf.length) break;
        const blockSize = buf[p];
        if (p + 1 + blockSize > buf.length) break;
        const appHeader = buf
          .subarray(p + 1, p + 1 + blockSize)
          .toString("latin1");
        p += 1 + blockSize;
        const { data, next } = _readGifSubBlocks(buf, p);
        p = next;
        if (appHeader.startsWith("XMP DataXMP")) {
          // GIF XMP convention: AppID is "XMP Data" + AuthCode "XMP", normally
          // declared with blockSize=11. We match by prefix (not strict equality)
          // because a non-canonical encoder — or an attacker — can set
          // blockSize≠11 while leaving the canonical 11-byte AppID intact at
          // the start of the read window. Lenient downstream consumers
          // (ExifTool, Adobe XMP Toolkit) prefix-match the AppID, so refusing
          // to extract here would leave a one-byte evasion path open. (PARSE-004)
          // Trailing convention is unchanged: data is the XMP packet followed
          // by a 258-byte magic trailer (0x01 then 0xFF 0xFE … 0x00 0x00).
          // Strip if present.
          let xmpEnd = data.length;
          if (xmpEnd >= 258) xmpEnd -= 258;
          const xmpBytes = data.subarray(0, xmpEnd);
          out.push(..._extractXmpFields(_decodePacket(xmpBytes), "gif:"));
        }
      } else if (label === 0x01) {
        // Plain Text Extension: 12-byte block header then sub-block chain.
        if (p >= buf.length) break;
        const blockSize = buf[p];
        if (p + 1 + blockSize > buf.length) break;
        p += 1 + blockSize;
        const { data, next } = _readGifSubBlocks(buf, p);
        out.push({
          location: "gif:PlainText",
          value: _decodeUtf8OrLatin1(data),
          encoding: "auto",
          decoded: false,
        });
        p = next;
      } else if (label === 0xf9) {
        // Graphic Control Extension — skip sub-blocks.
        const { next } = _readGifSubBlocks(buf, p);
        p = next;
      } else {
        // Unknown extension — consume its sub-block chain.
        const { next } = _readGifSubBlocks(buf, p);
        p = next;
      }
    } else if (tag === 0x2c) {
      // Image Descriptor: 9 bytes, then optional LCT, then LZW min code + sub-blocks
      if (p + 10 > buf.length) break;
      const idPacked = buf[p + 9];
      const lctFlag = (idPacked >> 7) & 1;
      const lctSize = lctFlag ? 3 * (1 << ((idPacked & 0x07) + 1)) : 0;
      p += 10 + lctSize;
      if (p >= buf.length) break;
      p += 1; // LZW min code size
      const { next } = _readGifSubBlocks(buf, p);
      p = next;
    } else {
      // Unknown block — bail out rather than risk runaway parsing.
      break;
    }
  }
  return out;
}

/** Read a GIF sub-block chain starting at `p` (chain ends at a 0-length block). */
function _readGifSubBlocks(buf, p) {
  const chunks = [];
  while (p < buf.length) {
    const n = buf[p];
    p += 1;
    if (n === 0) break;
    if (p + n > buf.length) break;
    chunks.push(buf.subarray(p, p + n));
    p += n;
  }
  return { data: Buffer.concat(chunks), next: p };
}

// ---------------------------------------------------------------------------
// TIFF / EXIF
// ---------------------------------------------------------------------------

/**
 * Read a TIFF stream and return allow-listed fields from IFD0 + every
 * subsequent IFD reachable through the nextIFD pointer chain (IFD1, IFD2…)
 * up to a depth cap, plus recursed SubIFD / GPS IFD. `srcLabel` becomes the
 * prefix for emitted locations, e.g. `jpeg:exif`, `png:eXIf`, `webp:exif`,
 * `tiff`.
 *
 * Why walk the chain: IFD1 is the canonical location for thumbnail metadata
 * in JPEG/EXIF and standalone TIFF. Standard readers (libtiff, ExifTool,
 * piexif, exifr with ifd1:true) traverse it, so any text-bearing tag in
 * IFD1+ would otherwise be a silent false-negative channel for prompt
 * injection while still being delivered to downstream LLM-feeding consumers.
 * Each top-level IFD uses the JPEG_TAG_ALLOW vocabulary (same as IFD0); a
 * visited-offset Set defuses malicious cycles.
 */
export function _readTiff(tiff, srcLabel) {
  const out = [];
  if (!tiff || tiff.length < 8) return out;
  let le;
  if (tiff[0] === 0x49 && tiff[1] === 0x49) le = true;
  else if (tiff[0] === 0x4d && tiff[1] === 0x4d) le = false;
  else return out;
  const magic = le ? tiff.readUInt16LE(2) : tiff.readUInt16BE(2);
  if (magic !== 0x002a) return out;
  const ifd0 = le ? tiff.readUInt32LE(4) : tiff.readUInt32BE(4);
  if (ifd0 < 8 || ifd0 >= tiff.length) return out;

  // Walk the linked-list of top-level IFDs (IFD0 -> IFD1 -> …). After each
  // IFD's entry array, a u32 nextIFD pointer says where the next IFD begins
  // (0 = end of chain). Cap chain length at 4 to match the SubIFD/GPS depth
  // guard already in _readIfd, and track visited offsets to short-circuit
  // any attacker-crafted cycle.
  const visited = new Set();
  let ifdOff = ifd0;
  for (let chainDepth = 0; chainDepth < 4; chainDepth++) {
    if (ifdOff < 8 || ifdOff + 2 > tiff.length) break;
    if (visited.has(ifdOff)) break;
    visited.add(ifdOff);

    out.push(..._readIfd(tiff, ifdOff, le, JPEG_TAG_ALLOW, srcLabel, 0));

    // Read the trailing nextIFD pointer at `ifdOff + 2 + n*12`.
    const n = le ? tiff.readUInt16LE(ifdOff) : tiff.readUInt16BE(ifdOff);
    const nextOff = ifdOff + 2 + n * 12;
    if (nextOff + 4 > tiff.length) break;
    const nextIfd = le ? tiff.readUInt32LE(nextOff) : tiff.readUInt32BE(nextOff);
    if (nextIfd === 0) break;
    ifdOff = nextIfd;
  }
  return out;
}

/**
 * Walk a single IFD. Returns the accumulated allow-listed fields. Recurses
 * into SubIFD / GPS IFD pointers (with a depth cap to defuse cycles).
 */
export function _readIfd(tiff, base, le, allow, srcLabel, depth) {
  const out = [];
  if (depth > 3) return out;
  if (base + 2 > tiff.length) return out;
  const n = le ? tiff.readUInt16LE(base) : tiff.readUInt16BE(base);
  const entriesStart = base + 2;
  if (entriesStart + n * 12 > tiff.length) return out;

  for (let i = 0; i < n; i++) {
    const off = entriesStart + i * 12;
    const tag = le ? tiff.readUInt16LE(off) : tiff.readUInt16BE(off);
    const type = le ? tiff.readUInt16LE(off + 2) : tiff.readUInt16BE(off + 2);
    const count = le ? tiff.readUInt32LE(off + 4) : tiff.readUInt32BE(off + 4);
    const valOff = off + 8;

    if (tag === 0x8769) {
      // SubIFD pointer (4-byte ULONG)
      if (type !== 4 || count !== 1) continue;
      const sub = le ? tiff.readUInt32LE(valOff) : tiff.readUInt32BE(valOff);
      if (sub >= 8 && sub < tiff.length) {
        out.push(..._readIfd(tiff, sub, le, EXIF_SUBIFD_ALLOW, srcLabel, depth + 1));
      }
      continue;
    }
    if (tag === 0x8825) {
      if (type !== 4 || count !== 1) continue;
      const sub = le ? tiff.readUInt32LE(valOff) : tiff.readUInt32BE(valOff);
      if (sub >= 8 && sub < tiff.length) {
        out.push(..._readIfd(tiff, sub, le, GPS_IFD_ALLOW, srcLabel, depth + 1));
      }
      continue;
    }

    // Compute byte-size of the value array.
    const typeSize = _tiffTypeSize(type);
    if (typeSize === 0) continue;
    const total = typeSize * count;
    let valueBytes;
    if (total <= 4) {
      valueBytes = tiff.subarray(valOff, valOff + total);
    } else {
      const ptr = le ? tiff.readUInt32LE(valOff) : tiff.readUInt32BE(valOff);
      if (ptr + total > tiff.length || ptr < 0) continue;
      valueBytes = tiff.subarray(ptr, ptr + total);
    }

    if (tag === 0x02bc) {
      // XMP embedded in TIFF (ApplicationNotes)
      out.push(..._extractXmpFields(_decodePacket(valueBytes), `${srcLabel}:`));
      continue;
    }
    if (tag === 0x83bb) {
      // RichTIFFIPTC — raw IPTC IIM record stream
      out.push(..._readIptcIim(valueBytes));
      continue;
    }

    // Resolve the field name. The primary lookup is the IFD-scoped allow map.
    // Fallback: real-world EXIF writers (and some fixture builders) sometimes
    // flatten SubIFD / GPS-IFD tags onto IFD0 instead of routing through the
    // 0x8769 / 0x8825 pointers. Accept those tags here too so the field is not
    // silently dropped — the resulting `contextLocation` still mirrors the
    // canonical SubIFD-emitted label (e.g. "exif:UserComment").
    let name = allow.get(tag);
    if (typeof name !== "string" || name.startsWith("__")) {
      if (allow !== EXIF_SUBIFD_ALLOW && EXIF_SUBIFD_ALLOW.has(tag)) {
        name = EXIF_SUBIFD_ALLOW.get(tag);
      } else if (allow !== GPS_IFD_ALLOW && GPS_IFD_ALLOW.has(tag)) {
        name = GPS_IFD_ALLOW.get(tag);
      } else {
        continue;
      }
    }

    const decoded = _decodeTiffValue(tag, type, valueBytes, le);
    if (decoded && decoded.value) {
      out.push({
        location: `${srcLabel}:${name}`,
        value: decoded.value,
        encoding: decoded.encoding,
        // R12 (S12 fix): UTF-16 paths (XP* tags, UserComment UNICODE) decode
        // 2-byte-per-char source bytes into single JS characters — the ASCII
        // attack tokens are never visible in the raw bytes. ASCII / Latin-1 /
        // JIS paths leave the bytes as-is, so they are not oracle leaks.
        decoded:
          decoded.encoding === "utf-16le" || decoded.encoding === "utf-16be",
      });
    }
  }
  return out;
}

/** Return TIFF type byte-size (only the ones we care about). 0 = unknown. */
function _tiffTypeSize(type) {
  switch (type) {
    case 1: // BYTE
    case 2: // ASCII
    case 6: // SBYTE
    case 7: // UNDEFINED
      return 1;
    case 3: // SHORT
    case 8: // SSHORT
      return 2;
    case 4: // LONG
    case 9: // SLONG
    case 11: // FLOAT
      return 4;
    case 5: // RATIONAL
    case 10: // SRATIONAL
    case 12: // DOUBLE
      return 8;
    default:
      return 0;
  }
}

/**
 * Decode a TIFF field's bytes to a JS string given its tag/type/endianness.
 * Returns {value, encoding} or null if we can't or won't decode it.
 */
function _decodeTiffValue(tag, type, bytes, le) {
  // XP* tags (Microsoft) are stored as type=1 (BYTE) UTF-16LE pairs.
  if (tag >= 0x9c9b && tag <= 0x9c9f && type === 1) {
    const str = _decodeUtf16(bytes, true).replace(/[\0 ]+$/, "");
    return { value: str, encoding: "utf-16le" };
  }
  if (type === 2) {
    // ASCII (NUL-terminated)
    let end = bytes.length;
    while (end > 0 && bytes[end - 1] === 0) end--;
    // BYPASS-01 fix: spec is Latin-1, but real-world EXIF writers (ExifTool,
    // libexif, Pillow) and attackers commonly emit UTF-8 bytes here. UTF-8-
    // first preserves attacker-supplied Unicode (RLO, ZWSP, Cyrillic
    // homoglyphs) so downstream invisibleUnicode/homoglyph detectors can
    // fire. ASCII-only inputs round-trip unchanged.
    const str = _decodeUtf8OrLatin1(bytes.subarray(0, end));
    return { value: str, encoding: "ascii" };
  }
  if (tag === 0x9286 && type === 7) {
    // UserComment — 8-byte charcode prefix then payload
    if (bytes.length < 8) return null;
    const code = bytes.subarray(0, 8).toString("latin1").replace(/\0+$/, "").trim();
    const body = bytes.subarray(8);
    // BYPASS-01 fix: UTF-8-first for ASCII/JIS/unknown charcode branches.
    if (code === "ASCII") return { value: _decodeUtf8OrLatin1(body), encoding: "ascii" };
    if (code === "UNICODE")
      return { value: _decodeUtf16(body, le).replace(/[\0 ]+$/, ""), encoding: le ? "utf-16le" : "utf-16be" };
    if (code === "JIS") return { value: _decodeUtf8OrLatin1(body), encoding: "jis-raw" };
    // Empty / undefined / unknown — UTF-8-first, fall back to Latin-1.
    return { value: _decodeUtf8OrLatin1(body), encoding: "auto" };
  }
  if (type === 1 || type === 7) {
    // BYPASS-01 fix: generic BYTE/UNDEFINED fallback — UTF-8-first pattern.
    return { value: _decodeUtf8OrLatin1(bytes), encoding: "auto" };
  }
  return null;
}

// ---------------------------------------------------------------------------
// IPTC (via APP13 or TIFF tag 0x83BB)
// ---------------------------------------------------------------------------

/**
 * Walk a JPEG APP13 segment, find the 'Photoshop 3.0\0' marker and the 8BIM
 * resource for IPTC (resource id 0x0404), then hand its payload to
 * _readIptcIim. Other 8BIM resources are skipped.
 */
export function _readApp13(seg) {
  const out = [];
  const marker = "Photoshop 3.0\0";
  const idx = seg.indexOf(marker);
  if (idx < 0) return out;
  let p = idx + marker.length;
  while (p + 11 <= seg.length) {
    if (seg.slice(p, p + 4).toString("latin1") !== "8BIM") break;
    p += 4;
    const resourceId = seg.readUInt16BE(p);
    p += 2;
    // Pascal name: 1 byte length + name, padded to even total (including length byte)
    const nameLen = seg[p];
    let nameTotal = 1 + nameLen;
    if (nameTotal & 1) nameTotal += 1;
    p += nameTotal;
    if (p + 4 > seg.length) break;
    const dataLen = seg.readUInt32BE(p);
    p += 4;
    if (p + dataLen > seg.length) break;
    const data = seg.subarray(p, p + dataLen);
    if (resourceId === 0x0404) {
      out.push(..._readIptcIim(data));
    }
    let dataPadded = dataLen;
    if (dataPadded & 1) dataPadded += 1;
    p += dataPadded;
  }
  return out;
}

/**
 * Read an IPTC IIM record stream. Records are `0x1C, record:u8, dataset:u8,
 * length:u16be, data`. If a 1:090 CodedCharacterSet '\x1b%G' record appears,
 * subsequent record-2 datasets switch from Latin-1 to UTF-8.
 */
export function _readIptcIim(iim) {
  const out = [];
  let utf8Mode = false;
  let p = 0;
  while (p + 5 <= iim.length) {
    if (iim[p] !== 0x1c) {
      p += 1;
      continue;
    }
    const rec = iim[p + 1];
    const ds = iim[p + 2];
    const len = iim.readUInt16BE(p + 3);
    p += 5;
    if (p + len > iim.length) break;
    const data = iim.subarray(p, p + len);
    p += len;

    if (rec === 1 && ds === 90) {
      if (data.toString("latin1").includes("\x1b%G")) utf8Mode = true;
      continue;
    }
    if (rec !== 2) continue;
    const key = `${rec}:${String(ds).padStart(3, "0")}`;
    if (!IPTC_ALLOW.has(key)) continue;
    const name = IPTC_ALLOW.get(key);
    // BYPASS-01 fix: in default (non-utf8Mode) IPTC, spec is Latin-1 but
    // real-world writers and attackers commonly emit UTF-8 bytes. UTF-8-first
    // preserves attacker-supplied Unicode for the central detector.
    const value = utf8Mode ? data.toString("utf8") : _decodeUtf8OrLatin1(data);
    out.push({
      location: `iptc:${name}`,
      value,
      encoding: utf8Mode ? "utf-8" : "auto",
      // R12 (S12 fix): utf8Mode is a mode-switch decoder primitive. For
      // ASCII attack tokens the bytes are still visible, but non-ASCII
      // multi-byte sequences synthesize plaintext that latin1-rendered raw
      // bytes don't expose. Mark utf8Mode entries as decoded for safety.
      // Non-utf8Mode is byte-as-is (`_decodeUtf8OrLatin1` over bytes that
      // already contain the literal text in either encoding).
      decoded: utf8Mode,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// XMP
// ---------------------------------------------------------------------------

const XML_ENTITY_MAP = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };
function _decodeXmlEntities(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (_m, body) => {
    if (body[0] === "#") {
      const cp =
        body[1] === "x" || body[1] === "X"
          ? parseInt(body.slice(2), 16)
          : parseInt(body.slice(1), 10);
      if (Number.isFinite(cp) && cp >= 0 && cp <= 0x10ffff) {
        try {
          return String.fromCodePoint(cp);
        } catch {
          return "";
        }
      }
      return "";
    }
    return XML_ENTITY_MAP[body] ?? `&${body};`;
  });
}

/**
 * Pull allow-listed fields out of an XMP RDF packet (string form). Recognises
 * both element form (`<ns:Field …>VALUE</ns:Field>`, including rdf:Alt/Bag/Seq
 * + rdf:li wrappers) and attribute shorthand (`ns:Field="VALUE"`). Field
 * names are matched case-sensitively against XMP_FIELD_ALLOW.
 *
 * XML 1.0 comments (`<!-- ... -->`) are stripped before extraction so commented
 * example tags in legitimate metadata documentation do not produce false-
 * positive findings (PARSE-006). Strict XML parsers ignore comment bodies per
 * spec; treating them as live content was over-eager.
 *
 * Emits {location: `${prefix}xmp:${fname}`, value, encoding: 'utf-8'}.
 */
export function _extractXmpFields(rdfPacket, prefix = "", packetDecoded = false) {
  const out = [];
  // Backwards-compat: callers historically passed a bare string. The new
  // tri-state `_decodePacket` returns `{ str, decoded }` — accept both.
  if (rdfPacket && typeof rdfPacket === "object" && typeof rdfPacket.str === "string") {
    packetDecoded = Boolean(rdfPacket.decoded);
    rdfPacket = rdfPacket.str;
  }
  if (typeof rdfPacket !== "string" || rdfPacket.length === 0) return out;
  // Strip XML comments so commented-out example tags do not get extracted.
  rdfPacket = rdfPacket.replace(/<!--[\s\S]*?-->/g, "");
  // PARSE-005 dedupe: a single logical XMP field (e.g. dc:description) can be
  // hit by the element-body, double-quoted attr, and single-quoted attr passes
  // simultaneously when the source uses both forms on the same / nested
  // element. Dedupe by (location, value) per call so one attacker-controlled
  // field cannot inflate raw.length from 1 → 2 and trip the split-payload
  // aggregate threshold via attribute shorthand alone. If duplicates disagree
  // on the `decoded` flag, the surviving record keeps `decoded: true` (the
  // more conservative R12 stance — any pass that synthesized plaintext wins).
  const seenIdx = new Map();
  const pushUnique = (entry) => {
    const key = `${entry.location}\x00${entry.value}`;
    const prev = seenIdx.get(key);
    if (prev !== undefined) {
      if (entry.decoded && !out[prev].decoded) out[prev].decoded = true;
      return;
    }
    seenIdx.set(key, out.length);
    out.push(entry);
  };
  for (const fname of XMP_FIELD_ALLOW) {
    const escName = fname.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    // Element form — capture whole element body, then peel rdf:li / Alt / Bag / Seq.
    const elRe = new RegExp(
      `<${escName}\\b[^>]*?(?:/>|>([\\s\\S]*?)</${escName}>)`,
      "g"
    );
    let m;
    while ((m = elRe.exec(rdfPacket)) !== null) {
      const body = m[1];
      if (body == null) continue; // self-closing
      const values = _xmpExtractLeafValues(body);
      for (const v of values) {
        const trimmedV = v.trim();
        const decodedStr = _decodeXmlEntities(v).trim();
        if (decodedStr) {
          pushUnique({
            location: `${prefix}xmp:${fname}`,
            value: decodedStr,
            encoding: "utf-8",
            // R12 (S12 fix): XML entity decoding can synthesize plaintext
            // (`&#x49;` → `I`) that the source bytes don't contain. Mark
            // decoded when the entity pass changed the string, OR when the
            // wrapping XMP packet was UTF-16-transcoded by `_decodePacket`
            // (in which case even byte-equal text was synthesized from
            // 2-byte-per-char source bytes).
            decoded: packetDecoded || decodedStr !== trimmedV,
          });
        }
      }
    }

    // Attribute shorthand — only count when it is an attribute on some other
    // element (i.e. preceded by whitespace within a tag, value in quotes).
    const attrRe = new RegExp(`\\s${escName}\\s*=\\s*"([^"]*)"`, "g");
    while ((m = attrRe.exec(rdfPacket)) !== null) {
      const raw = m[1];
      const trimmedRaw = raw.trim();
      const decodedStr = _decodeXmlEntities(raw).trim();
      if (decodedStr) {
        pushUnique({
          location: `${prefix}xmp:${fname}`,
          value: decodedStr,
          encoding: "utf-8",
          decoded: packetDecoded || decodedStr !== trimmedRaw,
        });
      }
    }
    const attrRe2 = new RegExp(`\\s${escName}\\s*=\\s*'([^']*)'`, "g");
    while ((m = attrRe2.exec(rdfPacket)) !== null) {
      const raw = m[1];
      const trimmedRaw = raw.trim();
      const decodedStr = _decodeXmlEntities(raw).trim();
      if (decodedStr) {
        pushUnique({
          location: `${prefix}xmp:${fname}`,
          value: decodedStr,
          encoding: "utf-8",
          decoded: packetDecoded || decodedStr !== trimmedRaw,
        });
      }
    }
  }
  return out;
}

/**
 * Given the inner body of an XMP element, return one string per leaf value.
 * If the body contains <rdf:Alt|Bag|Seq> with <rdf:li> children, return each
 * li payload separately. Otherwise return the trimmed body itself.
 */
function _xmpExtractLeafValues(body) {
  const liRe = /<rdf:li\b[^>]*?(?:\/>|>([\s\S]*?)<\/rdf:li>)/g;
  const out = [];
  let any = false;
  let m;
  while ((m = liRe.exec(body)) !== null) {
    any = true;
    if (m[1] != null) out.push(m[1]);
  }
  if (any) return out;
  // No rdf:li — strip a trailing rdf:Alt/Bag/Seq wrapper if any
  return [body.replace(/<\/?rdf:(?:Alt|Bag|Seq)\b[^>]*>/g, "").trim()];
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

/**
 * Best-effort UTF-8 decode, fall back to Latin-1 on invalid byte sequences.
 *
 * Uses fatal-mode `TextDecoder` (Node 18+ / browser) so that the legitimate
 * U+FFFD replacement character — encoded in valid UTF-8 as `EF BF BD` — is
 * preserved instead of being treated as a decode-failure sentinel. The
 * previous heuristic `Buffer.toString('utf8')` + `s.includes('�')` produced
 * false-positive fallbacks whenever the input contained a real U+FFFD and
 * caused MCP / Web parity to break (PARITY-001). Falls back to Latin-1
 * mojibake only when the bytes truly are not valid UTF-8.
 */
const _imgDecUtf8Strict = new TextDecoder("utf-8", { fatal: true });
// PARITY-002: Mirror the Web parser's WHATWG-spec UTF-16 decoding. A
// String.fromCharCode loop preserves lone surrogates as-is; TextDecoder
// substitutes U+FFFD per the Encoding spec, matching what the browser does.
// Without these decoders, the joined `text` blob and extraFindings.length
// differ between MCP and Web for any image with an XP* / UserComment /
// XMP-UTF-16 payload that contains a lone surrogate (violates byte-parity
// guardrail #8). Available in Node 18+ natively.
const _imgDecUtf16le = new TextDecoder("utf-16le");
const _imgDecUtf16be = new TextDecoder("utf-16be");
function _decodeUtf8OrLatin1(buf) {
  if (!buf || buf.length === 0) return "";
  try {
    return _imgDecUtf8Strict.decode(buf);
  } catch {
    return buf.toString("latin1");
  }
}

/**
 * Decode a UTF-16 buffer to a JS string. `le=true` → little-endian. Strips a
 * leading BOM if present.
 */
export function _decodeUtf16(buf, le) {
  if (!buf || buf.length < 2) return "";
  let start = 0;
  // Strip a leading UTF-16 BOM regardless of endianness. U+FEFF / U+FFFE
  // are noncharacter / format code points and are never legitimate first
  // characters of real text; leaving a wrong-endian BOM in the stream would
  // otherwise decode to a literal U+FFFE noise char (BYPASS-04). Stripping
  // both forms keeps result.text clean without altering the payload — the
  // per-field imageMetadataInjection gate is BOM-independent and still fires.
  if (buf[0] === 0xff && buf[1] === 0xfe) start = 2;
  else if (buf[0] === 0xfe && buf[1] === 0xff) start = 2;
  const usableLen = (buf.length - start) & ~1; // ensure even byte count
  // PARITY-002: Use TextDecoder so unpaired surrogates collapse to U+FFFD
  // exactly the way the Web parser (browser-native TextDecoder) does. The
  // old `String.fromCharCode` loop silently kept lone surrogates, which
  // diverged from the Web side and could let an attacker craft platform-
  // dependent decoded text. TextDecoder accepts Node Buffers via the
  // shared Uint8Array view, so no extra copy is needed.
  const body = buf.subarray(start, start + usableLen);
  return (le ? _imgDecUtf16le : _imgDecUtf16be).decode(body);
}

/**
 * Decode an XMP packet buffer. Sniffs BOMs for UTF-16BE/LE and UTF-8;
 * defaults to UTF-8.
 *
 * Returns `{ str, decoded }` where `decoded: true` means a UTF-16 transcode
 * was applied (the source bytes do NOT directly contain ASCII attack tokens
 * in a way `latin1` reading would expose). UTF-8 paths (with or without BOM)
 * leave the bytes as-is — they are not oracle leaks for ASCII content.
 *
 * Backwards-compatible callers can read `.str`; the new `decoded` flag is
 * what `_extractXmpFields` uses to seed each field's `decoded` marker.
 */
function _decodePacket(buf) {
  if (!buf || buf.length === 0) return { str: "", decoded: false };
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    return { str: _decodeUtf16(buf, false), decoded: true };
  }
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return { str: _decodeUtf16(buf, true), decoded: true };
  }
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return { str: buf.subarray(3).toString("utf8"), decoded: false };
  }
  return { str: buf.toString("utf8"), decoded: false };
}

/**
 * Inflate `bytes` with a hard upper bound on output size. Returns
 *   { bytes: Buffer, truncated: boolean }
 * on success, or null on decode error / empty input.
 *
 * Streaming-with-cap (per S12 spec adversarialChecklist #8): when the
 * decompressed payload would exceed MAX_INFLATED_BYTES we keep the first
 * MAX_INFLATED_BYTES bytes and flag `truncated: true`. The previous
 * inflateSync-with-maxOutputLength approach threw RangeError on overflow,
 * and the caller's `if (inflated)` gate then silently dropped the entire
 * field — turning the DoS guard into a detection bypass (BYPASS-02):
 * any zTXt padded past 5MB inflated had its prompt-injection payload
 * erased before LAYER 1 / LAYER 2 / sections.imageMetadata ever saw it.
 *
 * createInflate has been stable on every supported Node version; we use
 * the streaming API so we can abort once the cap is hit while keeping
 * the bytes captured so far.
 */
export async function _inflateBytesCapped(bytes) {
  if (!bytes || bytes.length === 0) return null;
  const cap = MAX_INFLATED_BYTES;
  const chunks = [];
  let total = 0;
  let truncated = false;
  const inflater = createInflate();

  return await new Promise((resolve) => {
    let settled = false;
    const finishOk = () => {
      if (settled) return;
      settled = true;
      resolve({ bytes: Buffer.concat(chunks, total), truncated });
    };
    const finishNull = () => {
      if (settled) return;
      settled = true;
      resolve(null);
    };

    inflater.on("data", (chunk) => {
      if (truncated) return;
      if (total + chunk.length >= cap) {
        const need = cap - total;
        if (need > 0) chunks.push(chunk.subarray(0, need));
        total = cap;
        truncated = true;
        // Detach the inflate stream — we have all the bytes the cap allows.
        // The subsequent 'close' (or 'error' from premature termination)
        // routes through finishOk because `truncated` is set.
        try { inflater.destroy(); } catch { /* noop */ }
      } else {
        chunks.push(chunk);
        total += chunk.length;
      }
    });
    inflater.on("end", finishOk);
    inflater.on("close", finishOk);
    inflater.on("error", () => {
      // Post-destroy error on a truncated stream is expected — keep bytes.
      // A true decode failure (malformed deflate) lands here with
      // truncated === false and total === 0, so resolve null.
      if (truncated || total > 0) finishOk();
      else finishNull();
    });

    try {
      inflater.end(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes));
    } catch {
      finishNull();
    }
  });
}

/**
 * Sync companion. Kept for back-compat (and for any future call site that
 * doesn't need streaming truncation semantics) — but the PNG walker no
 * longer uses it, because dropping the entire field on overflow is the
 * BYPASS-02 contract violation we're fixing.
 */
export function _inflateBytesCappedSync(bytes) {
  if (!bytes || bytes.length === 0) return null;
  try {
    return inflateSync(bytes, { maxOutputLength: MAX_INFLATED_BYTES });
  } catch {
    try {
      const out = inflateSync(bytes);
      if (out.length > MAX_INFLATED_BYTES) return null;
      return out;
    } catch {
      return null;
    }
  }
}

/**
 * PNG suggested-keyword allow-list (PNG 1.2 §11.3.4.2, table of suggested
 * tEXt/zTXt/iTXt keywords). Anything outside this set is collapsed to a
 * single fixed token so attacker-controlled key bytes never reach the
 * `location` string (which downstream becomes structural.sourceField,
 * structural.segments[], extraFindings[].contextLocation, the joined-text
 * `[IMG png:tEXt:<key>]` prefix, and sections.imageMetadata[].location).
 *
 * Guardrail R6: structural fields must be detector-controlled vocab only.
 * Without this allow-list, _safeKey passed up to 64 chars of attacker
 * prose straight through — e.g. a tEXt key of "ignore_all_previous_admin
 * _system_instructions" survived intact in segments[], gave injection-
 * flavoured keywords a free ride into the joined-text prefix, and let an
 * attacker bypass LAYER 1's per-field gate by parking instruction tokens
 * in the location label rather than the value.
 */
const PNG_KEYWORD_ALLOW = new Set([
  "Title",
  "Author",
  "Description",
  "Copyright",
  "Creation Time",
  "Software",
  "Disclaimer",
  "Warning",
  "Source",
  "Comment",
]);

/**
 * Return a safe PNG keyword token for the `location` string. Recognised
 * spec keywords pass through with whitespace collapsed to underscores
 * (so "Creation Time" → "Creation_Time"); everything else collapses to
 * the fixed token "other" — no attacker bytes survive.
 */
function _safeKey(s) {
  const raw = String(s == null ? "" : s);
  // Trim leading/trailing whitespace per PNG spec (keywords are 1-79
  // Latin-1 characters, no leading/trailing/consecutive spaces).
  const trimmed = raw.replace(/^\s+|\s+$/g, "");
  // Empty-key passthrough preserves PARSE-003's `|| "__empty"` fallback at
  // the call sites (so an empty/whitespace-only key still routes to the
  // distinct `__empty` location rather than silently joining the `other`
  // bucket).
  if (trimmed === "") return "";
  if (PNG_KEYWORD_ALLOW.has(trimmed)) {
    return trimmed.replace(/\s+/g, "_");
  }
  return "other";
}
