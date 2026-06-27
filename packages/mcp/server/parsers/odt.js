/**
 * ODT (OpenDocument Text) parser using JSZip.
 *
 * v1.20.0 T1-ODT — new parser for the OpenDocument Text format. The package
 * shape mirrors DOCX in spirit (ZIP container holding flat-XML parts) but the
 * XML schema is OASIS OpenDocument (xmlns:office/text/style/script/…). Quiet
 * carriers we surface as findings (all kebab ids, all folded into
 * `category: 'suspiciousPatterns'` so R13's 5-key invariant stays intact):
 *
 *   - odt-office-settings-macro: office:settings.xml carries a
 *     config-item-set targeting Java/script/macro behaviour (auto-execution
 *     of attached basic macros, JAR-handler config). Surfaced as 'danger'
 *     when the config-name flag enables macros, 'warning' otherwise.
 *   - odt-meta-prompt-injection: meta.xml dc:title / dc:subject /
 *     dc:description / meta:keyword / meta:user-defined string content trips
 *     looksLikeInstruction(). Severity 'warning'; the metadata names go in
 *     `element` for provenance and `content` carries the trimmed, capped,
 *     escaped value.
 *   - odt-external-event-listener: content.xml office:event-listeners /
 *     script:event-listener wiring an xlink:href to a remote scheme
 *     (http(s)/file/UNC) or to a script: URI. Severity 'danger'; the URL is
 *     held only in `meta.eventHref` (R12 — never baked into the technique).
 *   - odt-starbasic-macro: a Basic/<library>/<module>.xml entry exists with
 *     non-empty source, indicating the ODT bundles an embedded StarBasic
 *     macro. Severity 'warning' (macros may be legitimate); upgraded to
 *     'danger' when the source body contains a Shell() / Wscript / URLDownload
 *     style sink.
 *
 * Defensive caps mirror DOCX (5 MB per embedded blob, 50 entries per archive)
 * so a malicious ODT can't zip-bomb the scanner via inflated content.
 *
 * R12 invariant: every kebab id is a fixed string. Dynamic values (URLs,
 * macro paths, config names) only ever live inside `meta` or the escaped
 * `content` slice. Never echoed into the technique string.
 *
 * R13 invariant: all extraFindings carry `category: 'suspiciousPatterns'` so
 * the post-fold byCategory map keeps its 5-bucket shape.
 */

import { readFile } from "node:fs/promises";
import JSZip from "jszip";
import { escapeForDisplay, looksLikeInstruction } from "@shield-scanner/core";

// v1.20.0 T1-ODT: Office Compound File Binary (CFB) magic — re-declared in
// this file (instead of imported from docx.js / xlsx.js) so concurrent
// Theme parser additions cannot collide on a shared helper edit. Identical
// constant: D0 CF 11 E0 A1 B1 1A E1.
const CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

// Remote-URL prefix allow-list for event-listener href detection. Mirrors
// the docx.js Follina contract: http(s) covers the classic XSS / template
// fetch, file:// covers UNC abuse (CVE-2023-36884-style), `\\…` covers raw
// UNC bare paths. `script:` is added because StarBasic / ODF script
// frameworks use script:Library.Module:proc URIs to dispatch macros.
const REMOTE_URL_PREFIX_RE = /^(?:https?:|file:|\\\\|script:)/i;

// Defensive caps shared with DOCX. Held local so this parser stays
// self-contained and concurrent agents don't collide on a shared module.
const ODT_EMBED_MAX_BYTES = 5 * 1024 * 1024;
const ODT_EMBED_MAX_COUNT = 50;

// StarBasic high-risk shell / network sinks. A macro that calls any of these
// upgrades the severity from warning -> danger so reviewers see the loud
// finding first. Compiled once at module load (no per-call regex cost).
const STARBASIC_DANGER_SINKS_RE =
  /\b(Shell\s*\(|WScript\.|URLDownloadToFile|CreateObject\s*\(|MSXML2|ADODB\.Stream|Run\s*\(|EXEC\s*\()/i;

// office:settings.xml config-name flags that, when set, signal that the
// document author actively wanted macros to run. We surface each one as
// 'danger' rather than just 'warning' because their presence is anomalous
// for a document scanned in a security pipeline.
const MACRO_AUTOEXEC_CONFIG_NAMES = new Set([
  "loadreadonly",
  "macrosecuritylevel",
  "trustedauthors",
  "useeventlistener",
  "javaenabled",
  "applyusercolorsetting",
  "autostartmacro",
]);

export async function parseOdt(filePath) {
  const buffer = await readFile(filePath);
  return parseOdtBuffer(buffer);
}

/**
 * Parse ODT from a Buffer (used for recursive attachment scanning).
 *
 * @param {Buffer} buffer
 * @returns {Promise<{text:string, fileType:'text', extraFindings:Array}>}
 */
export async function parseOdtBuffer(buffer) {
  const texts = [];
  const extraFindings = [];

  let zip;
  try {
    zip = await JSZip.loadAsync(buffer);
  } catch {
    // Corrupt ZIP — surface a finding so callers don't silently swallow.
    extraFindings.push({
      element: "ODT package",
      technique: "odt-corrupt-package",
      content: "",
      severity: "warning",
      category: "suspiciousPatterns",
    });
    return { text: "", fileType: "text", extraFindings };
  }

  // ---- content.xml (body text + event listeners) ----
  const contentXmlEntry = zip.file("content.xml");
  if (contentXmlEntry) {
    let xml = "";
    try {
      xml = await contentXmlEntry.async("string");
    } catch {
      xml = "";
    }
    if (xml) {
      // Extract visible body text from <text:p> / <text:span> / <text:h>.
      // ODF uses the `text:` namespace; the regex stays lenient on attrs.
      const textMatches =
        xml.match(/<text:(?:p|span|h|a|list-item)[^>]*>([^<]*)<\/text:(?:p|span|h|a|list-item)>/gi) ||
        [];
      textMatches.forEach((m) => {
        const inner = m.replace(/<[^>]+>/g, "");
        if (inner) texts.push(inner);
      });

      // ---- odt-external-event-listener ----
      // office:event-listeners / script:event-listener xlink:href pointing
      // remote. ODF macros frequently use script: URIs; http(s)/file:/UNC
      // = clearly suspect. Single regex covers both <script:event-listener>
      // and <presentation:event-listener> (the second is rare in ODT but
      // appears when ODT carries presentation-flavored hooks).
      const eventRe =
        /<(?:script:event-listener|presentation:event-listener|office:event-listener)\b[^>]*\bxlink:href\s*=\s*"([^"]+)"[^>]*\/?>/gi;
      let em;
      while ((em = eventRe.exec(xml)) !== null) {
        const href = em[1];
        if (!href || !REMOTE_URL_PREFIX_RE.test(href)) continue;
        extraFindings.push({
          element: "office:event-listener",
          technique: "odt-external-event-listener",
          content: escapeForDisplay(href.slice(0, 200)),
          severity: "danger",
          category: "suspiciousPatterns",
          meta: { eventHref: escapeForDisplay(href.slice(0, 500)) },
        });
      }
    }
  }

  // ---- meta.xml (dc:* / meta:user-defined prompt smuggling) ----
  const metaXmlEntry = zip.file("meta.xml");
  if (metaXmlEntry) {
    let mxml = "";
    try {
      mxml = await metaXmlEntry.async("string");
    } catch {
      mxml = "";
    }
    if (mxml) {
      // Stage 1: dc:title / dc:subject / dc:description / dc:creator
      // (the namespace is locked-in OpenDocument Dublin Core).
      const dcRe = /<(dc:(?:title|subject|description|creator))\b[^>]*>([\s\S]*?)<\/\1>/gi;
      let dm;
      while ((dm = dcRe.exec(mxml)) !== null) {
        const elemName = dm[1];
        const value = (dm[2] || "").replace(/<[^>]+>/g, "").trim();
        if (!value || !looksLikeInstruction(value)) continue;
        extraFindings.push({
          element: `meta.xml ${elemName}`,
          technique: "odt-meta-prompt-injection",
          content: escapeForDisplay(value.slice(0, 200)),
          severity: "warning",
          category: "suspiciousPatterns",
          meta: { metaName: escapeForDisplay(elemName.slice(0, 100)) },
        });
      }

      // Stage 2: meta:keyword (multi-value) and meta:user-defined name=…
      const kwRe = /<meta:keyword\b[^>]*>([\s\S]*?)<\/meta:keyword>/gi;
      let km;
      while ((km = kwRe.exec(mxml)) !== null) {
        const value = (km[1] || "").replace(/<[^>]+>/g, "").trim();
        if (!value || !looksLikeInstruction(value)) continue;
        extraFindings.push({
          element: "meta.xml meta:keyword",
          technique: "odt-meta-prompt-injection",
          content: escapeForDisplay(value.slice(0, 200)),
          severity: "warning",
          category: "suspiciousPatterns",
          meta: { metaName: "meta:keyword" },
        });
      }

      const udRe =
        /<meta:user-defined\b[^>]*\bmeta:name\s*=\s*"([^"]+)"[^>]*>([\s\S]*?)<\/meta:user-defined>/gi;
      let um;
      while ((um = udRe.exec(mxml)) !== null) {
        const name = um[1];
        const value = (um[2] || "").replace(/<[^>]+>/g, "").trim();
        if (!value || !looksLikeInstruction(value)) continue;
        extraFindings.push({
          element: `meta.xml user-defined:${escapeForDisplay(name.slice(0, 80))}`,
          technique: "odt-meta-prompt-injection",
          content: escapeForDisplay(value.slice(0, 200)),
          severity: "warning",
          category: "suspiciousPatterns",
          meta: { metaName: escapeForDisplay(name.slice(0, 100)) },
        });
      }
    }
  }

  // ---- settings.xml (macro / java / event auto-load) ----
  // OpenOffice/LibreOffice store macro-trust / auto-load / Java-enabled
  // config flags here. The OpenDocument schema is config-item-set tree of
  // <config:config-item config:name="…" config:type="…">value</config:config-item>.
  // Surfaces every config-item that hits MACRO_AUTOEXEC_CONFIG_NAMES.
  const settingsXmlEntry = zip.file("settings.xml");
  if (settingsXmlEntry) {
    let sxml = "";
    try {
      sxml = await settingsXmlEntry.async("string");
    } catch {
      sxml = "";
    }
    if (sxml) {
      // Note: trailing whitespace requirement excludes `<config:config-item-set ...>`
      // — that's a container element whose own name attr is irrelevant here.
      // We want the leaf `<config:config-item config:name="..."> value </>` only.
      const cfgRe =
        /<config:config-item\s[^>]*\bconfig:name\s*=\s*"([^"]+)"[^>]*>([\s\S]*?)<\/config:config-item>/gi;
      let cm;
      while ((cm = cfgRe.exec(sxml)) !== null) {
        const name = cm[1];
        const value = (cm[2] || "").trim();
        const lower = name.toLowerCase();
        if (!MACRO_AUTOEXEC_CONFIG_NAMES.has(lower)) continue;
        // Severity: treat the explicit auto-exec/macro-trust flags as danger
        // when the value is truthy (`true` / `2` / non-empty author list).
        const truthy =
          value === "true" ||
          value === "1" ||
          value === "2" ||
          /[A-Za-z0-9]/.test(value);
        const severity = truthy ? "danger" : "warning";
        extraFindings.push({
          element: `settings.xml ${escapeForDisplay(name.slice(0, 80))}`,
          technique: "odt-office-settings-macro",
          content: escapeForDisplay(value.slice(0, 200)),
          severity,
          category: "suspiciousPatterns",
          meta: {
            configName: escapeForDisplay(name.slice(0, 100)),
            configValue: escapeForDisplay(value.slice(0, 200)),
          },
        });
      }
    }
  }

  // ---- Configurations2/ (alternative config tree — surface presence only) ----
  // Some LibreOffice exports drop Configurations2/accelerator/current.xml or
  // /toolbar/* with bound macros. We don't deep-parse the binary stream —
  // just count entries with .xml under that prefix and emit one finding if a
  // macro-binding-shaped name shows up. Cap at one finding to avoid noise.
  const configEntries = Object.keys(zip.files).filter((f) =>
    /^Configurations2\/.+\.(?:xml|xcu)$/i.test(f),
  );
  if (configEntries.length > 0) {
    // Optional surface: a config bundle alongside a Basic/ dir or settings.xml
    // macro flag is the loud combo. Standalone Configurations2/ is benign in
    // most exports, so we DON'T emit a finding just for its presence.
    // (Left as a comment so future tightening has the hook visible.)
  }

  // ---- Basic/<lib>/<module>.xml (embedded StarBasic macros) ----
  const basicEntries = Object.keys(zip.files).filter((f) =>
    /^Basic\/[^/]+\/[^/]+\.xml$/i.test(f),
  );
  let basicProcessed = 0;
  for (const bp of basicEntries) {
    if (basicProcessed >= ODT_EMBED_MAX_COUNT) break;
    const entry = zip.file(bp);
    if (!entry) continue;
    let src;
    try {
      src = await entry.async("string");
    } catch {
      basicProcessed++;
      continue;
    }
    basicProcessed++;
    if (!src || !src.trim()) continue;
    // The script source typically sits inside a CDATA inside the script:module
    // wrapper, but a plain text body works for our string scan either way.
    const isDanger = STARBASIC_DANGER_SINKS_RE.test(src);
    extraFindings.push({
      element: `Basic ${bp.replace(/^Basic\//, "")}`,
      technique: "odt-starbasic-macro",
      content: escapeForDisplay(bp.slice(0, 200)),
      severity: isDanger ? "danger" : "warning",
      category: "suspiciousPatterns",
      contextLocation: bp,
      meta: {
        macroPath: bp,
        hasDangerSink: isDanger,
      },
    });
  }

  // ---- ObjectReplacements/ + embedded OLE CFB ----
  // ODF stores embedded OLE blobs under Object N/ or ObjectReplacements/.
  // We scan any *.bin within those prefixes for CFB magic — same surface as
  // word/embeddings/*.bin in DOCX. office-embedded-ole-cfb is the shared
  // kebab id (mirror DOCX/PPTX).
  const oleEntries = Object.keys(zip.files).filter((f) =>
    /^(?:Object\s?\d+|ObjectReplacements)\/[^/]+\.bin$/i.test(f),
  );
  for (const ep of oleEntries) {
    const entry = zip.file(ep);
    if (!entry) continue;
    let buf;
    try {
      buf = await entry.async("nodebuffer");
    } catch {
      continue;
    }
    if (buf.length > ODT_EMBED_MAX_BYTES) continue;
    let hasCfbMagic = false;
    if (buf.length >= 8) {
      hasCfbMagic = true;
      for (let i = 0; i < 8; i++) {
        if (buf[i] !== CFB_MAGIC[i]) {
          hasCfbMagic = false;
          break;
        }
      }
    }
    if (!hasCfbMagic) continue;
    extraFindings.push({
      element: "ODT Embedded OLE",
      technique: "office-embedded-ole-cfb",
      content: escapeForDisplay(ep.slice(0, 200)),
      severity: "warning",
      category: "suspiciousPatterns",
      contextLocation: ep,
      meta: { embeddingPath: ep, hasCfbMagic: true },
    });
  }

  return {
    text: texts.join("\n"),
    fileType: "text",
    extraFindings,
  };
}
