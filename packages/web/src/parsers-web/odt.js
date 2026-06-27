// =============================================================
//  Shield Scanner Web — v1.20.0 T1-ODT OpenDocument Text parser
// =============================================================
// Web mirror of packages/mcp/server/parsers/odt.js. Byte-identical kebab ids,
// severities, meta keys, element labels so parity holds across both runtimes.
// All findings fold into category:'suspiciousPatterns' (R13 5-key invariant).
//
// Envelope: returns { text, hiddenFindings } (Web convention — analyze() in
// the core auto-tags fileType='text').
//
// Constants intentionally duplicated (not imported from docx.js) so concurrent
// parser additions never collide on a shared helper edit.
// =============================================================

import { escapeForDisplay, looksLikeInstruction } from '@shield-scanner/core';

const _CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const _REMOTE_URL_PREFIX_RE = /^(?:https?:|file:|\\\\|script:)/i;
const _ODT_EMBED_MAX_BYTES = 5 * 1024 * 1024;
const _ODT_EMBED_MAX_COUNT = 50;
const _STARBASIC_DANGER_SINKS_RE =
  /\b(Shell\s*\(|WScript\.|URLDownloadToFile|CreateObject\s*\(|MSXML2|ADODB\.Stream|Run\s*\(|EXEC\s*\()/i;
const _MACRO_AUTOEXEC_CONFIG_NAMES = new Set([
  'loadreadonly',
  'macrosecuritylevel',
  'trustedauthors',
  'useeventlistener',
  'javaenabled',
  'applyusercolorsetting',
  'autostartmacro',
]);

async function parseOdt(buffer) {
  const texts = [];
  const hiddenFindings = [];

  let zip;
  try {
    zip = await JSZip.loadAsync(buffer);
  } catch {
    hiddenFindings.push({
      element: 'ODT package',
      technique: 'odt-corrupt-package',
      content: '',
      severity: 'warning',
      category: 'suspiciousPatterns',
    });
    return { text: '', hiddenFindings };
  }

  // ---- content.xml ----
  const contentXmlEntry = zip.file('content.xml');
  if (contentXmlEntry) {
    let xml = '';
    try { xml = await contentXmlEntry.async('string'); } catch { xml = ''; }
    if (xml) {
      const textMatches =
        xml.match(/<text:(?:p|span|h|a|list-item)[^>]*>([^<]*)<\/text:(?:p|span|h|a|list-item)>/gi) || [];
      textMatches.forEach((m) => {
        const inner = m.replace(/<[^>]+>/g, '');
        if (inner) texts.push(inner);
      });

      const eventRe =
        /<(?:script:event-listener|presentation:event-listener|office:event-listener)\b[^>]*\bxlink:href\s*=\s*"([^"]+)"[^>]*\/?>/gi;
      let em;
      while ((em = eventRe.exec(xml)) !== null) {
        const href = em[1];
        if (!href || !_REMOTE_URL_PREFIX_RE.test(href)) continue;
        hiddenFindings.push({
          element: 'office:event-listener',
          technique: 'odt-external-event-listener',
          content: escapeForDisplay(href.slice(0, 200)),
          severity: 'danger',
          category: 'suspiciousPatterns',
          meta: { eventHref: escapeForDisplay(href.slice(0, 500)) },
        });
      }
    }
  }

  // ---- meta.xml ----
  const metaXmlEntry = zip.file('meta.xml');
  if (metaXmlEntry) {
    let mxml = '';
    try { mxml = await metaXmlEntry.async('string'); } catch { mxml = ''; }
    if (mxml) {
      const dcRe = /<(dc:(?:title|subject|description|creator))\b[^>]*>([\s\S]*?)<\/\1>/gi;
      let dm;
      while ((dm = dcRe.exec(mxml)) !== null) {
        const elemName = dm[1];
        const value = (dm[2] || '').replace(/<[^>]+>/g, '').trim();
        if (!value || !looksLikeInstruction(value)) continue;
        hiddenFindings.push({
          element: `meta.xml ${elemName}`,
          technique: 'odt-meta-prompt-injection',
          content: escapeForDisplay(value.slice(0, 200)),
          severity: 'warning',
          category: 'suspiciousPatterns',
          meta: { metaName: escapeForDisplay(elemName.slice(0, 100)) },
        });
      }

      const kwRe = /<meta:keyword\b[^>]*>([\s\S]*?)<\/meta:keyword>/gi;
      let km;
      while ((km = kwRe.exec(mxml)) !== null) {
        const value = (km[1] || '').replace(/<[^>]+>/g, '').trim();
        if (!value || !looksLikeInstruction(value)) continue;
        hiddenFindings.push({
          element: 'meta.xml meta:keyword',
          technique: 'odt-meta-prompt-injection',
          content: escapeForDisplay(value.slice(0, 200)),
          severity: 'warning',
          category: 'suspiciousPatterns',
          meta: { metaName: 'meta:keyword' },
        });
      }

      const udRe =
        /<meta:user-defined\b[^>]*\bmeta:name\s*=\s*"([^"]+)"[^>]*>([\s\S]*?)<\/meta:user-defined>/gi;
      let um;
      while ((um = udRe.exec(mxml)) !== null) {
        const name = um[1];
        const value = (um[2] || '').replace(/<[^>]+>/g, '').trim();
        if (!value || !looksLikeInstruction(value)) continue;
        hiddenFindings.push({
          element: `meta.xml user-defined:${escapeForDisplay(name.slice(0, 80))}`,
          technique: 'odt-meta-prompt-injection',
          content: escapeForDisplay(value.slice(0, 200)),
          severity: 'warning',
          category: 'suspiciousPatterns',
          meta: { metaName: escapeForDisplay(name.slice(0, 100)) },
        });
      }
    }
  }

  // ---- settings.xml ----
  const settingsXmlEntry = zip.file('settings.xml');
  if (settingsXmlEntry) {
    let sxml = '';
    try { sxml = await settingsXmlEntry.async('string'); } catch { sxml = ''; }
    if (sxml) {
      // Note: trailing whitespace requirement excludes `<config:config-item-set ...>`
      // — that's a container element. We want the leaf config-item only.
      const cfgRe =
        /<config:config-item\s[^>]*\bconfig:name\s*=\s*"([^"]+)"[^>]*>([\s\S]*?)<\/config:config-item>/gi;
      let cm;
      while ((cm = cfgRe.exec(sxml)) !== null) {
        const name = cm[1];
        const value = (cm[2] || '').trim();
        const lower = name.toLowerCase();
        if (!_MACRO_AUTOEXEC_CONFIG_NAMES.has(lower)) continue;
        const truthy =
          value === 'true' ||
          value === '1' ||
          value === '2' ||
          /[A-Za-z0-9]/.test(value);
        const severity = truthy ? 'danger' : 'warning';
        hiddenFindings.push({
          element: `settings.xml ${escapeForDisplay(name.slice(0, 80))}`,
          technique: 'odt-office-settings-macro',
          content: escapeForDisplay(value.slice(0, 200)),
          severity,
          category: 'suspiciousPatterns',
          meta: {
            configName: escapeForDisplay(name.slice(0, 100)),
            configValue: escapeForDisplay(value.slice(0, 200)),
          },
        });
      }
    }
  }

  // ---- Basic/<lib>/<module>.xml (StarBasic macros) ----
  const basicEntries = Object.keys(zip.files).filter((f) =>
    /^Basic\/[^/]+\/[^/]+\.xml$/i.test(f),
  );
  let basicProcessed = 0;
  for (const bp of basicEntries) {
    if (basicProcessed >= _ODT_EMBED_MAX_COUNT) break;
    const entry = zip.file(bp);
    if (!entry) continue;
    let src;
    try {
      src = await entry.async('string');
    } catch {
      basicProcessed++;
      continue;
    }
    basicProcessed++;
    if (!src || !src.trim()) continue;
    const isDanger = _STARBASIC_DANGER_SINKS_RE.test(src);
    hiddenFindings.push({
      element: `Basic ${bp.replace(/^Basic\//, '')}`,
      technique: 'odt-starbasic-macro',
      content: escapeForDisplay(bp.slice(0, 200)),
      severity: isDanger ? 'danger' : 'warning',
      category: 'suspiciousPatterns',
      contextLocation: bp,
      meta: {
        macroPath: bp,
        hasDangerSink: isDanger,
      },
    });
  }

  // ---- Object N / ObjectReplacements (embedded OLE CFB) ----
  const oleEntries = Object.keys(zip.files).filter((f) =>
    /^(?:Object\s?\d+|ObjectReplacements)\/[^/]+\.bin$/i.test(f),
  );
  for (const ep of oleEntries) {
    const entry = zip.file(ep);
    if (!entry) continue;
    let buf;
    try {
      buf = await entry.async('uint8array');
    } catch {
      continue;
    }
    if (buf.byteLength > _ODT_EMBED_MAX_BYTES) continue;
    let hasCfbMagic = false;
    if (buf.byteLength >= 8) {
      hasCfbMagic = true;
      for (let i = 0; i < 8; i++) {
        if (buf[i] !== _CFB_MAGIC[i]) {
          hasCfbMagic = false;
          break;
        }
      }
    }
    if (!hasCfbMagic) continue;
    hiddenFindings.push({
      element: 'ODT Embedded OLE',
      technique: 'office-embedded-ole-cfb',
      content: escapeForDisplay(ep.slice(0, 200)),
      severity: 'warning',
      category: 'suspiciousPatterns',
      contextLocation: ep,
      meta: { embeddingPath: ep, hasCfbMagic: true },
    });
  }

  return { text: texts.join('\n'), hiddenFindings };
}

export { parseOdt };
