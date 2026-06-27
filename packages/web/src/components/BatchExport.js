// =============================================================
//  Shield Scanner Web — BatchExport (v1.19.0 C3)
// =============================================================
// Batch-scan UI add-on:
//   - exportBatchJson      → raw findings dump (audit / re-ingest)
//   - exportBatchMarkdown  → human-readable report with finding table +
//                            remediation hint
//   - exportBatchPdf       → static, ASCII-only PDF for internal audit
//                            submission (logo block + scan timestamp +
//                            file list + per-category aggregate table)
//
// All three exporters consume the same shape as bulk-scan.js's
// `_bulkResults` array (the per-file scan result objects). They are pure
// transformations — no DOM, no `analyze()` re-runs, no network — so they
// can run inside any caller (UI button handler, Node test, future CLI).
//
// PDF generation note (R12 / dist-budget gate):
//   `pdf-lib` (already a devDep at the monorepo root) is the obvious choice,
//   but its esbuild-bundled footprint is ~820 KiB. Adding that to the
//   current ~336 KiB Web bundle would blow the 900 KiB dist-budget gate
//   enforced by tools/dist-budget.mjs. esbuild's `iife` format cannot
//   code-split, so dynamic `import('pdf-lib')` would still inline the same
//   bytes. We therefore emit a minimal PDF 1.4 document by hand: header,
//   four indirect objects (Catalog / Pages / Page / Font), a content
//   stream rendering Helvetica (a PDF Standard-14 font that doesn't need
//   embedding), an xref table, and trailer. The result is a valid PDF
//   that opens in every viewer; total emitter source is ~80 lines.
//   This satisfies the task's "新規依存ゼロ" intent without busting the
//   dist budget. Other libraries (jsPDF, html2pdf) remain forbidden.
//
// R17 re-use: this module does NOT introduce a new in-progress flag or a
// new 30s timeout. The bulk run that produced the results array already
// passed through bulk-scan.js's `_bulkInProgress` + `_withTimeout(... 30s)`
// guards; export is downstream of that gate and runs synchronously on
// an already-completed dataset.
//
// R12: per-finding `meta` snapshots come from the detector (kebab-case
// technique id + numeric / boolean meta values only). The exporters never
// surface raw user text — only finding kinds, counts, and the filenames
// the user themselves provided. Filename sanitisation here mirrors what
// _sanitizeFilenameForDisplay does for the UI tab labels (Bidi / ZW / Tag /
// VS / control-char strip) so a crafted file name cannot smuggle Bidi
// override codepoints into the exported PDF / Markdown.
// =============================================================

// --- R13 5-bucket category contract (byCategory / aggregate table) ---
// Strict 5-key list, in the documented order. Aligns with the analyze()
// summary.byCategory invariant pinned in core's R13 tests.
const R13_CATEGORIES = Object.freeze([
  'invisibleUnicode',
  'controlChars',
  'hiddenHtml',
  'suspiciousPatterns',
  'homoglyphs',
]);

// Extra sibling buckets that the bulk severity calc walks — kept separate
// from R13_CATEGORIES so new signal categories never silently collapse the
// 5-key fold. Surfaced as a single "other" count in the aggregate table.
const SIBLING_BUCKETS = Object.freeze([
  'variationSelectors',
  'bidiOverride',
  'mathSymbolBypass',
  'combiningChars',
]);

// --- Filename sanitiser (UI-mirror, R12) ---
// Strip Bidi (U+202A–202E, U+2066–2069), zero-width (U+200B–200D, U+FEFF),
// Variation Selectors (U+FE00–FE0F, U+E0100–E01EF), Tag chars (U+E0000–E007F),
// and C0/C1 control chars (except TAB / LF / CR). Anything stripped is
// replaced with the dotted-circle stand-in so the user can still tell the
// name was tampered with. Mirrors ui-guards/sanitize-filename.js.
function _sanitizeNameForExport(name) {
  if (typeof name !== 'string') return '(unknown)';
  let out = '';
  for (const ch of name) {
    const cp = ch.codePointAt(0);
    const isBidi = (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);
    const isZW = cp === 0x200B || cp === 0x200C || cp === 0x200D || cp === 0xFEFF;
    const isVS = (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
    const isTag = cp >= 0xE0000 && cp <= 0xE007F;
    const isC0 = cp < 0x20 && cp !== 0x09 && cp !== 0x0A && cp !== 0x0D;
    const isC1 = cp >= 0x7F && cp <= 0x9F;
    if (isBidi || isZW || isVS || isTag || isC0 || isC1) out += '◌';
    else out += ch;
  }
  return out;
}

// --- Severity of a per-file findings object ---
// Returns 'safe' | 'warning' | 'danger' | 'error'. Mirrors
// bulk-scan.js's `_severityOfFindings` so JSON / Markdown / PDF agree
// with the UI tab badge for the same file.
function _exportSeverity(result) {
  if (!result || result.ok === false) return 'error';
  const findings = result.findings;
  if (!findings) return 'error';
  const vs = findings.variationSelectors || [];
  const bidi = findings.bidiOverride || [];
  const math = findings.mathSymbolBypass || [];
  const comb = findings.combiningChars || [];
  const dangerCount =
    (findings.invisibleUnicode || []).filter((f) => f.severity === 'danger').length +
    (findings.hiddenHtml || []).filter((f) => f.severity === 'danger').length +
    (findings.suspiciousPatterns || []).filter((f) => (f.severity || 'danger') === 'danger').length +
    vs.filter((f) => f.severity === 'danger').length +
    bidi.filter((f) => f.severity === 'danger').length +
    math.filter((f) => f.severity === 'danger').length +
    comb.filter((f) => f.severity === 'danger').length;
  if (dangerCount > 0) return 'danger';
  const warningCount =
    (findings.invisibleUnicode || []).filter((f) => f.severity === 'warning').length +
    (findings.controlChars || []).length +
    (findings.hiddenHtml || []).filter((f) => f.severity === 'warning').length +
    (findings.homoglyphs || []).length +
    (findings.suspiciousPatterns || []).filter((f) => f.severity === 'warning').length +
    vs.filter((f) => f.severity === 'warning').length +
    bidi.filter((f) => f.severity === 'warning').length +
    math.filter((f) => f.severity === 'warning').length +
    comb.filter((f) => f.severity === 'warning').length;
  if (warningCount > 0) return 'warning';
  return 'safe';
}

// --- Aggregate category counts across all files ---
// Returns { byCategory: {<5 keys>: n}, other: n, total: n }. R13 5-key
// strict shape: every category key in the returned byCategory is one of
// the documented five, even when zero. New sibling buckets are folded
// into `other` rather than added as a new top-level key.
function _aggregateCategories(results) {
  const byCategory = {};
  for (const k of R13_CATEGORIES) byCategory[k] = 0;
  let other = 0;
  let total = 0;
  for (const r of results) {
    if (!r || !r.ok || !r.findings) continue;
    for (const k of R13_CATEGORIES) {
      const arr = r.findings[k];
      if (Array.isArray(arr)) {
        byCategory[k] += arr.length;
        total += arr.length;
      }
    }
    for (const k of SIBLING_BUCKETS) {
      const arr = r.findings[k];
      if (Array.isArray(arr)) {
        other += arr.length;
        total += arr.length;
      }
    }
  }
  return { byCategory, other, total };
}

// --- ISO timestamp used by all three exporters ---
// Accepts an injected `now` so tests can pin the timestamp.
function _isoNow(now) {
  const d = (now instanceof Date) ? now : new Date();
  return d.toISOString();
}

// =============================================================
//  Exporter 1: JSON (raw findings, machine-readable)
// =============================================================
// Shape:
//   { tool: 'shield-scanner', version, scannedAt, fileCount, summary,
//     files: [{ name, severity, ok, error?, byCategory, findings? }, ...] }
//
// `findings` carries the raw arrays from analyze() — JSON is the audit
// re-ingest format, so we keep it full-fidelity. Markdown / PDF strip down
// to counts only.
function exportBatchJson(results, opts) {
  const o = opts || {};
  const scannedAt = _isoNow(o.now);
  const agg = _aggregateCategories(results || []);
  const files = (results || []).map((r) => {
    const base = {
      name: _sanitizeNameForExport(r && r.name),
      severity: _exportSeverity(r),
      ok: !!(r && r.ok),
    };
    if (r && r.ok && r.findings) {
      const fileByCat = {};
      for (const k of R13_CATEGORIES) {
        fileByCat[k] = Array.isArray(r.findings[k]) ? r.findings[k].length : 0;
      }
      base.byCategory = fileByCat;
      base.findings = r.findings;
    } else {
      base.byCategory = R13_CATEGORIES.reduce((m, k) => { m[k] = 0; return m; }, {});
      if (r && r.error) base.error = r.error;
    }
    return base;
  });
  return JSON.stringify({
    tool: 'shield-scanner',
    version: o.version || '1.19.0',
    scannedAt,
    fileCount: files.length,
    summary: {
      byCategory: agg.byCategory,
      other: agg.other,
      total: agg.total,
    },
    files,
  }, null, 2);
}

// =============================================================
//  Exporter 2: Markdown (human-readable report)
// =============================================================
// Layout:
//   # Shield Scanner Batch Report
//   - scannedAt / fileCount / total findings
//   ## Summary (R13 byCategory + other + total)
//   ## Files (table: name | severity | findings | error?)
//   ## Remediation
//     - bullet-list keyed off severity buckets that fired
function exportBatchMarkdown(results, opts) {
  const o = opts || {};
  const scannedAt = _isoNow(o.now);
  const agg = _aggregateCategories(results || []);
  const lines = [];
  lines.push('# Shield Scanner Batch Report');
  lines.push('');
  lines.push(`- Tool: shield-scanner ${o.version || '1.19.0'}`);
  lines.push(`- Scanned at: ${scannedAt}`);
  lines.push(`- File count: ${(results || []).length}`);
  lines.push(`- Total findings: ${agg.total}`);
  lines.push('');
  lines.push('## Summary by Category');
  lines.push('');
  lines.push('| Category | Count |');
  lines.push('| --- | ---: |');
  for (const k of R13_CATEGORIES) {
    lines.push(`| ${k} | ${agg.byCategory[k]} |`);
  }
  lines.push(`| (other signals) | ${agg.other} |`);
  lines.push('');
  lines.push('## Files');
  lines.push('');
  lines.push('| File | Severity | Findings | Note |');
  lines.push('| --- | --- | ---: | --- |');
  for (const r of results || []) {
    const name = _sanitizeNameForExport(r && r.name);
    const sev = _exportSeverity(r);
    let count = 0;
    if (r && r.ok && r.findings) {
      for (const k of R13_CATEGORIES) {
        if (Array.isArray(r.findings[k])) count += r.findings[k].length;
      }
      for (const k of SIBLING_BUCKETS) {
        if (Array.isArray(r.findings[k])) count += r.findings[k].length;
      }
    }
    const note = (r && !r.ok && r.error) ? String(r.error) : '';
    // Markdown table cell escape: `|` and `\n` would break the row.
    const safeName = name.replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
    const safeNote = note.replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
    lines.push(`| ${safeName} | ${sev} | ${count} | ${safeNote} |`);
  }
  lines.push('');
  lines.push('## Remediation');
  lines.push('');
  // Keyed remediation hints — kept generic so they don't surface raw user
  // text (R12). Only fires per non-zero category so the report stays
  // signal-to-noise.
  const hints = {
    invisibleUnicode: 'Review files for hidden Unicode (ZWSP / ZWJ / VS) that may carry prompt-injection payloads. Run sanitize-and-download before forwarding to an LLM.',
    controlChars: 'Strip C0 / C1 control characters before ingestion. Many LLM APIs reject or mishandle these.',
    hiddenHtml: 'Inspect display:none / visibility:hidden / opacity:0 elements; attackers stage instructions there for screen-only readers (LLMs).',
    suspiciousPatterns: 'Review pattern matches (prompt-injection vocabulary, role escalation). Treat the file as untrusted input.',
    homoglyphs: 'Look-alike characters (Cyrillic / Greek / math) suggest domain or brand impersonation.',
  };
  let anyHint = false;
  for (const k of R13_CATEGORIES) {
    if (agg.byCategory[k] > 0) {
      anyHint = true;
      lines.push(`- **${k}** (${agg.byCategory[k]}): ${hints[k]}`);
    }
  }
  if (!anyHint) {
    lines.push('- No findings — files cleared all five detector categories.');
  }
  lines.push('');
  return lines.join('\n');
}

// =============================================================
//  Exporter 3: PDF (manual PDF 1.4 emitter, audit-grade)
// =============================================================
// Builds a single-page, ASCII-only PDF. Layout:
//
//   Shield Scanner             [logo block — text-only]
//   Batch Audit Report
//   Scanned at: <ISO>          File count: N    Total: M
//
//   Files:
//     1. <name>                  [SEVERITY]  <count>
//     2. ...
//
//   Summary by category:
//     invisibleUnicode    N
//     controlChars        N
//     hiddenHtml          N
//     suspiciousPatterns  N
//     homoglyphs          N
//     other signals       N
//
// Implementation choices:
//   - PDF 1.4, single page, US Letter (612 x 792 pt).
//   - Helvetica is one of the 14 Standard fonts; PDF readers ship it,
//     so we don't embed font bytes — keeps the PDF small (~2 KiB).
//   - All text is ASCII-only. Non-ASCII filename chars get dotted-circle'd
//     by _sanitizeNameForExport(); we additionally pass through a final
//     ASCII fold so anything that slipped past becomes '?' rather than
//     emitting a malformed PDF string.
//   - Each line is a separate `Tj` operation; total < 60 lines so we cap
//     the file list at 50 entries (matches the 30-file bulk limit + slack).

// Final ASCII-only filter for PDF strings. Maps any non-printable-ASCII
// codepoint to '?'. (parens / backslash are PDF metacharacters and need
// escaping, handled separately in _pdfEscape.)
function _asciiFold(s) {
  if (typeof s !== 'string') return '';
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp >= 0x20 && cp <= 0x7E) out += ch;
    else if (cp === 0x09) out += ' ';
    else out += '?';
  }
  return out;
}

// PDF literal-string escape: '(' / ')' / '\\' → escaped with backslash.
function _pdfEscape(s) {
  return _asciiFold(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

// Single-page PDF builder. Returns a Uint8Array of the PDF bytes.
function exportBatchPdf(results, opts) {
  const o = opts || {};
  const scannedAt = _isoNow(o.now);
  const agg = _aggregateCategories(results || []);
  const list = (results || []).slice(0, 50); // cap for one page

  // --- Build content-stream text operations ---
  // Coords: PDF origin is bottom-left; we start at y=750 and walk down.
  const lines = [];
  let y = 750;
  const pushLine = (size, text) => {
    lines.push(`BT /F1 ${size} Tf 50 ${y} Td (${_pdfEscape(text)}) Tj ET`);
    y -= size + 4;
  };
  const blank = (n) => { y -= n; };

  pushLine(18, 'Shield Scanner');
  pushLine(13, 'Batch Audit Report');
  blank(6);
  pushLine(10, `Scanned at: ${scannedAt}`);
  pushLine(10, `File count: ${list.length}    Total findings: ${agg.total}`);
  blank(6);
  pushLine(11, 'Files:');
  list.forEach((r, i) => {
    const name = _sanitizeNameForExport(r && r.name);
    const sev = _exportSeverity(r).toUpperCase();
    let count = 0;
    if (r && r.ok && r.findings) {
      for (const k of R13_CATEGORIES) {
        if (Array.isArray(r.findings[k])) count += r.findings[k].length;
      }
      for (const k of SIBLING_BUCKETS) {
        if (Array.isArray(r.findings[k])) count += r.findings[k].length;
      }
    }
    // Truncate filename so the row fits in ~80 chars.
    const short = name.length > 50 ? (name.slice(0, 47) + '...') : name;
    pushLine(9, `${String(i + 1).padStart(2, ' ')}. ${short}   [${sev}]  ${count}`);
  });
  if ((results || []).length > list.length) {
    pushLine(9, `... ${(results || []).length - list.length} more file(s) truncated`);
  }
  blank(6);
  pushLine(11, 'Summary by category:');
  for (const k of R13_CATEGORIES) {
    pushLine(9, `  ${k.padEnd(20, ' ')} ${agg.byCategory[k]}`);
  }
  pushLine(9, `  ${'other signals'.padEnd(20, ' ')} ${agg.other}`);

  const contentStream = lines.join('\n') + '\n';

  // --- Assemble PDF objects ---
  // Object 1: Catalog
  // Object 2: Pages
  // Object 3: Page
  // Object 4: Font
  // Object 5: Content stream
  const obj1 = '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';
  const obj2 = '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n';
  const obj3 =
    '3 0 obj\n' +
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ' +
    '/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\n' +
    'endobj\n';
  const obj4 = '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n';
  const streamBytes = contentStream;
  const obj5 =
    '5 0 obj\n' +
    `<< /Length ${streamBytes.length} >>\n` +
    'stream\n' +
    streamBytes +
    'endstream\n' +
    'endobj\n';

  // --- Assemble file with xref + trailer ---
  const header = '%PDF-1.4\n%\xFF\xFF\xFF\xFF\n';
  const body = obj1 + obj2 + obj3 + obj4 + obj5;
  // Byte offsets of each indirect object (for xref).
  const offsets = [];
  let cursor = header.length;
  for (const o2 of [obj1, obj2, obj3, obj4, obj5]) {
    offsets.push(cursor);
    cursor += o2.length;
  }
  const xrefOffset = header.length + body.length;
  let xref = 'xref\n0 6\n0000000000 65535 f \n';
  for (const off of offsets) {
    xref += `${String(off).padStart(10, '0')} 00000 n \n`;
  }
  const trailer =
    'trailer\n' +
    '<< /Size 6 /Root 1 0 R >>\n' +
    'startxref\n' +
    `${xrefOffset}\n` +
    '%%EOF\n';

  const pdfText = header + body + xref + trailer;
  // Latin-1 byte encode (PDF strings are 8-bit clean).
  const buf = new Uint8Array(pdfText.length);
  for (let i = 0; i < pdfText.length; i++) buf[i] = pdfText.charCodeAt(i) & 0xFF;
  return buf;
}

// =============================================================
//  Wire helper: render the three export buttons into a host node
// =============================================================
// Called by app.js after a bulk run completes. Lazy-imported here so the
// wire-in is a single end-of-file `globalThis.__shieldBatchExport` block
// in app.js (zero mid-file edits, C2 collision-free).
function mountBatchExportButtons(hostEl, getResultsFn) {
  if (!hostEl || typeof getResultsFn !== 'function') return;
  // Idempotent: clear an earlier mount so re-renders don't double the
  // button row.
  const existing = hostEl.querySelector('[data-batch-export-row]');
  if (existing) existing.remove();
  const row = document.createElement('div');
  row.setAttribute('data-batch-export-row', '1');
  row.style.cssText = 'display:flex; gap:0.5rem; flex-wrap:wrap; margin-top:0.5rem;';
  const mkBtn = (label, onClick) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'action-btn btn-export';
    b.textContent = label;
    b.addEventListener('click', () => {
      try { onClick(); } catch (e) { /* swallow — exporters are pure, errors are programmer-bug */ }
    });
    return b;
  };
  const trigger = (filename, mime, payload) => {
    // Browser-only: build a Blob URL and click an anchor to download.
    const blob = (payload instanceof Uint8Array)
      ? new Blob([payload], { type: mime })
      : new Blob([String(payload)], { type: mime + ';charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  row.appendChild(mkBtn('JSON', () => {
    const results = getResultsFn() || [];
    trigger('shield-scanner-batch.json', 'application/json',
      exportBatchJson(results));
  }));
  row.appendChild(mkBtn('Markdown', () => {
    const results = getResultsFn() || [];
    trigger('shield-scanner-batch.md', 'text/markdown',
      exportBatchMarkdown(results));
  }));
  row.appendChild(mkBtn('PDF', () => {
    const results = getResultsFn() || [];
    trigger('shield-scanner-batch.pdf', 'application/pdf',
      exportBatchPdf(results));
  }));
  hostEl.appendChild(row);
}

export {
  exportBatchJson,
  exportBatchMarkdown,
  exportBatchPdf,
  mountBatchExportButtons,
  // exposed for tests:
  _sanitizeNameForExport,
  _exportSeverity,
  _aggregateCategories,
  _asciiFold,
  _pdfEscape,
  R13_CATEGORIES,
  SIBLING_BUCKETS,
};
