// v1.19.0 Theme B3 — Jupyter Notebook (.ipynb) parser (Web mirror).
//
// Byte-for-byte mirror of packages/mcp/server/parsers/ipynb.js. Web bundle has
// no fs / fetch surface — entry point is parseIpynb(buffer) only. Same caps,
// same kebab ids, same R12/R13/R18 invariants:
//
//   - Output kebab ids (suspiciousPatterns fold):
//       ipynb-output-html-injection
//       ipynb-hidden-cell-instruction
//       ipynb-metadata-tag-smuggle
//       ipynb-untrusted-signature
//   - Defensive caps: 10 MB archive / 5000 cells / 100 outputs/cell / 1 MB per
//     output body.
//   - R12: cell index / tag / mime values flow through escapeForDisplay before
//     `content` / `contextLocation` surfacing.
//   - R13: every new id lands in `category: 'suspiciousPatterns'`.
//   - R18: only env-free `escapeForDisplay` / `looksLikeInstruction` imports.

import { escapeForDisplay, looksLikeInstruction } from '@shield-scanner/core';

const IPYNB_MAX_ARCHIVE_BYTES = 10 * 1024 * 1024;
const IPYNB_MAX_CELLS = 5000;
const IPYNB_MAX_OUTPUTS_PER_CELL = 100;
const IPYNB_MAX_OUTPUT_BYTES = 1 * 1024 * 1024;

const HTML_LIKE_MIMES = new Set([
  'text/html',
  'application/javascript',
  'application/x-javascript',
]);

const HIDE_TAG_RE = /^(?:hide[-_]input|hide[-_]cell|hide[-_]source|remove[-_]input|remove[-_]cell|injected[-_]parameters)$/i;

async function parseIpynb(buffer) {
  const hiddenFindings = [];

  const u8 =
    buffer instanceof Uint8Array
      ? buffer
      : new Uint8Array(buffer);

  if (u8.byteLength > IPYNB_MAX_ARCHIVE_BYTES) {
    hiddenFindings.push({
      element: 'IPYNB Notebook',
      technique: 'ipynb-scan-limit',
      content: `(notebook > ${IPYNB_MAX_ARCHIVE_BYTES} bytes; not scanned)`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'IPYNB Notebook',
      meta: { scope: 'archive', maxBytes: IPYNB_MAX_ARCHIVE_BYTES, byteLen: u8.byteLength },
    });
    return { text: '', hiddenFindings, fileType: 'ipynb' };
  }

  let raw = '';
  try {
    raw = new TextDecoder('utf-8', { fatal: false }).decode(u8);
  } catch {
    raw = '';
  }

  let nb;
  try {
    nb = JSON.parse(raw);
  } catch (err) {
    const msg = err && err.message ? err.message : 'JSON parse error';
    hiddenFindings.push({
      element: 'IPYNB Notebook',
      technique: 'ipynb-corrupt-json',
      content: escapeForDisplay(msg.slice(0, 200)),
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'IPYNB Notebook',
      meta: { errorMessage: escapeForDisplay(msg.slice(0, 64)) },
    });
    return { text: '', hiddenFindings, fileType: 'ipynb' };
  }

  if (!nb || typeof nb !== 'object' || Array.isArray(nb)) {
    return { text: '', hiddenFindings, fileType: 'ipynb' };
  }

  const nbformat = Number.isFinite(nb.nbformat) ? nb.nbformat : null;
  if (nbformat !== null && nbformat >= 4) {
    const topMeta = (nb.metadata && typeof nb.metadata === 'object') ? nb.metadata : {};
    const sig = typeof topMeta.signature === 'string' ? topMeta.signature : '';
    if (!sig || sig.trim().length === 0) {
      hiddenFindings.push({
        element: 'IPYNB Notebook',
        technique: 'ipynb-untrusted-signature',
        content: '(no metadata.signature on notebook)',
        severity: 'warning',
        category: 'suspiciousPatterns',
        contextLocation: 'IPYNB Notebook',
        meta: { nbformat, nbformatMinor: Number.isFinite(nb.nbformat_minor) ? nb.nbformat_minor : null },
      });
    }
  }

  const texts = [];
  const cells = Array.isArray(nb.cells) ? nb.cells : [];
  const cellLimit = Math.min(cells.length, IPYNB_MAX_CELLS);
  if (cells.length > IPYNB_MAX_CELLS) {
    hiddenFindings.push({
      element: 'IPYNB Notebook',
      technique: 'ipynb-scan-limit',
      content: `(cell count ${cells.length} > ${IPYNB_MAX_CELLS}; trailing cells skipped)`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'IPYNB Notebook',
      meta: { scope: 'cells', maxCells: IPYNB_MAX_CELLS, cellCount: cells.length },
    });
  }

  for (let i = 0; i < cellLimit; i++) {
    const cell = cells[i];
    if (!cell || typeof cell !== 'object') continue;

    const cellType = typeof cell.cell_type === 'string' ? cell.cell_type : 'unknown';
    const meta = (cell.metadata && typeof cell.metadata === 'object') ? cell.metadata : {};

    const sourceText = normalizeSource(cell.source);
    if (sourceText && sourceText.length > 0) {
      texts.push(`[ipynb cell ${i + 1} ${cellType}]\n${sourceText}`);
    }

    const hiddenSignals = collectHiddenSignals(meta);
    if (hiddenSignals.length > 0 && sourceText && looksLikeInstruction(sourceText)) {
      hiddenFindings.push({
        element: `IPYNB cell ${i + 1} (${escapeForDisplay(cellType)})`,
        technique: 'ipynb-hidden-cell-instruction',
        content: escapeForDisplay(sourceText.slice(0, 200)),
        severity: 'danger',
        category: 'suspiciousPatterns',
        contextLocation: `IPYNB cell ${i + 1}`,
        meta: {
          cellIndex: i + 1,
          cellType: escapeForDisplay(cellType),
          hideSignals: hiddenSignals.map((s) => escapeForDisplay(s)),
        },
      });
    }

    if (Array.isArray(meta.tags)) {
      for (const tag of meta.tags) {
        if (typeof tag !== 'string' || tag.length === 0) continue;
        if (looksLikeInstruction(tag) || HIDE_TAG_RE.test(tag)) {
          hiddenFindings.push({
            element: `IPYNB cell ${i + 1} metadata.tags`,
            technique: 'ipynb-metadata-tag-smuggle',
            content: escapeForDisplay(tag.slice(0, 200)),
            severity: looksLikeInstruction(tag) ? 'danger' : 'warning',
            category: 'suspiciousPatterns',
            contextLocation: `IPYNB cell ${i + 1} metadata.tags`,
            meta: {
              cellIndex: i + 1,
              tag: escapeForDisplay(tag.slice(0, 200)),
            },
          });
        }
        texts.push(`[ipynb cell ${i + 1} tag] ${tag}`);
      }
    }

    const outputs = Array.isArray(cell.outputs) ? cell.outputs : [];
    const outLimit = Math.min(outputs.length, IPYNB_MAX_OUTPUTS_PER_CELL);
    for (let j = 0; j < outLimit; j++) {
      const out = outputs[j];
      if (!out || typeof out !== 'object') continue;
      const data = (out.data && typeof out.data === 'object') ? out.data : null;
      if (!data) continue;
      for (const mime of Object.keys(data)) {
        if (!HTML_LIKE_MIMES.has(mime)) continue;
        const body = normalizeSource(data[mime]);
        if (!body || body.length === 0) continue;
        const slice = body.slice(0, IPYNB_MAX_OUTPUT_BYTES);
        hiddenFindings.push({
          element: `IPYNB cell ${i + 1} outputs[${j}] data["${escapeForDisplay(mime)}"]`,
          technique: 'ipynb-output-html-injection',
          content: escapeForDisplay(slice.slice(0, 200)),
          severity: 'danger',
          category: 'suspiciousPatterns',
          contextLocation: `IPYNB cell ${i + 1} output ${j + 1}`,
          meta: {
            cellIndex: i + 1,
            outputIndex: j + 1,
            mime: escapeForDisplay(mime),
            bodyBytes: body.length,
          },
        });
        texts.push(`[ipynb cell ${i + 1} output ${mime}]\n${slice}`);
      }
    }
  }

  return {
    text: texts.join('\n\n'),
    hiddenFindings,
    fileType: 'ipynb',
  };
}

function normalizeSource(src) {
  if (typeof src === 'string') return src;
  if (Array.isArray(src)) {
    let out = '';
    for (const part of src) {
      if (typeof part === 'string') out += part;
    }
    return out;
  }
  return '';
}

function collectHiddenSignals(meta) {
  if (!meta || typeof meta !== 'object') return [];
  const signals = [];
  if (meta.collapsed === true) signals.push('collapsed');
  if (meta.hide_input === true) signals.push('hide_input');
  if (meta.hide_output === true) signals.push('hide_output');
  if (meta.scrolled === true) signals.push('scrolled');
  const jup = meta.jupyter;
  if (jup && typeof jup === 'object') {
    if (jup.source_hidden === true) signals.push('jupyter.source_hidden');
    if (jup.outputs_hidden === true) signals.push('jupyter.outputs_hidden');
  }
  return signals;
}

export { parseIpynb };
