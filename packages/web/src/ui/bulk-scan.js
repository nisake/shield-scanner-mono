// S21 Bulk-scan UI - extracted from index.html L1140-L1148, L1191-L1573
// Web-only: R17 _bulkInProgress flag + try/finally pattern (re-entrancy guard)
import { escapeForDisplay } from '@shield-scanner/core';
import { t } from '../i18n.js';
import { _sanitizeFilenameForDisplay } from '../ui-guards/sanitize-filename.js';
import { parseDocx } from '../parsers-web/docx.js';
import { parsePdf } from '../parsers-web/pdf.js';
import { parsePptx } from '../parsers-web/pptx.js';
import { parseImage, _imgRedactDecodedFindings } from '../parsers-web/image.js';
import { analyze } from '@shield-scanner/core';

// --- S21 Bulk-scan limits (pure constants, kept top-of-file for visibility) ---
const _BULK_LIMITS = Object.freeze({
  PER_FILE_MAX_BYTES: 20 * 1024 * 1024,   // 20 MB / file
  TOTAL_MAX_BYTES: 100 * 1024 * 1024,     // 100 MB total
  MAX_FILES: 30,
  PER_FILE_TIMEOUT_MS: 30 * 1000,         // 30s per-file parser timeout
});

let _bulkInProgress = false;

// S21 verify fix: shared clear so single-file / direct-text entries
// (handleFile, scanDirectText, runScan) leave no stale bulk state behind.
function _clearBulkState() {
  _bulkResults = null;
  _bulkActiveIdx = -1;
  const tb = document.getElementById('fileTabsBar');
  if (tb) tb.remove();
}

// Wrap a Promise in a per-file timeout. The wrapped Promise resolves
// (never rejects) with the timeout sentinel object so the bulk loop's
// non-throwing contract is preserved.
function _withTimeout(promise, ms, onTimeout) {
  let timer = null;
  return new Promise((resolve) => {
    timer = setTimeout(() => resolve(onTimeout()), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      () => { clearTimeout(timer); resolve(onTimeout()); },
    );
  });
}

// Pure helper — validates a bulk selection up-front. Returns
// { ok: true } or { ok: false, code, file? } so callers can stay
// presentation-agnostic. Tested in run_web_tests.mjs (no DOM needed).
function _validateBulkSelection(files, limits) {
  const L = limits || _BULK_LIMITS;
  if (!files || files.length === 0) return { ok: false, code: 'empty' };
  if (files.length > L.MAX_FILES) return { ok: false, code: 'tooManyFiles' };
  let total = 0;
  for (const f of files) {
    const size = (f && typeof f.size === 'number') ? f.size : 0;
    if (size > L.PER_FILE_MAX_BYTES) {
      return { ok: false, code: 'perFileTooLarge', file: f };
    }
    total += size;
    if (total > L.TOTAL_MAX_BYTES) {
      return { ok: false, code: 'totalTooLarge' };
    }
  }
  return { ok: true };
}

// Pure helper — given a filename, returns the inferred {ext, kind} where
// kind ∈ 'text' | 'html' | 'markdown' | 'binary' | 'unsupported'.
// Kept structurally aligned with handleFile()'s allowedText/allowedBinary
// branches so both code paths agree on extensions.
function _classifyFilename(name) {
  const ext = String(name || '').split('.').pop().toLowerCase();
  const allowedText = ['txt','md','markdown','mdc','cursorrules','csv','json','html','htm','xml','svg'];
  const allowedBinary = ['docx','pdf','pptx','jpg','jpeg','png','webp','gif','tiff','tif'];
  if (allowedBinary.includes(ext)) return { ext, kind: 'binary' };
  if (['html','htm','xml','svg'].includes(ext)) return { ext, kind: 'html' };
  if (['md','markdown','mdc','cursorrules'].includes(ext)) return { ext, kind: 'markdown' };
  if (['txt','csv','json'].includes(ext)) return { ext, kind: 'text' };
  return { ext, kind: 'unsupported' };
}

// Bulk-scan dispatcher. Single-file selections route to the existing
// handleFile() path verbatim (zero behaviour change), multi-file selections
// go through handleMultipleFiles() which builds a per-file tab UI.
function handleFiles(fileList) {
  // S21 verify fix BULK-004: refuse new selections while a bulk run is
  // active so concurrent runs cannot interleave-corrupt _bulkResults.
  if (_bulkInProgress) {
    alert(t('bulkInProgress'));
    return;
  }
  const files = Array.from(fileList || []);
  const v = _validateBulkSelection(files, _BULK_LIMITS);
  if (!v.ok) {
    // S21 verify fix BULK-03: surface empty selection rather than silently
    // swallow it (typical: user dropped an empty folder).
    if (v.code === 'empty') {
      alert(t('bulkEmpty'));
    } else if (v.code === 'tooManyFiles') {
      alert(`${t('bulkTooManyFiles')} (max ${_BULK_LIMITS.MAX_FILES})`);
    } else if (v.code === 'perFileTooLarge') {
      // S21FIX-007: sanitize attacker-controlled filename before surfacing
      // it in an alert. _sanitizeFilenameForDisplay strips Bidi / ZW / Tag /
      // VS / control chars so a crafted name cannot visually spoof a
      // different file (e.g. evil‮fdp.docx rendering as eviltxd.pdf).
      const rawName = (v.file && v.file.name) || '(unknown)';
      const nm = _sanitizeFilenameForDisplay(rawName);
      alert(`${nm} ${t('bulkPerFileTooLarge')} (${_formatBytes(_BULK_LIMITS.PER_FILE_MAX_BYTES)})`);
    } else if (v.code === 'totalTooLarge') {
      alert(`${t('bulkTotalTooLarge')} (${_formatBytes(_BULK_LIMITS.TOTAL_MAX_BYTES)})`);
    }
    return;
  }
  if (files.length === 1) {
    // app.js exposes handleFile on globalThis so we can dispatch single-file
    // selections back into the existing single-file path without creating a
    // circular import (app.js already imports handleFiles from this module).
    if (typeof globalThis.handleFile === 'function') {
      globalThis.handleFile(files[0]);
    }
    return;
  }
  handleMultipleFiles(files);
}

function _formatBytes(n) {
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(0) + 'MB';
  if (n >= 1024) return (n / 1024).toFixed(0) + 'KB';
  return String(n) + 'B';
}

// Scans one file in isolation, returning a Promise<{ok, name, ext, kind,
// findings?, fileType?, rawText?, error?}>. The Promise never rejects —
// failures resolve with ok:false so a single broken file does not break
// the bulk run.
function _scanOneFile(file) {
  return new Promise((resolve) => {
    const c = _classifyFilename(file.name);
    if (c.kind === 'unsupported') {
      resolve({ ok: false, name: file.name, ext: c.ext, kind: c.kind, error: 'unsupported' });
      return;
    }
    const reader = new FileReader();
    reader.onerror = () => resolve({
      ok: false, name: file.name, ext: c.ext, kind: c.kind, error: 'readFailed',
    });
    if (c.kind === 'binary') {
      reader.onload = async (e) => {
        try {
          const buffer = e.target.result;
          let extracted;
          if (c.ext === 'docx') extracted = await parseDocx(buffer);
          else if (c.ext === 'pdf') extracted = await parsePdf(buffer);
          else if (c.ext === 'pptx') extracted = await parsePptx(buffer);
          else extracted = await parseImage(buffer, c.ext);
          const { findings: result, summary } = analyze(extracted.text, { fileType: 'text' });
          // Mirror app.js: hoist summary.topFindings onto the findings shape
          // so displayResults' S18 banner code keeps reading findings.topFindings.
          if (summary && Array.isArray(summary.topFindings)) {
            result.topFindings = summary.topFindings;
          }
          if (Array.isArray(extracted.decodedRanges) && extracted.decodedRanges.length > 0) {
            _imgRedactDecodedFindings(result, extracted.decodedRanges);
          }
          if (extracted.hiddenFindings && extracted.hiddenFindings.length > 0) {
            for (const f of extracted.hiddenFindings) {
              const cat = f && typeof f.category === 'string' ? f.category : null;
              if (cat && Array.isArray(result[cat])) result[cat].push(f);
              else result.hiddenHtml.push(f);
            }
          }
          resolve({
            ok: true, name: file.name, ext: c.ext, kind: c.kind,
            findings: result, fileType: 'text', rawText: extracted.text,
          });
        } catch (err) {
          resolve({
            ok: false, name: file.name, ext: c.ext, kind: c.kind,
            error: 'parseFailed', errorMessage: (err && err.message) || String(err),
          });
        }
      };
      reader.readAsArrayBuffer(file);
    } else {
      reader.onload = (e) => {
        try {
          const text = e.target.result;
          const fileType = c.kind === 'html' ? 'html' : (c.kind === 'markdown' ? 'markdown' : 'text');
          const { findings: result, summary } = analyze(text, { fileType });
          if (summary && Array.isArray(summary.topFindings)) {
            result.topFindings = summary.topFindings;
          }
          resolve({
            ok: true, name: file.name, ext: c.ext, kind: c.kind,
            findings: result, fileType, rawText: text,
          });
        } catch (err) {
          resolve({
            ok: false, name: file.name, ext: c.ext, kind: c.kind,
            error: 'parseFailed', errorMessage: (err && err.message) || String(err),
          });
        }
      };
      reader.readAsText(file, 'UTF-8');
    }
  });
}

// Computes per-file severity tag from a findings object — used to colour
// each tab. Mirrors the totalDanger/totalWarning logic in displayResults.
function _severityOfFindings(findings) {
  if (!findings) return 'error';
  const vs = findings.variationSelectors || [];
  const bidi = findings.bidiOverride || [];
  const math = findings.mathSymbolBypass || [];
  const comb = findings.combiningChars || [];
  const dangerCount =
    (findings.invisibleUnicode || []).filter(f => f.severity === 'danger').length +
    (findings.hiddenHtml || []).filter(f => f.severity === 'danger').length +
    (findings.suspiciousPatterns || []).filter(f => (f.severity || 'danger') === 'danger').length +
    vs.filter(f => f.severity === 'danger').length +
    bidi.filter(f => f.severity === 'danger').length +
    math.filter(f => f.severity === 'danger').length +
    comb.filter(f => f.severity === 'danger').length;
  if (dangerCount > 0) return 'danger';
  const warningCount =
    (findings.invisibleUnicode || []).filter(f => f.severity === 'warning').length +
    (findings.controlChars || []).length +
    (findings.hiddenHtml || []).filter(f => f.severity === 'warning').length +
    (findings.homoglyphs || []).length +
    (findings.suspiciousPatterns || []).filter(f => f.severity === 'warning').length +
    vs.filter(f => f.severity === 'warning').length +
    bidi.filter(f => f.severity === 'warning').length +
    math.filter(f => f.severity === 'warning').length +
    comb.filter(f => f.severity === 'warning').length;
  if (warningCount > 0) return 'warning';
  return 'safe';
}

let _bulkResults = null;   // Array<scan result> when in bulk mode, else null
let _bulkActiveIdx = -1;   // -1 = "All files" summary, 0..n-1 = per-file

async function handleMultipleFiles(files) {
  // S21 verify fix BULK-004: re-entrancy guard. handleFiles already checks
  // this; we set the flag here so any path that reaches handleMultipleFiles
  // directly is also covered, and so the flag is cleared even on throw.
  if (_bulkInProgress) return;
  const results = [];
  // S21FIX-002: set the flag and do DOM setup INSIDE try so any throw before
  // the loop still hits the finally that clears _bulkInProgress. Without this,
  // a missing #scanStatus / #results / #scanning element on a stale DOM
  // permanently locks the bulk path until a page reload.
  try {
    _bulkInProgress = true;
    _bulkResults = null;
    _bulkActiveIdx = -1;
    // S21 verify fix BULK-001: in case some prior render left a fileTabsBar,
    // clear it so the scanning overlay is the only visible state during scan.
    const stale = document.getElementById('fileTabsBar');
    if (stale) stale.remove();
    const resultsEl = document.getElementById('results');
    if (resultsEl) resultsEl.classList.remove('visible');
    const scanningEl = document.getElementById('scanning');
    if (scanningEl) scanningEl.classList.add('visible');
    const statusEl = document.getElementById('scanStatus');
    if (statusEl) statusEl.textContent = `${t('bulkScanning')} (0 / ${files.length})`;
    for (let i = 0; i < files.length; i++) {
      if (statusEl) statusEl.textContent = `${t('bulkScanning')} (${i + 1} / ${files.length})`;
      const f = files[i];
      // S21 verify fix BULK-005: per-file 30s timeout so one hung parser
      // does not stall the rest of the batch.
      // eslint-disable-next-line no-await-in-loop
      const r = await _withTimeout(
        _scanOneFile(f),
        _BULK_LIMITS.PER_FILE_TIMEOUT_MS,
        () => ({ ok: false, name: f.name, ext: '', kind: '', error: 'timeout' }),
      );
      results.push(r);
    }
  } finally {
    const scanningEl2 = document.getElementById('scanning');
    if (scanningEl2) scanningEl2.classList.remove('visible');
    _bulkResults = results;
    _bulkInProgress = false;
    displayMultiResults(results);
  }
}

function displayMultiResults(results) {
  // S21 verify fix S21-004: clamp _bulkActiveIdx into range so a re-render
  // against a smaller results array (e.g. after race) does not OOB.
  if (_bulkActiveIdx >= results.length) _bulkActiveIdx = -1;
  if (_bulkActiveIdx < -1) _bulkActiveIdx = -1;
  const resultsDiv = document.getElementById('results');
  document.getElementById('resultTitle').textContent = `📊 ${t('bulkSummary')}`;
  // Aggregate top-level status
  let anyDanger = false, anyWarning = false, anyError = false;
  for (const r of results) {
    if (!r.ok) { anyError = true; continue; }
    const sev = _severityOfFindings(r.findings);
    if (sev === 'danger') anyDanger = true;
    else if (sev === 'warning') anyWarning = true;
  }
  const statusEl = document.getElementById('resultStatus');
  if (anyDanger) { statusEl.textContent = t('statusDanger'); statusEl.className = 'result-status status-danger'; }
  else if (anyWarning || anyError) { statusEl.textContent = t('statusWarning'); statusEl.className = 'result-status status-warning'; }
  else { statusEl.textContent = t('statusSafe'); statusEl.className = 'result-status status-safe'; }

  // Tabs bar
  let tabsBar = document.getElementById('fileTabsBar');
  if (!tabsBar) {
    tabsBar = document.createElement('div');
    tabsBar.id = 'fileTabsBar';
    tabsBar.className = 'file-tabs-bar';
    const grid = document.getElementById('summaryGrid');
    grid.parentNode.insertBefore(tabsBar, grid);
  }
  const allTab = `<button class="file-tab ${_bulkActiveIdx === -1 ? 'active' : ''}" data-idx="-1">📚 ${escapeForDisplay(t('fileTabAll'))} <span class="file-tab-badge">${results.length}</span></button>`;
  const fileTabs = results.map((r, i) => {
    let sevClass = 'tab-safe', icon = '✅';
    if (!r.ok) { sevClass = 'tab-error'; icon = '⚠️'; }
    else {
      const sev = _severityOfFindings(r.findings);
      if (sev === 'danger') { sevClass = 'tab-danger'; icon = '🚨'; }
      else if (sev === 'warning') { sevClass = 'tab-warning'; icon = '⚠️'; }
    }
    // S21 verify fix BULK-002: strip Bidi / ZW / Tag / VS / control chars
    // from filenames before HTML escape so attacker-crafted filenames
    // cannot visually spoof which file a tab represents.
    const safeName = escapeForDisplay(_sanitizeFilenameForDisplay(r.name));
    return `<button class="file-tab ${sevClass} ${_bulkActiveIdx === i ? 'active' : ''}" data-idx="${i}" title="${safeName}">${icon} ${safeName}</button>`;
  }).join('');
  tabsBar.innerHTML = allTab + fileTabs;
  tabsBar.querySelectorAll('.file-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.getAttribute('data-idx'), 10);
      _bulkActiveIdx = isNaN(idx) ? -1 : idx;
      displayMultiResults(_bulkResults);
    });
  });

  // Hide the top-priority banner in bulk-summary view; show it for per-file view
  const banner = document.getElementById('topPriorityBanner');
  const grid = document.getElementById('summaryGrid');
  const detailsDiv = document.getElementById('detailSections');
  const actionsDiv = document.getElementById('actions');

  if (_bulkActiveIdx === -1) {
    // Summary view
    if (banner) { banner.classList.add('empty'); banner.innerHTML = ''; }
    grid.innerHTML = '';
    actionsDiv.innerHTML = `<button class="action-btn btn-reset" onclick="resetAll()">${t('reset')}</button>`;
    const rows = results.map((r, i) => {
      const safeName = escapeForDisplay(_sanitizeFilenameForDisplay(r.name));
      let badge, badgeClass, detail;
      if (!r.ok) {
        badge = t('bulkError'); badgeClass = 'bulk-row-error';
        if (r.error === 'unsupported') detail = `<code>.${escapeForDisplay(r.ext)}</code> ${t('bulkUnsupported')}`;
        else if (r.error === 'readFailed') detail = t('bulkParseFailed');
        else if (r.error === 'timeout') detail = t('bulkTimeout');
        else if (r.error === 'parseFailed') detail = `${t('bulkParseFailed')}: ${escapeForDisplay(r.errorMessage || '')}`;
        else detail = escapeForDisplay(r.error || '');
      } else {
        const sev = _severityOfFindings(r.findings);
        if (sev === 'danger') { badge = t('bulkDanger'); badgeClass = 'bulk-row-danger'; }
        else if (sev === 'warning') { badge = t('bulkWarn'); badgeClass = 'bulk-row-warning'; }
        else { badge = t('bulkOk'); badgeClass = 'bulk-row-safe'; }
        const tot = _severityOfFindings(r.findings) === 'safe' ? 0 :
          ['invisibleUnicode','controlChars','hiddenHtml','suspiciousPatterns','homoglyphs','variationSelectors','bidiOverride','mathSymbolBypass','combiningChars']
            .reduce((s, k) => s + ((r.findings[k] || []).length), 0);
        detail = `${tot} ${t('found')}`;
      }
      return `<div class="bulk-row" data-idx="${i}">
        <span class="bulk-row-badge ${badgeClass}">${badge}</span>
        <span class="bulk-row-name">${safeName}</span>
        <span class="bulk-row-detail">${detail}</span>
      </div>`;
    }).join('');
    detailsDiv.innerHTML = `<div class="detail-section open" style="padding:1rem;">
      <div class="bulk-summary-hint">${t('bulkLimitHint')}</div>
      <div class="bulk-rows">${rows}</div>
    </div>`;
    detailsDiv.querySelectorAll('.bulk-row').forEach(row => {
      row.addEventListener('click', () => {
        const idx = parseInt(row.getAttribute('data-idx'), 10);
        if (!isNaN(idx)) { _bulkActiveIdx = idx; displayMultiResults(_bulkResults); }
      });
    });
  } else {
    // Per-file detail view
    const r = results[_bulkActiveIdx];
    if (r && r.ok) {
      // app.js owns these state vars; bulk-scan writes to the global mirror
      // (which app.js reads via let-bindings refreshed inside displayResults).
      globalThis.lastScanResult = r.findings;
      globalThis.lastRawContent = r.rawText || '';
      globalThis.lastFileName = r.name;
      // S21 verify fix BULK-01: for binary files (docx/pdf/pptx/images),
      // downloadSanitized inspects lastFileType against ['docx','pdf','pptx']
      // to rewrite the extension to .txt. _scanOneFile returns
      // fileType='text' for analyze() purposes, so we restore the original
      // ext here so the sanitize download doesn't corrupt binary files.
      globalThis.lastFileType = r.kind === 'binary' ? r.ext : r.fileType;
      globalThis.displayResults(r.findings);
      document.getElementById('resultTitle').textContent =
        `📊 ${escapeForDisplay(_sanitizeFilenameForDisplay(r.name))}`;
    } else {
      if (banner) { banner.classList.add('empty'); banner.innerHTML = ''; }
      grid.innerHTML = '';
      const safeName = escapeForDisplay(_sanitizeFilenameForDisplay(r ? r.name : '(unknown)'));
      const detail = (r && r.error === 'unsupported')
        ? `<code>.${escapeForDisplay(r.ext)}</code> ${t('bulkUnsupported')}`
        : (r && r.error === 'timeout')
          ? t('bulkTimeout')
        : (r && r.error === 'parseFailed')
          ? `${t('bulkParseFailed')}: ${escapeForDisplay(r.errorMessage || '')}`
          : t('bulkParseFailed');
      detailsDiv.innerHTML = `<div class="detail-section open" style="padding:1.5rem;text-align:center;color:var(--danger);">
        <span style="font-size:2rem;">⚠️</span><br><br><strong>${safeName}</strong><br><br>${detail}</div>`;
      actionsDiv.innerHTML = `<button class="action-btn btn-reset" onclick="resetAll()">${t('reset')}</button>`;
    }
  }
  resultsDiv.classList.add('visible');
  resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Module-private state setters/getters so app.js can read/write _bulkInProgress
function _isBulkInProgress() { return _bulkInProgress; }
export {
  _BULK_LIMITS, _isBulkInProgress,
  _clearBulkState, _withTimeout, _validateBulkSelection, _classifyFilename,
  handleFiles, _formatBytes, _scanOneFile, _severityOfFindings,
  handleMultipleFiles, displayMultiResults,
};
