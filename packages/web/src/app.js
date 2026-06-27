// =============================================================
//  Shield Scanner — Web entry (Step 6 monorepo split)
// =============================================================
// This file owns:
//   - env-injection wiring (core/env/web before any detector import)
//   - DOM listeners (drop-zone, file-input)
//   - single-file orchestration: handleFile / scanDirectText / runScan
//   - displayResults + buildDetailSection + downloadSanitized
//   - exportReport + toggleReveal + resetAll
//   - globalThis bindings for inline onclick handlers
//
// Detection / sanitization / priority all come from @shield-scanner/core.
// Web-specific guards (R14 mirror, R16, R17) live in their own modules.
// =============================================================

// --- Step 1: wire env BEFORE importing any detector module ---
import { setEnv } from "@shield-scanner/core/env";
import { createWebEnv } from "@shield-scanner/core/env/web";
setEnv(createWebEnv());

// --- core API (post env-wiring) ---
import {
  analyze,
  sanitize as sanitizeContent,
  escapeForDisplay,
  attachPriorities,
  buildTopFindings,
} from "@shield-scanner/core";

// --- Web modules ---
import { i18n, currentLang, setLang, t, t_technique, applyLang } from "./i18n.js";
import {
  _renderRevealMarkers,
  _renderValueCell,
  _setRevealMode,
  _getRevealMode,
  _setDiffViewVisible,
  _getDiffViewVisible,
} from "./ui/reveal-mode.js";
import { toggleDiffView } from "./ui/diff-view.js";
import { _sanitizeFilenameForDisplay } from "./ui-guards/sanitize-filename.js";
import {
  handleFiles,
  _clearBulkState,
  _isBulkInProgress,
  displayMultiResults,
  _severityOfFindings,
} from "./ui/bulk-scan.js";
import { parseDocx } from "./parsers-web/docx.js";
import { parsePdf } from "./parsers-web/pdf.js";
import { parsePptx } from "./parsers-web/pptx.js";
import { parseImage, _imgRedactDecodedFindings } from "./parsers-web/image.js";
import { parseXlsx } from "./parsers-web/xlsx.js";
import { parseCsv } from "./parsers-web/csv.js";
import { parseArchiveBuffer } from "./parsers-web/archive.js";
// v1.19.0 B2: RTF parser. Mirrors MCP packages/mcp/server/parsers/rtf.js with
// byte-identical kebab ids / severities / meta keys for parity.
import { parseRtf } from "./parsers-web/rtf.js";
// v1.19.0 B3: Jupyter notebook parser. Mirrors MCP packages/mcp/server/parsers
// /ipynb.js with byte-identical kebab ids / severities / meta keys for parity.
import { parseIpynb } from "./parsers-web/ipynb.js";
// v1.20.0 T3-ODP: OpenDocument Presentation parser. Mirrors MCP
// packages/mcp/server/parsers/odp.js with byte-identical kebab ids /
// severities / meta keys for parity. Imported last so concurrent T1 / T2
// ODF parser additions land on independent lines.
import { parseOdp } from "./parsers-web/odp.js";

// Format a finding's technique label, substituting meta fields into the i18n
// placeholder if present. Detectors emit kebab-case technique ids + a numeric
// `meta` object (e.g. { height: 0.5 }), and the i18n dict carries the user-
// facing string with `{key}` placeholders. Keeps the detector pure (R12: no
// raw user text in the technique id) while letting the UI control formatting
// (e.g. height.toFixed(2)).
function formatTechniqueWithMeta(f) {
  let label = t_technique(f.technique);
  if (f && f.meta && typeof label === "string") {
    label = label.replace(/\{(\w+)\}/g, (m, k) => {
      const v = f.meta[k];
      if (typeof v === "number") return v.toFixed(2);
      if (v === undefined || v === null) return m;
      return String(v);
    });
  }
  return label;
}

// --- Web-side state ---
let lastScanResult = null;
let lastRawContent = "";
let lastFileName = "";
let lastFileType = "";

// --- Drop Zone listeners ---
const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");

dropZone.addEventListener("click", () => fileInput.click());
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
});
fileInput.addEventListener("change", (e) => {
  if (e.target.files.length) handleFiles(e.target.files);
  e.target.value = "";
});

// --- Text-mode toggle ---
function toggleTextMode() {
  const area = document.getElementById("textInputArea");
  area.classList.toggle("visible");
}

// --- Single-file handler (extracted L1580-L1677) ---
function handleFile(file) {
  if (_isBulkInProgress()) {
    alert(t("bulkInProgress"));
    return;
  }
  _clearBulkState();
  // S16-005: reset reveal-mode on every new scan so the previous file's
  // toggle state does not bleed into the next file's render. resetAll()
  // already does this on the explicit "Reset" path, but a plain re-drop
  // would otherwise inherit the stale toggle.
  _setRevealMode(false);
  const ext = file.name.split(".").pop().toLowerCase();
  // S10: 'csv' MUST live on the binary path so its hiddenFindings (encoding
  // warnings, defensive-cap warnings) flow through the {text, hiddenFindings}
  // merge below. The text-mode path (readAsText) bypasses that merge and
  // would drop them. 'xlsx' is binary by nature (zip container).
  const allowedText = ["txt","md","markdown","mdc","cursorrules","json","html","htm","xml","svg"];
  const allowedBinary = ["docx","pdf","pptx","xlsx","csv","zip","rtf","ipynb","jpg","jpeg","png","webp","gif","tiff","tif","odp","odt","ods"];
  if (!allowedText.includes(ext) && !allowedBinary.includes(ext)) {
    alert(currentLang === "ja" ? "このファイル形式には対応していません" : "Unsupported file format");
    return;
  }
  lastFileName = file.name;

  if (allowedBinary.includes(ext)) {
    lastFileType = ext;
    document.getElementById("results").classList.remove("visible");
    document.getElementById("scanning").classList.add("visible");
    document.getElementById("scanStatus").textContent = t("scanning");

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const buffer = e.target.result;
        let extracted;
        if (ext === "docx") extracted = await parseDocx(buffer);
        else if (ext === "pdf") extracted = await parsePdf(buffer);
        else if (ext === "pptx") extracted = await parsePptx(buffer);
        else if (ext === "xlsx") extracted = await parseXlsx(buffer);
        else if (ext === "csv") extracted = await parseCsv(buffer);
        else if (ext === "zip") extracted = await parseArchiveBuffer(buffer, { depth: 0 });
        else if (ext === "rtf") extracted = await parseRtf(buffer);
        else if (ext === "ipynb") extracted = await parseIpynb(buffer);
        // v1.20.0 T3-ODP — appended last so concurrent T1 / T2 ODF dispatch
        // branches stay merge-clean.
        else if (ext === "odp") extracted = await parseOdp(buffer);
        // v1.20.0 T1-ODT — appended after odp so the ODF cluster (odt/ods/odp)
        // sits together at the tail of the ext switch and the dispatch order
        // is deterministic across parallel agent merges.
        else if (ext === "odt") extracted = await _parseOdtForHandleFile(buffer);
        // v1.20.0 T2-ODS — appended after odt so the ODF cluster
        // (odp/odt/ods) sits together at the tail of the ext switch.
        else if (ext === "ods") extracted = await _parseOdsForHandleFile(buffer);
        else if (["jpg","jpeg","png","webp","gif","tiff","tif"].includes(ext))
          extracted = await parseImage(buffer, ext);

        lastRawContent = extracted.text;
        // S10: pass fileType through to analyze() so the CSV/XLSX
        // formula-injection fold engages. The parser carries this on the
        // extracted shape; default to "text" for everyone else.
        const analyzeFileType =
          extracted && typeof extracted.fileType === "string"
            ? extracted.fileType
            : "text";
        const { findings: result, summary } = analyze(extracted.text, { fileType: analyzeFileType });
        // Surface summary.topFindings onto the findings object so downstream
        // displayResults (which reads `findings.topFindings` for the S18
        // top-priority banner) keeps working after the {findings, summary}
        // split.
        if (summary && Array.isArray(summary.topFindings)) {
          result.topFindings = summary.topFindings;
        }

        // R12 decoded-range redaction (Web-only mirror).
        if (Array.isArray(extracted.decodedRanges) && extracted.decodedRanges.length > 0) {
          _imgRedactDecodedFindings(result, extracted.decodedRanges);
        }

        if (extracted.hiddenFindings && extracted.hiddenFindings.length > 0) {
          for (const f of extracted.hiddenFindings) {
            const cat = f && typeof f.category === "string" ? f.category : null;
            if (cat && Array.isArray(result[cat])) result[cat].push(f);
            else result.hiddenHtml.push(f);
          }
        }

        lastScanResult = result;
        // Refresh global mirrors so bulk-scan / diff-view can read.
        globalThis.lastScanResult = result;
        globalThis.lastRawContent = lastRawContent;
        globalThis.lastFileName = lastFileName;
        globalThis.lastFileType = lastFileType;

        document.getElementById("scanning").classList.remove("visible");
        displayResults(result);
      } catch (err) {
        console.error("Parse error:", err);
        document.getElementById("scanning").classList.remove("visible");
        alert(currentLang === "ja"
          ? `ファイルの解析に失敗しました: ${err.message}`
          : `Failed to parse file: ${err.message}`);
      }
    };
    reader.readAsArrayBuffer(file);
  } else {
    if (["html","htm","xml","svg"].includes(ext)) lastFileType = "html";
    else if (["md","markdown","mdc","cursorrules"].includes(ext)) lastFileType = "markdown";
    else lastFileType = "text";
    const reader = new FileReader();
    reader.onload = (e) => {
      lastRawContent = e.target.result;
      runScan(lastRawContent, lastFileType);
    };
    reader.readAsText(file, "UTF-8");
  }
}

function scanDirectText() {
  if (_isBulkInProgress()) {
    alert(t("bulkInProgress"));
    return;
  }
  const text = document.getElementById("directText").value;
  if (!text.trim()) return;
  _clearBulkState();
  // S16-005: same reveal-mode reset contract as handleFile() — a new direct
  // text scan must start with the toggle in its default OFF state.
  _setRevealMode(false);
  lastRawContent = text;
  lastFileName = "direct-input.txt";
  if (/<[a-z][\s\S]*>/i.test(text)) lastFileType = "html";
  else if (/<!--[\s\S]*?-->/.test(text)) lastFileType = "markdown";
  else lastFileType = "text";
  runScan(text, lastFileType);
}

function runScan(content, fileType) {
  document.getElementById("results").classList.remove("visible");
  document.getElementById("scanning").classList.add("visible");
  document.getElementById("scanStatus").textContent = t("scanning");

  setTimeout(() => {
    const { findings: result, summary } = analyze(content, { fileType });
    // Surface summary.topFindings onto the findings object — same pattern as
    // handleFile() above so displayResults() can keep reading the S18 banner
    // entries off the findings shape it has always used.
    if (summary && Array.isArray(summary.topFindings)) {
      result.topFindings = summary.topFindings;
    }
    lastScanResult = result;
    globalThis.lastScanResult = result;
    globalThis.lastRawContent = lastRawContent;
    globalThis.lastFileName = lastFileName;
    globalThis.lastFileType = lastFileType;
    document.getElementById("scanning").classList.remove("visible");
    displayResults(result);
  }, 600);
}

// --- displayResults (L5149-L5478) ---
function displayResults(findings) {
  // Sync local state from the global mirror so a bulk-scan tab click
  // (which writes globalThis.lastRawContent / lastFileName / lastFileType
  // before calling displayResults) hands the right file context to the
  // diff panel and downloadSanitized / exportReport.
  if (globalThis.lastRawContent !== undefined) lastRawContent = globalThis.lastRawContent;
  if (globalThis.lastFileName !== undefined) lastFileName = globalThis.lastFileName;
  if (globalThis.lastFileType !== undefined) lastFileType = globalThis.lastFileType;
  if (globalThis.lastScanResult !== undefined) lastScanResult = globalThis.lastScanResult || findings;
  const resultsDiv = document.getElementById("results");
  const vs = findings.variationSelectors || [];
  const bidi = findings.bidiOverride || [];
  const math = findings.mathSymbolBypass || [];
  const comb = findings.combiningChars || [];
  const totalDanger =
    findings.invisibleUnicode.filter((f) => f.severity === "danger").length +
    findings.hiddenHtml.filter((f) => f.severity === "danger").length +
    findings.suspiciousPatterns.filter((f) => (f.severity || "danger") === "danger").length +
    vs.filter((f) => f.severity === "danger").length +
    bidi.filter((f) => f.severity === "danger").length +
    math.filter((f) => f.severity === "danger").length +
    comb.filter((f) => f.severity === "danger").length;
  const totalWarning =
    findings.invisibleUnicode.filter((f) => f.severity === "warning").length +
    findings.controlChars.length +
    findings.hiddenHtml.filter((f) => f.severity === "warning").length +
    findings.homoglyphs.length +
    findings.suspiciousPatterns.filter((f) => f.severity === "warning").length +
    vs.filter((f) => f.severity === "warning").length +
    bidi.filter((f) => f.severity === "warning").length +
    math.filter((f) => f.severity === "warning").length +
    comb.filter((f) => f.severity === "warning").length;
  const totalFindings = totalDanger + totalWarning;

  const statusEl = document.getElementById("resultStatus");
  document.getElementById("resultTitle").textContent = t("resultTitle");
  if (totalDanger > 0) {
    statusEl.textContent = t("statusDanger");
    statusEl.className = "result-status status-danger";
  } else if (totalWarning > 0) {
    statusEl.textContent = t("statusWarning");
    statusEl.className = "result-status status-warning";
  } else {
    statusEl.textContent = t("statusSafe");
    statusEl.className = "result-status status-safe";
  }

  // S18: Top-Priority banner. core's analyze already attaches `topFindings`.
  const bannerEl = document.getElementById("topPriorityBanner");
  if (bannerEl) {
    const top = Array.isArray(findings.topFindings) ? findings.topFindings : [];
    if (top.length === 0) {
      bannerEl.classList.add("empty");
      bannerEl.innerHTML = "";
    } else {
      bannerEl.classList.remove("empty");
      const chips = top.map((entry) => {
        const cls = entry.severity === "danger" ? "chip-danger" : "chip-warning";
        const labelStr = String(entry.label || entry.category || "")
          .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
        return `<span class="priority-chip ${cls}"><span class="chip-score">${entry.priority}</span>${labelStr}</span>`;
      }).join("");
      bannerEl.innerHTML = `<span class="top-priority-label">${t("topPriority")}</span>${chips}`;
    }
  }

  const grid = document.getElementById("summaryGrid");
  const categories = [
    { key: "invisibleUnicode", label: t("invisibleUnicode"), count: findings.invisibleUnicode.length },
    { key: "controlChars", label: t("controlChars"), count: findings.controlChars.length },
    { key: "hiddenHtml", label: t("hiddenHtml"), count: findings.hiddenHtml.length },
    { key: "suspiciousPatterns", label: t("suspiciousPatterns"), count: findings.suspiciousPatterns.length },
    { key: "homoglyphs", label: t("homoglyphs"), count: findings.homoglyphs.length },
    { key: "variationSelectors", label: t("variationSelectors"), count: vs.length },
    { key: "bidiOverride", label: t("bidiOverride"), count: bidi.length },
    { key: "mathSymbolBypass", label: t("mathSymbolBypass"), count: math.length },
    { key: "combiningChars", label: t("combiningChars"), count: comb.length },
  ];
  grid.innerHTML = categories.map((cat) => {
    const arr = findings[cat.key] || [];
    let colorClass;
    if (cat.count === 0) colorClass = "count-safe";
    else if (arr.some((f) => f.severity === "danger")) colorClass = "count-danger";
    else if (arr.some((f) => f.severity === "warning")) colorClass = "count-warning";
    else colorClass = "count-safe";
    return `
      <div class="summary-card">
        <div class="summary-count ${colorClass}">${cat.count}</div>
        <div class="summary-label">${cat.label}</div>
      </div>`;
  }).join("");

  const detailsDiv = document.getElementById("detailSections");
  let detailsHtml = "";

  if (findings.invisibleUnicode.length > 0) {
    detailsHtml += buildDetailSection(
      "👻", t("invisibleUnicode"), findings.invisibleUnicode.length,
      findings.invisibleUnicode.some((f) => f.severity === "danger"),
      findings.invisibleUnicode.map((f) => `
        <div class="finding-item">
          <div class="finding-label">${t("charName")}: ${f.name} (${f.char})</div>
          <div class="finding-label">${t("position")}: ${f.position}</div>
          <div class="finding-value ${f.severity === "danger" ? "" : "warn-value"}">${_renderValueCell(f.context)}</div>
        </div>
      `).join("")
    );
  }

  if (findings.controlChars.length > 0) {
    detailsHtml += buildDetailSection(
      "⚙️", t("controlChars"), findings.controlChars.length, false,
      findings.controlChars.map((f) => `
        <div class="finding-item">
          <div class="finding-label">${t("charName")}: ${f.name} (${f.char}) — ${t("position")}: ${f.position}</div>
        </div>
      `).join("")
    );
  }

  if (findings.hiddenHtml.length > 0) {
    detailsHtml += buildDetailSection(
      "🕵️", t("hiddenHtml"), findings.hiddenHtml.length,
      findings.hiddenHtml.some((f) => f.severity === "danger"),
      findings.hiddenHtml.map((f) => `
        <div class="finding-item">
          <div class="finding-label">${t("element")}: &lt;${f.element}&gt; — ${t("technique")}: ${formatTechniqueWithMeta(f)}</div>
          <div class="finding-value ${f.severity === "danger" ? "" : "warn-value"}">${_renderValueCell(f.content)}</div>
        </div>
      `).join("")
    );
  }

  if (findings.suspiciousPatterns.length > 0) {
    const hasDanger = findings.suspiciousPatterns.some((f) => (f.severity || "danger") === "danger");
    detailsHtml += buildDetailSection(
      "🚨", t("suspiciousPatterns"), findings.suspiciousPatterns.length, hasDanger,
      findings.suspiciousPatterns.map((f) => {
        let shadowBadge = "";
        if (f.type && f.type.startsWith("shadow:")) {
          const src = Array.isArray(f.shadowSource)
            ? f.shadowSource.join("+") : (f.shadowSource || f.type.slice(7));
          shadowBadge = ` <span style="color:var(--accent);font-size:0.7rem;">[${t("shadowDetection")}: ${src}]</span>`;
        }
        const sevTag = f.severity === "warning" ? " [warning]" : "";
        const valueCls = f.severity === "warning" ? "warn-value" : "";
        return `
        <div class="finding-item">
          <div class="finding-label">${t("pattern")}: ${f.pattern}${sevTag}${shadowBadge}</div>
          <div class="finding-value ${valueCls}">${_renderValueCell(f.matched)}</div>
          <div class="finding-context">${t("context")}: ${_renderValueCell(f.context)}</div>
        </div>`;
      }).join("")
    );
  }

  if (findings.homoglyphs.length > 0) {
    detailsHtml += buildDetailSection(
      "🔤", t("homoglyphs"), findings.homoglyphs.length, false,
      findings.homoglyphs.map((f) => `
        <div class="finding-item">
          <div class="finding-label">${t("original")}: ${f.original} → ${t("replacement")}: ${f.replacement}</div>
          <div class="finding-value warn-value">${t("position")}: ${f.position} — ${_renderValueCell(f.context)}</div>
        </div>
      `).join("")
    );
  }

  if (vs.length > 0) {
    detailsHtml += buildDetailSection(
      "🧬", t("variationSelectors"), vs.length,
      vs.some((f) => f.severity === "danger"),
      vs.map((f) => {
        const valueCls = f.severity === "danger" ? "" : "warn-value";
        const runInfo = f.runLength && f.runLength > 1 ? ` — ${t("runLength")}: ${f.runLength}` : "";
        return `
        <div class="finding-item">
          <div class="finding-label">${t("charName")}: ${f.name} (${f.char})${runInfo}</div>
          <div class="finding-label">${t("position")}: ${f.position} — [${f.severity}]</div>
          <div class="finding-value ${valueCls}">${escapeForDisplay(f.message || "")}</div>
          <div class="finding-context">${t("context")}: ${_renderValueCell(f.context)}</div>
        </div>`;
      }).join("")
    );
  }

  if (bidi.length > 0) {
    detailsHtml += buildDetailSection(
      "↔️", t("bidiOverride"), bidi.length,
      bidi.some((f) => f.severity === "danger"),
      bidi.map((f) => {
        const valueCls = f.severity === "danger" ? "" : "warn-value";
        return `
        <div class="finding-item">
          <div class="finding-label">${t("charName")}: ${f.name} (${f.char}) — [${f.kind || ""} / ${f.severity}]</div>
          <div class="finding-label">${t("position")}: ${f.position}</div>
          <div class="finding-value ${valueCls}">${_renderValueCell(f.context)}</div>
        </div>`;
      }).join("")
    );
  }

  if (math.length > 0) {
    detailsHtml += buildDetailSection(
      "𝕏", t("mathSymbolBypass"), math.length,
      math.some((f) => f.severity === "danger"),
      math.map((f) => {
        const valueCls = f.severity === "danger" ? "" : "warn-value";
        return `
        <div class="finding-item">
          <div class="finding-label">${t("charName")}: ${f.name} (${f.char}) — [${f.severity}]</div>
          <div class="finding-label">${t("intentLooks")}: <code>${escapeForDisplay(f.normalized || "")}</code></div>
          <div class="finding-label">${t("position")}: ${f.position}</div>
          <div class="finding-value ${valueCls}">${_renderValueCell(f.context)}</div>
        </div>`;
      }).join("")
    );
  }

  if (comb.length > 0) {
    detailsHtml += buildDetailSection(
      "🌀", t("combiningChars"), comb.length,
      comb.some((f) => f.severity === "danger"),
      comb.map((f) => {
        const valueCls = f.severity === "danger" ? "" : "warn-value";
        const baseLabel = f.baseCodePoint === null
          ? "(none)"
          : "U+" + f.baseCodePoint.toString(16).toUpperCase().padStart(f.baseCodePoint > 0xFFFF ? 5 : 4, "0");
        return `
        <div class="finding-item">
          <div class="finding-label">${t("charName")}: combiningStack on ${baseLabel} — depth ${f.stackDepth} [${f.severity}]</div>
          <div class="finding-label">${t("position")}: ${f.position}</div>
          <div class="finding-value ${valueCls}">${escapeForDisplay(f.message || "")}</div>
          <div class="finding-context">${t("context")}: ${_renderValueCell(f.context)}</div>
        </div>`;
      }).join("")
    );
  }

  if (totalFindings === 0) {
    detailsHtml = `<div class="detail-section" style="padding:1.5rem;text-align:center;color:var(--safe);">
      <span style="font-size:2rem;">✅</span><br><br>${t("noThreats")}</div>`;
  }

  detailsDiv.innerHTML = detailsHtml;

  // S17 diff panel
  if (_getDiffViewVisible() && totalFindings > 0 && lastRawContent) {
    const before = String(lastRawContent || "");
    let after = "";
    try {
      // core sanitize now takes an options object and returns
      // {cleaned, removedCounts}. fileType must be "html" for the
      // hiddenHtml stripping branch to trigger — map markdown to html
      // (markdown can embed HTML) and binary placeholders to "text".
      // S10: csv / xlsx must be passed through so sanitize() runs the
      // stripFormulaPrefix branch BEFORE stripSuspiciousPatterns (round-trip
      // contract — see core sanitizer.js for the ordering rule).
      const sanFileType =
        lastFileType === "html" || lastFileType === "markdown"
          ? "html"
          : lastFileType === "csv" || lastFileType === "xlsx"
            ? lastFileType
            : "text";
      const { cleaned } = sanitizeContent(before, { fileType: sanFileType });
      after = cleaned;
    } catch (e) { after = ""; }
    const maxLen = 8000;
    const truncBefore = before.length > maxLen ? (before.slice(0, maxLen) + "\n…") : before;
    const truncAfter = after.length > maxLen ? (after.slice(0, maxLen) + "\n…") : after;
    const reveal = _getRevealMode();
    const beforeHtml = reveal ? _renderRevealMarkers(escapeForDisplay(truncBefore)) : escapeForDisplay(truncBefore);
    const afterHtml = reveal ? _renderRevealMarkers(escapeForDisplay(truncAfter)) : escapeForDisplay(truncAfter);
    const truncNote = before.length > maxLen
      ? ` <span class="diff-trunc">(${currentLang === "ja" ? "先頭8000文字のみ表示" : "first 8000 chars only"})</span>`
      : "";
    detailsDiv.innerHTML += `
      <div class="detail-section open diff-section">
        <div class="detail-header">
          <span class="detail-icon">📐</span>
          <span class="detail-title">${t("diffTitle")}${truncNote}</span>
          <span class="detail-count">Δ ${Math.max(0, before.length - after.length)}</span>
        </div>
        <div class="detail-body diff-body">
          <div class="diff-pane diff-before">
            <div class="diff-pane-label">${t("diffBefore")}</div>
            <pre class="diff-pre">${beforeHtml}</pre>
          </div>
          <div class="diff-pane diff-after">
            <div class="diff-pane-label">${t("diffAfter")} <span class="diff-warn">${t("diffCopyWarning")}</span></div>
            <pre class="diff-pre">${afterHtml}</pre>
          </div>
        </div>
      </div>`;
  }

  const actionsDiv = document.getElementById("actions");
  let actionsHtml = "";
  if (totalFindings > 0) {
    actionsHtml += `<button class="action-btn btn-sanitize" onclick="downloadSanitized()">${t("sanitize")}</button>`;
    actionsHtml += `<button class="action-btn btn-reveal ${_getRevealMode() ? "active" : ""}" onclick="toggleReveal()">${_getRevealMode() ? t("revealOff") : t("revealOn")}</button>`;
    if (lastRawContent) {
      actionsHtml += `<button class="action-btn btn-diff ${_getDiffViewVisible() ? "active" : ""}" onclick="toggleDiffView()">${_getDiffViewVisible() ? t("diffHide") : t("diffShow")}</button>`;
    }
  }
  actionsHtml += `<button class="action-btn btn-export" onclick="exportReport()">${t("exportReport")}</button>`;
  actionsHtml += `<button class="action-btn btn-reset" onclick="resetAll()">${t("reset")}</button>`;
  actionsDiv.innerHTML = actionsHtml;

  resultsDiv.classList.add("visible");
  resultsDiv.scrollIntoView({ behavior: "smooth", block: "start" });
}

function toggleReveal() {
  _setRevealMode(!_getRevealMode());
  if (lastScanResult) displayResults(lastScanResult);
}

function buildDetailSection(icon, title, count, isDanger, bodyHtml) {
  const countClass = isDanger ? "" : "warn-count";
  return `
    <div class="detail-section" onclick="this.classList.toggle('open')">
      <div class="detail-header">
        <span class="detail-icon">${icon}</span>
        <span class="detail-title">${title}</span>
        <span class="detail-count ${countClass}">${count} ${t("found")}</span>
        <span class="detail-chevron">▶</span>
      </div>
      <div class="detail-body">${bodyHtml}</div>
    </div>`;
}

function downloadSanitized() {
  // core sanitize now takes an options object and returns
  // {cleaned, removedCounts}. The previous call passed the scan-result
  // findings as the second arg, which the new signature ignored entirely
  // and which made the resulting Blob stringify to "[object Object]".
  // S10: xlsx/csv route through sanitize with their own fileType so the
  // formula-prefix sanitizer engages BEFORE the suspicious-pattern strip.
  const sanFileType =
    lastFileType === "html" || lastFileType === "markdown"
      ? "html"
      : lastFileType === "csv" || lastFileType === "xlsx"
        ? lastFileType
        : "text";
  const { cleaned } = sanitizeContent(lastRawContent, { fileType: sanFileType });
  const blob = new Blob([cleaned], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const baseName = lastFileName.replace(/\.[^.]+$/, "");
  // S10: xlsx is binary (zip container) — sanitized output is text, so it
  // gets the .txt extension. csv stays plaintext, so it keeps .csv.
  const binaryFormats = ["docx","pdf","pptx","xlsx","jpg","jpeg","png","webp","gif","tiff","tif"];
  const ext = binaryFormats.includes(lastFileType) ? "txt" : lastFileName.split(".").pop();
  a.href = url;
  a.download = `${baseName}_sanitized.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportReport() {
  if (!lastScanResult) return;
  const lines = ["=== Shield Scanner Report ===", `File: ${lastFileName}`, `Date: ${new Date().toISOString()}`, ""];
  const cats = [
    ["Invisible Unicode", lastScanResult.invisibleUnicode],
    ["Control Characters", lastScanResult.controlChars],
    ["Hidden HTML", lastScanResult.hiddenHtml],
    ["Suspicious Patterns", lastScanResult.suspiciousPatterns],
    ["Homoglyphs", lastScanResult.homoglyphs],
    ["Variation Selectors", lastScanResult.variationSelectors || []],
    ["Bidi Override", lastScanResult.bidiOverride || []],
    ["Math Symbol Bypass", lastScanResult.mathSymbolBypass || []],
    ["Combining Chars", lastScanResult.combiningChars || []],
  ];
  cats.forEach(([name, items]) => {
    lines.push(`[${name}] ${items.length} found`);
    items.forEach((item) => {
      if (item.type === "combiningStack") {
        const baseLabel = item.baseCodePoint === null
          ? "(none)"
          : "U+" + item.baseCodePoint.toString(16).toUpperCase().padStart(item.baseCodePoint > 0xFFFF ? 5 : 4, "0");
        lines.push(`  - combiningStack depth=${item.stackDepth} on ${baseLabel} at pos ${item.position} [${item.severity}]`);
      } else if (item.normalized) {
        lines.push(`  - ${item.name || ""} ${item.char} ~ "${item.normalized}" at pos ${item.position} [${item.severity}]`);
      } else if (item.char) {
        const sev = item.severity ? ` [${item.severity}]` : "";
        lines.push(`  - ${item.name || ""} ${item.char} at pos ${item.position}${sev}`);
      } else if (item.pattern) {
        const shadowTag = item.type && item.type.startsWith("shadow:") ? ` (${item.type})` : "";
        const sev = item.severity ? ` [${item.severity}]` : "";
        lines.push(`  - ${item.pattern}${shadowTag}${sev}: ${item.matched}`);
      } else if (item.technique) lines.push(`  - ${formatTechniqueWithMeta(item)} in <${item.element}>`);
      else if (item.original) lines.push(`  - ${item.original} -> ${item.replacement} at pos ${item.position}`);
    });
    lines.push("");
  });

  navigator.clipboard.writeText(lines.join("\n")).then(() => {
    alert(t("copiedMsg"));
  });
}

function resetAll() {
  document.getElementById("results").classList.remove("visible");
  document.getElementById("fileInput").value = "";
  document.getElementById("directText").value = "";
  lastScanResult = null;
  lastRawContent = "";
  lastFileName = "";
  globalThis.lastScanResult = null;
  globalThis.lastRawContent = "";
  globalThis.lastFileName = "";
  _clearBulkState();
  _setRevealMode(false);
  _setDiffViewVisible(false);
}

// --- Global bindings for inline onclick handlers ---
// The HTML template has `onclick="setLang('ja')"`, `onclick="resetAll()"` etc.
// These must be reachable on `window` after the IIFE bundle wraps the module.
globalThis.setLang = setLang;
globalThis.applyLang = applyLang;
globalThis.t = t;
globalThis.toggleTextMode = toggleTextMode;
globalThis.handleFiles = handleFiles;
// bulk-scan.js dispatches single-file selections back into app.js's
// handleFile() via this binding (an explicit import would create a
// circular module dep — app.js already imports handleFiles from
// bulk-scan.js).
globalThis.handleFile = handleFile;
globalThis.scanDirectText = scanDirectText;
globalThis.displayResults = displayResults;
globalThis.displayMultiResults = displayMultiResults;
globalThis.toggleReveal = toggleReveal;
globalThis.toggleDiffView = toggleDiffView;
globalThis.downloadSanitized = downloadSanitized;
globalThis.exportReport = exportReport;
globalThis.resetAll = resetAll;
globalThis._sanitizeFilenameForDisplay = _sanitizeFilenameForDisplay;
globalThis._severityOfFindings = _severityOfFindings;
// Expose state mirrors for cross-module reads (bulk-scan reads these
// to populate the per-file detail pane after click).
globalThis.lastScanResult = null;
globalThis.lastRawContent = "";
globalThis.lastFileName = "";
globalThis.lastFileType = "";

// --- v1.19.0 C2: DiffPreview component wiring (S17 successor) ---
// The DiffPreview is a side-by-side virtualized renderer that lives in
// its own component file. We expose the class on globalThis so any
// future UI surface (e.g. a future right-panel or a popout window) can
// mount it without re-importing. The existing diff-section block in
// displayResults() above is preserved (so the test-s17-diff.mjs API
// contract is unchanged); the new component is purely additive.
import { DiffPreview } from "./components/DiffPreview.js";
globalThis.DiffPreview = DiffPreview;

// =============================================================
//  v1.19.0 C3 — BatchExport wire-in (end-of-file, no mid-file edits)
// =============================================================
// Surfaces JSON / Markdown / PDF export buttons under the bulk-summary
// #actions row whenever displayMultiResults() paints. We wrap the
// globalThis.displayMultiResults binding installed above so bulk-scan.js
// itself stays untouched (C2/C3 collision-free).
//
// PDF builder uses a hand-rolled minimal PDF 1.4 emitter — pdf-lib was
// the natural choice but its esbuild footprint (~820 KiB) blows the
// 900 KiB dist-budget gate. See packages/web/src/components/BatchExport.js
// for the full rationale.
import { mountBatchExportButtons } from "./components/BatchExport.js";

let __c3_lastBulkResults = null;
function __c3_setBulkResultsSnapshot(results) {
  __c3_lastBulkResults = Array.isArray(results) ? results.slice() : null;
}
function __c3_getBulkResultsSnapshot() {
  return __c3_lastBulkResults;
}
globalThis.__shieldSetBulkResults = __c3_setBulkResultsSnapshot;
globalThis.__shieldGetBulkResults = __c3_getBulkResultsSnapshot;

const __c3_origDisplayMulti = globalThis.displayMultiResults;
if (typeof __c3_origDisplayMulti === "function") {
  globalThis.displayMultiResults = function (results) {
    __c3_setBulkResultsSnapshot(results);
    const ret = __c3_origDisplayMulti.apply(this, arguments);
    try {
      const actionsEl = document.getElementById("actions");
      if (actionsEl) {
        mountBatchExportButtons(actionsEl, __c3_getBulkResultsSnapshot);
      }
    } catch (_e) {
      // Non-fatal: export buttons are an enhancement, never a blocker.
    }
    return ret;
  };
}

// ---------------------------------------------------------------------------
// v1.20.0 T1-ODT: OpenDocument Text parser binding (Web).
//
// The inner handleFile() switch (above) routes ext === "odt" through
// _parseOdtForHandleFile. The import lives here at file-end (rather than in
// the top import block) so the ODF cluster (T1-ODT / T2 / T3-ODP) lands on
// independent lines and concurrent parser additions stay merge-clean.
// All findings fold into category:'suspiciousPatterns' (R13 5-key invariant).
// ---------------------------------------------------------------------------
import { parseOdt as _parseOdtForHandleFile } from "./parsers-web/odt.js";

// ---------------------------------------------------------------------------
// v1.20.0 T2-ODS: OpenDocument Spreadsheet parser binding (Web).
//
// The inner handleFile() switch (above) routes ext === "ods" through
// _parseOdsForHandleFile. Import lives here at file-end so the ODF cluster
// (T1-ODT / T2-ODS / T3-ODP) lands on independent lines. All findings fold
// into category:'suspiciousPatterns' (R13 5-key invariant).
// ---------------------------------------------------------------------------
import { parseOds as _parseOdsForHandleFile } from "./parsers-web/ods.js";
