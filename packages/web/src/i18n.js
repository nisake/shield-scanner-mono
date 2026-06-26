// i18n module - extracted from index.html L964-L1120
// Contains: i18n table + setLang/t/applyLang

// --- i18n ---
const i18n = {
  ja: {
    subtitle: 'Prompt Injection Detector',
    dropText: 'ファイルをドロップ、またはクリックして選択',
    dropHint: 'テキスト (.txt, .md, .csv, .json)・HTML (.html, .htm)・Office (.docx, .pdf, .pptx)・画像 (.jpg, .png, .webp, .gif, .tiff) に対応 — 複数ファイル同時選択OK',
    textModeBtn: 'テキストを直接入力してスキャン ▾',
    scanTextBtn: '🔍 スキャン実行',
    scanning: 'スキャン中...',
    resultTitle: '📊 スキャン結果',
    statusSafe: '✅ 安全',
    statusWarning: '⚠️ 注意',
    statusDanger: '🚨 危険検出',
    invisibleUnicode: '不可視Unicode文字',
    controlChars: '制御文字',
    hiddenHtml: 'HTML隠し要素',
    suspiciousPatterns: '疑わしいパターン',
    homoglyphs: 'ホモグリフ（類似文字偽装）',
    variationSelectors: 'Variation Selector（絵文字密輸）',
    bidiOverride: 'Bidi 制御文字（Trojan Source）',
    mathSymbolBypass: '数学英数字シンボル偽装',
    combiningChars: '結合文字密度（Zalgo）',
    shadowDetection: 'シャドー検出',
    intentLooks: '見た目',
    runLength: '連続数',
    found: '件検出',
    sanitize: '🧹 安全化してダウンロード',
    exportReport: '📋 レポートをコピー',
    reset: '🔄 リセット',
    charName: '文字',
    position: '位置',
    context: '前後の文脈',
    element: '要素',
    technique: '手法',
    content: '内容（エスケープ済み）',
    pattern: 'パターン',
    original: '原文字',
    replacement: '偽装文字',
    directTextPlaceholder: 'スキャンしたいテキストをここに貼り付けてください...',
    copiedMsg: 'レポートをクリップボードにコピーしました',
    noThreats: '脅威は検出されませんでした',
    topPriority: '最優先',
    bulkScanning: 'ファイルをスキャン中',
    bulkSummary: '一括スキャン結果',
    fileTabAll: '全ファイル',
    bulkOk: '安全',
    bulkWarn: '注意',
    bulkDanger: '危険',
    bulkError: 'エラー',
    bulkPerFileTooLarge: 'はサイズ上限を超えています',
    bulkTotalTooLarge: '合計サイズが上限を超えています',
    bulkTooManyFiles: 'ファイル数が上限を超えています',
    bulkUnsupported: 'はサポート外の形式です',
    bulkParseFailed: '解析に失敗しました',
    bulkLimitHint: '上限: ファイルあたり 20MB / 合計 100MB / 最大 30 件',
    bulkInProgress: 'スキャン進行中です。完了までお待ちください',
    bulkEmpty: 'ファイルが選択されていません',
    bulkTimeout: 'タイムアウトしました (30秒)',
    revealOn: '🔍 不可視文字を可視化',
    revealOff: '🔍 通常表示に戻す',
    diffShow: '📐 サニタイズ差分を表示',
    diffHide: '📐 差分を閉じる',
    diffTitle: 'サニタイズ差分 (Before / After)',
    diffBefore: '原文 (Before)',
    diffAfter: 'サニタイズ後 (After)',
    diffCopyWarning: '⚠️ サニタイズで意味が変わっている可能性があります。そのままLLMに渡す前に必ず内容を確認してください。',
    archiveBomb: 'Zip bomb 警告',
    archiveDepth: 'ネスト深度超過',
    archiveProtected: '暗号化エントリ',
    archiveEntryCap: 'エントリ数超過',
    archiveRenameSpoof: 'Office文書を ZIP に偽装の疑い',
    archiveSanitizeUnsupported: 'ZIP はサニタイズ対象外',
    structTreeCapExceeded: 'PDF構造ツリーの解析が上限に達しました',
    pdfEmbedsJavaScriptActions: 'PDFがJavaScriptアクションを含んでいます',
    oversizeAttachmentSkipped: '添付ファイルが大きすぎてスキップされました',
    emptyAttachment: '0バイトの添付ファイル',
    microscopicText: '極小サイズの文字 (高さ: {height})',
    microscopicFontSize: '極小フォントサイズ ({fontSize}pt)',
    oversizeEmbeddedImage: '埋め込み画像が大きすぎてスキップされました',
    emptyEmbeddedImage: '0バイトの埋め込み画像',
  },
  en: {
    subtitle: 'Prompt Injection Detector',
    dropText: 'Drop file here, or click to select',
    dropHint: 'Supports text (.txt, .md, .csv, .json), HTML (.html, .htm), Office (.docx, .pdf, .pptx), and images (.jpg, .png, .webp, .gif, .tiff) — multiple files OK',
    textModeBtn: 'Scan text directly ▾',
    scanTextBtn: '🔍 Run Scan',
    scanning: 'Scanning...',
    resultTitle: '📊 Scan Results',
    statusSafe: '✅ Safe',
    statusWarning: '⚠️ Caution',
    statusDanger: '🚨 Threats Detected',
    invisibleUnicode: 'Invisible Unicode',
    controlChars: 'Control Characters',
    hiddenHtml: 'Hidden HTML Elements',
    suspiciousPatterns: 'Suspicious Patterns',
    homoglyphs: 'Homoglyphs (Lookalike Chars)',
    variationSelectors: 'Variation Selectors (Emoji Smuggling)',
    bidiOverride: 'Bidi Controls (Trojan Source)',
    mathSymbolBypass: 'Mathematical Symbol Bypass',
    combiningChars: 'Combining Char Density (Zalgo)',
    shadowDetection: 'shadow detection',
    intentLooks: 'Looks like',
    runLength: 'Run length',
    found: 'found',
    sanitize: '🧹 Sanitize & Download',
    exportReport: '📋 Copy Report',
    reset: '🔄 Reset',
    charName: 'Character',
    position: 'Position',
    context: 'Context',
    element: 'Element',
    technique: 'Technique',
    content: 'Content (escaped)',
    pattern: 'Pattern',
    original: 'Original',
    replacement: 'Replaced with',
    directTextPlaceholder: 'Paste text to scan here...',
    copiedMsg: 'Report copied to clipboard',
    noThreats: 'No threats detected',
    topPriority: 'Top Priority',
    bulkScanning: 'Scanning files',
    bulkSummary: 'Bulk scan results',
    fileTabAll: 'All files',
    bulkOk: 'Safe',
    bulkWarn: 'Caution',
    bulkDanger: 'Danger',
    bulkError: 'Error',
    bulkPerFileTooLarge: 'exceeds per-file size limit',
    bulkTotalTooLarge: 'Total size exceeds limit',
    bulkTooManyFiles: 'Too many files',
    bulkUnsupported: 'is an unsupported format',
    bulkParseFailed: 'failed to parse',
    bulkLimitHint: 'Limits: 20MB per file / 100MB total / max 30 files',
    bulkInProgress: 'A scan is already in progress — please wait',
    bulkEmpty: 'No files selected',
    bulkTimeout: 'Timed out (30s)',
    revealOn: '🔍 Reveal invisible chars',
    revealOff: '🔍 Hide markers',
    diffShow: '📐 Show sanitize diff',
    diffHide: '📐 Hide diff',
    diffTitle: 'Sanitize diff (Before / After)',
    diffBefore: 'Original (Before)',
    diffAfter: 'Sanitized (After)',
    diffCopyWarning: '⚠️ Sanitization may change meaning. Review carefully before pasting into an LLM.',
    archiveBomb: 'Zip bomb warning',
    archiveDepth: 'Nest depth exceeded',
    archiveProtected: 'Encrypted entry',
    archiveEntryCap: 'Entry count exceeded',
    archiveRenameSpoof: 'Possible Office package rename',
    archiveSanitizeUnsupported: 'ZIP sanitize not supported',
    structTreeCapExceeded: 'PDF structure tree analysis cap exceeded',
    pdfEmbedsJavaScriptActions: 'PDF contains JavaScript actions',
    oversizeAttachmentSkipped: 'Attachment too large; scan skipped',
    emptyAttachment: 'Empty (0-byte) attachment',
    microscopicText: 'Microscopic text (height: {height})',
    microscopicFontSize: 'Microscopic font size ({fontSize}pt)',
    oversizeEmbeddedImage: 'Embedded image too large; scan skipped',
    emptyEmbeddedImage: 'Empty (0-byte) embedded image',
  }
};

let currentLang = 'ja';
let lastScanResult = null;
let lastRawContent = '';
let lastFileName = '';
let lastFileType = '';

function setLang(lang) {
  currentLang = lang;
  document.querySelectorAll('.lang-btn').forEach(b => b.classList.remove('active'));
  document.querySelector(`.lang-btn[onclick="setLang('${lang}')"]`).classList.add('active');
  applyLang();
}

function t(key) { return i18n[currentLang][key] || key; }

// Detector-controlled technique id (fixed strings only — R12) -> localized
// label via dict lookup. Three-tier lookup (raw -> kebab→camel -> token-camel):
//   1) raw id verbatim (e.g. 'structTreeCapExceeded' if a detector ever emits
//      the camel form directly — currently unused but cheap)
//   2) kebab-case -> camelCase ('struct-tree-cap-exceeded' -> 'structTreeCapExceeded')
//   3) free-form (spaces / punctuation) -> camelCase by splitting on
//      non-alphanumerics, lowercasing the head token, capitalizing the rest
//      ('PDF embeds JavaScript actions' -> 'pdfEmbedsJavaScriptActions';
//       'Oversize attachment skipped (> 5MB)' -> 'oversizeAttachmentSkipped5Mb')
// Graceful fallback returns the raw id when no translation is registered.
function t_technique(tech) {
  if (typeof tech !== 'string' || tech.length === 0) return tech;
  const dict = i18n[currentLang] || {};
  if (Object.prototype.hasOwnProperty.call(dict, tech)) return dict[tech];
  const camel = tech.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
  if (Object.prototype.hasOwnProperty.call(dict, camel)) return dict[camel];
  // Token-based camelCase normalization for space/punctuation-separated ids.
  // Inner-token casing is preserved so 'JavaScript' stays 'JavaScript' (not
  // 'Javascript') — dict keys follow the natural English casing of the
  // source phrase (e.g. 'pdfEmbedsJavaScriptActions').
  const tokens = tech.split(/[^A-Za-z0-9]+/).filter(Boolean);
  if (tokens.length > 0) {
    const tokenCamel = tokens
      .map((tok, i) => {
        // Head token: full lowercase ('PDF' -> 'pdf', 'Oversize' -> 'oversize')
        // so dict keys read naturally. Tail tokens: preserve inner casing,
        // only force the first char upper ('JavaScript' stays 'JavaScript',
        // 'embeds' becomes 'Embeds').
        if (i === 0) return tok.toLowerCase();
        return tok.charAt(0).toUpperCase() + tok.slice(1);
      })
      .join('');
    if (Object.prototype.hasOwnProperty.call(dict, tokenCamel)) return dict[tokenCamel];
    // Strip trailing number-suffix tokens (e.g. '5MB' -> camel '5Mb' from
    // 'oversizeAttachmentSkipped5Mb') and retry — lets dict keys ignore
    // size-suffix noise like '(> 5MB)'.
    const stripped = tokenCamel.replace(/[0-9][A-Za-z0-9]*$/, '');
    if (stripped && stripped !== tokenCamel
        && Object.prototype.hasOwnProperty.call(dict, stripped)) {
      return dict[stripped];
    }
  }
  return tech;
}

function applyLang() {
  document.getElementById('subtitle').textContent = t('subtitle');
  document.getElementById('dropText').textContent = t('dropText');
  document.getElementById('dropHint').textContent = t('dropHint');
  document.getElementById('textModeBtn').textContent = t('textModeBtn');
  document.getElementById('scanTextBtn').textContent = t('scanTextBtn');
  document.getElementById('directText').placeholder = t('directTextPlaceholder');
}

// ES exports
export { i18n, currentLang, setLang, t, t_technique, applyLang };
