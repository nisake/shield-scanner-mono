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
    pdfEmbedsJavascriptActions: 'PDFがJavaScriptアクションを含んでいます',
    oversizeAttachmentSkipped: '添付ファイル過大によりスキップ',
    emptyAttachment: '0バイトの添付ファイル',
    pdfOversizeAttachment: 'PDF添付ファイル過大によりスキップ (上限 {maxBytes} byte)',
    pdfEmbeddedBinaryAttachment: 'PDF埋込バイナリ添付 (.{ext})',
    pdfEmptyAttachment: 'PDF 0バイトの添付ファイル',
    pdfWidgetAction: 'PDF Widgetフィールドの追加アクション ({actionTypes})',
    pdfEmbeddedHtml: 'PDF埋込HTMLファイル (subtype={subtype})',
    pdfSubmitFormAction: 'PDF SubmitFormアクション (送信先 {targetUrl})',
    pdfGotoRemoteAction: 'PDF GoToRリモートアクション (遷移先 {target})',
    pdfRichmediaEmbed: 'PDF RichMedia埋め込み (subtype={subtype})',
    pdf3DEmbed: 'PDF 3D注釈の埋め込み (subtype={subtype})',
    pdfSoundAction: 'PDF Sound注釈 (subtype={subtype})',
    pdfMovieAction: 'PDF Movie注釈 (subtype={subtype})',
    microscopicText: '極小サイズの文字 (高さ: {height})',
    microscopicFontSize: '極小フォントサイズ ({fontSize}pt)',
    oversizeEmbeddedImage: '埋め込み画像過大によりスキップ',
    emptyEmbeddedImage: '0バイトの埋め込み画像',
    docxAttachedTemplateRemote: '外部テンプレート参照 (Follina系)',
    docxWebsettingsExternalLoad: 'webSettings からの外部フレーム読込',
    docxCustomxmlInstruction: 'customXml に指示文形状のテキスト',
    pptxAttachedTemplateRemote: '外部テンプレート参照 (Follina系)',
    officeEmbeddedOleCfb: '埋め込みOLEオブジェクト (CFB magic 検出)',
    sheetStateConfusion: '非標準のシートステートトークン (state confusion)',
    autoRunDefinedName: '自動実行 definedName を検出',
    hiddenNumFmt: '不可視 numFmt フォーマットコード',
    ddeLink: 'DDE リンクを検出',
    xlsxScanLimit: 'XLSX スキャン上限到達 ({scope})',
    xlsxCorruptZip: 'XLSX 破損 / ZIP 解析不能',
    vbaMacroProject: 'VBA マクロプロジェクト (xl/vbaProject.bin)',
    extensionContentTypeMismatch: '拡張子と ContentType の不一致 (.xlsx にマクロが偽装)',
    xlmMacrosheet: 'XLM 4.0 マクロシート (xl/macrosheets/)',
    hiddenSheet: '非表示シート (state="hidden")',
    veryhiddenSheet: 'veryHidden シート (UI からアクセス不可)',
    externalOleLink: '外部 OLE リンク参照',
    externalRelationship: '外部 OPC リレーションシップ ({scheme})',
    docpropsPromptInjection: 'ドキュメントプロパティへのプロンプト注入',
    hyperlinkBaseRewrite: 'HyperlinkBase によるリンク先サイレント書き換え',
    instructionShapedComment: '指示文形状のコメント',
    oversizeEmbeddedObject: '埋め込みオブジェクト過大によりスキップ',
    csvScanLimitBytes: 'CSVがスキャン上限を超過 — 先頭部分のみスキャン',
    csvEncodingFallback: 'CSVエンコーディング判定失敗 — UTF-8 にフォールバック',
    csvScanLimitRows: 'CSVが行数上限を超過 — 末尾行はスキップ',
    emptyAttachmentBody: '添付ファイル本体が空 (header size > 0)',
    whitespaceOnlyAttachment: '空白のみの添付ファイル (≤64 byte)',
    xlsxPowerQueryWebcontents: 'Power Query から外部HTTPフェッチ (Web.Contents)',
    xlsxDataConnectionShell: 'データ接続にシェル実行トークン (cmd / powershell 等)',
    xlsxActivexControl: 'ActiveX コントロールを検出 (Equation Editor 系)',
    xlsxCustomUiCallback: 'カスタムUI リボン コールバック ({callbackName})',
    mcpDescriptorInjection: 'MCPツール記述子の汚染 (description にインジェクション)',
    mcpRugPullDetected: 'MCP記述子のRug-Pull検出 (SHA256差分)',
    mcpShadowToolCollision: 'MCPツール名の重複 (Shadow Tool)',
    mcpHiddenInstructionInDescription: 'description内に隠し指示文',
    emlFromReplyToMismatch: 'From と Reply-To/Return-Path のドメイン不一致',
    emlSenderFromMismatch: 'Sender と From のドメイン不一致',
    emlAuthenticationFailure: 'Authentication-Results に失敗 (DMARC/SPF/DKIM)',
    emlPunycodeHomographDomain: 'Punycode/IDN 異種スクリプトドメイン (xn-- decode)',
    emlMixedScriptDomain: '混在スクリプトドメイン (Latin と Cyrillic/Greek の混在)',
    emlEncodedWordInvisibleUnicode: 'RFC2047 encoded-word 内の不可視 Unicode / Tags',
    urlQueryVariationSelector: 'URLクエリ値内の Variation Selector (ASCII Smuggling)',
    urlQueryInvisibleUnicode: 'URLクエリ値内の不可視 Unicode (ASCII Smuggling)',
    mdExfilAllowlistSuppressed: '信頼済みホスト宛のweak-keyを監査ログ化 (host={host})',
    mdExfilAllowlistDowngraded: '信頼済みホスト宛のstrong-keyを降格 ({originalSeverity} → warning, host={host})',
    pdfStructHeadingH1: 'PDF 構造ツリー 見出しレベル1 (H1) 内のテキスト',
    pdfStructHeadingH2: 'PDF 構造ツリー 見出しレベル2 (H2) 内のテキスト',
    pdfStructHeadingH3: 'PDF 構造ツリー 見出しレベル3 (H3) 内のテキスト',
    pdfStructHeadingH4: 'PDF 構造ツリー 見出しレベル4 (H4) 内のテキスト',
    pdfStructHeadingH5: 'PDF 構造ツリー 見出しレベル5 (H5) 内のテキスト',
    pdfStructHeadingH6: 'PDF 構造ツリー 見出しレベル6 (H6) 内のテキスト',
    pdfStructBlockquote: 'PDF 構造ツリー BlockQuote (引用ブロック) 内のテキスト',
    pdfStructQuote: 'PDF 構造ツリー Quote (インライン引用) 内のテキスト',
    pdfStructSpan: 'PDF 構造ツリー Span (汎用インライン) 内のテキスト',
    // v1.19.0 B4: structured-text frontmatter (YAML / TOML / JSON-LD) detector.
    frontmatterPromptInjection: 'frontmatter内の指示文 ({format} key={key})',
    yamlDangerousTag: 'YAML危険タグ ({tagName}) — CVE-2017-18342 系のRCE指標',
    yamlAnchorBomb: 'YAMLアンカー爆弾 / 深度超過 (depth={depth})',
    jsonldDescriptionInjection: 'JSON-LD構造化データに指示文 (field={field})',
    tomlInstructionKey: 'TOML指示文キー名 (key={key})',
    // v1.19.0 B1: Polyglot SVG (script / event-handler / javascript-href /
    // foreignObject / CDATA / external use) — kebab ids fold into the
    // suspiciousPatterns bucket; meta.attribute / meta.href are detector-
    // controlled scalars only (R12 invariant).
    svgScriptElement: 'SVG内に <script> 要素 (Polyglot SVG)',
    svgEventHandler: 'SVGイベントハンドラ属性 ({attribute}=…) — XSS 実行サーフェス',
    svgJavascriptHref: 'SVG href/xlink:href に javascript: スキーム',
    svgForeignobjectHtml: 'SVG <foreignObject> 経由のHTML/iframe 埋め込み',
    svgCdataSection: 'SVG <![CDATA[…]]> セクションに指示文の可能性',
    svgUseExternalRef: 'SVG <use href="…"> 外部参照 (href={href})',
    // v1.19.0 B2: RTF 制御ワード / オブジェクト injection (CVE-2023-21716 系)
    rtfOleObject: 'RTF 埋め込み OLE オブジェクト (\\objdata / \\objclass={objclass})',
    rtfFieldHyperlink: 'RTF \\field HYPERLINK (送信先 {url})',
    rtfHiddenTextV: 'RTF \\v 隠しテキスト ({charCount} 文字)',
    rtfMicroscopicFont: 'RTF \\fs 極小フォント ({fontSize}pt)',
    rtfBinaryBlock: 'RTF \\bin 生バイナリブロック ({byteCount} byte)',
    rtfUnknownDestination: 'RTF \\* 未知デスティネーション ({destination})',
    // v1.19.0 B3: Jupyter Notebook (.ipynb) — cell metadata / output / hidden
    // signal の各 kebab id。すべて suspiciousPatterns にfoldされ、meta は
    // detector 管理スカラのみ (R12 invariant)。
    ipynbOutputHtmlInjection: 'Jupyter 出力セルの HTML/JS 埋め込み (cell {cellIndex}, mime={mime})',
    ipynbHiddenCellInstruction: 'Jupyter 隠しセル内の指示文 (cell {cellIndex}, 種別={cellType})',
    ipynbMetadataTagSmuggle: 'Jupyter cell.metadata.tags に指示文/非表示タグ (cell {cellIndex})',
    ipynbUntrustedSignature: 'Jupyter Notebook に metadata.signature 無し (nbformat={nbformat})',
    // v1.19.0 D1: encoded payload decode pipeline (Base64 / Hex / Punycode /
    // HTML entity / multi-layer). R12: ラベルは fixed phrase + meta enum のみ。
    // decoded 本文は絶対に label / interpolation 経由でも露出させない。
    encodedBase64Instruction: 'Base64エンコードされた指示文 (decode 後に命令フレーズを検出)',
    encodedHexInstruction: 'Hexエンコードされた指示文 (decode 後に命令フレーズを検出)',
    encodedHtmlEntityInstruction: 'HTML数値文字参照で難読化された指示文 (&#xNN; decode)',
    punycodeHostHomograph: 'Punycode (xn--) ホストのホモグラフ攻撃 (Cyrillic/Greek/Latin混在)',
    multiLayerEncodedPayload: '多層難読化ペイロード (Base64+不可視Unicode等の組合せ)',
    // v1.20.0 T3-ODP: OpenDocument Presentation (.odp) — speaker note instruction
    // / slide transition macro / external embedded object / master-slide
    // instruction の各 kebab id。R13 fold: 全て suspiciousPatterns。
    odpNotesPromptInjection: 'ODPスピーカーノートに指示文 (slide {slideIndex})',
    odpSlideTransitionMacro: 'ODPスライドトランジションのマクロ/スクリプト参照 ({scriptHref})',
    odpEmbeddedObjectExternal: 'ODP埋め込みオブジェクトの外部参照 ({objectHref})',
    odpMasterSlideInstruction: 'ODPマスタースライドに指示文 (master {masterIndex})',
    // v1.20.0 T1-ODT: OpenDocument Text (.odt) — settings.xml マクロ自動実行
    // フラグ / meta.xml dc:* 内の指示文 / content.xml office:event-listener の
    // 外部 href / Basic/ 配下の StarBasic マクロ。R13 fold: 全て
    // suspiciousPatterns。R12: 動的値は meta オブジェクト内のみ。
    odtOfficeSettingsMacro: 'ODT settings.xml マクロ/自動実行フラグ ({configName})',
    odtMetaPromptInjection: 'ODT meta.xml に指示文 ({metaName})',
    odtExternalEventListener: 'ODT office:event-listener の外部参照 ({eventHref})',
    odtStarbasicMacro: 'ODT 埋め込み StarBasic マクロ ({macroPath})',
    // v1.20.0 T2-ODS: OpenDocument Spreadsheet (.ods) — content.xml の
    // table:formula 注入 / settings.xml の DDE・外部コマンド参照 / 非表示
    // (table:display="false") シート内の指示文 / Basic/ 配下マクロ。R13 fold:
    // 全て suspiciousPatterns。R12: 動的値は meta オブジェクト内のみ。
    odsFormulaInjection: 'ODS セルに数式注入 (sheet={sheetName}, ref={ref})',
    odsExternalDdeLink: 'ODS の DDE/外部コマンド参照 (source={source})',
    odsHiddenSheetInstruction: 'ODS 非表示/保護シート内の指示文 (sheet={sheetName})',
    odsMacroBearing: 'ODS マクロ含有 (source={source})',
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
    pdfEmbedsJavascriptActions: 'PDF contains JavaScript actions',
    oversizeAttachmentSkipped: 'Attachment too large; scan skipped',
    emptyAttachment: 'Empty (0-byte) attachment',
    pdfOversizeAttachment: 'PDF attachment too large; scan skipped (cap {maxBytes} bytes)',
    pdfEmbeddedBinaryAttachment: 'PDF embedded binary attachment (.{ext})',
    pdfEmptyAttachment: 'PDF empty (0-byte) attachment',
    pdfWidgetAction: 'PDF Widget field additional actions ({actionTypes})',
    pdfEmbeddedHtml: 'PDF embedded HTML file (subtype={subtype})',
    pdfSubmitFormAction: 'PDF SubmitForm action (target {targetUrl})',
    pdfGotoRemoteAction: 'PDF GoToR remote action (target {target})',
    pdfRichmediaEmbed: 'PDF RichMedia annotation embedded (subtype={subtype})',
    pdf3DEmbed: 'PDF 3D annotation embedded (subtype={subtype})',
    pdfSoundAction: 'PDF Sound annotation (subtype={subtype})',
    pdfMovieAction: 'PDF Movie annotation (subtype={subtype})',
    microscopicText: 'Microscopic text (height: {height})',
    microscopicFontSize: 'Microscopic font size ({fontSize}pt)',
    oversizeEmbeddedImage: 'Embedded image too large; scan skipped',
    emptyEmbeddedImage: 'Empty (0-byte) embedded image',
    docxAttachedTemplateRemote: 'External attached template (Follina family)',
    docxWebsettingsExternalLoad: 'External frameset load via webSettings',
    docxCustomxmlInstruction: 'Instruction-shaped text in customXml',
    pptxAttachedTemplateRemote: 'External attached template (Follina family)',
    officeEmbeddedOleCfb: 'Embedded OLE object (CFB magic detected)',
    sheetStateConfusion: 'Non-standard sheet-state token (state confusion)',
    autoRunDefinedName: 'Auto-run definedName detected',
    hiddenNumFmt: 'Hidden numFmt formatCode',
    ddeLink: 'DDE link detected',
    xlsxScanLimit: 'XLSX scan limit reached ({scope})',
    xlsxCorruptZip: 'Corrupt XLSX (zip parse failed)',
    vbaMacroProject: 'VBA macro project present (xl/vbaProject.bin)',
    extensionContentTypeMismatch: 'Extension/ContentType mismatch (macro hidden as xlsx)',
    xlmMacrosheet: 'XLM 4.0 macrosheet present (xl/macrosheets/)',
    hiddenSheet: 'Hidden sheet (state="hidden")',
    veryhiddenSheet: 'veryHidden sheet (UI-inaccessible)',
    externalOleLink: 'External OLE link reference',
    externalRelationship: 'External OPC relationship ({scheme})',
    docpropsPromptInjection: 'Prompt injection in document properties',
    hyperlinkBaseRewrite: 'Hyperlink base silent rewrite',
    instructionShapedComment: 'Instruction-shaped comment',
    oversizeEmbeddedObject: 'Embedded object too large; scan skipped',
    csvScanLimitBytes: 'CSV exceeds scan limits — partial scan',
    csvEncodingFallback: 'CSV encoding decode failure — falling back to UTF-8',
    csvScanLimitRows: 'CSV exceeds row limit — partial scan',
    emptyAttachmentBody: 'Empty attachment body (header size > 0)',
    whitespaceOnlyAttachment: 'Whitespace-only attachment (≤64 bytes)',
    xlsxPowerQueryWebcontents: 'Power Query fetches over HTTP (Web.Contents)',
    xlsxDataConnectionShell: 'Data connection carries shell-runner token (cmd / powershell etc.)',
    xlsxActivexControl: 'ActiveX control present (Equation Editor family)',
    xlsxCustomUiCallback: 'CustomUI ribbon callback ({callbackName})',
    mcpDescriptorInjection: 'MCP tool descriptor poisoning (injection in description)',
    mcpRugPullDetected: 'MCP descriptor rug-pull detected (SHA256 mismatch)',
    mcpShadowToolCollision: 'MCP shadow tool collision (duplicate tool name)',
    mcpHiddenInstructionInDescription: 'Hidden instruction in MCP description',
    emlFromReplyToMismatch: 'From / Reply-To / Return-Path domain mismatch',
    emlSenderFromMismatch: 'Sender / From domain mismatch',
    emlAuthenticationFailure: 'Authentication-Results failure (DMARC/SPF/DKIM)',
    emlPunycodeHomographDomain: 'Punycode/IDN non-Latin script domain (xn-- decoded)',
    emlMixedScriptDomain: 'Mixed-script domain (Latin + Cyrillic/Greek)',
    emlEncodedWordInvisibleUnicode: 'RFC2047 encoded-word with invisible Unicode / Tags',
    urlQueryVariationSelector: 'Variation Selector inside URL query value (ASCII smuggling)',
    urlQueryInvisibleUnicode: 'Invisible Unicode inside URL query value (ASCII smuggling)',
    mdExfilAllowlistSuppressed: 'Weak-key request to trusted-allowlist host suppressed to audit log (host={host})',
    mdExfilAllowlistDowngraded: 'Strong-key request to trusted-allowlist host downgraded ({originalSeverity} → warning, host={host})',
    pdfStructHeadingH1: 'PDF struct tree heading level 1 (H1) text',
    pdfStructHeadingH2: 'PDF struct tree heading level 2 (H2) text',
    pdfStructHeadingH3: 'PDF struct tree heading level 3 (H3) text',
    pdfStructHeadingH4: 'PDF struct tree heading level 4 (H4) text',
    pdfStructHeadingH5: 'PDF struct tree heading level 5 (H5) text',
    pdfStructHeadingH6: 'PDF struct tree heading level 6 (H6) text',
    pdfStructBlockquote: 'PDF struct tree BlockQuote (block-level quotation) text',
    pdfStructQuote: 'PDF struct tree Quote (inline quotation) text',
    pdfStructSpan: 'PDF struct tree Span (generic inline element) text',
    // v1.19.0 B4: structured-text frontmatter (YAML / TOML / JSON-LD) detector.
    frontmatterPromptInjection: 'Prompt injection inside frontmatter ({format} key={key})',
    yamlDangerousTag: 'Dangerous YAML tag ({tagName}) — CVE-2017-18342 family RCE indicator',
    yamlAnchorBomb: 'YAML anchor bomb / depth exceeded (depth={depth})',
    jsonldDescriptionInjection: 'JSON-LD instruction-shaped value (field={field})',
    tomlInstructionKey: 'TOML instruction-shaped key name (key={key})',
    // v1.19.0 B1: Polyglot SVG (script / event-handler / javascript-href /
    // foreignObject / CDATA / external use) — kebab ids fold into the
    // suspiciousPatterns bucket; meta.attribute / meta.href are detector-
    // controlled scalars only (R12 invariant).
    svgScriptElement: 'Inline <script> inside SVG (Polyglot SVG)',
    svgEventHandler: 'SVG event-handler attribute ({attribute}=…) — XSS execution surface',
    svgJavascriptHref: 'SVG href/xlink:href with javascript: scheme',
    svgForeignobjectHtml: 'SVG <foreignObject> embedding HTML / iframe',
    svgCdataSection: 'SVG <![CDATA[…]]> section containing instruction-shaped text',
    svgUseExternalRef: 'SVG <use href="…"> external reference (href={href})',
    // v1.19.0 B2: RTF control-word / object injection (CVE-2023-21716 family).
    rtfOleObject: 'RTF embedded OLE object (\\objdata / \\objclass={objclass})',
    rtfFieldHyperlink: 'RTF \\field HYPERLINK (target {url})',
    rtfHiddenTextV: 'RTF \\v hidden text ({charCount} chars)',
    rtfMicroscopicFont: 'RTF \\fs microscopic font ({fontSize}pt)',
    rtfBinaryBlock: 'RTF \\bin raw binary block ({byteCount} bytes)',
    rtfUnknownDestination: 'RTF \\* unknown destination ({destination})',
    // v1.19.0 B3: Jupyter Notebook (.ipynb) — cell metadata / output / hidden
    // signal kebab ids. All fold into suspiciousPatterns; meta carries
    // detector-controlled scalars only (R12 invariant).
    ipynbOutputHtmlInjection: 'Jupyter output cell embedded HTML/JS (cell {cellIndex}, mime={mime})',
    ipynbHiddenCellInstruction: 'Jupyter hidden cell carries instruction (cell {cellIndex}, type={cellType})',
    ipynbMetadataTagSmuggle: 'Jupyter cell.metadata.tags carries instruction / hide tag (cell {cellIndex})',
    ipynbUntrustedSignature: 'Jupyter Notebook missing metadata.signature (nbformat={nbformat})',
    // v1.19.0 D1: encoded payload decode pipeline (Base64 / Hex / Punycode /
    // HTML entity / multi-layer). R12: labels are fixed-phrase + meta enum
    // only; decoded raw text NEVER appears in label or interpolation.
    encodedBase64Instruction: 'Base64-encoded instruction phrase (decoded form matches a prompt-injection signature)',
    encodedHexInstruction: 'Hex-encoded instruction phrase (decoded form matches a prompt-injection signature)',
    encodedHtmlEntityInstruction: 'HTML numeric character references obfuscating an instruction phrase (&#xNN; decoded)',
    punycodeHostHomograph: 'Punycode (xn--) host homograph attack (Cyrillic / Greek / Latin mixed-script)',
    multiLayerEncodedPayload: 'Multi-layer obfuscated payload (Base64 wrapping invisible-Unicode-shaped instruction)',
    // v1.20.0 T3-ODP: OpenDocument Presentation (.odp) — speaker note /
    // transition macro / external embedded object / master-slide instruction
    // surfaces. R13 fold: all into suspiciousPatterns.
    odpNotesPromptInjection: 'ODP speaker note carries instruction (slide {slideIndex})',
    odpSlideTransitionMacro: 'ODP slide transition with macro / script reference ({scriptHref})',
    odpEmbeddedObjectExternal: 'ODP embedded object external reference ({objectHref})',
    odpMasterSlideInstruction: 'ODP master-slide carries instruction (master {masterIndex})',
    // v1.20.0 T1-ODT: OpenDocument Text (.odt) — settings.xml macro/auto-exec
    // flags / meta.xml dc:* instruction text / content.xml office:event-listener
    // remote href / Basic/ StarBasic macros. R13 fold: all into
    // suspiciousPatterns. R12 invariant: dynamic values live only inside meta.
    odtOfficeSettingsMacro: 'ODT settings.xml macro / auto-exec config flag ({configName})',
    odtMetaPromptInjection: 'ODT meta.xml carries instruction ({metaName})',
    odtExternalEventListener: 'ODT office:event-listener with remote reference ({eventHref})',
    odtStarbasicMacro: 'ODT embedded StarBasic macro ({macroPath})',
    // v1.20.0 T2-ODS: OpenDocument Spreadsheet (.ods) — content.xml
    // table:formula injection / settings.xml DDE / external command refs /
    // hidden (table:display="false") sheet instruction bodies / Basic/ macros.
    // R13 fold: all suspiciousPatterns. R12: dynamic values in meta only.
    odsFormulaInjection: 'ODS cell formula injection (sheet={sheetName}, ref={ref})',
    odsExternalDdeLink: 'ODS DDE / external command reference (source={source})',
    odsHiddenSheetInstruction: 'ODS hidden / protected sheet carries instruction (sheet={sheetName})',
    odsMacroBearing: 'ODS macro-bearing spreadsheet (source={source})',
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
//   3) free-form (spaces / punctuation / compound camels) -> camelCase by
//      splitting on non-alphanumerics, then SUB-splitting each token on
//      `/[A-Z][a-z]+|\d+/g`-style camel boundaries so 'JavaScript' decomposes
//      into ['Java', 'Script'] before re-joining. Head token lowercased, tail
//      tokens PascalCased.
//      ('PDF embeds JavaScript actions' -> 'pdfEmbedsJavaScriptActions';
//       'Oversize attachment skipped (> 5MB)' -> 'oversizeAttachmentSkipped5Mb')
//
// v1.17.1 (T3) note: kebab inputs like 'pdf-embeds-javascript-actions' fall
// through path 2 producing 'pdfEmbedsJavascriptActions' (lowercase 's' — the
// kebab loses the 'JavaScript' compound-word boundary). The dict therefore
// keeps DUAL keys (legacy 'pdfEmbedsJavaScriptActions' + kebab-target
// 'pdfEmbedsJavascriptActions'). A pure-resolver fix would need a compound-
// word dictionary, which is out of scope and brittle.
// Graceful fallback returns the raw id when no translation is registered.
function t_technique(tech) {
  if (typeof tech !== 'string' || tech.length === 0) return tech;
  const dict = i18n[currentLang] || {};
  if (Object.prototype.hasOwnProperty.call(dict, tech)) return dict[tech];
  const camel = tech.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
  if (Object.prototype.hasOwnProperty.call(dict, camel)) return dict[camel];
  // Token-based camelCase normalization for space/punctuation-separated ids.
  // Each separator-delimited token is sub-split on camel-boundary regex
  // `/[A-Z][a-z]+|\d+/g` so internal compounds ('JavaScript' -> 'Java',
  // 'Script') become first-class tokens. Acronyms ('PDF', 'XLSX') survive
  // because the `[A-Z]+(?=[A-Z]|\d|$)` and `[a-z]+` alternatives catch them.
  const tokens = tech.split(/[^A-Za-z0-9]+/).filter(Boolean);
  if (tokens.length > 0) {
    const SUB = /[A-Z][a-z]+|[A-Z]+(?=[A-Z]|\d|$)|\d+|[a-z]+/g;
    const subTokens = [];
    for (const tok of tokens) {
      const m = tok.match(SUB);
      if (m && m.length > 0) {
        for (const part of m) subTokens.push(part);
      } else {
        // Token had no recognizable substructure — keep verbatim.
        subTokens.push(tok);
      }
    }
    const tokenCamel = subTokens
      .map((tok, i) => {
        // Head token: full lowercase ('PDF' -> 'pdf', 'Oversize' -> 'oversize')
        // so dict keys read naturally. Tail tokens: PascalCase the first char,
        // preserve the rest — so 'Java'+'Script' joins as 'JavaScript' and
        // 'embeds' becomes 'Embeds'.
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
