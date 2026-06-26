# Shield Scanner

LLM プロンプトインジェクション・隠し命令・難読化テキストを検出／無害化するためのスキャナ。
Web 単一 HTML 版と Claude Desktop 用 MCP サーバ版の 2 distribution を、ひとつのモノレポから配信する。

- **検出**: 不可視文字 (BiDi / ZWJ など)、ホモグリフ、隠し HTML、PDF / Office メタデータ、JSON 化された命令文字列ほか
- **無害化 (sanitize)**: 検出と同じルールセットで除去し、cleaned 文字列を返す
- **2 distribution 共通コア**: ルール・優先度・サニタイザは `@shield-scanner/core` に集約し、MCP / Web 間 drift = 0 (parity-check で保証)

---

## ⚠️ v1.6.0 BREAKING change

`@shield-scanner/core` の `analyze` / `sanitize` は **options オブジェクト引数** に変更された。旧シグネチャ呼び出しはエラーになる。

### 新シグネチャ

```js
import { analyze, sanitize } from '@shield-scanner/core';

// analyze: 解析のみ、findings / summary を返す
const { findings, summary } = analyze(content, {
  fileType,      // 'text' | 'html' | 'pdf' | 'docx' | ...
  categories,    // 任意。指定カテゴリのみ評価
});

// sanitize: 検出と同じルールで除去、cleaned / removedCounts を返す
const { cleaned, removedCounts } = sanitize(content, {
  fileType,
  categories,
});
```

### 旧シグネチャ (v1.5.0 以前、**今は動かない**)

```js
analyze(content, 'text');         // ❌ 第 2 引数が string → throw
sanitize(content, findings);      // ❌ 第 2 引数が array → throw
```

呼び出し側 (MCP tools / Web app.js / parity-check) は v1.6.0 で全て新シグネチャに移行済み。外部から core を直 import している箇所がある場合は要修正。

---

## リポジトリ構成

```
shield-scanner-mono/
├── packages/
│   ├── core/      # 共通コア (ルール JSON + analyze / sanitize / priority)
│   ├── mcp/       # Claude Desktop 用 MCP サーバ (Node)
│   └── web/       # 単一 HTML 配布物 (esbuild ビルド)
├── tools/
│   └── parity-check.mjs  # MCP と Web の検出結果 drift を毎回 0 で担保
└── package.json   # npm workspaces ルート
```

| パッケージ | 役割 |
| --- | --- |
| `@shield-scanner/core` | ルール定義 (4 JSON) と解析・無害化ロジック。env 抽象 (`rulesLoader` / `htmlParser`) で Node / Web 両対応 |
| `@shield-scanner/mcp`  | `server/index.js` から MCP ツールを公開。`scan_text` / `scan_file` / `sanitize_text` / `sanitize_file` / `scan_email` / `scan_url` |
| `@shield-scanner/web`  | `packages/web/src/` を esbuild で `dist/index.html` (約 807KB) に単一バンドル。JSZip / pdf.js は CDN script タグで読込 |
| `tools/parity-check.mjs` | 13 fixtures × {MCP, Web} = 36 結果を deep-equal 比較。drift があれば exit 1 |

---

## 開発フロー

### セットアップ

```bash
npm install
```

### テスト

```bash
# 全ワークスペースのテストを実行 (core 21 + MCP 441 + Web harness 19)
npm test --workspaces

# parity drift 検証 (= 0 を維持)
npm run parity
```

### Web ビルド

```bash
npm run build -w web
# → packages/web/dist/index.html (単一HTML)
```

`build.mjs` は `external: ['jszip', 'pdfjs-dist']` で CDN script タグ運用を維持し、
ルール JSON を `globalThis.__SHIELD_RULES__` に inject する。
**minify: false** を維持すること (R12-R17 grep audit が成立しなくなるため)。

### MCP サーバ単体起動 (デバッグ用)

```bash
node packages/mcp/server/index.js
```

通常は Claude Desktop が自動で起動する。

---

## Claude Desktop 接続

`%APPDATA%\Claude\claude_desktop_config.json` に下記を追加。

```json
{
  "mcpServers": {
    "shield-scanner": {
      "command": "node",
      "args": [
        "<path-to>\\shield-scanner-mono\\packages\\mcp\\server\\index.js"
      ]
    }
  }
}
```

設定変更後は Claude Desktop の再起動が必要。

### ブルーグリーン移行 (旧版との並行運用)

旧 `shield-scanner` を残したまま `shield-scanner-v2` として新版を登録し、
両者の挙動を比較してから切替える運用を推奨。

---

## Web 版 配信

ビルド成果物 `packages/web/dist/index.html` を任意の静的 CDN にアップロードするだけ。
依存スクリプト (JSZip / pdf.js) は HTML 内の `<script src="https://...">` で取得する。

```bash
npm run build -w web
# packages/web/dist/index.html を CDN (例: Netlify / Cloudflare Pages) にアップロード
```

### Web 規約 (v1.6.0 で明文化)

> v1.5.0 までの「外部JS追加禁止」を実態に即して書き直したもの。**運用上の挙動は変わっていない**、契約を文章化しただけ。

- **最終配布物は単一HTML** (`packages/web/dist/index.html`) — これ 1 ファイルで完結する
- **CDN script タグの既存利用は OK** (JSZip / pdf.js)。HTML 内で `<script src="https://...">` 読込する現状運用を維持。ローカル `node_modules` に持ち込まない
- **core + app.js は esbuild で bundle inline** → 配布時は単一HTMLに集約される
- **開発ソースは `packages/web/src/` 配下で分割可** (`app.js` / `parsers-web/` / `ui/` / `ui-guards/` / `i18n.js` など)。分割は build 時に bundle されるので、配布物の「単一HTML」契約とは独立
- **`minify: false` を維持** すること (R12-R17 grep audit が成立しなくなるため)

---

## テスト構成

| スイート | 件数 | 内容 |
| --- | --- | --- |
| `@shield-scanner/core` vitest | 21 | analyze / sanitize / priority / homoglyph |
| `@shield-scanner/mcp` vitest | 441 | MCP ツール統合・parsers・edge cases |
| MCP smoke harness | 19 | base 16 + HTML fileType 伝播 + sanitize round-trip 2 |
| Web harness | 19 | core 直 import 方式 (DOM 不要) で MCP smoke と同等 |
| parity-check | 13 fixtures / 36 結果 / drift **0** | MCP ⇔ Web 出力一致を背理法込みで担保 |

合計 ~500 test。CI / 手元いずれも `npm test --workspaces && npm run parity` で完了。

---

### コアバージョン

- v1.6.0 (2026-06-26): 2 リポ統合 → monorepo 化。core/mcp/web の workspaces 構成、parity drift 0 を初めて静的に証明。
