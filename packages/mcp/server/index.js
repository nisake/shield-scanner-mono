#!/usr/bin/env node
/**
 * Shield Scanner MCP - Entry Point
 *
 * MCP server for detecting prompt injection threats in text, files, URLs, and emails.
 * Uses stdio transport for communication with AI hosts (Claude Desktop, etc.).
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { scanText } from "./tools/scan-text.js";
import { scanFile } from "./tools/scan-file.js";
import { scanUrl } from "./tools/scan-url.js";
import { scanEmail } from "./tools/scan-email.js";
import { sanitizeText } from "./tools/sanitize-text.js";
import { sanitizeFile } from "./tools/sanitize-file.js";
import { scanMcpDescriptor } from "./tools/scan_mcp_descriptor.js";

const SERVER_NAME = "shield-scanner-mcp";
const SERVER_VERSION = "1.20.0";

// ============================================================
// Server initialization
// ============================================================

const server = new Server(
  {
    name: SERVER_NAME,
    version: SERVER_VERSION,
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// ============================================================
// Tool definitions
// ============================================================

const CATEGORY_ENUM = [
  "invisibleUnicode",
  "controlChars",
  "hiddenHtml",
  "suspiciousPatterns",
  "homoglyphs",
];

// QW3: shared verbosity property. "compact" returns counts + max severity only
// (no findings array, no JSON dump) so that batched/looped tool calls — most
// notably scan_email — don't blow the LLM context window. "normal" is the
// previous default and is fully backward compatible.
const VERBOSITY_PROP = {
  verbosity: {
    type: "string",
    enum: ["compact", "normal", "detailed"],
    default: "normal",
    description:
      "Output detail level. 'compact'=counts only (10-50x smaller, no findings), 'normal'=existing default, 'detailed'=normal + wider context per finding.",
  },
};

const TOOLS = [
  {
    name: "scan_text",
    description:
      "テキストを直接スキャンしてプロンプトインジェクションの脅威を検出する。不可視Unicode、制御文字、疑わしいパターン、Homoglyph等を5カテゴリで分析。AIに渡す前の事前チェックに使用。",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "The text content to scan",
        },
        categories: {
          type: "array",
          items: { type: "string", enum: CATEGORY_ENUM },
          description: "Optional: limit to specific categories. Omit to scan all.",
        },
        ...VERBOSITY_PROP,
      },
      required: ["text"],
    },
  },
  {
    name: "scan_file",
    description:
      "ファイルパスを指定してスキャン。対応形式: txt/md/csv/json/html/htm/xml/svg/docx/pdf/pptx/eml。DOCX/PDF/PPTXは隠し要素・白文字・極小フォントも検出。",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Absolute path to the file to scan",
        },
        categories: {
          type: "array",
          items: { type: "string", enum: CATEGORY_ENUM },
          description: "Optional: limit to specific categories",
        },
        ...VERBOSITY_PROP,
      },
      required: ["file_path"],
    },
  },
  {
    name: "scan_url",
    description:
      "URLを取得して生HTMLをスキャン。AIにWeb記事を読ませる前に白文字・隠し要素・仕込まれた指示文を検出するのに使用。リダイレクト対応、10MB上限。",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "The URL to fetch and scan (http/https)",
        },
        timeout_ms: {
          type: "number",
          description: "Fetch timeout in milliseconds (default: 15000)",
        },
        ...VERBOSITY_PROP,
      },
      required: ["url"],
    },
  },
  {
    name: "scan_email",
    description:
      ".emlファイルまたは生メールテキストをスキャン。ヘッダー/本文/HTML/添付ファイル名を別々に分析するので、どの部分に脅威があるか分かる。添付ファイルの二重拡張子やRLO攻撃も検出。",
    inputSchema: {
      type: "object",
      properties: {
        eml_path: {
          type: "string",
          description: "Absolute path to .eml file (use this OR raw_text)",
        },
        raw_text: {
          type: "string",
          description:
            "Raw email source including headers (use this OR eml_path)",
        },
        ...VERBOSITY_PROP,
      },
    },
  },
  {
    name: "sanitize_text",
    description:
      "検出された脅威を除去したクリーンなテキストを返す。不可視文字・制御文字・隠し要素・疑わしいパターンを削除/置換し、Homoglyphを正規化。",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "The text content to sanitize",
        },
        categories: {
          type: "array",
          items: { type: "string", enum: CATEGORY_ENUM },
          description: "Optional: limit to specific categories",
        },
        ...VERBOSITY_PROP,
      },
      required: ["text"],
    },
  },
  {
    name: "sanitize_file",
    description:
      "検出された脅威を除去したクリーン版ファイルを出力。テキスト系(.txt/.md/.html等)は元形式を保持。バイナリ系(.docx/.pdf/.pptx/.eml)は抽出テキストを.txtで出力。",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Absolute path to the input file",
        },
        output_path: {
          type: "string",
          description:
            "Optional: output path (default: adds '_sanitized' before extension)",
        },
        categories: {
          type: "array",
          items: { type: "string", enum: CATEGORY_ENUM },
          description: "Optional: limit to specific categories",
        },
        ...VERBOSITY_PROP,
      },
      required: ["file_path"],
    },
  },
  {
    name: "scan_mcp_descriptor",
    description:
      "MCP tool descriptor (mcp.json / claude_desktop_config.json / tools-list response) をスキャンしてディスクリプタ汚染攻撃 (CVE-2025-54136 / OWASP MCP03:2025) を検出する。description 内のプロンプトインジェクション・Tags 密輸・隠し指示文、name 重複 (shadow-tool collision)、baseline との SHA256 差分 (rug-pull) を分析。",
    inputSchema: {
      type: "object",
      properties: {
        descriptor: {
          type: "string",
          description:
            "Raw JSON string of the MCP descriptor (tools-list response / mcp.json / claude_desktop_config.json). Use EITHER this OR 'path'.",
        },
        path: {
          type: "string",
          description:
            "Absolute path to the MCP descriptor JSON file. Use EITHER this OR 'descriptor'.",
        },
        baselinePath: {
          type: "string",
          description:
            "Optional: absolute path to a baseline descriptor JSON for rug-pull SHA256 diff detection.",
        },
        ...VERBOSITY_PROP,
      },
    },
  },
];

// ============================================================
// Request handlers
// ============================================================

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools: TOOLS };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    let result;
    switch (name) {
      case "scan_text":
        result = await scanText(args);
        break;
      case "scan_file":
        result = await scanFile(args);
        break;
      case "scan_url":
        result = await scanUrl(args);
        break;
      case "scan_email":
        result = await scanEmail(args);
        break;
      case "sanitize_text":
        result = await sanitizeText(args);
        break;
      case "sanitize_file":
        result = await sanitizeFile(args);
        break;
      case "scan_mcp_descriptor":
        result = await scanMcpDescriptor(args);
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    // QW3: compact verbosity returns ONLY the one-line summary JSON — no
    // findings array, no full JSON dump. This is the 10-50x token-saving path
    // for batch/loop callers (scan_email repeated, dashboard polling, etc.).
    if (args && args.verbosity === "compact") {
      return {
        content: [
          {
            type: "text",
            text:
              (result && result.one_line ? result.one_line + "\n" : "") +
              JSON.stringify(result, null, 2),
          },
        ],
      };
    }

    // Return the report as human-readable text, with full JSON in a second block
    const reportText = result.report || buildFallbackReport(result);

    return {
      content: [
        { type: "text", text: reportText },
        {
          type: "text",
          text: "\n--- Full result (JSON) ---\n" + JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (err) {
    return {
      content: [
        {
          type: "text",
          text: `[Shield Scanner MCP Error] ${err.message}`,
        },
      ],
      isError: true,
    };
  }
});

function buildFallbackReport(result) {
  if (!result) return "(empty result)";
  const lines = ["=== Shield Scanner Result ==="];
  if (result.cleaned_path) {
    lines.push(`Cleaned file saved to: ${result.cleaned_path}`);
    if (result.removed_counts) {
      lines.push(
        `Removed: ${JSON.stringify(result.removed_counts)}`
      );
    }
  } else if (result.cleaned_text !== undefined) {
    lines.push(
      `Sanitized text (${result.cleaned_length}/${result.original_length} chars kept)`
    );
    if (result.removed_counts) {
      lines.push(`Removed: ${JSON.stringify(result.removed_counts)}`);
    }
  }
  return lines.join("\n");
}

// ============================================================
// Start server
// ============================================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Log to stderr so it doesn't interfere with stdio protocol
  console.error(`[${SERVER_NAME} v${SERVER_VERSION}] Server running on stdio`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
