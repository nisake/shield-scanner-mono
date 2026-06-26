/**
 * Tool: scan_url
 *
 * Fetch a URL and scan its raw HTML for hidden threats.
 * Use this BEFORE letting AI read a web article to catch white-text,
 * hidden elements, and injection prompts embedded in the page.
 *
 * Uses Node 18+'s global fetch.
 *
 * `verbosity` (QW3): "compact" | "normal" (default) | "detailed"
 */

import { analyze, formatReport } from "@shield-scanner/core";
import { compactSummary, expandFindingsContext } from "@shield-scanner/core";

const DEFAULT_TIMEOUT_MS = 15000;
const MAX_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB safety cap

export async function scanUrl({
  url,
  timeout_ms = DEFAULT_TIMEOUT_MS,
  verbosity = "normal",
}) {
  if (!url || typeof url !== "string") {
    throw new Error("'url' is required");
  }

  // Validate URL
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error(`Invalid URL: ${url}`);
  }
  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    throw new Error(`Only http/https URLs are supported (got ${parsedUrl.protocol})`);
  }

  // Fetch with timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout_ms);

  let response;
  try {
    response = await fetch(url, {
      signal: controller.signal,
      headers: {
        // Identify ourselves so operators know the source
        "User-Agent": "Shield-Scanner-MCP/1.0 (security scanner)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      redirect: "follow",
    });
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      throw new Error(`Fetch timed out after ${timeout_ms}ms`);
    }
    throw new Error(`Fetch failed: ${err.message}`);
  }
  clearTimeout(timeoutId);

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} ${response.statusText}`);
  }

  // Size cap
  const contentLength = response.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_SIZE_BYTES) {
    throw new Error(
      `Response too large: ${contentLength} bytes (max ${MAX_SIZE_BYTES})`
    );
  }

  const contentType = response.headers.get("content-type") || "";
  const html = await response.text();

  if (html.length > MAX_SIZE_BYTES) {
    throw new Error(
      `Response too large: ${html.length} bytes (max ${MAX_SIZE_BYTES})`
    );
  }

  // Detect fileType by content-type (falls back to html if it contains tags)
  const looksLikeHtml = /<[a-z][\s\S]*>/i.test(html);
  const fileType =
    contentType.includes("html") || contentType.includes("xml") || looksLikeHtml
      ? "html"
      : "text";

  const result = analyze(html, { fileType });

  if (verbosity === "compact") {
    return {
      verbosity: "compact",
      url: response.url,
      fetched_at: new Date().toISOString(),
      status: response.status,
      content_type: contentType,
      html_size: html.length,
      ...compactSummary(result),
    };
  }

  const report = formatReport(result, {
    fileName: url,
    scannedAt: new Date().toISOString(),
  });

  const findings =
    verbosity === "detailed"
      ? expandFindingsContext(result.findings, html)
      : result.findings;

  return {
    verbosity,
    summary: result.summary,
    findings,
    url: response.url, // final URL after redirects
    fetched_at: new Date().toISOString(),
    status: response.status,
    content_type: contentType,
    html_size: html.length,
    report,
  };
}
