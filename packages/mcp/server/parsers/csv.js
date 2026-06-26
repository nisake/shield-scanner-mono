/**
 * S10 — CSV parser (RFC 4180-aware).
 *
 * Replaces the generic text-route handling for `.csv` so the file's actual
 * structure (rows, columns, quoted cells) participates in detection. Each
 * cell is emitted on its own line with a `[Row N, Col M] ` prefix; the
 * downstream formula-injection detector in `@shield-scanner/core` (wired into
 * `analyze()` when `fileType === 'csv'`) walks that line stream and keeps
 * per-cell numeric / phone suppression anchored correctly.
 *
 * Why a hand-rolled splitter:
 *   - Zero new dependencies (R14 library trap — docx / pptx use JSZip + regex
 *     by convention).
 *   - The detection contract only needs cell text; full CSV semantics (header
 *     row, type inference, etc.) are not relevant.
 *   - RFC 4180 quote-handling is ~60 LOC.
 *
 * Defensive caps:
 *   - CSV_MAX_BYTES = 10 MB (whole archive — protects against tab OOM on Web
 *     and unbounded memory on MCP). Over-cap → emit warning extraFinding and
 *     scan the leading slice only.
 *   - CSV_MAX_ROWS  = 100 000 rows.
 *
 * BOM sniff:
 *   - UTF-8 BOM (EF BB BF) — strip and decode as UTF-8.
 *   - UTF-16 LE BOM (FF FE) — TextDecoder('utf-16le').
 *   - UTF-16 BE BOM (FE FF) — TextDecoder('utf-16be').
 *   - No BOM → UTF-8 (TextDecoder fatal:false). Shift-JIS heuristics are
 *     shouldHave scope for next session (the parity contract is BOM-based
 *     only this round — see s10-spec.json risks).
 *
 * Output shape:
 *   { text, fileType: 'csv', extraFindings, fileInfo }
 *
 * extraFindings carry only structural / encoding warnings — formula-injection
 * findings are emitted by the core `detectFormulaInjection` detector when
 * `analyze()` is called with fileType === 'csv', so the parser does NOT
 * pre-call the detector here (avoids double-counting).
 *
 * R12: cell text is prefixed with `[Row N, Col M] `, which is parser
 * scaffolding (we know the row/col coordinate). The cell content is NOT
 * touched — downstream detectors see the raw cell value and pass it through
 * escapeForDisplay before any UI label use.
 */

import { readFile } from "node:fs/promises";

const CSV_MAX_BYTES = 10 * 1024 * 1024;
const CSV_MAX_ROWS = 100000;

export async function parseCsv(filePath) {
  const buffer = await readFile(filePath);
  return parseCsvBuffer(buffer);
}

/**
 * Parse a CSV from a Buffer / Uint8Array. Returns the line-stream form expected
 * by `detectFormulaInjection`.
 *
 * @param {Buffer|Uint8Array} buffer
 * @param {Object} [opts]
 * @returns {Promise<{text:string, fileType:'csv', extraFindings:Array}>}
 */
export async function parseCsvBuffer(buffer, opts = {}) {
  const extraFindings = [];

  // Coerce to Uint8Array so the BOM + size checks are uniform across Buffer
  // (Node) and Uint8Array (Web) callers.
  const u8 =
    buffer instanceof Uint8Array
      ? buffer
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  // --- Defensive cap: oversize archive ---
  let scanU8 = u8;
  let truncated = false;
  if (u8.byteLength > CSV_MAX_BYTES) {
    scanU8 = u8.subarray(0, CSV_MAX_BYTES);
    truncated = true;
    extraFindings.push({
      element: "CSV File",
      technique: "CSV exceeds scan limits — partial scan",
      content: `(file > ${CSV_MAX_BYTES} bytes; scanning leading slice only)`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "CSV File",
    });
  }

  // --- BOM sniff + decode ---
  let text = "";
  try {
    text = decodeWithBom(scanU8);
  } catch (err) {
    // Fail-soft on unsupported encoding (Safari historically lacks shift-jis).
    extraFindings.push({
      element: "CSV File",
      technique: "Encoding decode failure — falling back to UTF-8",
      content: `(${err && err.message ? err.message : "unknown decode error"})`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "CSV File",
    });
    try {
      text = new TextDecoder("utf-8", { fatal: false }).decode(scanU8);
    } catch {
      text = "";
    }
  }

  // --- RFC 4180-aware splitter ---
  // Walks the decoded text once, tracking a single quoted-state flag. Cells are
  // emitted into `cellsByRow[r] = [cellText, ...]` so we can apply the
  // per-cell `[Row N, Col M] ` prefix at line emit time.
  const cellsByRow = parseCsvRows(text, CSV_MAX_ROWS);

  if (cellsByRow.length === CSV_MAX_ROWS && !truncated) {
    // Row cap hit — emit a structural warning so the consumer knows the trailing
    // rows are not covered. Truncated archive already emits its own oversize
    // warning, so we only emit when row cap fires standalone.
    extraFindings.push({
      element: "CSV File",
      technique: "CSV exceeds row limit — partial scan",
      content: `(row count >= ${CSV_MAX_ROWS}; trailing rows skipped)`,
      severity: "warning",
      category: "hiddenHtml",
      contextLocation: "CSV File",
    });
  }

  // --- Emit one cell per line with [Row N, Col M] prefix ---
  // 1-based row / column indices for human-readable contextLocation strings.
  const out = [];
  for (let r = 0; r < cellsByRow.length; r++) {
    const row = cellsByRow[r];
    for (let c = 0; c < row.length; c++) {
      const cell = row[c];
      // Skip wholly empty cells — they cannot carry an attack and emitting
      // them only inflates the line stream. Whitespace-only cells DO pass
      // (the formula-injection detector normalizes them and short-circuits
      // benignly).
      if (cell.length === 0) continue;
      out.push(`[Row ${r + 1}, Col ${c + 1}] ${cell}`);
    }
  }

  return {
    text: out.join("\n"),
    fileType: "csv",
    extraFindings,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Decode a Uint8Array with BOM sniff. Throws on unsupported labels (caller
 * catches and falls back to UTF-8).
 */
function decodeWithBom(u8) {
  if (u8.byteLength >= 3 && u8[0] === 0xef && u8[1] === 0xbb && u8[2] === 0xbf) {
    return new TextDecoder("utf-8", { fatal: false }).decode(u8.subarray(3));
  }
  if (u8.byteLength >= 2 && u8[0] === 0xff && u8[1] === 0xfe) {
    return new TextDecoder("utf-16le", { fatal: false }).decode(u8.subarray(2));
  }
  if (u8.byteLength >= 2 && u8[0] === 0xfe && u8[1] === 0xff) {
    return new TextDecoder("utf-16be", { fatal: false }).decode(u8.subarray(2));
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(u8);
}

/**
 * RFC 4180 quote-aware splitter.
 *
 * Returns a 2-D array `rows[r][c]` of unquoted cell strings. Recognized line
 * terminators: \n, \r\n, \r (bare CR — uncommon but allowed by RFC 4180 §2.2).
 * Quotes inside a quoted field are escaped by doubling (`""` → `"`).
 *
 * Caps:
 *   - maxRows hard-stops the row counter; cells from the in-progress row are
 *     dropped to keep the boundary deterministic.
 *
 * @param {string} text
 * @param {number} maxRows
 * @returns {string[][]}
 */
function parseCsvRows(text, maxRows) {
  const rows = [];
  if (typeof text !== "string" || text.length === 0) return rows;

  let row = [];
  let cell = "";
  let inQuotes = false;
  const len = text.length;
  let i = 0;
  while (i < len) {
    const ch = text.charCodeAt(i);
    if (inQuotes) {
      if (ch === 0x22 /* '"' */) {
        // Doubled quote inside a quoted field → literal quote.
        if (i + 1 < len && text.charCodeAt(i + 1) === 0x22) {
          cell += '"';
          i += 2;
          continue;
        }
        // Closing quote.
        inQuotes = false;
        i++;
        continue;
      }
      // Any other char (including , \n \r) is literal inside a quoted field.
      cell += text[i];
      i++;
      continue;
    }
    if (ch === 0x22 /* '"' */) {
      // Opening quote — only legal at cell start in strict RFC 4180, but we
      // accept embedded opens too (matches Excel's lenient parser).
      inQuotes = true;
      i++;
      continue;
    }
    if (ch === 0x2c /* ',' */) {
      row.push(cell);
      cell = "";
      i++;
      continue;
    }
    if (ch === 0x0a /* \n */) {
      row.push(cell);
      rows.push(row);
      if (rows.length >= maxRows) return rows;
      row = [];
      cell = "";
      i++;
      continue;
    }
    if (ch === 0x0d /* \r */) {
      // Treat \r and \r\n as a single line terminator.
      row.push(cell);
      rows.push(row);
      if (rows.length >= maxRows) return rows;
      row = [];
      cell = "";
      i++;
      if (i < len && text.charCodeAt(i) === 0x0a) i++;
      continue;
    }
    cell += text[i];
    i++;
  }

  // Trailing cell / row (file does not need to end with a newline).
  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}
