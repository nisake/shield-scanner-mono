// CSV parser (S10) - Web mirror of packages/mcp/server/parsers/csv.js.
//
// Pure JS RFC 4180-aware quote-tracking line + cell splitter (no Papa Parse,
// no CDN addition). Emits ONE CELL PER LINE with a `[Row N, Col M] ` bracket
// prefix so detectFormulaInjection's per-cell numeric/phone suppression
// regexes (anchored ^...$) work correctly.
//
// Encoding handling:
//   - BOM sniff: UTF-8 (EF BB BF), UTF-16 LE (FF FE), UTF-16 BE (FE FF)
//   - No BOM + high-bit bytes → try TextDecoder('shift-jis')
//   - Shift-JIS unsupported (Safari historically) → emit info-only warning
//
// Caps:
//   CSV_MAX_BYTES = 10 MB (short-circuit + warning)
//   CSV_MAX_ROWS  = 100000 (stop walking + warning)
//
// R12 (no shadow-leak): raw cell content is wrapped in `[Row N, Col M] cell`
// scaffolding only. Cell content goes through escapeForDisplay when surfaced
// in a hiddenFinding label/content.
// R13: hiddenFindings here only carry encoding info — category 'hiddenHtml'.
//      Formula-injection findings flow through analyze() with fileType='csv'.

import { escapeForDisplay } from '@shield-scanner/core';

const CSV_MAX_BYTES = 10 * 1024 * 1024;
const CSV_MAX_ROWS = 100000;

function _decodeBuffer(buffer) {
  const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  // BOM sniff
  if (u8.length >= 3 && u8[0] === 0xef && u8[1] === 0xbb && u8[2] === 0xbf) {
    return {
      text: new TextDecoder('utf-8', { fatal: false }).decode(u8.subarray(3)),
      encoding: 'utf-8',
      note: null,
    };
  }
  if (u8.length >= 2 && u8[0] === 0xff && u8[1] === 0xfe) {
    return {
      text: new TextDecoder('utf-16le', { fatal: false }).decode(u8.subarray(2)),
      encoding: 'utf-16le',
      note: null,
    };
  }
  if (u8.length >= 2 && u8[0] === 0xfe && u8[1] === 0xff) {
    return {
      text: new TextDecoder('utf-16be', { fatal: false }).decode(u8.subarray(2)),
      encoding: 'utf-16be',
      note: null,
    };
  }

  // No BOM. Try UTF-8 first; if there are high-bit bytes and UTF-8 fatal
  // would have failed, fall back to Shift-JIS.
  let hasHighBit = false;
  for (let i = 0; i < u8.length; i++) {
    if (u8[i] >= 0x80) {
      hasHighBit = true;
      break;
    }
  }
  // Try strict UTF-8 first when high-bit bytes are present so we can tell if
  // the file is genuinely UTF-8 (no fallback needed) vs. a non-UTF-8 export.
  if (hasHighBit) {
    try {
      const strict = new TextDecoder('utf-8', { fatal: true }).decode(u8);
      return { text: strict, encoding: 'utf-8', note: null };
    } catch {
      // Fall through to Shift-JIS attempt.
    }
    try {
      const sj = new TextDecoder('shift-jis', { fatal: false }).decode(u8);
      return { text: sj, encoding: 'shift-jis', note: null };
    } catch {
      // Browser doesn't support Shift-JIS (historically Safari) — fall back
      // to lenient UTF-8 and surface an info finding for the caller.
      return {
        text: new TextDecoder('utf-8', { fatal: false }).decode(u8),
        encoding: 'utf-8-lenient',
        note: 'encoding may be non-UTF8',
      };
    }
  }

  // Pure ASCII path.
  return {
    text: new TextDecoder('utf-8', { fatal: false }).decode(u8),
    encoding: 'utf-8',
    note: null,
  };
}

// RFC 4180 quote-aware row + cell splitter.
//  - Fields may be wrapped in "..." with doubled-quote ("") for literal ".
//  - CRLF, LF, and CR all terminate rows.
//  - Inside a quoted field, line terminators do NOT split the row.
function _parseCsv(text, rowCap) {
  const rows = [];
  let row = [];
  let field = '';
  let i = 0;
  let inQuotes = false;
  const len = text.length;
  let rowCount = 0;
  let cappedAt = -1;

  while (i < len) {
    const ch = text.charCodeAt(i);
    if (inQuotes) {
      if (ch === 0x22 /* " */) {
        if (i + 1 < len && text.charCodeAt(i + 1) === 0x22) {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      field += text.charAt(i);
      i++;
      continue;
    }
    if (ch === 0x22) {
      // Quoted-field opener (or stray " inside non-quoted field — emit literal)
      if (field.length === 0) {
        inQuotes = true;
        i++;
        continue;
      }
      field += '"';
      i++;
      continue;
    }
    if (ch === 0x2c /* , */) {
      row.push(field);
      field = '';
      i++;
      continue;
    }
    if (ch === 0x0d /* \r */ || ch === 0x0a /* \n */) {
      row.push(field);
      field = '';
      rows.push(row);
      row = [];
      rowCount++;
      if (rowCount >= rowCap) {
        cappedAt = rowCount;
        break;
      }
      // Skip CRLF as one terminator.
      if (ch === 0x0d && i + 1 < len && text.charCodeAt(i + 1) === 0x0a) {
        i += 2;
      } else {
        i++;
      }
      continue;
    }
    field += text.charAt(i);
    i++;
  }

  if (cappedAt < 0 && (field.length > 0 || row.length > 0)) {
    row.push(field);
    rows.push(row);
  }

  return { rows, cappedAt };
}

async function parseCsv(buffer) {
  const hiddenFindings = [];
  const byteLen = buffer.byteLength != null ? buffer.byteLength : buffer.length;

  if (byteLen > CSV_MAX_BYTES) {
    hiddenFindings.push({
      element: 'CSV',
      technique: 'csv-scan-limit-bytes',
      content: `(${byteLen} bytes)`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'CSV',
      meta: { maxBytes: CSV_MAX_BYTES, byteLen },
    });
    // Continue with a truncated buffer view.
  }

  const u8 =
    buffer instanceof Uint8Array
      ? buffer.subarray(0, Math.min(buffer.length, CSV_MAX_BYTES))
      : new Uint8Array(buffer, 0, Math.min(byteLen, CSV_MAX_BYTES));

  const decoded = _decodeBuffer(u8);
  if (decoded.note) {
    hiddenFindings.push({
      element: 'CSV encoding',
      technique: 'csv-encoding-fallback',
      content: `(decoded as ${decoded.encoding})`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'CSV',
      meta: { encoding: decoded.encoding, note: decoded.note },
    });
  }

  const { rows, cappedAt } = _parseCsv(decoded.text, CSV_MAX_ROWS);
  if (cappedAt >= 0) {
    hiddenFindings.push({
      element: 'CSV',
      technique: 'csv-scan-limit-rows',
      content: `(stopped at row ${cappedAt})`,
      severity: 'warning',
      category: 'hiddenHtml',
      contextLocation: 'CSV',
      meta: { maxRows: CSV_MAX_ROWS, cappedAt },
    });
  }

  // Emit one cell per output line with `[Row N, Col M] ` prefix.
  // Row / Col are 1-indexed for human readability (matches MCP).
  const out = [];
  for (let r = 0; r < rows.length; r++) {
    const row = rows[r];
    for (let c = 0; c < row.length; c++) {
      const cell = row[c];
      if (cell === undefined || cell === null) continue;
      // Always emit a prefix — even for empty cells — so the line numbering
      // is stable and downstream detection / sanitization round-trips
      // produce a deterministic output stream.
      out.push(`[Row ${r + 1}, Col ${c + 1}] ${cell}`);
    }
  }

  // Defensive: escapeForDisplay is intentionally NOT applied to the joined
  // text — analyze()/sanitize() operate on the raw cell content. Hidden
  // findings (above) are the only path where cell text would surface to UI,
  // and those are clamped + escaped already.
  void escapeForDisplay; // silence unused-import-only lint in case future strip

  return {
    text: out.join('\n'),
    hiddenFindings,
    fileType: 'csv',
  };
}

export { parseCsv };
