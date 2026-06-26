/**
 * OPC (Open Packaging Conventions) shared helpers for XLSX / DOCX / PPTX
 * parsers. Pure-JS, no dependencies, no env access.
 *
 * Exported helpers:
 *   - parseRelationships(xmlString)   — walk <Relationship Id Type Target TargetMode/>
 *   - parseContentTypes(xmlString)    — walk <Override PartName ContentType/>
 *   - normalizeXlfn(formulaText)      — strip _xlfn. / _xlfn._xlws. multi-prefix
 *   - normalizeFormulaPrefix(cellText)— strip leading whitespace + map
 *                                       U+FF1D / U+FE66 / U+2E40 to '='
 *
 * Regex-on-XML by design (R14 library trap — no fast-xml-parser / cheerio).
 * R18 (env-abstract order contract): this module is dependency-free and does
 * NOT call loadRule() at module-load time, so it is safe to import before
 * setEnv() runs.
 */

/**
 * Parse an OPC .rels XML string into a flat array of relationships.
 *
 * Input shape (typical):
 *   <Relationships xmlns="...">
 *     <Relationship Id="rId1" Type="..." Target="..." TargetMode="External"/>
 *     ...
 *   </Relationships>
 *
 * Attribute order is NOT guaranteed by the OOXML producer, so we scan each
 * <Relationship .../> element body with per-attribute regexes rather than a
 * single fixed-order pattern. Self-closing form (`/>`) and explicit-close form
 * (`></Relationship>`) are both accepted.
 *
 * Returns: [{ id, type, target, targetMode }]. Missing attributes come back as
 * empty strings (callers expect a stable shape).
 *
 * @param {string} xmlString
 * @returns {Array<{id:string,type:string,target:string,targetMode:string}>}
 */
export function parseRelationships(xmlString) {
  if (typeof xmlString !== "string" || xmlString.length === 0) return [];
  const out = [];
  // Capture each <Relationship ...> opening tag body (handles both self-close
  // /> and open >).
  const tagRe = /<Relationship\b([^>]*)\/?>/gi;
  let m;
  while ((m = tagRe.exec(xmlString)) !== null) {
    const attrs = m[1] || "";
    out.push({
      id: _attr(attrs, "Id"),
      type: _attr(attrs, "Type"),
      target: _attr(attrs, "Target"),
      targetMode: _attr(attrs, "TargetMode"),
    });
  }
  return out;
}

/**
 * Parse an OPC [Content_Types].xml into a flat array of per-part overrides.
 *
 * Input shape:
 *   <Types xmlns="...">
 *     <Default Extension="xml" ContentType="application/xml"/>
 *     <Override PartName="/xl/workbook.xml" ContentType="application/vnd...xml"/>
 *     ...
 *   </Types>
 *
 * We only emit <Override> entries here (PartName-keyed). <Default> entries
 * are extension-keyed and rarely useful for the security-related checks
 * (extension/contentType mismatch is best evaluated via Override entries +
 * the file's actual extension).
 *
 * @param {string} xmlString
 * @returns {Array<{partName:string,contentType:string}>}
 */
export function parseContentTypes(xmlString) {
  if (typeof xmlString !== "string" || xmlString.length === 0) return [];
  const out = [];
  const tagRe = /<Override\b([^>]*)\/?>/gi;
  let m;
  while ((m = tagRe.exec(xmlString)) !== null) {
    const attrs = m[1] || "";
    out.push({
      partName: _attr(attrs, "PartName"),
      contentType: _attr(attrs, "ContentType"),
    });
  }
  return out;
}

/**
 * Strip `_xlfn.` and `_xlfn._xlws.` multi-prefix from a formula text.
 *
 * Excel uses `_xlfn.` to namespace functions added after the original
 * formula-set (CONCAT, IFS, etc.). Attackers stack the prefix multiple times
 * (`_xlfn._xlfn.HYPERLINK(...)`) to defeat naive function-name regexes.
 * We collapse the prefix run repeatedly until none remains.
 *
 * Match is case-insensitive at the start of the string only (no inner
 * stripping — `=A1+_xlfn.NORM.S(B1)` legitimately ships the prefix mid-formula
 * and we must not touch the rest of the expression).
 *
 * @param {string} formulaText
 * @returns {string}
 */
export function normalizeXlfn(formulaText) {
  if (typeof formulaText !== "string" || formulaText.length === 0) {
    return formulaText;
  }
  let s = formulaText;
  // Strip an optional leading '=' for the prefix scan, restore at the end.
  let lead = "";
  if (s.charCodeAt(0) === 0x3d) {
    lead = "=";
    s = s.slice(1);
  }
  // Repeat-strip _xlfn. and _xlfn._xlws. (and the inverse order) until none.
  // Case-insensitive at the head.
  // We use a simple while-loop so stacked prefixes (_xlfn._xlfn.HYPERLINK,
  // _xlfn._xlws._xlfn.IMPORTXML, etc.) all collapse.
  const prefixRe = /^_xlfn\.(?:_xlws\.)?/i;
  // Safety cap (defensive: bounded loop in case of pathological input).
  for (let i = 0; i < 16; i++) {
    if (!prefixRe.test(s)) break;
    s = s.replace(prefixRe, "");
  }
  return lead + s;
}

/**
 * Normalize a CSV / XLSX cell text BEFORE applying the formula-injection
 * leading-char gate.
 *
 * Steps (order matters):
 *   1. Strip leading ASCII whitespace (\t \r \n is intentionally LEFT
 *      in-place — TAB and CR ARE attack-relevant leading chars per FI-02).
 *      Only spaces (U+0020) and U+00A0 (no-break space) are dropped. This
 *      keeps `'\t=cmd|...'` (TAB-prefix bypass) detectable.
 *   2. Map common fullwidth / decorative equals to ASCII '=':
 *        U+FF1D FULLWIDTH EQUALS SIGN
 *        U+FE66 SMALL EQUALS SIGN
 *        U+2E40 DOUBLE HYPHEN (visually similar in some terminals)
 *      Note: U+2E40 is an aggressive include from the spec list — the spec
 *      says "U+FF1D / U+FE66 / U+2E40 to '='". We honor that verbatim.
 *
 * @param {string} cellText
 * @returns {string}
 */
export function normalizeFormulaPrefix(cellText) {
  if (typeof cellText !== "string" || cellText.length === 0) return cellText;
  // Strip leading spaces / no-break-space only. Do NOT strip \t / \r / \n —
  // they ARE the prefix triggers per FI-02 (TAB / CR bypass).
  let i = 0;
  while (i < cellText.length) {
    const cp = cellText.charCodeAt(i);
    if (cp === 0x20 || cp === 0xa0) {
      i++;
      continue;
    }
    break;
  }
  let s = i > 0 ? cellText.slice(i) : cellText;
  if (s.length === 0) return s;
  const first = s.charCodeAt(0);
  // Map fullwidth / small / double-hyphen equals to ASCII '='.
  if (first === 0xff1d || first === 0xfe66 || first === 0x2e40) {
    s = "=" + s.slice(1);
  }
  return s;
}

/**
 * Extract an XML attribute value from an attribute-bearing string fragment.
 * Accepts both double-quoted and single-quoted forms. Returns "" when not
 * found. Pure helper — used by parseRelationships / parseContentTypes only.
 */
function _attr(attrFragment, name) {
  if (!attrFragment) return "";
  // Look for name="value" first (the OOXML default), then fall back to
  // single-quoted form for hand-rolled inputs.
  const reD = new RegExp(`\\b${_escapeRe(name)}\\s*=\\s*"([^"]*)"`, "i");
  const md = reD.exec(attrFragment);
  if (md) return md[1];
  const reS = new RegExp(`\\b${_escapeRe(name)}\\s*=\\s*'([^']*)'`, "i");
  const ms = reS.exec(attrFragment);
  if (ms) return ms[1];
  return "";
}

function _escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
