/**
 * PDF-DEEP-05 — Structure-tree walker primitives.
 *
 * Pure-logic helpers used by `packages/mcp/server/parsers/pdf.js` and
 * `packages/web/src/parsers-web/pdf.js`. No pdfjs / fs / env dependencies —
 * this module is safe to import from any environment and from tests without
 * setEnv() wiring.
 *
 * Background: pdf.js v4's `pdf.getStructTree()` returns a serializable tree
 *
 *   { role: 'Root', children: [
 *       { role: 'Document', children: [
 *           { role: 'Figure', alt?: 'caption', children: [
 *               { type: 'content', id: '...' } | { type: 'object', id: '...' }
 *           ] },
 *           { role: 'P', children: [...] },
 *           ...
 *       ] },
 *   ] }
 *
 * Each StructTreeNode carries a `role` (mapped through the document's role map)
 * and an optional `alt` field that pdf.js synthesizes from either /Alt or
 * /ActualText on the underlying PDF struct element. Children are either nested
 * StructTreeNode objects or terminal StructTreeContent / object / annotation
 * references.
 *
 * Image XObjects appear as struct elements with role === 'Figure' (or any
 * standard-structure-type that role-maps to Figure). Their /Alt and
 * /ActualText payloads are attacker-controlled text that, prior to PDF-DEEP-05,
 * never reached the central suspicious-patterns / instruction detectors —
 * users who relied on screen-reader-style metadata to surface hidden prompts
 * had no signal.
 *
 * walkStructTree() yields one record per Figure-class node with text content,
 * with cycle defense, depth/node caps, and per-field length truncation. The
 * caller is responsible for pushing the yielded text through the normal scan
 * pipeline (with `escapeForDisplay` via pushText) and for cap-exceed warnings.
 *
 * R12 reminder for callers:
 *   - alt / actualText are attacker-controlled. Pass them through
 *     `escapeForDisplay` (or the parser's existing pushText) before surfacing
 *     them in finding.content fields. NEVER place raw alt text into
 *     contextLocation.
 *   - contextLocation must be detector-controlled values only:
 *     `Page N, StructTree[Figure] /Alt` — role is a small enum, field is a
 *     fixed string.
 *
 * R13 reminder for callers:
 *   - Surface findings via pushText so they fold into the existing 5 buckets
 *     (invisibleUnicode / controlChars / hiddenHtml / suspiciousPatterns /
 *     homoglyphs). Do NOT introduce a new top-level byCategory key for struct
 *     tree findings — they ride the existing pipeline.
 */

export const PDF_STRUCT_CAPS = Object.freeze({
  MAX_DEPTH: 5,
  MAX_NODES: 256,
  MAX_TEXT_LEN: 500,
});

// Roles whose /Alt or /ActualText the walker surfaces. Spec-aligned standard
// structure types we cover (v1.19.0): Figure, Formula, Form, Sect, L, Table,
// Caption, TOC, TOCI, Index, LI, Note, H1, H2, H3, H4, H5, H6, BlockQuote,
// Quote, Span.
// Originally introduced (v1.12.0/v1.13.0) as "IMAGE_ROLES" for image-bearing
// elements (Figure / Formula / Form). v1.15.0 Theme C extended the set to
// section / list / table containers (Sect / L / Table) because their /Alt and
// /ActualText carry the same caption-style attacker-controlled text
// (screen-reader metadata channel) — the threat model is identical, only the
// spec-defined role name differs. Renamed to STRUCT_ROLES to truthfully
// describe the generalization. v1.16.0 Theme T-B further extends the set with
// 6 more standard structure types (ISO 32000-1 §14.8.4): Caption (figure /
// table caption — highest-leverage screen-reader metadata channel), TOC + TOCI
// (table-of-contents container + per-item), Index (alphabetical reference
// container), LI (list-item child of L, closes the L/LI granularity gap), and
// Note (inline footnote/endnote). v1.19.0 A3 further extends with 9 more
// standard structure types (ISO 32000-1 §14.8.4): H1-H6 (heading levels 1-6 —
// high-leverage TTS / outline metadata channel; the heading role is the most
// commonly-tagged element in real-world accessible PDFs alongside P), BlockQuote
// (block-level quotation container — common channel for "quoted from another
// document" payloads), Quote (inline quotation — short-form sibling of
// BlockQuote), and Span (generic inline-level element used for screen-reader
// hints and inline metadata, identical threat model to Caption). All wire
// identically via the walker — pure Set-literal extension, zero walker logic
// changes.
const STRUCT_ROLES = Object.freeze(
  new Set([
    "Figure",
    "Formula",
    "Form",
    "Sect",
    "L",
    "Table",
    "Caption",
    "TOC",
    "TOCI",
    "Index",
    "LI",
    "Note",
    "H1",
    "H2",
    "H3",
    "H4",
    "H5",
    "H6",
    "BlockQuote",
    "Quote",
    "Span",
  ]),
);

/**
 * Walk a pdf.js StructTreeNode (the value returned by `page.getStructTree()`)
 * yielding one record per image-bearing struct element that carries either
 * an `alt` field (set by pdf.js from PDF /Alt OR /ActualText — pdf.js merges
 * them; see pdf.worker.mjs L41104-L41110) or an explicit `actualText` field
 * (some callers / synthetic test mocks set both).
 *
 * Each yielded record:
 *   {
 *     role: string,              // 'Figure' | 'Formula' | 'Form' | 'Sect' | 'L' | 'Table' | 'Caption' | 'TOC' | 'TOCI' | 'Index' | 'LI' | 'Note' | 'H1'..'H6' | 'BlockQuote' | 'Quote' | 'Span'
 *     alt: string,               // /Alt value, truncated to MAX_TEXT_LEN
 *     actualText: string,        // /ActualText value, truncated to MAX_TEXT_LEN
 *     pathSegments: number[],    // child indexes from root to this node
 *   }
 *
 * Yields nothing when alt and actualText are both empty / non-string.
 *
 * Caps:
 *   - depth > MAX_DEPTH → subtree skipped silently
 *   - cumulative nodes visited >= MAX_NODES → walk stops; caller decides
 *     whether to surface a separate cap-exceeded warning
 *   - cycle (visited Set) → revisit skipped silently
 *
 * @param {{ role?: string, children?: Array, alt?: string, actualText?: string }} rootNode
 * @param {{ maxDepth?: number, maxNodes?: number, maxTextLen?: number, structRoles?: Set<string> }} [opts]
 * @returns {{ records: Array<{role:string, alt:string, actualText:string, pathSegments:number[]}>, capExceeded: boolean, nodeCount: number }}
 */
export function walkStructTree(rootNode, opts = {}) {
  const records = [];
  const out = { records, capExceeded: false, nodeCount: 0 };
  if (!rootNode || typeof rootNode !== "object") return out;

  const MAX_DEPTH = Number.isInteger(opts.maxDepth) ? opts.maxDepth : PDF_STRUCT_CAPS.MAX_DEPTH;
  const MAX_NODES = Number.isInteger(opts.maxNodes) ? opts.maxNodes : PDF_STRUCT_CAPS.MAX_NODES;
  const MAX_TEXT_LEN = Number.isInteger(opts.maxTextLen) ? opts.maxTextLen : PDF_STRUCT_CAPS.MAX_TEXT_LEN;
  const structRoles = opts.structRoles instanceof Set ? opts.structRoles : STRUCT_ROLES;

  // Cycle defense: identity-based Set so two distinct nodes with the same
  // role+alt don't collide. pdf.js's serializer hands us a fresh object graph
  // per call, but malformed PDFs (or future API changes that reuse refs) could
  // expose us to cycles; the visited Set keeps the walk bounded either way.
  const visited = new WeakSet();

  function truncate(s) {
    if (typeof s !== "string") return "";
    if (s.length <= MAX_TEXT_LEN) return s;
    return s.slice(0, MAX_TEXT_LEN);
  }

  function walk(node, depth, pathSegments) {
    if (out.capExceeded) return;
    if (!node || typeof node !== "object") return;
    if (visited.has(node)) return;
    visited.add(node);

    if (out.nodeCount >= MAX_NODES) {
      out.capExceeded = true;
      return;
    }
    out.nodeCount += 1;

    // Only StructTreeNode (has role / children) is interesting. Terminal
    // StructTreeContent entries ({ type: 'content', id: '...' }) carry no
    // alt / actualText / children so they pass through here as a no-op aside
    // from the nodeCount tick.
    const role = typeof node.role === "string" ? node.role : "";

    if (role && structRoles.has(role)) {
      // pdf.js sets `obj.alt` from /Alt OR /ActualText (Alt wins, ActualText
      // fallback) — see pdf.worker.mjs ~L41104. We surface both fields as
      // separate slots so synthetic test mocks (which can set both) and any
      // future pdf.js change that surfaces them separately keep working. In
      // real captured PDFs only one will typically be non-empty.
      const alt = truncate(typeof node.alt === "string" ? node.alt : "");
      const actualText = truncate(typeof node.actualText === "string" ? node.actualText : "");
      if (alt.trim() || actualText.trim()) {
        records.push({
          role,
          alt,
          actualText,
          pathSegments: pathSegments.slice(),
        });
      }
    }

    if (depth >= MAX_DEPTH) return;
    const kids = Array.isArray(node.children) ? node.children : null;
    if (!kids) return;
    for (let i = 0; i < kids.length; i++) {
      if (out.capExceeded) return;
      pathSegments.push(i);
      walk(kids[i], depth + 1, pathSegments);
      pathSegments.pop();
    }
  }

  walk(rootNode, 0, []);
  return out;
}

/**
 * Tiny utility: derive a single `[PDF page=N kind=structtree role=R field=F]`
 * header key segment for the role + field name. Mirrors `sanitizeKey` in
 * pdf.js parsers (replace whitespace / brackets, cap length). Exported so MCP
 * + Web parsers can format the header identically without duplicating logic.
 *
 * @param {string} s
 * @returns {string}
 */
export function sanitizeStructKey(s) {
  return String(s).replace(/[\s\[\]]+/g, "_").slice(0, 64);
}
