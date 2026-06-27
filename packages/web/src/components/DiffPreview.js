// =============================================================
//  Shield Scanner Web — v1.19.0 C2: DiffPreview component
// =============================================================
// Side-by-side Before / After preview of analyze() + sanitize().
//
// LEFT pane  = original text with each finding's range wrapped in a
//              <span class="diff-mark diff-mark-{category}"> so the user
//              can see WHERE the warning lives in the document.
// RIGHT pane = sanitized text. The removed positions from the LEFT pane
//              are rendered as <span class="diff-strike">…</span> with
//              a CSS strikethrough so the user can see WHAT got removed.
//              When a position survives sanitize (e.g. homoglyph
//              normalization that keeps length), it is not struck.
//
// Click contract:
//   The host wires the per-finding cards. When a card is clicked,
//   `DiffPreview.scrollToFinding(id)` is invoked: the matching span(s)
//   scroll into view with a brief CSS pulse. The component itself does
//   NOT call sendPrompt() — that wiring lives in the host (app.js); we
//   expose an `onSpanClick(handler)` hook so the host can emit a
//   sendPrompt('show finding') style message if it wants to.
//
// Virtualization (R-LongDoc):
//   Strings longer than VIRTUAL_THRESHOLD (default 50_000 UTF-16 units)
//   render only the SLICE_WINDOW around the active finding plus a
//   leading/trailing "…N more chars…" sentinel. The user can shift the
//   window via the next/prev buttons in the component header.
//
// Zero-dependency contract:
//   - No cheerio / parse5 / htmlparser2 / dom-serializer / cheerio-select.
//   - No diff-match-patch, no third-party npm.
//   - Pure native DOM API (document.createElement, appendChild,
//     classList, textContent). Any string -> HTML conversion path goes
//     through textContent assignment, never innerHTML with user bytes.
//
// R12 contract:
//   Marker / category labels come from the detector or this component
//   itself. The raw user bytes are passed to textContent so the
//   browser escapes them; no path concatenates `<span>` + user text
//   via innerHTML.
// =============================================================

// ---------------------------------------------------------------------------
// Constants — frozen so the budget audit can grep them statically.
// ---------------------------------------------------------------------------
export const VIRTUAL_THRESHOLD = 50_000;
export const SLICE_WINDOW = 4_000;

// 5-key R13 category fold — must mirror displayResults' detail buckets.
// New categories cannot be added here (R13: byCategory 5 keys 厳密一致).
const CATEGORY_CLASS = Object.freeze({
  invisibleUnicode: 'diff-mark-invisible',
  controlChars: 'diff-mark-control',
  hiddenHtml: 'diff-mark-hidden',
  suspiciousPatterns: 'diff-mark-suspicious',
  homoglyphs: 'diff-mark-homoglyph',
});

// ---------------------------------------------------------------------------
// Pure helpers — exported so the test harness can unit-test them in
// isolation without instantiating a DiffPreview.
// ---------------------------------------------------------------------------

/**
 * Compute the byte-range each finding occupies in the BEFORE text.
 *
 * Rules:
 *   - Findings with a numeric `position` get a range starting at that
 *     position. Length comes from (a) the explicit `runLength` /
 *     `count` field when present (variation-selector run, math run),
 *     (b) the UTF-16 unit length of the `char` field when it is a
 *     single codepoint string, or (c) 1 as the safe default.
 *   - Findings without a `position` (e.g. hiddenHtml/regex hits with
 *     no offset) get an entry with start = end = -1 so they appear in
 *     the legend but contribute no range marker. The component
 *     filters those out when rendering spans.
 *
 * The function returns a NEW array sorted ascending by start, then by
 * end. Overlapping ranges are kept as-is — the renderer collapses
 * them when emitting spans.
 *
 * @param {string} before  the original text
 * @param {Object} findingsByCategory  the analyze() findings object
 *   (5-key R13 shape; extra keys are ignored).
 * @returns {Array<{start:number,end:number,category:string,id:string,severity:string}>}
 */
export function computeMaskedRanges(before, findingsByCategory) {
  const out = [];
  if (typeof before !== 'string' || before.length === 0) return out;
  if (!findingsByCategory || typeof findingsByCategory !== 'object') return out;

  for (const cat of Object.keys(CATEGORY_CLASS)) {
    const arr = Array.isArray(findingsByCategory[cat])
      ? findingsByCategory[cat]
      : [];
    for (let i = 0; i < arr.length; i++) {
      const f = arr[i];
      if (!f || typeof f !== 'object') continue;
      const pos = typeof f.position === 'number' ? f.position : -1;
      if (pos < 0 || pos > before.length) continue;
      let len = 1;
      if (typeof f.runLength === 'number' && f.runLength > 0) len = f.runLength;
      else if (typeof f.count === 'number' && f.count > 0) len = f.count;
      else if (typeof f.char === 'string') {
        // `char` may be the literal char OR a "U+XXXX" descriptor. Only
        // count it as a literal length when it is short and contains no
        // "U+" prefix.
        if (!/^U\+/.test(f.char) && f.char.length <= 4) {
          len = f.char.length;
        }
      } else if (typeof f.matched === 'string') {
        len = Math.min(f.matched.length, 200); // cap stupendous regex hits
      }
      const start = pos;
      const end = Math.min(before.length, pos + len);
      if (end <= start) continue;
      out.push({
        start,
        end,
        category: cat,
        id: `f-${cat}-${i}`,
        severity: typeof f.severity === 'string' ? f.severity : 'warning',
      });
    }
  }
  out.sort((a, b) => (a.start - b.start) || (a.end - b.end));
  return out;
}

/**
 * Walk the BEFORE string and emit a sequence of (text-or-mark) tokens
 * the renderer can convert to DOM nodes. Pure — no DOM access.
 *
 * Overlap policy: when two ranges overlap, the FIRST one wins for the
 * common slice and the second one is clipped to start where the first
 * ends. This keeps the output stream linear and idempotent.
 *
 * @returns {Array<{kind:'text'|'mark', text:string, category?:string, id?:string, severity?:string}>}
 */
export function tokenizeBefore(before, ranges) {
  const tokens = [];
  if (typeof before !== 'string' || before.length === 0) return tokens;
  if (!Array.isArray(ranges) || ranges.length === 0) {
    tokens.push({ kind: 'text', text: before });
    return tokens;
  }
  let cursor = 0;
  for (const r of ranges) {
    const start = Math.max(cursor, r.start);
    const end = r.end;
    if (end <= start) continue;
    if (start > cursor) {
      tokens.push({ kind: 'text', text: before.slice(cursor, start) });
    }
    tokens.push({
      kind: 'mark',
      text: before.slice(start, end),
      category: r.category,
      id: r.id,
      severity: r.severity,
    });
    cursor = end;
  }
  if (cursor < before.length) {
    tokens.push({ kind: 'text', text: before.slice(cursor) });
  }
  return tokens;
}

/**
 * Compute strike-through ranges for the AFTER pane.
 *
 * Strategy: a finding is "removed" in the AFTER pane when its BEFORE
 * substring (before[start..end]) does not appear at the same offset in
 * the AFTER text. We compare by char-equality — the After pane shows
 * those slices wrapped in a <span class="diff-strike"> so the user can
 * still see WHAT was removed (the strikethrough is CSS).
 *
 * The walk is anchored on a single index pair (i_before, i_after) that
 * tries to keep the two strings aligned by skipping past removed
 * slices. Pure — no DOM access.
 *
 * @returns {Array<{kind:'text'|'strike', text:string}>}
 */
export function tokenizeAfter(before, after, ranges) {
  const tokens = [];
  if (typeof after !== 'string') return tokens;
  if (typeof before !== 'string' || !Array.isArray(ranges) || ranges.length === 0) {
    tokens.push({ kind: 'text', text: after });
    return tokens;
  }
  // We walk the BEFORE string + ranges, tracking the After cursor
  // separately. Any range whose BEFORE slice is missing at the
  // current After cursor is emitted as a 'strike' token (the removed
  // bytes are shown crossed out in the After pane). Otherwise the
  // After cursor advances past it.
  let bi = 0;
  let ai = 0;
  for (const r of ranges) {
    if (r.start < bi) continue; // overlap already consumed
    // First copy the unchanged stretch BEFORE this range from the
    // After string into the output.
    const unchangedLen = r.start - bi;
    if (unchangedLen > 0) {
      const slice = after.slice(ai, ai + unchangedLen);
      if (slice.length > 0) tokens.push({ kind: 'text', text: slice });
      ai += unchangedLen;
      bi = r.start;
    }
    const beforeSlice = before.slice(r.start, r.end);
    // Does the After string still contain this slice at the cursor?
    if (after.slice(ai, ai + beforeSlice.length) === beforeSlice) {
      // Sanitize left it intact (e.g. a position-only warning that
      // didn't remove bytes). Emit as plain text.
      tokens.push({ kind: 'text', text: beforeSlice });
      ai += beforeSlice.length;
    } else {
      // Sanitize removed (or replaced) the slice. Show the BEFORE
      // bytes struck through so the user can see what was dropped.
      tokens.push({ kind: 'strike', text: beforeSlice });
      // We do NOT advance ai — the After string already lacks the
      // bytes, so the next unchanged stretch starts from the same
      // position.
    }
    bi = r.end;
  }
  // Trailing unchanged stretch.
  if (ai < after.length) {
    tokens.push({ kind: 'text', text: after.slice(ai) });
  }
  return tokens;
}

// ---------------------------------------------------------------------------
// Windowed render (long-document virtualization).
// ---------------------------------------------------------------------------

/**
 * Slice the BEFORE / AFTER pair around a center position. Returns the
 * new strings plus the offset deltas so the caller can re-anchor
 * ranges into the windowed view.
 *
 * @returns {{ beforeSlice:string, afterSlice:string,
 *             beforeStart:number, beforeEnd:number,
 *             afterStart:number, afterEnd:number,
 *             leadingHidden:number, trailingHidden:number }}
 */
export function sliceWindow(before, after, center, halfWindow) {
  const half = typeof halfWindow === 'number' && halfWindow > 0
    ? halfWindow
    : SLICE_WINDOW;
  const bStart = Math.max(0, center - half);
  const bEnd = Math.min(before.length, center + half);
  // After is shorter (or same length). Use a proportional clamp.
  const ratio = before.length === 0 ? 1 : after.length / before.length;
  const aStart = Math.max(0, Math.floor(bStart * ratio));
  const aEnd = Math.min(after.length, Math.ceil(bEnd * ratio));
  return {
    beforeSlice: before.slice(bStart, bEnd),
    afterSlice: after.slice(aStart, aEnd),
    beforeStart: bStart,
    beforeEnd: bEnd,
    afterStart: aStart,
    afterEnd: aEnd,
    leadingHidden: bStart,
    trailingHidden: before.length - bEnd,
  };
}

/**
 * Re-anchor an array of ranges into a windowed view. Ranges that fall
 * entirely outside the window are dropped; ones that straddle the
 * boundary are clipped.
 */
export function clipRangesToWindow(ranges, winStart, winEnd) {
  const out = [];
  if (!Array.isArray(ranges)) return out;
  for (const r of ranges) {
    if (r.end <= winStart) continue;
    if (r.start >= winEnd) continue;
    out.push({
      start: Math.max(r.start, winStart) - winStart,
      end: Math.min(r.end, winEnd) - winStart,
      category: r.category,
      id: r.id,
      severity: r.severity,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// DOM render — native DOM API only. No innerHTML on user bytes.
// ---------------------------------------------------------------------------

/**
 * Render an array of tokens as a DocumentFragment. Text tokens become
 * Text nodes; mark tokens become <span class="diff-mark diff-mark-X">.
 * The caller appends the fragment to its container.
 *
 * R12: every user-byte path uses textContent assignment, so the
 * browser escapes the bytes. No path injects raw HTML.
 */
export function renderBeforeFragment(doc, tokens, onSpanClick) {
  const frag = doc.createDocumentFragment();
  for (const tok of tokens) {
    if (tok.kind === 'text') {
      frag.appendChild(doc.createTextNode(tok.text));
      continue;
    }
    const span = doc.createElement('span');
    span.className = `diff-mark ${CATEGORY_CLASS[tok.category] || ''}`.trim();
    if (tok.id) span.setAttribute('data-finding-id', tok.id);
    if (tok.severity) span.setAttribute('data-severity', tok.severity);
    // R12: textContent — never innerHTML — for raw user bytes.
    span.textContent = tok.text;
    if (typeof onSpanClick === 'function') {
      span.addEventListener('click', () => onSpanClick(tok.id));
    }
    frag.appendChild(span);
  }
  return frag;
}

/**
 * Render the AFTER pane tokens. Strike tokens become a span with
 * class="diff-strike" so the host CSS can render them with a
 * text-decoration: line-through rule. Text tokens become Text nodes.
 */
export function renderAfterFragment(doc, tokens) {
  const frag = doc.createDocumentFragment();
  for (const tok of tokens) {
    if (tok.kind === 'text') {
      frag.appendChild(doc.createTextNode(tok.text));
      continue;
    }
    const span = doc.createElement('span');
    span.className = 'diff-strike';
    span.textContent = tok.text;
    frag.appendChild(span);
  }
  return frag;
}

// ---------------------------------------------------------------------------
// DiffPreview — the component class.
// ---------------------------------------------------------------------------

/**
 * Mount a side-by-side diff preview into a host element.
 *
 * Usage (from app.js):
 *   import { DiffPreview } from './components/DiffPreview.js';
 *   const dp = new DiffPreview({
 *     host: document.getElementById('diffHost'),
 *     before, after, findings,
 *     labels: { before: 'Before', after: 'After (sanitized)' },
 *     onSpanClick: (id) => { ... },   // optional
 *   });
 *   // Later:
 *   dp.scrollToFinding('f-invisibleUnicode-0');
 *   dp.destroy();
 *
 * The component owns its own DOM subtree under `host`. Calling
 * `destroy()` removes every node it added and detaches every listener.
 */
export class DiffPreview {
  constructor(opts) {
    const o = opts || {};
    this.host = o.host || null;
    this.before = typeof o.before === 'string' ? o.before : '';
    this.after = typeof o.after === 'string' ? o.after : '';
    this.findings = o.findings || {};
    this.labels = o.labels || { before: 'Before', after: 'After' };
    this.onSpanClick = typeof o.onSpanClick === 'function' ? o.onSpanClick : null;
    this.doc = (this.host && this.host.ownerDocument)
      || (typeof document !== 'undefined' ? document : null);

    this._ranges = computeMaskedRanges(this.before, this.findings);
    this._windowed = this.before.length > VIRTUAL_THRESHOLD;
    this._activeRangeIdx = this._ranges.length > 0 ? 0 : -1;
    this._listeners = [];   // [{el, type, fn}] for clean teardown
    this._root = null;
    this._beforePane = null;
    this._afterPane = null;

    if (this.host && this.doc) {
      this._mount();
    }
  }

  // ----- Public API -----

  /**
   * Update the diff with new before/after/findings. Re-renders in place.
   */
  update(next) {
    const n = next || {};
    if (typeof n.before === 'string') this.before = n.before;
    if (typeof n.after === 'string') this.after = n.after;
    if (n.findings) this.findings = n.findings;
    this._ranges = computeMaskedRanges(this.before, this.findings);
    this._windowed = this.before.length > VIRTUAL_THRESHOLD;
    this._activeRangeIdx = this._ranges.length > 0 ? 0 : -1;
    this._renderPanes();
  }

  /**
   * Scroll the BEFORE pane so the marker for the given finding id is
   * centered, then add a transient 'diff-pulse' class so the host CSS
   * can flash it. Safe no-op when the id is unknown or the component
   * is unmounted.
   */
  scrollToFinding(id) {
    if (!this._beforePane || typeof id !== 'string') return false;
    const sel = '[data-finding-id="' + id.replace(/"/g, '\\"') + '"]';
    const target = this._beforePane.querySelector
      ? this._beforePane.querySelector(sel)
      : null;
    if (!target) {
      // The finding might be outside the current window — re-center
      // the window on its range and retry.
      const idx = this._ranges.findIndex((r) => r.id === id);
      if (idx >= 0 && this._windowed) {
        this._activeRangeIdx = idx;
        this._renderPanes();
        return this.scrollToFinding(id);
      }
      return false;
    }
    if (typeof target.scrollIntoView === 'function') {
      try { target.scrollIntoView({ block: 'center' }); } catch (_) {}
    }
    target.classList.add('diff-pulse');
    const doc = this.doc;
    if (doc && doc.defaultView && typeof doc.defaultView.setTimeout === 'function') {
      doc.defaultView.setTimeout(() => {
        try { target.classList.remove('diff-pulse'); } catch (_) {}
      }, 1200);
    }
    return true;
  }

  /**
   * Detach every listener and remove the root subtree from the host.
   */
  destroy() {
    for (const { el, type, fn } of this._listeners) {
      try { el.removeEventListener(type, fn); } catch (_) {}
    }
    this._listeners.length = 0;
    if (this._root && this._root.parentNode === this.host) {
      this.host.removeChild(this._root);
    }
    this._root = null;
    this._beforePane = null;
    this._afterPane = null;
  }

  // ----- Internals -----

  _mount() {
    const doc = this.doc;
    const root = doc.createElement('div');
    root.className = 'diff-preview';
    if (this._windowed) root.classList.add('diff-windowed');

    const header = doc.createElement('div');
    header.className = 'diff-preview-header';
    const title = doc.createElement('span');
    title.className = 'diff-preview-title';
    title.textContent = 'Diff Preview';
    header.appendChild(title);
    if (this._windowed) {
      const nav = doc.createElement('span');
      nav.className = 'diff-preview-nav';
      const prev = doc.createElement('button');
      prev.type = 'button';
      prev.className = 'diff-preview-prev';
      prev.textContent = '◀';
      const next = doc.createElement('button');
      next.type = 'button';
      next.className = 'diff-preview-next';
      next.textContent = '▶';
      this._addListener(prev, 'click', () => this._shiftWindow(-1));
      this._addListener(next, 'click', () => this._shiftWindow(1));
      nav.appendChild(prev);
      nav.appendChild(next);
      header.appendChild(nav);
    }
    root.appendChild(header);

    const body = doc.createElement('div');
    body.className = 'diff-preview-body';

    const beforeCol = doc.createElement('div');
    beforeCol.className = 'diff-preview-col diff-preview-before';
    const beforeLabel = doc.createElement('div');
    beforeLabel.className = 'diff-preview-label';
    beforeLabel.textContent = this.labels.before || 'Before';
    const beforePane = doc.createElement('pre');
    beforePane.className = 'diff-preview-pane';
    beforeCol.appendChild(beforeLabel);
    beforeCol.appendChild(beforePane);

    const afterCol = doc.createElement('div');
    afterCol.className = 'diff-preview-col diff-preview-after';
    const afterLabel = doc.createElement('div');
    afterLabel.className = 'diff-preview-label';
    afterLabel.textContent = this.labels.after || 'After';
    const afterPane = doc.createElement('pre');
    afterPane.className = 'diff-preview-pane';
    afterCol.appendChild(afterLabel);
    afterCol.appendChild(afterPane);

    body.appendChild(beforeCol);
    body.appendChild(afterCol);
    root.appendChild(body);

    this.host.appendChild(root);
    this._root = root;
    this._beforePane = beforePane;
    this._afterPane = afterPane;
    this._renderPanes();
  }

  _renderPanes() {
    if (!this._beforePane || !this._afterPane) return;
    let before = this.before;
    let after = this.after;
    let ranges = this._ranges;
    if (this._windowed && this._activeRangeIdx >= 0
        && this._activeRangeIdx < ranges.length) {
      const center = ranges[this._activeRangeIdx].start;
      const win = sliceWindow(before, after, center, SLICE_WINDOW);
      before = win.beforeSlice;
      after = win.afterSlice;
      ranges = clipRangesToWindow(this._ranges, win.beforeStart, win.beforeEnd);
      // Add hidden-chars sentinels so the user knows there is more.
      if (win.leadingHidden > 0) {
        before = '…(' + win.leadingHidden + ' more)…\n' + before;
        after = '…(' + win.leadingHidden + ' more)…\n' + after;
      }
      if (win.trailingHidden > 0) {
        before = before + '\n…(' + win.trailingHidden + ' more)…';
        after = after + '\n…(' + win.trailingHidden + ' more)…';
      }
      // Shift range offsets to account for the leading sentinel we just
      // prepended.
      if (win.leadingHidden > 0) {
        const shift = ('…(' + win.leadingHidden + ' more)…\n').length;
        ranges = ranges.map((r) => ({
          start: r.start + shift,
          end: r.end + shift,
          category: r.category,
          id: r.id,
          severity: r.severity,
        }));
      }
    }
    const beforeTokens = tokenizeBefore(before, ranges);
    const afterTokens = tokenizeAfter(before, after, ranges);
    // Re-render: clear + append fragment.
    while (this._beforePane.firstChild) {
      this._beforePane.removeChild(this._beforePane.firstChild);
    }
    while (this._afterPane.firstChild) {
      this._afterPane.removeChild(this._afterPane.firstChild);
    }
    this._beforePane.appendChild(
      renderBeforeFragment(this.doc, beforeTokens, this.onSpanClick),
    );
    this._afterPane.appendChild(renderAfterFragment(this.doc, afterTokens));
  }

  _shiftWindow(delta) {
    if (!this._windowed || this._ranges.length === 0) return;
    this._activeRangeIdx = (this._activeRangeIdx + delta + this._ranges.length)
      % this._ranges.length;
    this._renderPanes();
  }

  _addListener(el, type, fn) {
    el.addEventListener(type, fn);
    this._listeners.push({ el, type, fn });
  }
}

// Default export = class for `import DiffPreview from ...` ergonomics.
export default DiffPreview;
