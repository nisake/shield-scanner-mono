// =============================================================
//  Shield Scanner Web — v1.19.0 C2 DiffPreview harness
// =============================================================
// Unit + thin integration tests for packages/web/src/components/
// DiffPreview.js. The pure helpers (computeMaskedRanges /
// tokenizeBefore / tokenizeAfter / sliceWindow / clipRangesToWindow)
// run without any DOM at all. The class-level tests use a tiny
// hand-rolled DOM stub instead of jsdom — the workspace ships zero
// third-party test deps (see package.json) and the spec forbids
// adding new npm packages.
//
// The stub implements ONLY the DOM surface DiffPreview actually
// touches:
//   document.createElement / createTextNode / createDocumentFragment
//   element.appendChild / removeChild / firstChild / parentNode
//   element.classList.add / remove / contains
//   element.setAttribute / textContent
//   element.addEventListener / removeEventListener
//   element.querySelector  (supports only `[data-finding-id="..."]`)
//   pre/span/div tag names — no styling, no layout.
// A real browser test would catch styling regressions; we are after
// the DOM-graph shape + the pure-function correctness here.
// =============================================================

import {
  computeMaskedRanges,
  tokenizeBefore,
  tokenizeAfter,
  sliceWindow,
  clipRangesToWindow,
  renderBeforeFragment,
  renderAfterFragment,
  DiffPreview,
  VIRTUAL_THRESHOLD,
} from '../src/components/DiffPreview.js';
import { analyze, sanitize } from '@shield-scanner/core';

// ---------------------------------------------------------------------------
// DOM stub.
// ---------------------------------------------------------------------------

function makeFakeDoc() {
  const doc = {
    defaultView: { setTimeout: (fn, _ms) => { /* fire-and-forget */ } },
    createElement(tag) { return makeFakeEl(tag, doc); },
    createTextNode(text) { return makeFakeText(text); },
    createDocumentFragment() {
      const frag = makeFakeEl('#fragment', doc);
      frag.isFragment = true;
      return frag;
    },
  };
  return doc;
}

function makeFakeText(text) {
  return {
    nodeType: 3,
    textContent: String(text),
    parentNode: null,
    children: [],
    childNodes: [],
    _serialize() { return String(text); },
  };
}

function makeFakeEl(tag, doc) {
  const el = {
    nodeType: 1,
    tagName: tag.toUpperCase(),
    parentNode: null,
    children: [],
    childNodes: [],
    _attrs: {},
    _listeners: {},
    isFragment: false,
    _doc: doc,
    get firstChild() { return this.childNodes[0] || null; },
    appendChild(child) {
      if (child && child.isFragment) {
        // Inline the fragment's children (mimics real DOM).
        const moved = child.childNodes.slice();
        for (const c of moved) {
          c.parentNode = this;
          this.childNodes.push(c);
          if (c.nodeType === 1) this.children.push(c);
        }
        child.childNodes.length = 0;
        child.children.length = 0;
        return child;
      }
      child.parentNode = this;
      this.childNodes.push(child);
      if (child.nodeType === 1) this.children.push(child);
      return child;
    },
    removeChild(child) {
      const i = this.childNodes.indexOf(child);
      if (i >= 0) this.childNodes.splice(i, 1);
      const j = this.children.indexOf(child);
      if (j >= 0) this.children.splice(j, 1);
      child.parentNode = null;
      return child;
    },
    get className() { return this._attrs.class || ''; },
    set className(v) { this._attrs.class = String(v); },
    get textContent() {
      // Reading: concatenate descendants' text.
      return collectText(this);
    },
    set textContent(v) {
      // Writing: drop children, install one text node.
      this.childNodes.length = 0;
      this.children.length = 0;
      const t = makeFakeText(String(v));
      t.parentNode = this;
      this.childNodes.push(t);
    },
    setAttribute(name, value) { this._attrs[name] = String(value); },
    getAttribute(name) { return this._attrs[name]; },
    addEventListener(type, fn) {
      this._listeners[type] = this._listeners[type] || [];
      this._listeners[type].push(fn);
    },
    removeEventListener(type, fn) {
      const arr = this._listeners[type] || [];
      const i = arr.indexOf(fn);
      if (i >= 0) arr.splice(i, 1);
    },
    classList: {
      add: (...cls) => {
        const cur = (el._attrs.class || '').split(/\s+/).filter(Boolean);
        for (const c of cls) if (!cur.includes(c)) cur.push(c);
        el._attrs.class = cur.join(' ');
      },
      remove: (...cls) => {
        const cur = (el._attrs.class || '').split(/\s+/).filter(Boolean);
        el._attrs.class = cur.filter((c) => !cls.includes(c)).join(' ');
      },
      contains: (c) => (el._attrs.class || '').split(/\s+/).includes(c),
    },
    querySelector(sel) {
      // Only `[data-finding-id="X"]` is supported (that is all the
      // class actually uses).
      const m = /^\[data-finding-id="([^"]+)"\]$/.exec(sel);
      if (!m) return null;
      return findByAttr(this, 'data-finding-id', m[1]);
    },
    scrollIntoView(_opts) { el._scrolled = true; },
    get ownerDocument() { return this._doc; },
    _trigger(type) {
      for (const fn of (this._listeners[type] || [])) fn();
    },
  };
  return el;
}

function collectText(node) {
  if (node.nodeType === 3) return node.textContent;
  let out = '';
  for (const c of node.childNodes) out += collectText(c);
  return out;
}

function findByAttr(node, attr, value) {
  if (node.nodeType !== 1) return null;
  if (node._attrs && node._attrs[attr] === value) return node;
  for (const c of node.childNodes) {
    const hit = findByAttr(c, attr, value);
    if (hit) return hit;
  }
  return null;
}

function countMarks(node, className) {
  let n = 0;
  if (node.nodeType === 1
      && (node._attrs.class || '').split(/\s+/).includes(className)) n++;
  for (const c of node.childNodes) n += countMarks(c, className);
  return n;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

const tests = [
  {
    name: '01 computeMaskedRanges: ZWSP invisible finding -> 1 range with category=invisibleUnicode',
    run: () => {
      const before = 'Hello​World';
      const findings = analyze(before, { fileType: 'text' }).findings;
      const ranges = computeMaskedRanges(before, findings);
      return {
        ok: ranges.length === 1
          && ranges[0].category === 'invisibleUnicode'
          && ranges[0].start === 5
          && ranges[0].end === 6,
        detail: ranges,
      };
    },
  },
  {
    name: '02 computeMaskedRanges: returns NEW sorted array, never mutates input',
    run: () => {
      const before = 'abc​‌def';
      const findings = analyze(before, { fileType: 'text' }).findings;
      const ranges = computeMaskedRanges(before, findings);
      const sorted = ranges.every((r, i) => i === 0 || ranges[i - 1].start <= r.start);
      return { ok: sorted && ranges.length >= 2, detail: ranges };
    },
  },
  {
    name: '03 computeMaskedRanges: empty / null input -> empty array',
    run: () => {
      const empty = computeMaskedRanges('', { invisibleUnicode: [] });
      const nullFindings = computeMaskedRanges('hello', null);
      return { ok: empty.length === 0 && nullFindings.length === 0 };
    },
  },
  {
    name: '04 computeMaskedRanges: ignores categories outside the R13 5-key set',
    run: () => {
      const before = 'abc';
      const ranges = computeMaskedRanges(before, {
        invisibleUnicode: [],
        controlChars: [],
        hiddenHtml: [],
        suspiciousPatterns: [],
        homoglyphs: [],
        // Out-of-set bogus key — must be ignored.
        someBogusCategory: [{ position: 0, char: 'a' }],
      });
      return { ok: ranges.length === 0 };
    },
  },
  {
    name: '05 tokenizeBefore: produces alternating text + mark tokens',
    run: () => {
      const tokens = tokenizeBefore('Hello​World', [
        { start: 5, end: 6, category: 'invisibleUnicode', id: 'f-0', severity: 'warning' },
      ]);
      const text0 = tokens[0].kind === 'text' && tokens[0].text === 'Hello';
      const mark = tokens[1].kind === 'mark' && tokens[1].text === '​'
        && tokens[1].category === 'invisibleUnicode';
      const text1 = tokens[2].kind === 'text' && tokens[2].text === 'World';
      return { ok: text0 && mark && text1, detail: tokens };
    },
  },
  {
    name: '06 tokenizeBefore: empty input -> empty array',
    run: () => {
      return { ok: tokenizeBefore('', []).length === 0 };
    },
  },
  {
    name: '07 tokenizeBefore: overlapping ranges are clipped (no duplicate text)',
    run: () => {
      const before = 'ABCDEF';
      const tokens = tokenizeBefore(before, [
        { start: 1, end: 4, category: 'invisibleUnicode', id: 'a' },
        { start: 2, end: 5, category: 'controlChars',     id: 'b' },
      ]);
      const reassembled = tokens.map((t) => t.text).join('');
      // Length-preserving (each char appears exactly once).
      return { ok: reassembled === before, detail: tokens };
    },
  },
  {
    name: '08 tokenizeAfter: removed bytes become strike tokens',
    run: () => {
      const before = 'Hello​World';
      const { cleaned: after } = sanitize(before, { fileType: 'text' });
      const ranges = [
        { start: 5, end: 6, category: 'invisibleUnicode', id: 'f-0' },
      ];
      const tokens = tokenizeAfter(before, after, ranges);
      const hasStrike = tokens.some((t) => t.kind === 'strike' && t.text === '​');
      return { ok: hasStrike, detail: tokens };
    },
  },
  {
    name: '09 tokenizeAfter: surviving bytes become plain text (no false strike)',
    run: () => {
      const before = 'abc';
      const after = 'abc';
      const ranges = [{ start: 0, end: 1, category: 'homoglyphs', id: 'f-0' }];
      const tokens = tokenizeAfter(before, after, ranges);
      const noStrike = tokens.every((t) => t.kind === 'text');
      return { ok: noStrike, detail: tokens };
    },
  },
  {
    name: '10 sliceWindow / clipRangesToWindow round-trip',
    run: () => {
      const before = 'X'.repeat(1000);
      const after = 'X'.repeat(1000);
      const ranges = [
        { start: 100, end: 110, category: 'invisibleUnicode', id: 'a' },
        { start: 500, end: 510, category: 'invisibleUnicode', id: 'b' },
        { start: 900, end: 910, category: 'invisibleUnicode', id: 'c' },
      ];
      const win = sliceWindow(before, after, 500, 100);
      const clipped = clipRangesToWindow(ranges, win.beforeStart, win.beforeEnd);
      const onlyB = clipped.length === 1 && clipped[0].id === 'b';
      return { ok: onlyB && win.beforeSlice.length === 200, detail: { win, clipped } };
    },
  },
  {
    name: '11 renderBeforeFragment: 1 mark span gets the diff-mark class + data-finding-id',
    run: () => {
      const doc = makeFakeDoc();
      const frag = renderBeforeFragment(doc, [
        { kind: 'text', text: 'Hello' },
        { kind: 'mark', text: '​', category: 'invisibleUnicode', id: 'f-0', severity: 'warning' },
        { kind: 'text', text: 'World' },
      ], null);
      const host = doc.createElement('pre');
      host.appendChild(frag);
      const mark = findByAttr(host, 'data-finding-id', 'f-0');
      const okClass = mark && mark._attrs.class.includes('diff-mark')
        && mark._attrs.class.includes('diff-mark-invisible');
      const okText = collectText(host) === 'Hello​World';
      return { ok: okClass && okText, detail: { mark, host } };
    },
  },
  {
    name: '12 renderBeforeFragment: raw user bytes go through textContent (no innerHTML)',
    run: () => {
      // R12 contract: a finding whose `text` looks like HTML must still
      // round-trip as literal characters via the Text node — never as
      // parsed HTML. The fake DOM's `_serialize()` echoes raw text, so
      // we just check the leaf is a text node with the exact bytes.
      const doc = makeFakeDoc();
      const frag = renderBeforeFragment(doc, [
        { kind: 'mark', text: '<img src=x>', category: 'hiddenHtml', id: 'f-0' },
      ], null);
      const host = doc.createElement('pre');
      host.appendChild(frag);
      const span = findByAttr(host, 'data-finding-id', 'f-0');
      const leaf = span && span.childNodes[0];
      return {
        ok: leaf && leaf.nodeType === 3 && leaf.textContent === '<img src=x>',
        detail: { spanClass: span && span._attrs.class, leaf },
      };
    },
  },
  {
    name: '13 renderAfterFragment: strike tokens emit diff-strike spans',
    run: () => {
      const doc = makeFakeDoc();
      const frag = renderAfterFragment(doc, [
        { kind: 'text', text: 'Hello' },
        { kind: 'strike', text: '​' },
        { kind: 'text', text: 'World' },
      ]);
      const host = doc.createElement('pre');
      host.appendChild(frag);
      const strikeCount = countMarks(host, 'diff-strike');
      return { ok: strikeCount === 1, detail: { strikeCount } };
    },
  },
  {
    name: '14 DiffPreview integration: analyze + sanitize -> mark + strike both rendered',
    run: () => {
      const doc = makeFakeDoc();
      const host = doc.createElement('div');
      const before = 'Hello​World';
      const { findings } = analyze(before, { fileType: 'text' });
      const { cleaned: after } = sanitize(before, { fileType: 'text' });
      const dp = new DiffPreview({ host, before, after, findings });
      const beforeMarkCount = countMarks(host, 'diff-mark');
      const afterStrikeCount = countMarks(host, 'diff-strike');
      dp.destroy();
      const cleaned = host.childNodes.length === 0;
      return {
        ok: beforeMarkCount >= 1 && afterStrikeCount >= 1 && cleaned,
        detail: { beforeMarkCount, afterStrikeCount, cleaned },
      };
    },
  },
  {
    name: '15 DiffPreview.scrollToFinding: pulse class applied to the right span',
    run: () => {
      const doc = makeFakeDoc();
      const host = doc.createElement('div');
      const before = 'A​B‌C';
      const { findings } = analyze(before, { fileType: 'text' });
      const ranges = computeMaskedRanges(before, findings);
      const dp = new DiffPreview({
        host,
        before,
        after: 'ABC',
        findings,
      });
      const targetId = ranges[0].id;
      const ok = dp.scrollToFinding(targetId);
      const span = findByAttr(host, 'data-finding-id', targetId);
      const pulsed = span && (span._attrs.class || '').includes('diff-pulse');
      dp.destroy();
      return { ok: ok && pulsed, detail: { targetId, pulsed } };
    },
  },
  {
    name: '16 DiffPreview windowed mode: VIRTUAL_THRESHOLD-sized input picks up diff-windowed class',
    run: () => {
      const doc = makeFakeDoc();
      const host = doc.createElement('div');
      const padding = 'x'.repeat(VIRTUAL_THRESHOLD + 100);
      const before = padding + '​';
      const { findings } = analyze(before, { fileType: 'text' });
      const dp = new DiffPreview({ host, before, after: padding, findings });
      const rootClass = host.children[0]._attrs.class;
      dp.destroy();
      return {
        ok: rootClass.includes('diff-windowed'),
        detail: { rootClass },
      };
    },
  },
  {
    name: '17 DiffPreview.onSpanClick fires the supplied handler',
    run: () => {
      const doc = makeFakeDoc();
      const host = doc.createElement('div');
      const before = 'Hello​World';
      const { findings } = analyze(before, { fileType: 'text' });
      let receivedId = null;
      const dp = new DiffPreview({
        host,
        before,
        after: 'HelloWorld',
        findings,
        onSpanClick: (id) => { receivedId = id; },
      });
      const ranges = computeMaskedRanges(before, findings);
      const span = findByAttr(host, 'data-finding-id', ranges[0].id);
      span._trigger('click');
      dp.destroy();
      return { ok: receivedId === ranges[0].id, detail: { receivedId } };
    },
  },
  {
    name: '18 DiffPreview.update: replaces existing render with new content',
    run: () => {
      const doc = makeFakeDoc();
      const host = doc.createElement('div');
      const dp = new DiffPreview({
        host,
        before: 'plain',
        after: 'plain',
        findings: { invisibleUnicode: [], controlChars: [], hiddenHtml: [], suspiciousPatterns: [], homoglyphs: [] },
      });
      const initialMarks = countMarks(host, 'diff-mark');
      const newBefore = 'Hello​World';
      const { findings } = analyze(newBefore, { fileType: 'text' });
      dp.update({ before: newBefore, after: 'HelloWorld', findings });
      const newMarks = countMarks(host, 'diff-mark');
      dp.destroy();
      return { ok: initialMarks === 0 && newMarks >= 1, detail: { initialMarks, newMarks } };
    },
  },
];

let passed = 0;
let failed = 0;
for (const t of tests) {
  let ok = false;
  let err = null;
  let detail = null;
  try {
    const res = t.run();
    ok = !!res.ok;
    detail = res.detail;
  } catch (e) {
    err = e;
  }
  if (ok) {
    passed++;
    console.log(`PASS ${t.name}`);
  } else {
    failed++;
    console.log(`FAIL ${t.name}`);
    if (err) {
      console.log('       error:', err.message);
      if (err.stack) console.log('       stack:', err.stack.split('\n').slice(0, 4).join('\n'));
    } else if (detail !== null && detail !== undefined) {
      try {
        const j = JSON.stringify(detail, (k, v) => {
          if (k === 'parentNode' || k === '_doc' || k === '_listeners') return undefined;
          return v;
        });
        console.log('       detail:', j ? j.slice(0, 400) : String(detail));
      } catch (_) {
        console.log('       detail: (unstringifiable)');
      }
    }
  }
}
console.log(`\nTotal: ${passed} passed / ${failed} failed`);
process.exitCode = failed === 0 ? 0 : 1;
