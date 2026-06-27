// =============================================================
//  T4 — i18n-descriptions registry + FindingDetailPanel
// =============================================================
// Coverage:
//   1. descriptions['ja'] / descriptions['en'] expose the same set
//      of keys (parity).
//   2. Every value has why / example / remediation as non-empty
//      strings.
//   3. R12 guard: example/why/remediation never contain interpolation
//      placeholders ({foo}) — they must be fixed phrases.
//   4. getDescription resolves both kebab and camel forms.
//   5. FindingDetailPanel renders into a jsdom-free DOM stub
//      identical in spirit to test-diff-preview.mjs.
//   6. Toggle click flips the hidden attribute and aria-expanded.
//   7. Unknown finding ids produce an empty fragment (no broken UI).
// =============================================================

import { descriptions, getDescription, listDescriptionKeys }
  from '../src/i18n-descriptions.js';
import { FindingDetailPanel } from '../src/components/finding-detail-panel.js';

let passed = 0;
let failed = 0;
function assert(name, cond, detail) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (detail ? ' — ' + detail : '')); }
}

// --- 1: parity --------------------------------------------------------
{
  const ja = new Set(listDescriptionKeys('ja'));
  const en = new Set(listDescriptionKeys('en'));
  const jaOnly = [...ja].filter((k) => !en.has(k));
  const enOnly = [...en].filter((k) => !ja.has(k));
  assert('ja/en key parity (ja-only)', jaOnly.length === 0,
    'ja-only: ' + jaOnly.slice(0, 5).join(','));
  assert('ja/en key parity (en-only)', enOnly.length === 0,
    'en-only: ' + enOnly.slice(0, 5).join(','));
  assert('description count >= 70', ja.size >= 70,
    'got ' + ja.size);
}

// --- 2 + 3: every value is well-formed --------------------------------
for (const lang of ['ja', 'en']) {
  const dict = descriptions[lang];
  for (const [key, val] of Object.entries(dict)) {
    const shape = val && typeof val === 'object'
      && typeof val.why === 'string'
      && typeof val.example === 'string'
      && typeof val.remediation === 'string'
      && val.why.length > 0 && val.example.length > 0 && val.remediation.length > 0;
    if (!shape) {
      assert(`shape ${lang}/${key}`, false, JSON.stringify(val));
      continue;
    }
    // R12: no {placeholder} substitution allowed in description strings.
    // (The short label in i18n.js keeps the interpolation surface; the
    // long-form prose must be a fixed phrase.) Reject ANY {token}
    // pattern that looks like a placeholder, but allow literal {} pairs
    // that happen to appear inside example code (e.g. JSON braces).
    const hasPlaceholder = /\{[a-zA-Z_][a-zA-Z0-9_]*\}/.test(val.why)
      || /\{[a-zA-Z_][a-zA-Z0-9_]*\}/.test(val.example)
      || /\{[a-zA-Z_][a-zA-Z0-9_]*\}/.test(val.remediation);
    assert(`R12 no placeholder ${lang}/${key}`, !hasPlaceholder,
      hasPlaceholder ? 'found {placeholder} pattern' : '');
  }
}

// --- 4: getDescription resolves both forms ----------------------------
{
  const camel = getDescription('pdfEmbedsJavaScriptActions', 'en');
  const kebab = getDescription('pdf-embeds-java-script-actions', 'en');
  assert('camel id resolves', camel !== null && typeof camel.why === 'string');
  // The kebab form maps via -X-Y-Z -> XYZ in camelCase. The current
  // resolver uses the same kebab->camel rule that i18n.js applies, so
  // 'pdf-embeds-java-script-actions' -> 'pdfEmbedsJavaScriptActions'.
  assert('kebab id resolves', kebab !== null && typeof kebab.why === 'string');
  assert('unknown id returns null', getDescription('nope-zzz-zzz', 'en') === null);
  assert('empty id returns null', getDescription('', 'en') === null);
  assert('non-string id returns null', getDescription(null, 'en') === null);
}

// --- 5/6: FindingDetailPanel DOM contract -----------------------------
function makeStubDoc() {
  // Tiny DOM stub — same approach as test-diff-preview.mjs. Only
  // implements the surface the panel touches.
  class Elem {
    constructor(tag) {
      this.tagName = String(tag).toUpperCase();
      this.children = [];
      this.attrs = {};
      this.classes = new Set();
      this._text = '';
      this._listeners = [];
      this.classList = {
        add: (c) => this.classes.add(c),
        remove: (c) => this.classes.delete(c),
        contains: (c) => this.classes.has(c),
      };
      this.parentNode = null;
    }
    appendChild(child) {
      if (child && child._isFragment) {
        for (const c of child.children) {
          c.parentNode = this;
          this.children.push(c);
        }
        child.children = [];
        return child;
      }
      child.parentNode = this;
      this.children.push(child);
      return child;
    }
    removeChild(child) {
      const i = this.children.indexOf(child);
      if (i >= 0) {
        this.children.splice(i, 1);
        child.parentNode = null;
      }
      return child;
    }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    removeAttribute(k) { delete this.attrs[k]; }
    getAttribute(k) { return this.attrs[k] != null ? this.attrs[k] : null; }
    hasAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k); }
    addEventListener(type, fn) { this._listeners.push({ type, fn }); }
    removeEventListener(type, fn) {
      this._listeners = this._listeners.filter(
        (l) => !(l.type === type && l.fn === fn));
    }
    _dispatch(type) {
      for (const l of this._listeners.slice()) {
        if (l.type === type) l.fn({ type, target: this });
      }
    }
    set textContent(v) { this._text = String(v); this.children = []; }
    get textContent() {
      if (this._text) return this._text;
      return this.children.map((c) => c.textContent || '').join('');
    }
    get firstChild() { return this.children[0] || null; }
  }
  class Fragment {
    constructor() { this._isFragment = true; this.children = []; }
    appendChild(c) {
      if (c && c._isFragment) {
        for (const cc of c.children) this.children.push(cc);
        c.children = [];
        return c;
      }
      this.children.push(c);
      return c;
    }
  }
  return {
    createElement: (tag) => new Elem(tag),
    createDocumentFragment: () => new Fragment(),
  };
}

{
  const doc = makeStubDoc();
  let lang = 'ja';
  const panel = new FindingDetailPanel(doc, { getLang: () => lang });

  // known id: button + hidden panel
  const fragKnown = panel.createToggle('svgScriptElement');
  assert('known id: fragment has 2 children', fragKnown.children.length === 2);
  const btn = fragKnown.children[0];
  const detailPanel = fragKnown.children[1];
  assert('known id: button has label', btn.textContent === 'なぜ？');
  assert('known id: panel starts hidden', detailPanel.hasAttribute('hidden'));
  assert('known id: panel has data-finding-id',
    detailPanel.getAttribute('data-finding-id') === 'svgScriptElement');

  // Click: should reveal
  btn._dispatch('click');
  assert('click 1: panel revealed', !detailPanel.hasAttribute('hidden'));
  assert('click 1: aria-expanded=true',
    btn.getAttribute('aria-expanded') === 'true');
  // The revealed panel should now have why/example/remediation sections.
  const sectionCount = detailPanel.children.filter
    ? detailPanel.children.filter((c) => c.classes.has('sx-fd-section')).length
    : detailPanel.children.reduce((n, c) => n + (c.classes.has('sx-fd-section') ? 1 : 0), 0);
  assert('click 1: 3 sections rendered', sectionCount === 3,
    'got ' + sectionCount);

  // Click again: should collapse
  btn._dispatch('click');
  assert('click 2: panel hidden again', detailPanel.hasAttribute('hidden'));
  assert('click 2: aria-expanded=false',
    btn.getAttribute('aria-expanded') === 'false');

  // Language switch + re-open
  lang = 'en';
  btn._dispatch('click');
  // Heading text changes per-lang
  const firstSection = detailPanel.children[0];
  const firstHeading = firstSection && firstSection.children[0];
  assert('lang switch: en heading rendered',
    firstHeading && firstHeading.textContent === 'Why this matters');
}

// --- 7: unknown id ----------------------------------------------------
{
  const doc = makeStubDoc();
  const panel = new FindingDetailPanel(doc, { getLang: () => 'ja' });
  const frag = panel.createToggle('nope-zzz-zzz');
  assert('unknown id: empty fragment', frag.children.length === 0);
}

// --- Final tally ------------------------------------------------------
console.log(`\nTotal: ${passed} passed / ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
