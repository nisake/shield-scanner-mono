// =============================================================
//  Shield Scanner Web — v1.20.0 T4: FindingDetailPanel
// =============================================================
// Expand-on-click detail UI for individual findings.
//
// Usage (host wiring):
//
//   import { FindingDetailPanel } from './components/finding-detail-panel.js';
//
//   const panel = new FindingDetailPanel(document, {
//     getLang: () => currentLang,
//   });
//   // On every finding row render:
//   const expand = panel.createToggle(findingRowEl, findingId);
//   findingRowEl.appendChild(expand);
//
// The toggle is a small "?" button. When the user clicks it, the panel
// looks up the description registry (i18n-descriptions.js), renders
// why/example/remediation into a sibling <div>, and toggles its
// visibility. If no description is registered for the finding id, the
// toggle short-circuits and renders nothing (the row stays collapsed
// as before — no broken UI for unknown ids).
//
// R12 invariant:
//   The panel NEVER substitutes the per-finding meta into the rendered
//   strings. The example / why / remediation strings are constants
//   compiled into the bundle. The finding id itself IS rendered (in a
//   small subscript) so the operator can correlate with logs.
//
// DOM contract:
//   The panel uses ONLY the same DOM surface DiffPreview.js documents
//   (createElement / textContent / addEventListener / classList / etc.)
//   so the existing jsdom-free test stub keeps working.
// =============================================================

import { getDescription } from '../i18n-descriptions.js';

// Stable CSS class prefix — keeps the audit grep target predictable
// and avoids colliding with any other component's classes.
const CSS_PREFIX = 'sx-fd';

class FindingDetailPanel {
  /**
   * @param {Document} doc            DOM document (real or stubbed).
   * @param {{getLang:()=>string}} opts
   *   getLang must return 'ja' or 'en'. Re-evaluated on every render
   *   so language toggles refresh the panel without re-mounting.
   */
  constructor(doc, opts) {
    if (!doc || typeof doc.createElement !== 'function') {
      throw new TypeError('FindingDetailPanel: doc.createElement required');
    }
    const getLang = opts && typeof opts.getLang === 'function'
      ? opts.getLang
      : () => 'ja';
    this.doc = doc;
    this.getLang = getLang;
    // expanded[findingId] = true|false for memoizing the open state
    // across re-renders. Capped at 256 entries via FIFO to keep memory
    // bounded if the user opens hundreds of findings.
    this._expanded = new Map();
    this._listeners = [];
  }

  /**
   * Create a small expand toggle anchored at the right side of a
   * finding row, plus a collapsed detail panel placed AFTER the row.
   * Returns a DocumentFragment so the host can `appendChild` once.
   *
   * If no description is registered for the id, returns a zero-child
   * fragment (caller appends it harmlessly).
   *
   * @param {string} findingId  Kebab or camel finding id.
   * @returns {DocumentFragment}
   */
  createToggle(findingId) {
    const frag = (typeof this.doc.createDocumentFragment === 'function')
      ? this.doc.createDocumentFragment()
      : null;
    if (!frag) return null;
    const lang = this.getLang();
    const desc = getDescription(findingId, lang);
    if (!desc) return frag;

    const btn = this.doc.createElement('button');
    btn.setAttribute('type', 'button');
    btn.classList.add(CSS_PREFIX + '-toggle');
    btn.setAttribute('aria-expanded', 'false');
    btn.textContent = lang === 'en' ? 'Why?' : 'なぜ？';

    const panel = this.doc.createElement('div');
    panel.classList.add(CSS_PREFIX + '-panel');
    panel.setAttribute('hidden', 'hidden');
    panel.setAttribute('data-finding-id', findingId);

    this._renderPanel(panel, findingId, desc, lang);

    this._addListener(btn, 'click', () => {
      const wasOpen = !!this._expanded.get(findingId);
      const open = !wasOpen;
      this._expanded.set(findingId, open);
      this._capExpandedMap();
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) {
        panel.removeAttribute('hidden');
        // Re-render in case the language changed since first click.
        this._renderPanel(panel, findingId, getDescription(findingId, this.getLang()), this.getLang());
      } else {
        panel.setAttribute('hidden', 'hidden');
      }
    });

    frag.appendChild(btn);
    frag.appendChild(panel);
    return frag;
  }

  /**
   * Drop all DOM listeners attached so far. Call when the host tears
   * down the result panel (e.g. on reset).
   */
  destroy() {
    for (const { el, type, fn } of this._listeners) {
      if (el && typeof el.removeEventListener === 'function') {
        el.removeEventListener(type, fn);
      }
    }
    this._listeners = [];
    this._expanded.clear();
  }

  /**
   * @private
   * Detect whether the registry knows about a kebab id without
   * paying for the full render. Useful for hosts that want to hide
   * the "?" toggle entirely on unknown ids.
   */
  hasDescription(findingId) {
    return !!getDescription(findingId, this.getLang());
  }

  // ----- internal helpers ---------------------------------------------
  _renderPanel(panelEl, findingId, desc, lang) {
    while (panelEl.firstChild) panelEl.removeChild(panelEl.firstChild);
    if (!desc) return;
    panelEl.appendChild(this._section('why', lang === 'en' ? 'Why this matters' : 'なぜ問題か', desc.why));
    panelEl.appendChild(this._section('example', lang === 'en' ? 'Example' : '例', desc.example));
    panelEl.appendChild(this._section('remediation', lang === 'en' ? 'How to mitigate' : '対処方法', desc.remediation));
    const idLabel = this.doc.createElement('div');
    idLabel.classList.add(CSS_PREFIX + '-id');
    idLabel.textContent = (lang === 'en' ? 'finding id: ' : '検出ID: ') + findingId;
    panelEl.appendChild(idLabel);
  }

  _section(kind, heading, body) {
    const wrap = this.doc.createElement('div');
    wrap.classList.add(CSS_PREFIX + '-section');
    wrap.classList.add(CSS_PREFIX + '-section-' + kind);
    const h = this.doc.createElement('div');
    h.classList.add(CSS_PREFIX + '-heading');
    h.textContent = heading;
    const p = this.doc.createElement('div');
    p.classList.add(CSS_PREFIX + '-body');
    p.textContent = body;
    wrap.appendChild(h);
    wrap.appendChild(p);
    return wrap;
  }

  _addListener(el, type, fn) {
    if (!el || typeof el.addEventListener !== 'function') return;
    el.addEventListener(type, fn);
    this._listeners.push({ el, type, fn });
  }

  _capExpandedMap() {
    const CAP = 256;
    if (this._expanded.size <= CAP) return;
    // Drop the oldest until we're under cap. Map iteration is insertion
    // order so the first key is the FIFO-oldest.
    const drop = this._expanded.size - CAP;
    let i = 0;
    for (const k of this._expanded.keys()) {
      if (i++ >= drop) break;
      this._expanded.delete(k);
    }
  }
}

export { FindingDetailPanel, CSS_PREFIX };
export default FindingDetailPanel;
