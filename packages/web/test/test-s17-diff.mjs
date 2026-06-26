// =============================================================
//  Shield Scanner Web — S17 Diff View harness (Phase 1 migration)
// =============================================================
// Port of the legacy harness's S17 "diff view" tests (Tests 91-93).
// The diff view's logic lives in two pure pieces:
//   - sanitize()           from @shield-scanner/core
//   - _renderRevealMarkers from packages/web/src/ui/reveal-mode.js
// Both are DOM-free, so Node can drive them without jsdom / setEnv.
//
// New API shape vs. legacy:
//   sanitizeContent(before, findings)  -->  sanitize(before, {fileType, ...})
//   (findings argument dropped — sanitize re-detects internally.)
//
// R12 contract pinned: _renderRevealMarkers escapes user bytes via
// escapeForDisplay BEFORE wrapping invisibles in <span class="reveal-marker">,
// so attacker `<img onerror>` cannot break out of the Before pane.
// =============================================================

import { analyze, sanitize } from '@shield-scanner/core';
import { _renderRevealMarkers } from '../src/ui/reveal-mode.js';

const tests = [
  {
    name: '91 S17 sanitize round-trip strips ZWSP/RLO so Before/After diverge',
    run: () => {
      const before = 'Hello​World‮Reverse';
      const { findings } = analyze(before, { fileType: 'text' });
      const { cleaned: after } = sanitize(before, { fileType: 'text' });
      return {
        ok:
          after !== before &&
          !after.includes('​') &&
          !after.includes('‮') &&
          after.includes('Hello') &&
          (findings.invisibleUnicode || []).length >= 2,
        detail: {
          before: JSON.stringify(before),
          after: JSON.stringify(after),
          invisibleCount: (findings.invisibleUnicode || []).length,
        },
      };
    },
  },
  {
    name: '92 S17 sanitize + _renderRevealMarkers: After pane has fewer reveal-markers than Before',
    run: () => {
      const before = 'a​b‮c​d';
      const { cleaned: after } = sanitize(before, { fileType: 'text' });
      const beforeHtml = _renderRevealMarkers(before);
      const afterHtml = _renderRevealMarkers(after);
      const countBefore = (beforeHtml.match(/reveal-marker/g) || []).length;
      const countAfter = (afterHtml.match(/reveal-marker/g) || []).length;
      return {
        ok: countBefore >= 3 && countAfter === 0,
        detail: { countBefore, countAfter, afterRaw: JSON.stringify(after) },
      };
    },
  },
  {
    name: '93 S17 escape-and-marker on diff Before pane: HTML tags neutralized + ZWSP marker emitted',
    run: () => {
      const evil = '<img src=x onerror=alert(1)>​';
      const html = _renderRevealMarkers(evil);
      // R12 cross-check: full JSON of the rendered HTML must not contain a
      // raw `<img` substring (only the escaped `&lt;img` form is acceptable).
      const serialized = JSON.stringify(html);
      const ok =
        !html.includes('<img') &&
        html.includes('&lt;img') &&
        html.includes('&gt;') &&
        html.includes('⟦ZWSP⟧') &&
        !serialized.includes('<img');
      return {
        ok,
        detail: { html },
      };
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
    } else if (detail) {
      console.log('       detail:', JSON.stringify(detail));
    }
  }
}

console.log(`\nTotal: ${passed} passed / ${failed} failed`);
process.exitCode = failed === 0 ? 0 : 1;
