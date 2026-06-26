// =============================================================
//  Shield Scanner Web — S1-α homoglyph regression suite
// =============================================================
// Phase 1 follow-up: ports the homoglyph-specific assertions from the
// pre-monorepo archive harness (Tests 94 / 95 / 96 / 97) into the
// post-split @shield-scanner/core surface. The companion MCP-side suite
// lives at packages/mcp/test/regression/homoglyphs-cherokee-armenian.test.js;
// here we cover the same intent through the Web-facing analyze() entry point
// so the Web bundle keeps parity with MCP after any rules-data refactor.
//
// Codepoint correction note: the archive harness Test 96 listed buggy
// pre-S1ALPHA-002 Cherokee codepoints (offset by ~0x10 from the canonical
// Unicode confusables set). Those values are no longer present in
// homoglyphs.json. We honor the test INTENT (every Cherokee confusable
// fires next to Latin) with the canonical fixed codepoints — copying the
// archive list verbatim would produce a test that fails against the
// (correctly fixed) production code.
//
// R12 (no shadow-copy leakage): every assertion reads only original /
// replacement / severity from each finding, all of which are derived from
// HOMOGLYPH_MAP, not from any shadow buffer. Safe.
// R13 (5-key top-level bucket invariant): all reads go through r.homoglyphs
// only; we never invent r.cherokee or r.armenian.
// R18 (env-abstract order): not relevant for the pure-string homoglyph
// detector — no DOM / FS / network. Default Node env adapter is fine, and
// `analyze` is imported directly from @shield-scanner/core (case B) so no
// setEnv() shim is needed here.
// =============================================================

import { analyze } from '@shield-scanner/core';

// _pureHomo accessor: strip mathAlphanumeric entries from the homoglyphs
// bucket. The Math Bold Sans bypass folds into the same bucket post-split;
// for the S1-α regression we only care about real Cyrillic / Cherokee /
// Armenian / Fullwidth hits. Matches the convention used in harness.mjs
// (line 37) — kept local to keep this file self-contained.
const _pureHomo = (r) => (r.homoglyphs || []).filter((f) => f.type !== 'mathAlphanumeric');

const cp = (n) => String.fromCodePoint(n);

// Canonical Unicode confusables Cherokee→Latin set, post-S1ALPHA-002 fix.
// DO NOT replace with the archive harness Test 96 values
// [0x13AA, 0x13B1, 0x13BC, 0x13C3, 0x13C7, 0x13CB, 0x13E4, 0x13EF, 0x13F4]
// — those were the pre-fix buggy values that are no longer in the rule map.
const CHEROKEE_CANONICAL = [
  { cpVal: 0x13aa, latin: 'A' }, // Ꭺ → A
  { cpVal: 0x13a1, latin: 'R' }, // Ꭱ → R
  { cpVal: 0x13ac, latin: 'E' }, // Ꭼ → E
  { cpVal: 0x13b3, latin: 'W' }, // Ꮃ → W
  { cpVal: 0x13b7, latin: 'M' }, // Ꮇ → M
  { cpVal: 0x13bb, latin: 'H' }, // Ꮋ → H
  { cpVal: 0x13d4, latin: 'W' }, // Ꮤ → W
  { cpVal: 0x13df, latin: 'C' }, // Ꮯ → C
  { cpVal: 0x13f4, latin: 'B' }, // Ᏼ → B
];

const tests = [
  {
    name: 'S1-alpha-01 Cherokee homoglyph set fires adjacent to Latin (canonical 9 codepoints, S1ALPHA-002 regression guard)',
    run: () => {
      for (const { cpVal, latin } of CHEROKEE_CANONICAL) {
        const inserted = cp(cpVal);
        const out = analyze('a' + inserted + 'b', { fileType: 'text' });
        const findings = out.findings || {};
        const pure = _pureHomo(findings);

        // (i) Cherokee warning must be present.
        const hasCherokee = pure.some(
          (f) => (f.original || '').includes('Cherokee') && f.severity === 'warning',
        );
        if (!hasCherokee) {
          return {
            ok: false,
            why: `codepoint U+${cpVal.toString(16)}: no Cherokee/warning finding (pure homoglyphs=${pure.length})`,
          };
        }

        // (ii) Leading codepoint of finding.original equals the inserted
        // codepoint (S1ALPHA-001/003 label parity).
        const first = pure.find((f) => (f.original || '').includes('Cherokee'));
        if (!first || typeof first.original !== 'string' || !first.original.startsWith(inserted)) {
          return {
            ok: false,
            why: `codepoint U+${cpVal.toString(16)}: finding.original "${first && first.original}" does not start with inserted glyph`,
          };
        }

        // (iii) For U+13AA, replacement must contain 'A (Latin)' — matches
        // old harness Test 94 assertion shape.
        if (cpVal === 0x13aa) {
          if (!(first.replacement || '').includes('A (Latin)')) {
            return {
              ok: false,
              why: `U+13AA: replacement "${first.replacement}" missing 'A (Latin)'`,
            };
          }
        }

        // R12 sanity: raw user input was 'a<X>b'; ensure the finding does not
        // accidentally embed the entire shadow span. We allow `original` to
        // contain the single inserted glyph (that's how the label works), but
        // the full 'a<X>b' wrapper text must not appear in a serialized
        // finding.
        const blob = JSON.stringify(first);
        if (blob.includes('a' + inserted + 'b')) {
          return {
            ok: false,
            why: `codepoint U+${cpVal.toString(16)}: raw wrapper 'a<X>b' leaked into finding JSON`,
          };
        }
      }
      return { ok: true };
    },
  },

  {
    name: 'S1-alpha-02 Armenian inclusion/exclusion gate: oh (U+0585) fires, he (U+0570) deliberately does NOT',
    run: () => {
      // (a) Armenian small o (U+0585) between two Latin p → must fire.
      const outA = analyze('p' + cp(0x0585) + 'p', { fileType: 'text' });
      const fA = outA.findings || {};
      const pureA = _pureHomo(fA);
      const hitA = pureA.some(
        (f) =>
          (f.original || '').includes('Armenian') && (f.replacement || '').includes('o (Latin)'),
      );
      if (!hitA) {
        return {
          ok: false,
          why: `(a) Armenian U+0585 between Latin p..p did not produce 'Armenian'/'o (Latin)' finding (pure=${pureA.length})`,
        };
      }

      // (b) Armenian he (U+0570) between two Latin chars — deliberately
      // EXCLUDED from the rule map. No homoglyph finding may reference
      // U+0570.
      const outB = analyze('a' + cp(0x0570) + 'b', { fileType: 'text' });
      const fB = outB.findings || {};
      const allB = fB.homoglyphs || [];
      const leak = allB.find((f) => (f.original || '').includes(cp(0x0570)));
      if (leak) {
        return {
          ok: false,
          why: `(b) Armenian U+0570 must NOT fire but found finding: ${JSON.stringify(leak)}`,
        };
      }

      // (c) Armenian ո (U+0578 → n) between two Latin chars — must fire as
      // the second canonical Armenian inclusion (MCP-side parity).
      const outC = analyze('a' + cp(0x0578) + 'd', { fileType: 'text' });
      const fC = outC.findings || {};
      const pureC = _pureHomo(fC);
      const hitC = pureC.some(
        (f) =>
          (f.original || '').includes('Armenian') && (f.replacement || '').includes('n (Latin)'),
      );
      if (!hitC) {
        return {
          ok: false,
          why: `(c) Armenian U+0578 between Latin a..d did not produce 'Armenian'/'n (Latin)' finding (pure=${pureC.length})`,
        };
      }

      return { ok: true };
    },
  },

  {
    name: 'S1-alpha-03 pure non-Latin context gate: pure Cherokee / pure Armenian text does NOT fire',
    run: () => {
      // (a) Pure Cherokee (no Latin) — detector short-circuits.
      const pureCherokee = cp(0x13aa) + cp(0x13a1) + cp(0x13ac) + cp(0x13b3);
      const outA = analyze(pureCherokee, { fileType: 'text' });
      const fA = outA.findings || {};
      const lenA = (fA.homoglyphs || []).length;
      if (lenA !== 0) {
        return {
          ok: false,
          why: `(a) pure Cherokee text produced ${lenA} homoglyph finding(s); expected 0`,
        };
      }

      // (b) Pure Armenian context (greeting + included codepoints, no Latin).
      const pureArmenian = 'Բարեւ ' + cp(0x0585) + ' ' + cp(0x0578);
      const outB = analyze(pureArmenian, { fileType: 'text' });
      const fB = outB.findings || {};
      const lenB = (fB.homoglyphs || []).length;
      if (lenB !== 0) {
        return {
          ok: false,
          why: `(b) pure Armenian text produced ${lenB} homoglyph finding(s); expected 0`,
        };
      }

      return { ok: true };
    },
  },
];

let passed = 0;
let failed = 0;

for (const t of tests) {
  let result = { ok: false, why: 'did not run' };
  let err = null;
  try {
    result = t.run();
  } catch (e) {
    err = e;
  }
  if (!err && result && result.ok) {
    passed++;
    console.log(`PASS ${t.name}`);
  } else {
    failed++;
    console.log(`FAIL ${t.name}`);
    if (err) console.log('       error:', err && err.message ? err.message : String(err));
    else if (result && result.why) console.log('       reason:', result.why);
  }
}

console.log(`\nTotal: ${passed} passed / ${failed} failed`);
process.exitCode = failed === 0 ? 0 : 1;
