/**
 * S1-α regression: Cherokee + Armenian homoglyph expansion (v1.5.0).
 *
 * - Cherokee letters that visually impersonate Latin uppercase fire when
 *   adjacent to Latin context (same "near Latin only" gate as Cyrillic).
 * - Armenian: only օ (U+0585 → o) and ո (U+0578 → n) included. հ (U+0570)
 *   is DELIBERATELY EXCLUDED because it appears in virtually every
 *   Armenian word and would FP-storm on bilingual content.
 * - Greek is NOT included in this pass (论文/formula FP risk).
 */

import { describe, it, expect } from "vitest";
import { detectHomoglyphs, auditHomoglyphMap, normalizeHomoglyphs } from "@shield-scanner/core";

const cp = (n) => String.fromCodePoint(n);

describe("S1-α: Cherokee homoglyphs", () => {
  it("flags Cherokee Ꭺ (U+13AA) inside a Latin word", () => {
    const out = detectHomoglyphs(`p${cp(0x13aa)}ypal`);
    expect(out.length).toBeGreaterThanOrEqual(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].original).toContain("Cherokee");
    expect(out[0].replacement).toContain("A (Latin)");
  });

  it("flags Cherokee Ꮃ (U+13B3) inside a Latin word", () => {
    const out = detectHomoglyphs(`o${cp(0x13b3)}ner`);
    expect(out.length).toBeGreaterThanOrEqual(1);
    expect(out[0].replacement).toContain("W (Latin)");
  });

  it("flags Cherokee Ꮤ (U+13D4) inside a Latin word", () => {
    const out = detectHomoglyphs(`s${cp(0x13d4)}ord`);
    expect(out.length).toBeGreaterThanOrEqual(1);
    expect(out[0].original).toContain("Cherokee");
  });

  it("does NOT flag Cherokee chars in pure Cherokee text (no Latin context)", () => {
    // Pure Cherokee text (no Latin letters) — detector short-circuits.
    const allCherokee = cp(0x13aa) + cp(0x13a1) + cp(0x13ac) + cp(0x13b3);
    const out = detectHomoglyphs(allCherokee);
    expect(out).toEqual([]);
  });

  it("covers the full v1.5.0 Cherokee set (9 canonical confusables codepoints)", () => {
    // Each codepoint must produce >= 1 finding when adjacent to Latin.
    // These are the canonical Unicode confusables Cherokee→Latin set
    // (S1ALPHA-002 fix: previous values were offset by ~0x10 and did not
    // actually resemble the claimed Latin letter).
    const cherokeeCodepoints = [
      0x13aa, // Ꭺ → A
      0x13a1, // Ꭱ → R
      0x13ac, // Ꭼ → E
      0x13b3, // Ꮃ → W
      0x13b7, // Ꮇ → M
      0x13bb, // Ꮋ → H
      0x13d4, // Ꮤ → W
      0x13df, // Ꮯ → C
      0x13f4, // Ᏼ → B
    ];
    for (const c of cherokeeCodepoints) {
      const out = detectHomoglyphs(`a${cp(c)}b`);
      expect(out.length, `codepoint U+${c.toString(16)}`).toBeGreaterThanOrEqual(1);
    }
  });

  it("S1ALPHA-001/003: every finding's `original` starts with the actual inserted codepoint (label parity)", () => {
    // Regression guard: previously the Cherokee `orig` labels referenced a
    // DIFFERENT codepoint than the JSON key (e.g. key U+13B1 with label
    // starting U+13A1), so the user saw a different glyph than the one
    // present in the input. Lock the invariant per finding.
    const cherokeeCodepoints = [
      0x13aa, 0x13a1, 0x13ac, 0x13b3, 0x13b7,
      0x13bb, 0x13d4, 0x13df, 0x13f4,
    ];
    for (const c of cherokeeCodepoints) {
      const inserted = cp(c);
      const out = detectHomoglyphs(`a${inserted}b`);
      expect(out.length, `codepoint U+${c.toString(16)}`).toBeGreaterThanOrEqual(1);
      expect(
        out[0].original.startsWith(inserted),
        `finding.original "${out[0].original}" must start with inserted U+${c.toString(16)}`,
      ).toBe(true);
    }
  });
});

describe("S1-α: Armenian homoglyphs (հ excluded)", () => {
  it("flags Armenian օ (U+0585 → o) inside a Latin word", () => {
    const out = detectHomoglyphs(`p${cp(0x0585)}p`);
    expect(out.length).toBeGreaterThanOrEqual(1);
    expect(out[0].replacement).toContain("o (Latin)");
    expect(out[0].original).toContain("Armenian");
  });

  it("flags Armenian ո (U+0578 → n) inside a Latin word", () => {
    const out = detectHomoglyphs(`a${cp(0x0578)}d`);
    expect(out.length).toBeGreaterThanOrEqual(1);
    expect(out[0].replacement).toContain("n (Latin)");
  });

  it("R-Armenian: հ (U+0570) is DELIBERATELY EXCLUDED — must not fire even adjacent to Latin", () => {
    // Bilingual context with the excluded character. The detector MUST stay
    // silent here to keep Armenian-content FP suppressed.
    const out = detectHomoglyphs(`a${cp(0x0570)}b`);
    // Other characters in the input may fire (none here), but no finding
    // should reference հ.
    for (const f of out) {
      expect(f.original).not.toContain(cp(0x0570));
    }
  });

  it("does NOT flag Armenian chars in pure Armenian text", () => {
    // Pure Armenian (no Latin) — the function short-circuits on the
    // /[a-zA-Z]/.test(content) gate.
    const pure = "Բարեւ " + cp(0x0585) + " " + cp(0x0578);
    const out = detectHomoglyphs(pure);
    expect(out).toEqual([]);
  });
});

describe("S1-α: byCategory shape invariant (R13)", () => {
  it("R13: new homoglyphs land in the existing homoglyphs bucket only", () => {
    // Confirms the detector does not invent a new top-level category for
    // Cherokee or Armenian — they fold into homoglyphs per the existing
    // 5-key shape.
    const out = detectHomoglyphs(`p${cp(0x13aa)}${cp(0x0585)}p`);
    expect(out.length).toBeGreaterThanOrEqual(2);
    for (const f of out) {
      // All findings have the same shape as Cyrillic ones (no extra
      // top-level fields that would betray a new category routing).
      expect(f).toHaveProperty("original");
      expect(f).toHaveProperty("replacement");
      expect(f).toHaveProperty("position");
      expect(f).toHaveProperty("context");
      expect(f.severity).toBe("warning");
    }
  });
});

describe("S1ALPHA-001/004: homoglyphs.json key/label invariant", () => {
  it("auditHomoglyphMap() returns no mismatches for the whole map", () => {
    // Regression for S1ALPHA-001/003/004: previously 7 Cherokee entries had
    // `orig` labels whose leading codepoint differed from the JSON key
    // (e.g. key U+13B1 with label starting U+13A1). That broke the UI
    // (wrong glyph displayed) and the sanitizer (normalizeHomoglyphs would
    // resolve the wrong Latin letter for whichever side was canonical).
    // The audit MUST stay green across the entire map (Cyrillic / Fullwidth
    // / Cherokee / Armenian) — not just Cherokee — to prevent silent
    // regressions in any future rule additions.
    const mismatches = auditHomoglyphMap();
    expect(
      mismatches,
      `homoglyphs.json mismatches: ${JSON.stringify(mismatches)}`,
    ).toEqual([]);
  });
});

describe("S1ALPHA-002/004: normalizeHomoglyphs uses canonical Cherokee→Latin mapping", () => {
  // The canonical Unicode confusables Cherokee→Latin set. Before the
  // S1ALPHA-002 fix, these codepoints were not even present in the map
  // (offset by ~0x10), so `Ꮃikipedia` (with canonical U+13B3) was a hit
  // for attackers but went undetected.
  const cases = [
    [0x13a1, "R"], // Ꭱ → R
    [0x13ac, "E"], // Ꭼ → E
    [0x13b3, "W"], // Ꮃ → W
    [0x13b7, "M"], // Ꮇ → M
    [0x13bb, "H"], // Ꮋ → H
    [0x13d4, "W"], // Ꮤ → W
    [0x13df, "C"], // Ꮯ → C
  ];

  for (const [codepoint, latin] of cases) {
    it(`normalizes U+${codepoint.toString(16).toUpperCase()} to ${latin} when adjacent to Latin`, () => {
      const out = normalizeHomoglyphs(`a${cp(codepoint)}b`);
      expect(out).toBe(`a${latin}b`);
    });
  }
});
