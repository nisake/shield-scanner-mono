/**
 * S1ALPHA-004 regression: load-time sanity check on the homoglyphs rule map.
 *
 * Background: when an `orig` label's leading codepoint disagrees with the
 * map key (as happened in v1.5.0 for 7 Cherokee rows), the user-facing
 * `original` string in findings refers to a different codepoint than what
 * was actually detected, AND any future label-derived sanitizer would
 * substitute the wrong character. We add `auditHomoglyphMap()` so that
 * regression test fixtures pin this invariant, and a warn-only load-time
 * audit so the issue is loud in the logs even when nobody runs the tests.
 *
 * The audit deliberately does NOT throw at load time — a single bad rules
 * row should not brick the entire MCP — but new rule rows are expected to
 * keep the map clean. This test pins the contract of the helper itself
 * (it correctly identifies a mismatched row) without asserting on the
 * current production map state, which is being fixed independently under
 * S1ALPHA-002 at the rules-data layer.
 */

import { describe, it, expect } from "vitest";
import { auditHomoglyphMap } from "@shield-scanner/core";

describe("S1ALPHA-004: homoglyph map sanity check", () => {
  it("auditHomoglyphMap returns [] for a clean map (key == orig leading codepoint)", () => {
    const clean = {
      А: { orig: "А (Cyrillic)", looks: "A (Latin)" },
      Ꭺ: { orig: "Ꭺ (Cherokee)", looks: "A (Latin)" },
    };
    expect(auditHomoglyphMap(clean)).toEqual([]);
  });

  it("auditHomoglyphMap flags an entry whose orig leads with a different codepoint", () => {
    // This is exactly the S1ALPHA-001/004 shape: key is U+13B1 (Ꮁ) but
    // orig label leads with U+13A1 (Ꭱ) — same Cherokee block, different
    // glyph, silent corruption when the label is used downstream.
    const broken = {
      "Ꮁ": { orig: "Ꭱ (Cherokee)", looks: "R (Latin)" },
    };
    const out = auditHomoglyphMap(broken);
    expect(out).toHaveLength(1);
    expect(out[0].keyCp).toBe("U+13B1");
    expect(out[0].origLeadCp).toBe("U+13A1");
  });

  it("auditHomoglyphMap flags missing/empty orig as a mismatch (not a crash)", () => {
    const broken = {
      А: { looks: "A (Latin)" }, // no orig
      В: { orig: "", looks: "B (Latin)" }, // empty orig
    };
    const out = auditHomoglyphMap(broken);
    expect(out).toHaveLength(2);
    expect(out[0].origLeadCp).toBe("(missing)");
  });

  it("auditHomoglyphMap distinguishes multiple bad rows", () => {
    const broken = {
      А: { orig: "А (Cyrillic)", looks: "A (Latin)" }, // clean
      "Ꮁ": { orig: "Ꭱ (Cherokee)", looks: "R (Latin)" }, // bad
      "Ꮌ": { orig: "Ꭼ (Cherokee)", looks: "E (Latin)" }, // bad
    };
    const out = auditHomoglyphMap(broken);
    expect(out).toHaveLength(2);
    const keys = out.map((m) => m.keyCp).sort();
    expect(keys).toEqual(["U+13B1", "U+13BC"]);
  });
});
