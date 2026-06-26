/**
 * Sanitizer round-trip smoke tests.
 */
import { describe, it, expect } from "vitest";
import { sanitize } from "../src/sanitizer.js";

describe("sanitize", () => {
  it("returns the same text when nothing is suspicious", () => {
    const txt = "hello world";
    const r = sanitize(txt);
    expect(r.cleaned).toBe(txt);
    expect(r.removedCounts).toBeTypeOf("object");
  });

  it("strips invisible Tag-block chars", () => {
    const txt = "before\u{E0041}after";
    const r = sanitize(txt);
    expect(r.cleaned.includes("\u{E0041}")).toBe(false);
    expect(r.cleaned.includes("before")).toBe(true);
    expect(r.cleaned.includes("after")).toBe(true);
  });

  it("strips control characters (NUL)", () => {
    const txt = "hello\x00world";
    const r = sanitize(txt);
    expect(r.cleaned.includes("\x00")).toBe(false);
  });

  it("removedCounts reflects work performed", () => {
    const txt = "x\u{E0041}y\u{E0042}z";
    const r = sanitize(txt);
    // At minimum, invisibleUnicode count should be > 0
    const total = Object.values(r.removedCounts || {}).reduce(
      (a, b) => a + (typeof b === "number" ? b : 0),
      0,
    );
    expect(total).toBeGreaterThan(0);
  });
});
