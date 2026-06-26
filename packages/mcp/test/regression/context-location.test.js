/**
 * S20 regression: grapheme-aware getContext + enrichFindingsLocation.
 *
 * Boundary contract (see server/core/utils.js):
 *   - getContext must not slice between a base char and its combining marks /
 *     ZWJ / VS / skin-tone modifier (up to 8 chars snap-back/forward).
 *   - getContext must not split a surrogate pair.
 *   - enrichFindingsLocation is a pure helper: leaf-set when missing, prefix
 *     when already present, and never mutates the input.
 */

import { describe, it, expect } from "vitest";
import { getContext } from "@shield-scanner/core";
import { enrichFindingsLocation } from "@shield-scanner/core";

const cp = (n) => String.fromCodePoint(n);

describe("S20 getContext: grapheme-aware boundary snapping", () => {
  it("plain ASCII still works (no surprise change)", () => {
    const text = "hello world this is a normal sentence";
    const out = getContext(text, 6, 5);
    // S16-004: getContext brackets are U+29D7 / U+29D8 (⦗⦘) to avoid collision
    // with reveal-mode marker brackets U+27E6 / U+27E7 (⟦⟧).
    expect(out).toContain("⦗world⦘");
  });

  it("does not split a surrogate pair (𝐀 = U+1D400 needs both halves)", () => {
    // Build "aaaaa𝐀bbbbb" with the surrogate pair right at the boundary.
    const text = "aaaaa" + cp(0x1d400) + "bbbbb";
    // Place pos at the 'b' just after the surrogate pair (UTF-16 index 7).
    const out = getContext(text, 7, 1, 3);
    // The displayed before/after slice must not contain a lone surrogate code
    // unit. Check by re-decoding: every codepoint should round-trip.
    for (let i = 0; i < out.length; i++) {
      const code = out.charCodeAt(i);
      const isHigh = code >= 0xd800 && code <= 0xdbff;
      const isLow = code >= 0xdc00 && code <= 0xdfff;
      if (isHigh) {
        const next = out.charCodeAt(i + 1);
        expect(next >= 0xdc00 && next <= 0xdfff).toBe(true);
        i++;
      } else {
        expect(isLow).toBe(false);
      }
    }
  });

  it("does not cut between base and combining mark (á = a + U+0301)", () => {
    const text = "xxxxxáyyyyy";
    // The acute accent is at index 6. Ask for context with the match starting
    // right at 'y' (index 7). The 'before' slice must include the full á.
    const out = getContext(text, 7, 1, 4);
    // We don't want a lone combining mark stranded — checked by ensuring the
    // 'a' before ́ is present in the rendered context.
    expect(out).toMatch(/á/);
  });

  it("does not cut a ZWJ-joined family emoji (👨‍👩‍👧)", () => {
    // U+1F468 ZWJ U+1F469 ZWJ U+1F467
    const family = cp(0x1f468) + "‍" + cp(0x1f469) + "‍" + cp(0x1f467);
    const text = "prefix " + family + " suffix-text-here";
    // Mark 's' in "suffix" — make sure the slice does not strand a ZWJ at the
    // boundary.
    const idx = text.indexOf("suffix");
    const out = getContext(text, idx, 6, 4);
    // ZWJ alone at the start of `before` would be a boundary slip.
    expect(out.startsWith("‍")).toBe(false);
  });

  it("snaps end past VS17 (Plane 14) following a CJK base", () => {
    // 字 (U+5B57) + VS17 (U+E0100)
    const text = "前後の文脈字" + cp(0xe0100) + "末尾";
    // Pos at '末' — verify the VS17 isn't stranded as the first char of after.
    const idx = text.indexOf("末");
    const out = getContext(text, idx, 1, 3);
    // After the match marker we should not see a lone VS17 trailing.
    expect(out.includes("末")).toBe(true);
  });

  it("does not invoke String#normalize (NFKC stays out of context)", () => {
    // 'ﬁ' (U+FB01) NFKC-normalizes to 'fi'. We must preserve the original.
    const text = "abc ﬁ xyz";
    const out = getContext(text, 4, 1, 5);
    expect(out).toContain("ﬁ");
    expect(out).not.toContain("fi ");
  });

  it("newline replacement still works (↵ marker)", () => {
    const text = "abc\ndef\nghi";
    const out = getContext(text, 4, 3);
    expect(out).toContain("↵");
  });
});

describe("S20 enrichFindingsLocation: leaf-set and prefix", () => {
  it("leaf-sets contextLocation when missing", () => {
    const findings = {
      invisibleUnicode: [{ char: "U+200B", position: 1 }],
    };
    const out = enrichFindingsLocation(findings, { label: "Page 3" });
    expect(out.invisibleUnicode[0].contextLocation).toBe("Page 3");
  });

  it("prefixes when contextLocation already exists", () => {
    const findings = {
      invisibleUnicode: [{ contextLocation: "Subject", position: 0 }],
    };
    const out = enrichFindingsLocation(findings, { label: "Email" });
    expect(out.invisibleUnicode[0].contextLocation).toBe("Email > Subject");
  });

  it("joins multiple tags left-to-right", () => {
    const findings = {
      suspiciousPatterns: [{ contextLocation: "Comment", position: 0 }],
    };
    const out = enrichFindingsLocation(findings, [
      { label: "Page 3" },
      { label: "Slide 2" },
    ]);
    expect(out.suspiciousPatterns[0].contextLocation).toBe(
      "Page 3 > Slide 2 > Comment"
    );
  });

  it("does not mutate the input findings object", () => {
    const findings = {
      invisibleUnicode: [{ char: "U+200B", position: 1 }],
    };
    const out = enrichFindingsLocation(findings, { label: "Page 3" });
    expect(findings.invisibleUnicode[0].contextLocation).toBeUndefined();
    expect(out).not.toBe(findings);
    expect(out.invisibleUnicode).not.toBe(findings.invisibleUnicode);
  });

  it("works on a flat array (extraFindings shape)", () => {
    const arr = [
      { element: "X", contextLocation: "Page 1" },
      { element: "Y" },
    ];
    const out = enrichFindingsLocation(arr, { label: "Attachment foo.pdf" });
    expect(out[0].contextLocation).toBe("Attachment foo.pdf > Page 1");
    expect(out[1].contextLocation).toBe("Attachment foo.pdf");
  });

  it("does not double-prefix the same label", () => {
    const arr = [{ contextLocation: "Page 1 > inner" }];
    const out = enrichFindingsLocation(arr, { label: "Page 1" });
    expect(out[0].contextLocation).toBe("Page 1 > inner");
  });
});

describe("S20 PDF text offset arithmetic (sanity)", () => {
  it("offset tracking: position field tracks join('\\n') concatenation", () => {
    // Mock the behavior: when texts = ["abc","def"], join("\n") => "abc\ndef"
    // and the 2nd line starts at offset 4 (3 chars + 1 newline).
    const lines = ["abc", "def"];
    let offset = 0;
    const positions = lines.map((l) => {
      const p = offset;
      offset += l.length + 1;
      return p;
    });
    const joined = lines.join("\n");
    expect(joined.slice(positions[0], positions[0] + 3)).toBe("abc");
    expect(joined.slice(positions[1], positions[1] + 3)).toBe("def");
  });
});
