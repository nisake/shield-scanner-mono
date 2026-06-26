/**
 * Bug #4 regression: IPv6 bracket strip in markdown-exfil classifyUrl.
 *
 * Before: WHATWG URL keeps the brackets on `urlObj.hostname` for IPv6
 * literals (e.g. `[::1]`), so the `^[0-9a-fA-F:.]+$` literal regex returned
 * false. `[::1]` + a suspicious key got mis-classified as a regular hostname
 * with a strong key — *danger*, not "private IP host" warning.
 *
 * After: brackets are stripped once at the top of classifyUrl, so v6
 * literals flow through the same `isPrivateOrLoopback` path as `127.0.0.1`.
 */

import { describe, it, expect } from "vitest";
import { detectMarkdownExfil } from "@shield-scanner/core";

function findingsFor(md) {
  return detectMarkdownExfil(md);
}

describe("Bug #4 regression: IPv6 md-exfil classification", () => {
  it("loopback [::1] + strong key => warning + private IP host label", () => {
    const md = "![cat](http://[::1]/log?prompt=leak)";
    const out = findingsFor(md);
    expect(out.length).toBe(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toMatch(/private IP host/);
    // Host is no longer embedded in `technique` (R12 — would leak attacker
    // host through priority.js#labelFor into the banner). It now lives on
    // `meta.host`, bare (no brackets).
    expect(out[0].meta.host).toBe("::1");
    expect(out[0].meta.host).not.toContain("[");
  });

  it("link-local fe80::1 + strong key => warning + private IP host label", () => {
    const md = "![x](http://[fe80::1]/?prompt=p)";
    const out = findingsFor(md);
    expect(out.length).toBe(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toMatch(/private IP host/);
  });

  it("unique-local fc00:: + strong key => warning + private IP host label", () => {
    const md = "![x](http://[fc00::1]/?prompt=p)";
    const out = findingsFor(md);
    expect(out.length).toBe(1);
    expect(out[0].severity).toBe("warning");
    expect(out[0].technique).toMatch(/private IP host/);
  });

  it("public IPv6 + strong key still escalates to danger + public IP host label", () => {
    const md = "![x](http://[2001:db8::1]/?prompt=p)";
    const out = findingsFor(md);
    expect(out.length).toBe(1);
    expect(out[0].severity).toBe("danger");
    expect(out[0].technique).toMatch(/public IP host/);
    expect(out[0].meta.host).toBe("2001:db8::1");
    expect(out[0].meta.host).not.toContain("[");
  });

  it("loopback IPv6 with no suspicious key stays silent (no noise on internal links)", () => {
    const md = "![x](http://[::1]/static/img.png)";
    const out = findingsFor(md);
    expect(out).toEqual([]);
  });
});
