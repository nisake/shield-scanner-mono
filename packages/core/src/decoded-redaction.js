/**
 * R12 decoded-text redaction (S12 fix for R12-IMG-002).
 *
 * Some parsers (currently only the image parser) synthesize plaintext from
 * non-plaintext source bytes — XML entity expansion (`&#x49;` → `I`), UTF-16
 * transcoding, zlib inflation, IPTC UTF-8 mode-switch. The synthesized strings
 * flow into the detector as `text`, and any `suspiciousPatterns` hit inside
 * them would otherwise echo `matched` / `context` back to the caller verbatim
 * — turning Shield Scanner into a decoding oracle exactly the way Risk #12 of
 * the spec forbids (and exactly the way `scanShadowForSuspiciousPatterns`
 * already protects against for the NFKC / invisibleStripped shadow paths).
 *
 * The parser hands us `decodedRanges`: an array of `{start, end, location,
 * encoding}` covering the character spans inside the parser's joined text
 * whose VALUE bytes were synthesized. This helper rewrites any finding whose
 * `position` falls inside a decoded range so:
 *   - `matched` becomes a structural placeholder that does NOT contain the
 *     decoded text (pattern name + decoded-source breadcrumb only).
 *   - `context` becomes a structural placeholder for the same reason.
 *   - `decodedSource` / `decodedEncoding` structural breadcrumbs are added so
 *     downstream UIs can still explain *why* the hit was redacted.
 *
 * The detector-controlled `pattern` field is preserved verbatim — it is rule-
 * name vocabulary, not user text, so it never leaks the attack payload. The
 * `severity` is preserved too (the hit still counts toward danger / warning
 * totals; the alert is real, only the verbatim quote is scrubbed).
 *
 * NOTE: shadow-bypass findings (via scanShadowForSuspiciousPatterns) carry
 * `matched` taken from the ORIGINAL (untouched) text via mapSpanToOriginal —
 * so for image-decoded text, the "original" is the decoder-synthesized text
 * itself, which means even shadow hits leak. We redact both direct and
 * shadow hits when they land inside a decoded range.
 */

/**
 * Mutate `findings.suspiciousPatterns` in place: redact any entry whose
 * `position` lies inside any decoded range. Pure no-op when `decodedRanges`
 * is empty / missing or `findings.suspiciousPatterns` is empty / missing.
 *
 * @param {Object} findings - the canonical detector findings object
 * @param {Array<{start:number,end:number,location:string,encoding:string}>} decodedRanges
 */
export function redactDecodedFindings(findings, decodedRanges) {
  if (!findings || typeof findings !== "object") return findings;
  if (!Array.isArray(decodedRanges) || decodedRanges.length === 0) {
    return findings;
  }
  const arr = findings.suspiciousPatterns;
  if (!Array.isArray(arr) || arr.length === 0) return findings;

  for (let i = 0; i < arr.length; i++) {
    const f = arr[i];
    if (!f || typeof f.position !== "number") continue;
    const matchLen =
      (typeof f.matchLen === "number" && f.matchLen) ||
      (typeof f.matched === "string" && f.matched.length) ||
      1;
    const hitStart = f.position;
    const hitEnd = f.position + matchLen;
    const hostRange = decodedRanges.find(
      (r) =>
        typeof r === "object" &&
        typeof r.start === "number" &&
        typeof r.end === "number" &&
        hitStart >= r.start &&
        hitEnd <= r.end
    );
    if (!hostRange) continue;
    // Build a structural placeholder that cannot itself be parsed as a new
    // attack instruction. It names the pattern and location only — no
    // user-controlled tokens, no verbatim slice of the decoded text.
    const placeholder = `[REDACTED — decoded from ${hostRange.location} (${hostRange.encoding || "decoded"})]`;
    arr[i] = {
      ...f,
      matched: placeholder,
      context: placeholder,
      // Structural breadcrumbs so consumers can still explain the alert.
      decodedSource: hostRange.location,
      decodedEncoding: hostRange.encoding || null,
      r12Redacted: true,
    };
  }
  return findings;
}

export default { redactDecodedFindings };
