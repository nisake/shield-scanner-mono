/**
 * S10 — formula-injection detector unit tests.
 *
 * Drives detectFormulaInjection() directly with synthetic CSV/XLSX-shaped
 * input. No parser involvement — these tests exercise the leading-char gate
 * + normalizeFormulaPrefix + normalizeXlfn + the FI-01 dangerous-function
 * blocklist + the FI-02 prefix-only warning path (with numeric/phone
 * suppression).
 *
 * Coverage map:
 *   FI-01 — dangerous-function blocklist: HYPERLINK / WEBSERVICE / FILTERXML
 *           / IMPORTXML / IMPORTHTML / IMPORTDATA / IMPORTFEED / IMPORTRANGE
 *           / DDE / DDEAUTO / CALL / REGISTER / EXEC / RTD plus DDE-pipe
 *           command tokens (cmd|, powershell|, mshta|, wscript|, cscript|,
 *           rundll32|, regsvr32|).
 *   FI-02 — prefix triggers: = + - @ \t \r, U+FF1D fullwidth equals,
 *           _xlfn. and _xlfn._xlws. multi-prefix bypass.
 *   Suppression — numeric / decimal / phone shapes.
 *   Benign — =SUM / =AVERAGE / =VLOOKUP / =IF (no danger; FI-02 may flag
 *           as info-only warning, which is acceptable).
 *   FileType gate — only csv|xlsx; text returns [].
 */
import { describe, it, expect } from "vitest";
import { detectFormulaInjection } from "../src/formula-injection.js";

// ---------------------------------------------------------------------------
// Small helpers to assert finding shape without duplicating every property.
// ---------------------------------------------------------------------------
function hasDanger(findings) {
  return findings.some(
    (f) => f.severity === "danger" && f.category === "formula-injection",
  );
}
function hasPrefixWarning(findings) {
  return findings.some(
    (f) => f.severity === "warning" && f.category === "formula-prefix",
  );
}

describe("detectFormulaInjection — fileType gate", () => {
  it("returns [] for non-CSV/XLSX fileType (text)", () => {
    const r = detectFormulaInjection("=HYPERLINK(\"http://x\",\"y\")", "text");
    expect(r).toEqual([]);
  });

  it("returns [] for empty content", () => {
    expect(detectFormulaInjection("", "csv")).toEqual([]);
  });

  it("returns [] for non-string content", () => {
    expect(detectFormulaInjection(null, "csv")).toEqual([]);
    expect(detectFormulaInjection(undefined, "csv")).toEqual([]);
  });

  it("runs for csv fileType", () => {
    const r = detectFormulaInjection("=HYPERLINK(\"http://x\",\"y\")", "csv");
    expect(hasDanger(r)).toBe(true);
  });

  it("runs for xlsx fileType", () => {
    const r = detectFormulaInjection("=HYPERLINK(\"http://x\",\"y\")", "xlsx");
    expect(hasDanger(r)).toBe(true);
  });
});

describe("FI-01 — Excel network exfil function blocklist", () => {
  const funcs = [
    "HYPERLINK",
    "WEBSERVICE",
    "FILTERXML",
    "IMPORTXML",
    "IMPORTHTML",
    "IMPORTDATA",
    "IMPORTFEED",
    "IMPORTRANGE",
  ];
  for (const fn of funcs) {
    it(`flags =${fn}(...) as danger`, () => {
      const r = detectFormulaInjection(`=${fn}("http://attacker/x")`, "csv");
      expect(hasDanger(r)).toBe(true);
    });
  }

  it("is case-insensitive (=hyperlink)", () => {
    const r = detectFormulaInjection('=hyperlink("http://x","y")', "csv");
    expect(hasDanger(r)).toBe(true);
  });

  it("flags GOOGLESHEETS IMPORTXML variant", () => {
    const r = detectFormulaInjection(
      '=IMPORTXML("https://attacker.example/feed","//token")',
      "csv",
    );
    expect(hasDanger(r)).toBe(true);
  });
});

describe("FI-01 — Excel macro registration function blocklist", () => {
  const funcs = ["DDE", "DDEAUTO", "CALL", "REGISTER", "EXEC", "RTD"];
  for (const fn of funcs) {
    it(`flags =${fn}(...) as danger`, () => {
      const r = detectFormulaInjection(`=${fn}("arg1","arg2")`, "csv");
      expect(hasDanger(r)).toBe(true);
    });
  }
});

describe("FI-01 — DDE pipe-command blocklist", () => {
  const cmds = [
    "cmd",
    "powershell",
    "mshta",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
  ];
  for (const cmd of cmds) {
    it(`flags =${cmd}|... as danger`, () => {
      const r = detectFormulaInjection(`=${cmd}|'/C calc'!A0`, "csv");
      expect(hasDanger(r)).toBe(true);
    });
  }

  it("flags powershell -enc base64 payload via DDE pipe", () => {
    const r = detectFormulaInjection(
      "=powershell|'-NoP -W Hidden -Enc QQBBAA=='!A0",
      "csv",
    );
    expect(hasDanger(r)).toBe(true);
  });
});

describe("FI-02 — prefix-only triggers (no blocklisted function)", () => {
  it("flags '+' prefix on opaque token as warning", () => {
    const r = detectFormulaInjection("+arbitrary-token-here", "csv");
    expect(hasPrefixWarning(r)).toBe(true);
  });

  it("flags '@' prefix on opaque token as warning", () => {
    const r = detectFormulaInjection("@arbitrary-token-here", "csv");
    expect(hasPrefixWarning(r)).toBe(true);
  });

  it("flags TAB prefix as warning (never suppressed by numeric shape)", () => {
    const r = detectFormulaInjection("\t123456", "csv");
    expect(hasPrefixWarning(r)).toBe(true);
  });

  it("flags CR prefix as warning (never suppressed by numeric shape)", () => {
    const r = detectFormulaInjection("\r123456", "csv");
    expect(hasPrefixWarning(r)).toBe(true);
  });

  it("flags U+FF1D fullwidth equals as danger when followed by HYPERLINK", () => {
    const r = detectFormulaInjection(
      "＝HYPERLINK(\"http://x\",\"y\")",
      "csv",
    );
    expect(hasDanger(r)).toBe(true);
  });

  it("flags _xlfn. prefix bypass on HYPERLINK as danger", () => {
    const r = detectFormulaInjection(
      '=_xlfn.HYPERLINK("http://attacker/x","go")',
      "xlsx",
    );
    expect(hasDanger(r)).toBe(true);
  });

  it("flags _xlfn._xlws. multi-prefix bypass on IMPORTXML as danger", () => {
    const r = detectFormulaInjection(
      '=_xlfn._xlws.IMPORTXML("http://attacker/x","//tok")',
      "xlsx",
    );
    expect(hasDanger(r)).toBe(true);
  });

  it("flags stacked _xlfn._xlfn. on WEBSERVICE as danger", () => {
    const r = detectFormulaInjection(
      '=_xlfn._xlfn.WEBSERVICE("http://attacker/x")',
      "xlsx",
    );
    expect(hasDanger(r)).toBe(true);
  });
});

describe("FI-02 — numeric / phone suppression", () => {
  it("does NOT flag '-123.45' (signed decimal)", () => {
    const r = detectFormulaInjection("-123.45", "csv");
    expect(r.length).toBe(0);
  });

  it("does NOT flag '+81-3-1234-5678' (international phone)", () => {
    const r = detectFormulaInjection("+81-3-1234-5678", "csv");
    expect(r.length).toBe(0);
  });

  it("does NOT flag '+1 (415) 555-0100' (US phone shape)", () => {
    const r = detectFormulaInjection("+1 (415) 555-0100", "csv");
    expect(r.length).toBe(0);
  });

  it("does NOT flag '-0' / '+0' edge cases", () => {
    expect(detectFormulaInjection("-0", "csv").length).toBe(0);
    expect(detectFormulaInjection("+0", "csv").length).toBe(0);
  });

  it("does NOT flag '+.5' (signed decimal without leading digit)", () => {
    const r = detectFormulaInjection("+.5", "csv");
    expect(r.length).toBe(0);
  });

  it("DOES flag '-123 ignore previous instructions' (numeric body + junk)", () => {
    const r = detectFormulaInjection("-123 ignore previous instructions", "csv");
    expect(hasPrefixWarning(r)).toBe(true);
  });

  it("DOES flag '+arbitrary text' (sign followed by non-numeric)", () => {
    const r = detectFormulaInjection("+arbitrary text payload", "csv");
    expect(hasPrefixWarning(r)).toBe(true);
  });
});

describe("FI-02 — leading whitespace + fullwidth equals normalization", () => {
  it("strips leading space before equals (' =HYPERLINK(...)')", () => {
    const r = detectFormulaInjection(
      ' =HYPERLINK("http://attacker/x","go")',
      "csv",
    );
    expect(hasDanger(r)).toBe(true);
  });

  it("strips leading U+00A0 (no-break space) before equals", () => {
    const r = detectFormulaInjection(
      ' =HYPERLINK("http://attacker/x","go")',
      "csv",
    );
    expect(hasDanger(r)).toBe(true);
  });

  it("maps U+FE66 small equals → '='", () => {
    const r = detectFormulaInjection(
      '﹦HYPERLINK("http://attacker/x","go")',
      "csv",
    );
    expect(hasDanger(r)).toBe(true);
  });
});

describe("benign formulas — info-only acceptable, never danger-tier", () => {
  // Per spec: benign aggregation functions MUST NOT produce a danger finding.
  // The FI-02 prefix path may still emit a warning (acceptable per Q&A:
  // "benign =SUM ... → 0 danger (info-only OK)"). We only assert no danger.
  const benigns = [
    "=SUM(A1:A10)",
    "=AVERAGE(A1:A10)",
    "=VLOOKUP(B2,Sheet1!A:D,3,FALSE)",
    "=IF(A1>10,\"big\",\"small\")",
  ];
  for (const f of benigns) {
    it(`emits no danger for ${f}`, () => {
      const r = detectFormulaInjection(f, "csv");
      expect(hasDanger(r)).toBe(false);
    });
  }
});

describe("includePrefixWarnings option", () => {
  it("suppresses FI-02 warnings when includePrefixWarnings=false", () => {
    const r = detectFormulaInjection("+arbitrary-token", "csv", {
      includePrefixWarnings: false,
    });
    expect(r.length).toBe(0);
  });

  it("still emits FI-01 danger when includePrefixWarnings=false", () => {
    const r = detectFormulaInjection(
      '=HYPERLINK("http://x","y")',
      "csv",
      { includePrefixWarnings: false },
    );
    expect(hasDanger(r)).toBe(true);
  });
});

describe("parser-emitted bracket prefix handling", () => {
  it("preserves [Sheet 'Name'!A1] as contextLocation, scans cell text only", () => {
    const line = "[Sheet 'Data'!A1] =HYPERLINK(\"http://attacker/x\",\"go\")";
    const r = detectFormulaInjection(line, "xlsx");
    expect(hasDanger(r)).toBe(true);
    const f = r.find((x) => x.severity === "danger");
    expect(f.contextLocation).toBe("Sheet 'Data'!A1");
  });

  it("preserves [Row N, Col M] as contextLocation for CSV", () => {
    const line = "[Row 2, Col 3] +arbitrary token here";
    const r = detectFormulaInjection(line, "csv");
    expect(hasPrefixWarning(r)).toBe(true);
    const f = r.find((x) => x.severity === "warning");
    expect(f.contextLocation).toBe("Row 2, Col 3");
  });

  it("does NOT mis-strip a literal '[' cell (no closing '] ')", () => {
    // No "] " in the line — cell text remains the full string, prefix gate
    // sees '[' (NOT in DANGEROUS_PREFIX_CHARS) and produces nothing.
    const r = detectFormulaInjection("[not-a-bracket-prefix=HYPERLINK", "csv");
    expect(r.length).toBe(0);
  });
});

describe("multi-line input — per-cell scanning", () => {
  it("flags multiple cells across LF-separated lines", () => {
    const content = [
      "[Row 1, Col 1] =HYPERLINK(\"http://a\",\"x\")",
      "[Row 2, Col 1] =WEBSERVICE(\"http://b\")",
      "[Row 3, Col 1] benign value",
    ].join("\n");
    const r = detectFormulaInjection(content, "csv");
    const dangers = r.filter((f) => f.severity === "danger");
    expect(dangers.length).toBe(2);
  });

  it("handles CRLF line endings identically to LF", () => {
    const content =
      "=HYPERLINK(\"http://a\",\"x\")\r\n=WEBSERVICE(\"http://b\")\r\nbenign";
    const r = detectFormulaInjection(content, "csv");
    const dangers = r.filter((f) => f.severity === "danger");
    expect(dangers.length).toBe(2);
  });
});

describe("finding shape — R12 / R13 invariants", () => {
  it("danger finding carries category='formula-injection' (item-level only)", () => {
    const r = detectFormulaInjection('=HYPERLINK("http://x","y")', "csv");
    const f = r.find((x) => x.severity === "danger");
    expect(f).toBeDefined();
    expect(f.category).toBe("formula-injection");
    expect(f.pattern).toBeTypeOf("string");
    expect(f.technique).toBeTypeOf("string");
    expect(f.matched).toBeTypeOf("string");
    expect(typeof f.position).toBe("number");
  });

  it("warning finding carries category='formula-prefix' (item-level only)", () => {
    const r = detectFormulaInjection("+arbitrary-token-here", "csv");
    const f = r.find((x) => x.severity === "warning");
    expect(f).toBeDefined();
    expect(f.category).toBe("formula-prefix");
  });

  it("matched is HTML-escaped (quotes / angle brackets neutralised)", () => {
    // escapeForDisplay HTML-encodes & < > " '. We pin the quote form to
    // confirm the raw matched text was passed through it on the way out.
    const r = detectFormulaInjection(
      '=HYPERLINK("http://x","y")',
      "csv",
    );
    const f = r.find((x) => x.severity === "danger");
    expect(f).toBeDefined();
    expect(f.matched.includes("&quot;")).toBe(true);
    expect(f.matched.includes('"')).toBe(false);
  });
});
