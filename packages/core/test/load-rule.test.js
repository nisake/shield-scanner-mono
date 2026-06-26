/**
 * env-abstract rules-loader contract test (Node impl).
 *
 * Validates:
 *  - createNodeRulesLoader() reads JSON from packages/core/data/
 *  - Accepts both "homoglyphs" and "homoglyphs.json"
 *  - Caches repeat calls (identity equality)
 *  - utils.js#loadRule falls back to Node default when no env is set
 *  - setEnv() override is honored
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createNodeRulesLoader, createNodeEnv } from "../src/env/node/index.js";
import { setEnv, resetEnv } from "../src/env/index.js";
import { loadRule } from "../src/utils.js";

describe("Node rules-loader adapter", () => {
  beforeEach(() => resetEnv());

  it("loads homoglyphs.json by short name", () => {
    const loader = createNodeRulesLoader();
    const rule = loader.loadRule("homoglyphs");
    expect(rule).toBeTypeOf("object");
    expect(rule.map).toBeTypeOf("object");
    expect(Object.keys(rule.map).length).toBeGreaterThan(10);
  });

  it("loads invisible-chars.json by short name", () => {
    const loader = createNodeRulesLoader();
    const rule = loader.loadRule("invisible-chars");
    expect(Array.isArray(rule.chars)).toBe(true);
    expect(rule.chars.length).toBeGreaterThan(0);
  });

  it("accepts .json suffix for back-compat", () => {
    const loader = createNodeRulesLoader();
    const a = loader.loadRule("suspicious-patterns");
    const b = loader.loadRule("suspicious-patterns.json");
    expect(a).toBe(b);
  });

  it("caches: repeat loadRule returns same reference", () => {
    const loader = createNodeRulesLoader();
    const a = loader.loadRule("exfil-patterns");
    const b = loader.loadRule("exfil-patterns");
    expect(a).toBe(b);
  });

  it("throws on missing rule file", () => {
    const loader = createNodeRulesLoader();
    expect(() => loader.loadRule("does-not-exist")).toThrow();
  });
});

describe("utils.loadRule fallback + setEnv override", () => {
  beforeEach(() => resetEnv());

  it("falls back to Node fs when no env is set", () => {
    const rule = loadRule("homoglyphs.json");
    expect(rule.map).toBeTypeOf("object");
  });

  it("honors setEnv override", () => {
    let called = 0;
    setEnv({
      rulesLoader: {
        loadRule(name) {
          called++;
          if (name === "homoglyphs") return { map: { x: "y" } };
          throw new Error("unexpected");
        },
      },
    });
    const r = loadRule("homoglyphs.json");
    expect(called).toBe(1);
    expect(r.map.x).toBe("y");
  });

  it("createNodeEnv exposes rulesLoader + htmlParser", () => {
    const env = createNodeEnv();
    expect(env.rulesLoader.loadRule).toBeTypeOf("function");
    expect(env.htmlParser.parse).toBeTypeOf("function");
  });
});
