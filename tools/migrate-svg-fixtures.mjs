// =============================================================
//  Shield Scanner — One-shot SVG attack-fixture migration
//                   (v1.20.0 T7-SVG-B64)
// =============================================================
// Walks the MCP attack-fixture directory and produces ".svg.b64" siblings
// for every ".svg" attack file, then (optionally) deletes the originals.
//
// Why a script and not "rm + svn add"?
//   * The migration is destructive (the original .svg files contain live
//     payloads that Claude Desktop's file-preview will inline-render).
//   * Re-running it must be safe (idempotent) — if a .svg.b64 sibling
//     already exists and decodes to the same bytes, the script does
//     nothing instead of double-encoding.
//   * Local dev only — CI never invokes this. The integration phase wires
//     the .svg.b64 files through tools/svg-fixture-loader.mjs.
//
// Usage:
//   node tools/migrate-svg-fixtures.mjs            # dry-run (default)
//   node tools/migrate-svg-fixtures.mjs --apply    # actually write .b64
//   node tools/migrate-svg-fixtures.mjs --apply --delete-source
//
// Safety contract:
//   * Only files matching SVG_ATTACK_FIXTURES are touched. Benign SVGs are
//     deliberately out of scope (they do not contain executable script
//     surfaces; Desktop inline-render is harmless for them).
//   * --delete-source removes the original .svg only after the .b64
//     sibling has been written *and* round-trip-verified.
// =============================================================

import { readFile, writeFile, unlink, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const ATTACKS_DIR = resolve(
  REPO_ROOT,
  "packages",
  "mcp",
  "test",
  "fixtures",
  "attacks",
);

// Authoritative list — six v1.19.0 B1 SVG attack fixtures. Add new entries
// here only when a new attack surface is introduced (and Theme owner
// confirms Desktop inline-render would actually execute it).
const SVG_ATTACK_FIXTURES = [
  "svg_cdata_instruction",
  "svg_foreignobject_prompt",
  "svg_javascript_href",
  "svg_onerror_handler",
  "svg_script_tag",
  "svg_use_external_ref",
];

const argv = new Set(process.argv.slice(2));
const APPLY = argv.has("--apply");
const DELETE_SOURCE = argv.has("--delete-source");

function encodeSvgToB64(buf) {
  // Wrap base64 output at 76-cols-equivalent? No — keep it single-line so
  // the round-trip is trivially diff-able. Trailing newline only.
  return buf.toString("base64") + "\n";
}

async function migrateOne(stem) {
  const svgPath = join(ATTACKS_DIR, `${stem}.svg`);
  const b64Path = join(ATTACKS_DIR, `${stem}.svg.b64`);
  const svgExists = existsSync(svgPath);
  const b64Exists = existsSync(b64Path);

  if (!svgExists && !b64Exists) {
    return { stem, status: "missing", note: "neither .svg nor .svg.b64 found" };
  }

  // Already migrated: verify round-trip then NOOP.
  if (!svgExists && b64Exists) {
    return { stem, status: "already-migrated", note: ".svg.b64 only" };
  }

  // Read source.
  const svgBuf = await readFile(svgPath);

  if (b64Exists) {
    const existingText = await readFile(b64Path, "utf8");
    const compact = existingText.replace(/[\s]+/g, "");
    const decoded = Buffer.from(compact, "base64");
    if (decoded.equals(svgBuf)) {
      // Already in sync — only act on --delete-source.
      if (DELETE_SOURCE && APPLY) {
        await unlink(svgPath);
        return { stem, status: "deleted", note: ".svg removed; .b64 in sync" };
      }
      return { stem, status: "in-sync", note: ".b64 already matches .svg" };
    }
    if (!APPLY) {
      return {
        stem,
        status: "would-overwrite",
        note: "existing .b64 differs from .svg; --apply will overwrite",
      };
    }
    await writeFile(b64Path, encodeSvgToB64(svgBuf), "utf8");
    if (DELETE_SOURCE) {
      await unlink(svgPath);
      return { stem, status: "overwrote+deleted", note: "" };
    }
    return { stem, status: "overwrote", note: "" };
  }

  if (!APPLY) {
    return {
      stem,
      status: "would-encode",
      note: "no .b64 yet; --apply will create",
    };
  }

  await writeFile(b64Path, encodeSvgToB64(svgBuf), "utf8");

  // Round-trip verify.
  const written = await readFile(b64Path, "utf8");
  const back = Buffer.from(written.replace(/[\s]+/g, ""), "base64");
  if (!back.equals(svgBuf)) {
    throw new Error(`round-trip mismatch for ${stem}; aborting`);
  }
  if (DELETE_SOURCE) {
    await unlink(svgPath);
    return { stem, status: "encoded+deleted", note: "" };
  }
  return { stem, status: "encoded", note: "" };
}

async function main() {
  // Sanity-check the attacks dir exists before iterating.
  try {
    const st = await stat(ATTACKS_DIR);
    if (!st.isDirectory()) {
      throw new Error(`${ATTACKS_DIR} is not a directory`);
    }
  } catch (err) {
    console.error(`[svg-migrate] cannot stat ${ATTACKS_DIR}:`, err.message);
    process.exit(2);
  }

  const mode = APPLY
    ? DELETE_SOURCE
      ? "apply + delete-source"
      : "apply"
    : "dry-run";
  console.log(`[svg-migrate] mode: ${mode}`);
  console.log(`[svg-migrate] attacks dir: ${ATTACKS_DIR}`);

  const results = [];
  for (const stem of SVG_ATTACK_FIXTURES) {
    try {
      results.push(await migrateOne(stem));
    } catch (err) {
      results.push({ stem, status: "error", note: err.message });
    }
  }
  for (const r of results) {
    console.log(`  ${r.stem.padEnd(30)} ${r.status.padEnd(20)} ${r.note}`);
  }
  const errors = results.filter((r) => r.status === "error").length;
  process.exit(errors === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("[svg-migrate] fatal:", err);
  process.exit(1);
});
