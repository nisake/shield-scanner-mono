// =============================================================
// Shield Scanner Web — S12-XR-03 embedded binary attachment i18n
// =============================================================
// Forward-prep i18n coverage for v1.14.0: the parser refactor that emits
// kebab-case technique ids ('oversize-embedded-image' / 'empty-embedded-image')
// ships in v1.15.0. This harness pins the dict + t_technique lookup chain
// now so v1.15.0 can flip the parser path without an i18n round-trip.
//
// Mirrors test-s19-pdf-struct.mjs Test C2 (PDF i18n 3 labels) shape:
//   - JA / EN dict entries present and non-empty
//   - t_technique() kebab->camelCase resolution for both new keys
//   - locale parity (ja and en have identical key sets)
//   - R12: detector-controlled fixed strings only (no template variables,
//     no attacker text path through these labels)
//   - graceful fallback for unknown kebab ids
//
// No parser execution / no env wiring — pure dict + lookup checks.
// =============================================================

const tests = [];
function add(name, fn) { tests.push({ name, fn }); }

const { i18n, t_technique } = await import('../src/i18n.js');

// --- Test 1: JA dict entries present + non-empty ---
add('1 i18n.ja embedded-image keys present and non-empty', () => {
  if (typeof i18n.ja.oversizeEmbeddedImage !== 'string' || i18n.ja.oversizeEmbeddedImage.length === 0) {
    throw new Error('i18n.ja.oversizeEmbeddedImage missing or empty');
  }
  if (typeof i18n.ja.emptyEmbeddedImage !== 'string' || i18n.ja.emptyEmbeddedImage.length === 0) {
    throw new Error('i18n.ja.emptyEmbeddedImage missing or empty');
  }
});

// --- Test 2: EN dict entries present + non-empty ---
add('2 i18n.en embedded-image keys present and non-empty', () => {
  if (typeof i18n.en.oversizeEmbeddedImage !== 'string' || i18n.en.oversizeEmbeddedImage.length === 0) {
    throw new Error('i18n.en.oversizeEmbeddedImage missing or empty');
  }
  if (typeof i18n.en.emptyEmbeddedImage !== 'string' || i18n.en.emptyEmbeddedImage.length === 0) {
    throw new Error('i18n.en.emptyEmbeddedImage missing or empty');
  }
});

// --- Test 3: t_technique kebab->camel resolution (default lang ja) ---
add('3 t_technique resolves kebab embedded-image ids to ja labels', () => {
  const oversize = t_technique('oversize-embedded-image');
  if (oversize !== i18n.ja.oversizeEmbeddedImage) {
    throw new Error(`t_technique('oversize-embedded-image') mismatch: got "${oversize}"`);
  }
  const empty = t_technique('empty-embedded-image');
  if (empty !== i18n.ja.emptyEmbeddedImage) {
    throw new Error(`t_technique('empty-embedded-image') mismatch: got "${empty}"`);
  }
});

// --- Test 4: Locale parity (ja and en have identical key sets) ---
add('4 locale parity: ja and en have identical key sets', () => {
  const jaKeys = Object.keys(i18n.ja).sort();
  const enKeys = Object.keys(i18n.en).sort();
  if (jaKeys.length !== enKeys.length) {
    throw new Error(`key count mismatch: ja=${jaKeys.length} en=${enKeys.length}`);
  }
  const jaOnly = jaKeys.filter((k) => !enKeys.includes(k));
  const enOnly = enKeys.filter((k) => !jaKeys.includes(k));
  if (jaOnly.length > 0) throw new Error(`ja-only keys: ${jaOnly.join(',')}`);
  if (enOnly.length > 0) throw new Error(`en-only keys: ${enOnly.join(',')}`);
});

// --- Test 5: R12 pin — labels contain no attack literals ---
// Labels are detector-controlled fixed strings, never format strings with
// user-controlled variables. The microscopic* keys do hold a {placeholder}
// for numeric meta only — the new embedded-image labels follow the
// kebab-case-only contract with no template slots.
add('5 R12: embedded-image labels are fixed strings (no format placeholders)', () => {
  const ja1 = i18n.ja.oversizeEmbeddedImage;
  const ja2 = i18n.ja.emptyEmbeddedImage;
  const en1 = i18n.en.oversizeEmbeddedImage;
  const en2 = i18n.en.emptyEmbeddedImage;
  for (const s of [ja1, ja2, en1, en2]) {
    if (/[{}]/.test(s)) {
      throw new Error(`embedded-image label leaked template placeholder: "${s}"`);
    }
  }
});

// --- Test 6: graceful fallback for unknown kebab id ---
add('6 t_technique graceful fallback for unknown embedded-image variant', () => {
  const unknown = t_technique('unknown-embedded-variant');
  if (unknown !== 'unknown-embedded-variant') {
    throw new Error(`graceful fallback broken: got "${unknown}"`);
  }
});

// --- Test 7: R13 pin — new keys do NOT collide with byCategory 5-key set ---
// byCategory canonical keys are: sensitiveData, confidentialInfo,
// privacyExpressions, suspiciousPatterns, personalIdentifiers. The new i18n
// keys are technique labels, NOT category keys — pin that they don't
// accidentally land in the byCategory namespace.
add('7 R13: embedded-image keys are not byCategory canonical names', () => {
  const byCategoryKeys = new Set([
    'sensitiveData',
    'confidentialInfo',
    'privacyExpressions',
    'suspiciousPatterns',
    'personalIdentifiers',
  ]);
  for (const k of ['oversizeEmbeddedImage', 'emptyEmbeddedImage']) {
    if (byCategoryKeys.has(k)) {
      throw new Error(`R13 collision: i18n key "${k}" overlaps byCategory 5-key set`);
    }
  }
});

// ---- Runner ----

let passed = 0;
let failed = 0;

for (const t of tests) {
  try {
    await t.fn();
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
