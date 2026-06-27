// =============================================================
//  Shield Scanner Web — v1.18.0 S16 PDF non-JS high-risk actions
// =============================================================
// Pins the Web mirror of MCP regression `pdf-s16-nonjs-actions.test.js`:
//   - SubmitForm via a.actions[SubmitForm]   → pdf-submit-form-action
//   - GoToR via a.actions[GoToR]              → pdf-goto-remote-action
//   - Link a.url + actionType='GoToR'         → pdf-goto-remote-action
//   - subtype === 'RichMedia'                 → pdf-richmedia-embed
//   - subtype === '3D'                        → pdf-3d-embed
//   - subtype === 'Sound'                     → pdf-sound-action
//   - subtype === 'Movie'                     → pdf-movie-action
// All 6 ids: element='PDF Catalog', severity='warning',
// contextLocation='Catalog', ONE per document (1-per-doc invariant), and
// FP guard on plain empty PDF.

import { setEnv } from '@shield-scanner/core/env';
import { createWebEnv } from '@shield-scanner/core/env/web';

if (typeof globalThis.DOMParser === 'undefined') {
  globalThis.DOMParser = class {
    parseFromString() {
      return {
        querySelectorAll: () => [],
        createTreeWalker: () => ({ nextNode: () => null }),
      };
    }
  };
  globalThis.NodeFilter = globalThis.NodeFilter || { SHOW_COMMENT: 128 };
}

setEnv(createWebEnv());

const { parsePdf } = await import('../src/parsers-web/pdf.js');

function installPdfjsMock(fakePdf) {
  const prev = globalThis.pdfjsLib;
  globalThis.pdfjsLib = {
    getDocument() { return { promise: Promise.resolve(fakePdf) }; },
  };
  return () => {
    if (prev === undefined) delete globalThis.pdfjsLib;
    else globalThis.pdfjsLib = prev;
  };
}

function makeFakePdf(opts = {}) {
  const { pages = 1, annotationsFor = () => [], attachments = null } = opts;
  return {
    numPages: pages,
    async getPage(i) {
      return {
        async getTextContent() { return { items: [] }; },
        async getAnnotations() { return annotationsFor(i); },
      };
    },
    async getAttachments() { return attachments; },
    async getMetadata() { return { info: {}, metadata: null }; },
    async getFieldObjects() { return null; },
    async getJSActions() { return null; },
    async getOpenAction() { return null; },
    async getOutline() { return null; },
  };
}

const STUB = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
const tests = [];
function add(name, fn) { tests.push({ name, fn }); }

function assertSingleHit(out, kebab) {
  const hits = (out.hiddenFindings || []).filter((f) => f.technique === kebab);
  if (hits.length !== 1) throw new Error(`expected 1 ${kebab}, got ${hits.length}`);
  const hit = hits[0];
  if (hit.element !== 'PDF Catalog') throw new Error(`element mismatch on ${kebab}: ${hit.element}`);
  if (hit.severity !== 'warning') throw new Error(`severity mismatch on ${kebab}: ${hit.severity}`);
  if (hit.contextLocation !== 'Catalog') throw new Error(`ctxLoc mismatch on ${kebab}: ${hit.contextLocation}`);
  if (!hit.meta) throw new Error(`meta missing on ${kebab}`);
  return hit;
}

// SubmitForm
add('S16: SubmitForm via Widget /A emits ONE pdf-submit-form-action', async () => {
  const fakePdf = makeFakePdf({
    annotationsFor: () => [{
      subtype: 'Widget', fieldName: 'btn',
      actions: { SubmitForm: ['https://evil.example/exfil'] },
    }],
  });
  const restore = installPdfjsMock(fakePdf);
  try {
    const out = await parsePdf(STUB);
    const hit = assertSingleHit(out, 'pdf-submit-form-action');
    if (typeof hit.meta.targetUrl !== 'string') throw new Error('targetUrl missing');
    if (hit.meta.targetUrl.length > 64) throw new Error('targetUrl exceeds 64 chars');
    if (/[\s\[\]]/.test(hit.meta.targetUrl)) throw new Error('targetUrl not sanitized');
  } finally { restore(); }
});

add('S16: SubmitForm absent → no emit', async () => {
  const restore = installPdfjsMock(makeFakePdf());
  try {
    const out = await parsePdf(STUB);
    const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'pdf-submit-form-action');
    if (hits.length !== 0) throw new Error(`expected 0, got ${hits.length}`);
  } finally { restore(); }
});

// GoToR via a.actions
add('S16: GoToR via Widget /A emits ONE pdf-goto-remote-action', async () => {
  const fakePdf = makeFakePdf({
    annotationsFor: () => [{
      subtype: 'Widget', fieldName: 'g',
      actions: { GoToR: ['https://evil.example/other.pdf'] },
    }],
  });
  const restore = installPdfjsMock(fakePdf);
  try {
    const out = await parsePdf(STUB);
    const hit = assertSingleHit(out, 'pdf-goto-remote-action');
    if (typeof hit.meta.target !== 'string') throw new Error('target missing');
  } finally { restore(); }
});

// GoToR via Link a.url + actionType
add('S16: Link a.url with actionType=GoToR emits pdf-goto-remote-action', async () => {
  const fakePdf = makeFakePdf({
    annotationsFor: () => [{
      subtype: 'Link',
      url: 'https://evil.example/other.pdf',
      actionType: 'GoToR',
    }],
  });
  const restore = installPdfjsMock(fakePdf);
  try {
    const out = await parsePdf(STUB);
    assertSingleHit(out, 'pdf-goto-remote-action');
  } finally { restore(); }
});

add('S16: plain external Link → no pdf-goto-remote-action emit', async () => {
  const fakePdf = makeFakePdf({
    annotationsFor: () => [{ subtype: 'Link', url: 'https://benign.example/page' }],
  });
  const restore = installPdfjsMock(fakePdf);
  try {
    const out = await parsePdf(STUB);
    const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'pdf-goto-remote-action');
    if (hits.length !== 0) throw new Error(`expected 0, got ${hits.length}`);
  } finally { restore(); }
});

// Subtype-only signals: RichMedia / 3D / Sound / Movie
for (const [subtype, kebab] of [
  ['RichMedia', 'pdf-richmedia-embed'],
  ['3D', 'pdf-3d-embed'],
  ['Sound', 'pdf-sound-action'],
  ['Movie', 'pdf-movie-action'],
]) {
  add(`S16: subtype=${subtype} emits ONE ${kebab}`, async () => {
    const fakePdf = makeFakePdf({ annotationsFor: () => [{ subtype }] });
    const restore = installPdfjsMock(fakePdf);
    try {
      const out = await parsePdf(STUB);
      const hit = assertSingleHit(out, kebab);
      if (hit.meta.subtype !== subtype) throw new Error(`meta.subtype mismatch: ${hit.meta.subtype}`);
    } finally { restore(); }
  });
}

add('S16: multiple RichMedia annotations collapse to ONE signal', async () => {
  const fakePdf = makeFakePdf({
    pages: 2,
    annotationsFor: () => [{ subtype: 'RichMedia' }, { subtype: 'RichMedia' }],
  });
  const restore = installPdfjsMock(fakePdf);
  try {
    const out = await parsePdf(STUB);
    const hits = (out.hiddenFindings || []).filter((f) => f.technique === 'pdf-richmedia-embed');
    if (hits.length !== 1) throw new Error(`expected 1, got ${hits.length}`);
  } finally { restore(); }
});

// Benign FP guard
add('S16: empty PDF emits 0 of all 6 new kebab ids', async () => {
  const restore = installPdfjsMock(makeFakePdf());
  try {
    const out = await parsePdf(STUB);
    const kebabs = [
      'pdf-submit-form-action', 'pdf-goto-remote-action',
      'pdf-richmedia-embed', 'pdf-3d-embed',
      'pdf-sound-action', 'pdf-movie-action',
    ];
    for (const k of kebabs) {
      const hits = (out.hiddenFindings || []).filter((f) => f.technique === k);
      if (hits.length !== 0) throw new Error(`expected 0 ${k}, got ${hits.length}`);
    }
  } finally { restore(); }
});

// Multi-signal coexistence
add('S16: 6 distinct annotations coexist, each emits ONE signal', async () => {
  const fakePdf = makeFakePdf({
    annotationsFor: () => [
      { subtype: 'RichMedia' },
      { subtype: '3D' },
      { subtype: 'Sound' },
      { subtype: 'Movie' },
      { subtype: 'Widget', fieldName: 'x', actions: { SubmitForm: ['https://a.example'] } },
      { subtype: 'Widget', fieldName: 'y', actions: { GoToR: ['https://b.example/y.pdf'] } },
    ],
  });
  const restore = installPdfjsMock(fakePdf);
  try {
    const out = await parsePdf(STUB);
    const expectedCounts = {
      'pdf-richmedia-embed': 1, 'pdf-3d-embed': 1,
      'pdf-sound-action': 1, 'pdf-movie-action': 1,
      'pdf-submit-form-action': 1, 'pdf-goto-remote-action': 1,
    };
    for (const [k, n] of Object.entries(expectedCounts)) {
      const c = (out.hiddenFindings || []).filter((f) => f.technique === k).length;
      if (c !== n) throw new Error(`${k}: expected ${n}, got ${c}`);
    }
  } finally { restore(); }
});

// ---- Runner ----
let passed = 0, failed = 0;
for (const t of tests) {
  try { delete globalThis.pdfjsLib; } catch {}
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
