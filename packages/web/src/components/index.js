// =============================================================
//  Shield Scanner Web — components barrel
// =============================================================
// Re-exports public component surface. Built as an append-only file
// so independent v1.20.0 themes can add their components without
// stepping on each other's diffs (each theme appends one block at
// the bottom).
//
// Wire pattern for app.js (kept out of T4 scope; app.js owner can
// switch to this barrel at their discretion):
//   import { FindingDetailPanel } from './components/index.js';
// =============================================================

// --- v1.20.0 T4: FindingDetailPanel ---------------------------------
export { FindingDetailPanel } from './finding-detail-panel.js';
