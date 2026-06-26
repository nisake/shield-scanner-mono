// S17 Diff View module
//
// NOTE: The diff-pane rendering markup (L5429-L5469 in the original
// index.html) is tightly woven into displayResults() and uses the
// scoped `lastRawContent` / sanitizeContent flow. For Step 6 we keep
// the actual render inside app.js (where displayResults lives) and
// expose only the visibility toggle here.
//
// The `_diffViewVisible` flag itself is owned by reveal-mode.js (kept
// alongside `_revealMode` since both are reset together on resetAll
// and share the same toggle-pair S16+S17 contract).
import {
  _getDiffViewVisible,
  _setDiffViewVisible,
} from "./reveal-mode.js";

function toggleDiffView() {
  _setDiffViewVisible(!_getDiffViewVisible());
  // Re-render via displayResults; lastScanResult is on globalThis.
  if (typeof globalThis.displayResults === "function" && globalThis.lastScanResult) {
    globalThis.displayResults(globalThis.lastScanResult);
  }
}

export { toggleDiffView };
