/**
 * env barrel — exposes the env-injection context.
 *
 * Phase 2 design: detectors call `loadRule(name)` at module init time, so the
 * env must be settable BEFORE detector modules import utils.js. The default
 * provider is the Node fs loader, which makes the package work out-of-the-box
 * in Node without any explicit env setup. Web entrypoints must call
 * `setEnv(createWebEnv())` BEFORE importing any detector module.
 */
export { setEnv, getEnv, resetEnv } from "./context.js";
