/**
 * Module-singleton env holder.
 *
 * Default behavior (Node): utils.js falls back to its built-in Node fs loader
 * if no env is set. This keeps the package working out-of-the-box for the MCP
 * entrypoint without any explicit env setup.
 *
 * Web entrypoint MUST call setEnv(createWebEnv()) BEFORE importing detector
 * modules, because detectors call loadRule() at module initialization time.
 */
let _env = null;

export function setEnv(env) {
  if (!env || typeof env !== "object") {
    throw new Error("setEnv: env must be an object");
  }
  if (!env.rulesLoader || typeof env.rulesLoader.loadRule !== "function") {
    throw new Error("setEnv: env.rulesLoader.loadRule is required");
  }
  _env = env;
}

/**
 * Returns the current env or null if none was set.
 * utils.js#loadRule treats null as "use Node fallback".
 */
export function getEnv() {
  return _env;
}

export function resetEnv() {
  _env = null;
}
