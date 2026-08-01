import { defineConfig } from "tsup";

/**
 * Chrome MV3 extension build (doc 07 §6.3). Every entry is a fully self-
 * contained IIFE bundle (no remote code, no dynamic imports — MV3 CSP).
 * __PHISH_DEV__ gates the dev-mode option (unsigned policies) and is compiled
 * to `false` unless PHISH_DEV=on is set at build time (doc 07 §6.3).
 */
export default defineConfig({
  entry: {
    "service-worker": "src/ext/service-worker.ts",
    "content-script": "src/ext/content-script.ts",
    popup: "src/ext/popup.ts",
    options: "src/ext/options.ts",
  },
  outDir: "extension/dist",
  format: ["iife"],
  target: "chrome120",
  platform: "browser",
  dts: false,
  sourcemap: false,
  clean: true,
  splitting: false,
  // Plain ".js" names — the manifest references dist/<entry>.js directly.
  outExtension: () => ({ js: ".js" }),
  define: {
    __PHISH_DEV__: process.env.PHISH_DEV === "on" ? "true" : "false",
  },
});
