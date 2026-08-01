#!/usr/bin/env node
/**
 * Pack the Chrome MV3 extension (doc 07 §6.3): validates the manifest,
 * copies extension/ + built dist/ bundles into release/phish-ext/ as a
 * load-unpacked directory. Run `npm run build:ext` first.
 */
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const extDir = join(root, "extension");
const outDir = join(root, "release", "phish-ext");

const required = [
  "manifest.json",
  "popup.html",
  "options.html",
  "dist/service-worker.js",
  "dist/content-script.js",
  "dist/popup.js",
  "dist/options.js",
];

const manifest = JSON.parse(readFileSync(join(extDir, "manifest.json"), "utf8"));
if (manifest.manifest_version !== 3) {
  console.error("manifest_version must be 3");
  process.exit(1);
}
const missing = required.filter((f) => !existsSync(join(extDir, f)));
if (missing.length > 0) {
  console.error(`missing build artifacts (run npm run build:ext first): ${missing.join(", ")}`);
  process.exit(1);
}
for (const ref of [manifest.background?.service_worker, ...(manifest.content_scripts ?? []).flatMap((c) => c.js ?? [])]) {
  if (ref && !existsSync(join(extDir, ref))) {
    console.error(`manifest references missing file: ${ref}`);
    process.exit(1);
  }
}

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });
cpSync(extDir, outDir, { recursive: true });
console.log(`packed → ${outDir}`);
console.log("load unpacked: chrome://extensions → Developer mode → Load unpacked → select that directory");
