#!/usr/bin/env node
/**
 * phish-catcher CLI shim (doc 07 §6.1). Delegates to the built Node entry;
 * run `npm run build` first (tsup → dist/).
 */
import { runCli } from "../dist/node.js";

const code = await runCli(process.argv.slice(2), {
  stdout: (l) => process.stdout.write(l + "\n"),
  stderr: (l) => process.stderr.write(l + "\n"),
  cwd: process.cwd(),
  env: process.env,
});
process.exit(code);
