import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    node: "src/node/index.ts",
    browser: "src/browser/index.ts",
  },
  format: ["esm"],
  target: "node20",
  dts: true,
  sourcemap: false,
  clean: true,
});
