import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node20",
  dts: true,
  sourcemap: false,
  clean: true,
  // Runtime deps stay external; @aegisbastion/gen (TypeScript-only stubs) is
  // compiled and bundled in so the dist output runs under plain Node.
  noExternal: ["@aegisbastion/gen"],
  external: [
    "@aws-sdk/client-s3",
    "@bufbuild/protobuf",
    "@connectrpc/connect",
    "@connectrpc/connect-node",
    "canonicalize",
    "jose",
    "nats",
  ],
});
