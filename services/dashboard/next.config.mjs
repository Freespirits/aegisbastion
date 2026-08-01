import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Standalone output for the MVP-A compose host image (doc 12 §Deploy: SPA+BFF
  // in one container at MVP-A).
  output: "standalone",
  reactStrictMode: true,
  // This app is a standalone npm project inside a monorepo with its own
  // lockfile — keep Next's file tracing scoped to services/dashboard.
  outputFileTracingRoot: dirname(fileURLToPath(import.meta.url)),
  // All backend URLs are server-only env (see src/env.ts); nothing secret is
  // exposed to the browser — the BFF API routes are the only egress (doc 10
  // §2.1: no tokens reach the browser beyond the session).
};

export default nextConfig;
