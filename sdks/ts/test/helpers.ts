/**
 * Shared test helpers: Ed25519 keypairs, JWK conversion, and Scope Token
 * minting (tests stand in for gatekeeper's token-service).
 */

import { createHash } from "node:crypto";
import { create } from "@bufbuild/protobuf";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  JsonWebKeySchema,
  type JsonWebKey,
} from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/token_pb.js";

export interface TestKey {
  kid: string;
  privateKey: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
  publicJwk: JsonWebKey;
}

export async function makeKey(kid: string): Promise<TestKey> {
  const { publicKey, privateKey } = await generateKeyPair("Ed25519", { extractable: true });
  const jwk = await exportJWK(publicKey);
  return {
    kid,
    privateKey,
    publicJwk: create(JsonWebKeySchema, {
      kty: "OKP",
      crv: "Ed25519",
      kid,
      alg: "EdDSA",
      use: "sig",
      x: jwk.x ?? "",
    }),
  };
}

export const NOW = 1_800_000_000; // fixed "now" for deterministic tests

export interface ClaimOverrides {
  iss?: string;
  aud?: string;
  jti?: string;
  sub?: string;
  task_id?: string;
  roe_id?: string;
  roe_version?: number;
  risk_class?: string;
  capabilities?: string[];
  targets?: Record<string, unknown>;
  scope_bound?: boolean;
  rate_caps?: Record<string, unknown>;
  approval_id?: string;
  iat?: number;
  nbf?: number;
  exp?: number;
}

export function defaultClaims(overrides: ClaimOverrides = {}): Record<string, unknown> {
  return {
    iss: "gatekeeper.platform",
    aud: "aegisbastion.modules",
    jti: "tok_01J9ZM8W3F",
    sub: "agent_01J92F",
    task_id: "tsk_01J92H",
    roe_id: "roe_01J8ZM",
    roe_version: 3,
    risk_class: "R1",
    capabilities: ["monitor.watch"],
    targets: {
      hash_alg: "sha256",
      manifest_uri: "blob://token-manifests/tok_01J9ZM8W3F/targets.json",
      manifest_sha256: "a".repeat(64),
    },
    iat: NOW - 300,
    nbf: NOW - 300,
    exp: NOW + 600, // TTL 900 — the maximum allowed
    ...overrides,
  };
}

export async function signToken(
  key: TestKey,
  overrides: ClaimOverrides = {},
  header: Record<string, unknown> = {},
): Promise<string> {
  const claims = defaultClaims(overrides);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: key.kid, ...header })
    .sign(key.privateKey);
}

export function sha256OfJson(doc: unknown): string {
  return createHash("sha256").update(JSON.stringify(doc)).digest("hex");
}

export function claimsForManifest(
  manifestBytes: string,
  overrides: ClaimOverrides = {},
): ClaimOverrides {
  return {
    targets: {
      hash_alg: "sha256",
      manifest_uri: "blob://token-manifests/tok_01J9ZM8W3F/targets.json",
      manifest_sha256: createHash("sha256").update(manifestBytes).digest("hex"),
    },
    ...overrides,
  };
}
