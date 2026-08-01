/**
 * Shared test fixtures: Ed25519 keypairs, gatekeeper-shaped Scope Tokens,
 * sample AlertEvents, in-memory manifest fetchers.
 */

import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { SignJWT } from "jose";
import { create } from "@bufbuild/protobuf";
import { JsonWebKeySchema, type JsonWebKey, type ManifestFetcher } from "@aegisbastion/agent-sdk";
import type { AlertEvent } from "../src/types.js";

export interface TestKeys {
  kid: string;
  privateKey: KeyObject;
  publicJwk: JsonWebKey;
}

export function makeKeys(kid = "test-key-1"): TestKeys {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  // Ed25519 SPKI DER: 12-byte prefix || 32-byte raw key.
  const raw = spki.subarray(spki.length - 32);
  return {
    kid,
    privateKey,
    publicJwk: create(JsonWebKeySchema, {
      kty: "OKP",
      crv: "Ed25519",
      kid,
      alg: "EdDSA",
      use: "sig",
      x: Buffer.from(raw).toString("base64url"),
    }),
  };
}

export interface TokenOpts {
  jti?: string;
  capabilities?: string[];
  iat?: number;
  exp?: number;
  nbf?: number;
  manifestSha256?: string;
  manifestUri?: string;
  riskClass?: "R1" | "R2" | "R3";
  scopeBound?: boolean;
}

export async function mintToken(keys: TestKeys, opts: TokenOpts = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const iat = opts.iat ?? now - 60;
  const claims: Record<string, unknown> = {
    iss: "gatekeeper.platform",
    aud: "aegisbastion.modules",
    jti: opts.jti ?? "tok_test01",
    sub: "agent-test",
    task_id: "task_test01",
    roe_id: "roe_test01",
    roe_version: 1,
    risk_class: opts.riskClass ?? "R2",
    capabilities: opts.capabilities ?? ["stress.http_flood"],
    targets: {
      hash_alg: "sha256",
      manifest_uri: opts.manifestUri ?? "blob://token-manifests/test.json",
      manifest_sha256: opts.manifestSha256 ?? "0".repeat(64),
      count: 1,
    },
    iat,
    exp: opts.exp ?? iat + 900,
    ...(opts.nbf !== undefined ? { nbf: opts.nbf } : {}),
    ...(opts.scopeBound !== undefined ? { scope_bound: opts.scopeBound } : {}),
  };
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "EdDSA", kid: keys.kid, typ: "JWT" })
    .sign(keys.privateKey as never);
}

/** Exact-enumerated manifest fetcher: serves `targets` for any URI. */
export function exactManifestFetcher(targets: string[]): { fetcher: ManifestFetcher; sha256: string } {
  const bytes = new TextEncoder().encode(JSON.stringify(targets));
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  return {
    sha256,
    fetcher: { fetch: async () => bytes },
  };
}

export function sampleEvent(overrides: Partial<AlertEvent> = {}): AlertEvent {
  return {
    schema_version: "1.0",
    event_id: `evt_${Math.random().toString(36).slice(2, 12)}`,
    org_id: "org_acme",
    source_module: "monitor",
    source_event_id: "chg_01",
    title: "TLS certificate expires soon",
    description: "test event",
    severity: "high",
    confidence: "probable",
    category: "config-drift",
    asset: { asset_id: "asset_1", kind: "subdomain", identifier: "api.example.com", criticality: "high" },
    occurred_at: new Date().toISOString(),
    ...overrides,
  };
}

/** A detect-style CONFIRMED vuln alert — requires an authorization context (§13.1). */
export function offensiveEvent(overrides: Partial<AlertEvent> = {}): AlertEvent {
  return sampleEvent({
    source_module: "detect",
    source_event_id: "fnd_01",
    category: "vuln",
    confidence: "confirmed",
    severity: "critical",
    authorization_token_id: "tok_test01",
    title: "Confirmed RCE exposure",
    ...overrides,
  });
}
