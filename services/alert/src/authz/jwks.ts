/**
 * HTTP JWKS fetcher for the SDK's JwksCache (doc 11 §3.2: gatekeeper
 * publishes its keys at /.well-known/gatekeeper-jwks.json on :8080; herald
 * verifies tokens locally against them — Ruling B, doc 05 §5.7).
 *
 * The REST body is a plain JWKS document {"keys":[{kty,crv,kid,alg,use,x}]};
 * entries are mapped into the proto JsonWebKey shape the SDK cache consumes.
 */

import { create } from "@bufbuild/protobuf";
import { JsonWebKeySchema, type JsonWebKey } from "@aegisbastion/agent-sdk";

export function httpJwksFetcher(jwksUrl: string, timeoutMs = 5_000): () => Promise<JsonWebKey[]> {
  return async () => {
    const res = await fetch(jwksUrl, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error(`JWKS fetch failed: HTTP ${res.status} from ${jwksUrl}`);
    }
    const body = (await res.json()) as { keys?: unknown };
    if (!body || !Array.isArray(body.keys)) {
      throw new Error(`JWKS fetch failed: malformed document from ${jwksUrl} (no keys array)`);
    }
    return (body.keys as Record<string, string>[]).map((k) =>
      create(JsonWebKeySchema, {
        kty: k.kty ?? "",
        crv: k.crv ?? "",
        kid: k.kid ?? "",
        alg: k.alg ?? "EdDSA",
        use: k.use ?? "sig",
        x: k.x ?? "",
      }),
    );
  };
}
