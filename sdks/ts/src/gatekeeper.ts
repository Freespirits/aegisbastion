/**
 * Gatekeeper clients (doc 11): the TokenService surface the SDK needs —
 * GetJWKS (key material for local verification) and RefreshToken (mid-run
 * re-authorization, doc 11 §3.2). The SDK never mints; only gatekeeper's
 * token-service mints (Ruling B/C9).
 */

import { createClient, type Client } from "@connectrpc/connect";
import { createGrpcTransport } from "@connectrpc/connect-node";
import { Buffer } from "node:buffer";
import { TokenService } from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/token_pb.js";
import type {
  JsonWebKey,
  RefreshTokenResponse,
} from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/token_pb.js";

export interface GrpcTlsOptions {
  /** Platform CA cert (PEM) — mTLS everywhere (doc 01 §11). */
  caCert?: Uint8Array | string;
  /** Agent's platform-CA-issued client cert (PEM; SPIFFE ID in SANs). */
  clientCert?: Uint8Array | string;
  clientKey?: Uint8Array | string;
}

export interface GrpcClientOptions {
  /** e.g. "https://gatekeeper:8443" (or http:// for the compose dev host). */
  baseUrl: string;
  tls?: GrpcTlsOptions;
}

function pem(v: Uint8Array | string): string | Buffer {
  return typeof v === "string" ? v : Buffer.from(v);
}

export function grpcNodeOptions(tls: GrpcTlsOptions): {
  ca?: string | Buffer;
  cert?: string | Buffer;
  key?: string | Buffer;
} {
  return {
    ...(tls.caCert ? { ca: pem(tls.caCert) } : {}),
    ...(tls.clientCert ? { cert: pem(tls.clientCert) } : {}),
    ...(tls.clientKey ? { key: pem(tls.clientKey) } : {}),
  };
}

function transportFor(opts: GrpcClientOptions) {
  return createGrpcTransport({
    baseUrl: opts.baseUrl,
    nodeOptions: opts.tls ? grpcNodeOptions(opts.tls) : undefined,
  });
}

export type TokenServiceClient = Client<typeof TokenService>;

export function createTokenServiceClient(opts: GrpcClientOptions): TokenServiceClient {
  return createClient(TokenService, transportFor(opts));
}

/** fetchKeys implementation for JwksCache, backed by TokenService.GetJWKS. */
export function jwksFetcher(client: TokenServiceClient): () => Promise<JsonWebKey[]> {
  return async () => {
    const res = await client.getJWKS({ kid: "" });
    return res.keys;
  };
}

/**
 * Mid-run re-authorization (docs 01 §5.5, 03 §9.2, 11 §3.2): RefreshToken is
 * NOT an unauthenticated refresh — token-service re-runs the policy check
 * (RoE still active, not revoked, approval still valid) before minting a
 * successor token for the same task_id. An empty successor token means the
 * re-authorization was DENIED: the agent must halt when its current token
 * expires.
 */
export async function refreshScopeToken(
  client: TokenServiceClient,
  currentToken: string,
): Promise<RefreshTokenResponse> {
  return client.refreshToken({ currentToken });
}
