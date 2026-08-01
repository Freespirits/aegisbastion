/**
 * Target manifest fetch + verify (doc 01 §5.5, doc 11 §3.2, Ruling A.3).
 *
 * Concrete targets never live inside the token; the token carries
 * `targets.manifest_uri` / `targets.manifest_sha256` pointing at an object in
 * MinIO (bucket `token-manifests`; S3 API, forcePathStyle). Two forms exist:
 *
 *  - exact-enumerated: a JSON array of target strings (R2/R3, and R1
 *    non-watch capabilities);
 *  - scope-bound watch form (Ruling A): the canonical RoE scope document
 *    (schemas/gatekeeper/v1/scope-manifest.schema.json), whose sha256 IS the
 *    audit value "scope:sha256:<hash>".
 *
 * The manifest bytes are hashed and compared against the token claim BEFORE
 * parsing; any mismatch or fetch failure is a hard failure (fail-closed).
 */

import { createHash } from "node:crypto";
import { PepError } from "./errors.js";
import type { CanonicalScope } from "./scope.js";
import type { TargetManifestRef } from "./token.js";

/** Canonical scope manifest document (scope-bound watch tokens, Ruling A). */
export interface ScopeManifest {
  roe_id: string;
  roe_version: number;
  resolved_at?: string;
  scope: CanonicalScope;
}

export type VerifiedManifest =
  | { form: "exact"; sha256: string; targets: string[] }
  | { form: "scope"; sha256: string; manifest: ScopeManifest };

/** Transport abstraction for manifest bytes — injectable for tests. */
export interface ManifestFetcher {
  /** Fetch the raw bytes for a manifest URI. Throws on transport failure. */
  fetch(manifestUri: string): Promise<Uint8Array>;
}

export interface S3ManifestFetcherOptions {
  /** MinIO endpoint, e.g. "http://localhost:9000" (MVP-A compose host). */
  endpoint: string;
  region?: string;
  accessKeyId: string;
  secretAccessKey: string;
  /**
   * Manifest bucket override. Default: the bucket from the blob:// URI
   * (gatekeeper writes to the `token-manifests` bucket).
   */
  bucketOverride?: string;
}

/** Parse a "blob://<bucket>/<key>" manifest URI. */
export function parseManifestUri(uri: string): { bucket: string; key: string } {
  const m = /^blob:\/\/([^/]+)\/(.+)$/.exec(uri);
  if (!m) {
    throw new PepError("MANIFEST_MALFORMED", `unparseable manifest_uri: ${uri}`);
  }
  return { bucket: m[1]!, key: m[2]! };
}

/**
 * Default fetcher: MinIO via the S3 API (@aws-sdk/client-s3, forcePathStyle —
 * the same client family works against Azure Blob later, doc 01 §11).
 * The AWS SDK is loaded lazily so PEP-only consumers (e.g. browser-adjacent
 * phish-catcher checks) never pay for it.
 */
export function createS3ManifestFetcher(opts: S3ManifestFetcherOptions): ManifestFetcher {
  let clientPromise: Promise<{
    send: (cmd: unknown) => Promise<{ Body?: { transformToByteArray?: () => Promise<Uint8Array> } }>;
  }> | null = null;

  const getClient = async () => {
    clientPromise ??= import("@aws-sdk/client-s3").then(
      ({ S3Client }) =>
        new S3Client({
          endpoint: opts.endpoint,
          region: opts.region ?? "us-east-1",
          forcePathStyle: true,
          credentials: { accessKeyId: opts.accessKeyId, secretAccessKey: opts.secretAccessKey },
        }) as never,
    );
    return clientPromise;
  };

  return {
    async fetch(manifestUri: string): Promise<Uint8Array> {
      const { bucket, key } = parseManifestUri(manifestUri);
      const client = await getClient();
      const { GetObjectCommand } = await import("@aws-sdk/client-s3");
      let res: Awaited<ReturnType<typeof client.send>>;
      try {
        res = await client.send(
          new GetObjectCommand({ Bucket: opts.bucketOverride ?? bucket, Key: key }) as never,
        );
      } catch (err) {
        throw new PepError(
          "MANIFEST_FETCH_FAILED",
          `manifest fetch failed for ${manifestUri}: ${(err as Error).message}`,
        );
      }
      if (!res.Body?.transformToByteArray) {
        throw new PepError("MANIFEST_FETCH_FAILED", `empty manifest body for ${manifestUri}`);
      }
      return res.Body.transformToByteArray();
    },
  };
}

/**
 * Fetch and verify a manifest against the token's TargetManifestRef, then
 * parse it into its typed form. Fail-closed at every step:
 * hash_alg must be sha256, sha256(bytes) must equal manifest_sha256, the
 * document must match its declared form.
 */
export async function fetchAndVerifyManifest(
  ref: TargetManifestRef,
  scopeBound: boolean,
  fetcher: ManifestFetcher,
): Promise<VerifiedManifest> {
  if (ref.hash_alg !== "sha256") {
    throw new PepError("MANIFEST_MALFORMED", `unsupported manifest hash_alg: ${ref.hash_alg}`);
  }
  let bytes: Uint8Array;
  try {
    bytes = await fetcher.fetch(ref.manifest_uri);
  } catch (err) {
    if (err instanceof PepError) throw err;
    throw new PepError("MANIFEST_FETCH_FAILED", `manifest fetch failed: ${(err as Error).message}`);
  }
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== ref.manifest_sha256.toLowerCase()) {
    throw new PepError("MANIFEST_HASH_MISMATCH", "manifest sha256 does not match the token claim", {
      expected: ref.manifest_sha256,
      actual,
    });
  }

  let doc: unknown;
  try {
    doc = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new PepError("MANIFEST_MALFORMED", "manifest is not valid JSON");
  }

  if (scopeBound) {
    return { form: "scope", sha256: actual, manifest: parseScopeManifest(doc) };
  }
  return { form: "exact", sha256: actual, targets: parseExactManifest(doc, ref.count) };
}

function parseExactManifest(doc: unknown, expectedCount?: number): string[] {
  // Exact-enumerated form: {"targets": [...]} or a bare array of strings.
  const targets = Array.isArray(doc)
    ? doc
    : doc !== null && typeof doc === "object" && Array.isArray((doc as { targets?: unknown }).targets)
      ? ((doc as { targets: unknown[] }).targets as unknown[])
      : null;
  if (targets === null || !targets.every((t) => typeof t === "string" && t !== "")) {
    throw new PepError("MANIFEST_MALFORMED", "exact manifest must be a string array of targets");
  }
  if (expectedCount !== undefined && expectedCount !== 0 && targets.length !== expectedCount) {
    throw new PepError("MANIFEST_MALFORMED", "manifest target count does not match the token claim", {
      expected: expectedCount,
      actual: targets.length,
    });
  }
  return targets as string[];
}

function parseScopeManifest(doc: unknown): ScopeManifest {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw new PepError("MANIFEST_MALFORMED", "scope manifest must be an object");
  }
  const m = doc as Record<string, unknown>;
  if (typeof m.roe_id !== "string" || !m.roe_id.startsWith("roe_")) {
    throw new PepError("MANIFEST_MALFORMED", "scope manifest missing valid roe_id");
  }
  if (typeof m.roe_version !== "number" || !Number.isInteger(m.roe_version) || m.roe_version < 1) {
    throw new PepError("MANIFEST_MALFORMED", "scope manifest missing valid roe_version");
  }
  if (m.resolved_at !== undefined && typeof m.resolved_at !== "string") {
    throw new PepError("MANIFEST_MALFORMED", "scope manifest resolved_at must be a string");
  }
  if (m.scope === null || typeof m.scope !== "object" || Array.isArray(m.scope)) {
    throw new PepError("MANIFEST_MALFORMED", "scope manifest missing scope object");
  }
  const scope = m.scope as Record<string, unknown>;
  const stringArray = (v: unknown, name: string, required: boolean): string[] => {
    if (v === undefined) {
      if (required) throw new PepError("MANIFEST_MALFORMED", `scope manifest missing scope.${name}`);
      return [];
    }
    if (!Array.isArray(v) || !v.every((x) => typeof x === "string" && x !== "")) {
      throw new PepError("MANIFEST_MALFORMED", `scope.${name} must be a non-empty-string array`);
    }
    return v as string[];
  };
  return {
    roe_id: m.roe_id,
    roe_version: m.roe_version,
    ...(m.resolved_at !== undefined ? { resolved_at: m.resolved_at as string } : {}),
    scope: {
      domains: stringArray(scope.domains, "domains", true),
      cidrs: stringArray(scope.cidrs, "cidrs", true),
      explicit_excludes: stringArray(scope.explicit_excludes, "explicit_excludes", true),
      asset_group_ids: stringArray(scope.asset_group_ids, "asset_group_ids", false),
      cloud_accounts: stringArray(scope.cloud_accounts, "cloud_accounts", false),
    },
  };
}
