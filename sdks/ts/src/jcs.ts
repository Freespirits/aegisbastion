/**
 * JCS (JSON Canonicalization Scheme, RFC 8785) helpers — the platform's single
 * canonicalization (doc 01 §10.2; doc 07 §12: "Do not invent a second
 * canonicalization"). Uses the `canonicalize` package; SHA-256 via node:crypto.
 */

import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

/** Serialize a JSON value in JCS (RFC 8785) canonical form. */
export function jcs(value: unknown): string {
  const out = canonicalize(value as never);
  if (out === undefined) {
    throw new Error("value is not JCS-serializable");
  }
  return out;
}

/** SHA-256 hex digest of a string or byte buffer. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** SHA-256 of the JCS-canonical form of a JSON value, hex-encoded. */
export function sha256JcsHex(value: unknown): string {
  return sha256Hex(jcs(value));
}

/**
 * The audit value form for scope-bound watch tokens (Ruling A.3):
 * the manifest hash IS the "scope:sha256:<hash>" checkpoint value accepted in
 * TaskResult.targets_touched — only alongside per-probe TARGET_TOUCHED records.
 */
export function scopeHashCheckpoint(manifestSha256: string): string {
  return `scope:sha256:${manifestSha256.toLowerCase()}`;
}

/**
 * Hash-chain helper for audit events (doc 01 §5.9, §10.4):
 *   hash = "sha256:" + sha256(prev_hash || JCS(event minus hash))
 * `prevHash` is the previous event's hash string ("" for the genesis event).
 */
export function auditChainHash(eventWithoutHash: unknown, prevHash: string): string {
  return `sha256:${sha256Hex(prevHash + jcs(eventWithoutHash))}`;
}
