/**
 * Signed bundle/policy verification (doc 07 §4.3/§4.4, §8.6, §9):
 *
 *  - Ed25519 over JCS (RFC 8785) of the document minus its `signature` field.
 *  - Verified against PINNED hub public keys (two pinned for rotation).
 *  - Monotonic versions: rollback rejected (bundleVersion, policyVersion).
 *  - Freshness: stale bundle → accepted-but-degraded (§9); expired policy →
 *    rejected (fall back to last non-expired policy, else compiled-in
 *    defaults).
 *  - Rotation: a valid bundle may carry `nextKey` dual-signed by the SAME
 *    pinned key that signed the bundle (§8.6) — the new key is adopted as a
 *    pin. Any other new key is rejected (fleet stays on last-good, §9).
 *
 * Everything here is fail-closed: any structural or cryptographic problem is
 * a rejection with a reason code, never an exception path the caller can
 * forget to check.
 */

import { validatePolicyConfig, type PolicyConfig } from "../core/policy.js";
import { base64urlToBytes, utf8ToBytes } from "./base64.js";
import {
  bundleIsStale,
  compareBundleVersions,
  validateIntelBundle,
  type IntelBundle,
} from "./bundle.js";
import { importPinnedPublicKey, verifyBytes } from "./ed25519.js";
import { jcs } from "./jcs.js";

export type RejectReason =
  | "SCHEMA_INVALID"
  | "SIGNATURE_MISSING"
  | "SIGNATURE_INVALID"
  | "UNTRUSTED_KEY"
  | "ROLLBACK"
  | "VERSION_INVALID"
  | "POLICY_EXPIRED"
  | "ROTATION_SIGNATURE_INVALID";

export interface VerifyOptions {
  /** base64url raw Ed25519 pinned hub public keys (≤ 2 for rotation). */
  pinnedKeys: readonly string[];
  /** Current bundle version (rollback check); undefined = first apply. */
  currentBundleVersion?: string;
  /** Current policy version (rollback check); undefined = first apply. */
  currentPolicyVersion?: number;
  now?: Date;
}

export interface VerifiedBundle {
  ok: true;
  bundle: IntelBundle;
  /** Index into pinnedKeys whose key verified the signature. */
  keyIndex: number;
  /** §9 degraded_mode: integrity OK but freshness window exceeded. */
  stale: boolean;
  /** Validated rotation to adopt (already signature-checked), if present. */
  rotation?: { publicKey: string };
}

export interface VerifyBundleResult {
  ok: boolean;
  reason?: RejectReason;
  errors?: { field: string; message: string }[];
  bundle?: IntelBundle;
  keyIndex?: number;
  stale?: boolean;
  rotation?: { publicKey: string };
}

/** Strip the signature field before JCS (signed form = doc minus signature). */
function signedBody(doc: Record<string, unknown>): string {
  const { signature: _sig, ...body } = doc;
  return jcs(body);
}

async function verifyAgainstPins(
  doc: Record<string, unknown>,
  signature: unknown,
  pinnedKeys: readonly string[],
): Promise<number /* keyIndex */ | null> {
  if (typeof signature !== "string" || signature === "") return null;
  const payload = utf8ToBytes(signedBody(doc));
  for (const [index, pin] of pinnedKeys.entries()) {
    try {
      const key = await importPinnedPublicKey(pin);
      if (await verifyBytes(key, signature, payload)) return index;
    } catch {
      // Untrusted/malformed pin simply fails this candidate.
    }
  }
  return null;
}

export async function verifyIntelBundle(raw: unknown, opts: VerifyOptions): Promise<VerifyBundleResult> {
  const errors = validateIntelBundle(raw);
  if (errors.length > 0) return { ok: false, reason: "SCHEMA_INVALID", errors };
  const bundle = raw as IntelBundle;
  if (opts.pinnedKeys.length === 0) return { ok: false, reason: "UNTRUSTED_KEY" };

  const keyIndex = await verifyAgainstPins(raw as Record<string, unknown>, bundle.signature, opts.pinnedKeys);
  if (keyIndex === null) return { ok: false, reason: "SIGNATURE_INVALID" };

  if (opts.currentBundleVersion !== undefined) {
    const cmp = compareBundleVersions(bundle.bundleVersion, opts.currentBundleVersion);
    if (cmp === null) return { ok: false, reason: "VERSION_INVALID" };
    if (cmp <= 0) return { ok: false, reason: "ROLLBACK" };
  }

  // §8.6 rotation: nextKey must be dual-signed by the SAME pinned key.
  let rotation: { publicKey: string } | undefined;
  if (bundle.nextKey !== undefined) {
    const signingPin = opts.pinnedKeys[keyIndex];
    if (signingPin === undefined) return { ok: false, reason: "UNTRUSTED_KEY" };
    let rotationOk = false;
    try {
      const key = await importPinnedPublicKey(signingPin);
      const rotationPayload = utf8ToBytes(jcs({ publicKey: bundle.nextKey.publicKey }));
      rotationOk =
        base64urlToBytes(bundle.nextKey.publicKey).length === 32 &&
        (await verifyBytes(key, bundle.nextKey.signature, rotationPayload));
    } catch {
      rotationOk = false;
    }
    if (!rotationOk) return { ok: false, reason: "ROTATION_SIGNATURE_INVALID" };
    rotation = { publicKey: bundle.nextKey.publicKey };
  }

  const stale = bundleIsStale(bundle, opts.now ?? new Date());
  return { ok: true, bundle, keyIndex, stale, ...(rotation ? { rotation } : {}) };
}

export interface VerifyPolicyResult {
  ok: boolean;
  reason?: RejectReason;
  errors?: { field: string; message: string }[];
  policy?: PolicyConfig;
  keyIndex?: number;
}

export async function verifyPolicyConfig(raw: unknown, opts: VerifyOptions): Promise<VerifyPolicyResult> {
  const errors = validatePolicyConfig(raw);
  if (errors.length > 0) return { ok: false, reason: "SCHEMA_INVALID", errors };
  const policy = raw as PolicyConfig;
  if (opts.pinnedKeys.length === 0) return { ok: false, reason: "UNTRUSTED_KEY" };
  if (typeof policy.signature !== "string" || policy.signature === "") {
    return { ok: false, reason: "SIGNATURE_MISSING" };
  }

  const keyIndex = await verifyAgainstPins(raw as Record<string, unknown>, policy.signature, opts.pinnedKeys);
  if (keyIndex === null) return { ok: false, reason: "SIGNATURE_INVALID" };

  // §5.2 policy.push: agent rejects if older than current.
  if (opts.currentPolicyVersion !== undefined && policy.policyVersion <= opts.currentPolicyVersion) {
    return { ok: false, reason: "ROLLBACK" };
  }
  // §9 policy expiry: rejected here; caller falls back to last non-expired.
  if (Date.parse(policy.expiresAt) <= (opts.now ?? new Date()).getTime()) {
    return { ok: false, reason: "POLICY_EXPIRED" };
  }
  return { ok: true, policy, keyIndex };
}
