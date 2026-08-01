/**
 * Revocation cache + kill-switch handling (doc 11 §7, Ruling C11).
 *
 * gatekeeper's revocation-service emits `tasks.revocations.v1` (durable
 * JetStream); the Orchestrator maps those to `control.kill` (CORE NATS
 * broadcast, no stream). PEPs must ACK and halt in-flight work ≤ 5 s
 * (graceful: stop new requests, drain ≤ 5 s, report execution.halted).
 *
 * This cache is the local revocation set the PEP consults before every
 * network action; entries honor `expires_at` (temporary revocations lift).
 * Fail-safe direction: an unparseable control.kill broadcast is treated as a
 * GLOBAL kill — kill signals fail toward halting, never toward continuing.
 */

import { fromBinary } from "@bufbuild/protobuf";
import { anyUnpack, timestampDate } from "@bufbuild/protobuf/wkt";
import { EnvelopeSchema } from "@aegisbastion/gen/aegisbastion/platform/v1/bus_pb.js";
import {
  RevocationEventSchema,
  RevocationScope,
  type Revocation,
  type RevocationEvent,
} from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/revocation_pb.js";
import { PepError } from "./errors.js";
import { canonicalizeTarget } from "./scope.js";
import type { ScopeTokenClaims } from "./token.js";

interface CacheEntry {
  revocationId: string;
  expiresAtMs: number | null;
}

export type KillSignal =
  | { kind: "global"; reason: string }
  | { kind: "roe"; roeId: string; reason: string }
  | { kind: "target"; target: string; reason: string }
  | { kind: "capability"; capability: string; reason: string };

export class RevocationCache {
  private global: CacheEntry | null = null;
  private readonly roes = new Map<string, CacheEntry>();
  private readonly targets = new Map<string, CacheEntry>();
  private readonly capabilities = new Map<string, CacheEntry>();
  private readonly seenRevocationIds = new Set<string>();

  constructor(private readonly nowMs: () => number = () => Date.now()) {}

  /** Apply one Revocation (idempotent on revocation_id). */
  apply(rev: Revocation): void {
    if (rev.revocationId && this.seenRevocationIds.has(rev.revocationId)) return;
    if (rev.revocationId) this.seenRevocationIds.add(rev.revocationId);
    const entry: CacheEntry = {
      revocationId: rev.revocationId,
      expiresAtMs: rev.expiresAt ? timestampDate(rev.expiresAt).getTime() : null,
    };
    switch (rev.scope) {
      case RevocationScope.GLOBAL:
        this.global = entry;
        break;
      case RevocationScope.ROE:
        if (rev.key) this.roes.set(rev.key, entry);
        break;
      case RevocationScope.TARGET: {
        if (rev.key) {
          let canonical = rev.key;
          try {
            canonical = canonicalizeTarget(rev.key).canonical;
          } catch {
            // Unparseable target key: store raw — matching is done on
            // canonicalized targets, so a raw entry can only under-match,
            // and the GLOBAL/ROE scopes still cover the halt.
          }
          this.targets.set(canonical, entry);
        }
        break;
      }
      case RevocationScope.CAPABILITY:
        if (rev.key) this.capabilities.set(rev.key, entry);
        break;
      default:
        // Unknown scope: fail-safe — treat as global halt.
        this.global = entry;
        break;
    }
  }

  /** Apply a bus RevocationEvent. */
  applyEvent(event: RevocationEvent): void {
    if (event.revocation) this.apply(event.revocation);
  }

  private live(entry: CacheEntry | null | undefined): entry is CacheEntry {
    return entry != null && (entry.expiresAtMs === null || entry.expiresAtMs > this.nowMs());
  }

  /**
   * The kill signal applying to this token/target/capability right now, or
   * null when nothing is revoked. Checked before EVERY network action.
   */
  check(claims: ScopeTokenClaims, rawTarget?: string, capability?: string): KillSignal | null {
    if (this.live(this.global)) {
      return { kind: "global", reason: "platform-wide revocation active" };
    }
    if (this.live(this.roes.get(claims.roe_id))) {
      return { kind: "roe", roeId: claims.roe_id, reason: `RoE ${claims.roe_id} revoked` };
    }
    if (capability !== undefined && this.live(this.capabilities.get(capability))) {
      return { kind: "capability", capability, reason: `capability ${capability} revoked` };
    }
    for (const cap of claims.capabilities) {
      if (this.live(this.capabilities.get(cap))) {
        return { kind: "capability", capability: cap, reason: `capability ${cap} revoked` };
      }
    }
    if (rawTarget !== undefined) {
      let canonical: string | null = null;
      try {
        canonical = canonicalizeTarget(rawTarget).canonical;
      } catch {
        canonical = null;
      }
      const entry =
        (canonical !== null ? this.targets.get(canonical) : undefined) ?? this.targets.get(rawTarget);
      if (this.live(entry)) {
        return { kind: "target", target: rawTarget, reason: `target revoked` };
      }
    }
    return null;
  }

  /** Throw PepError(REVOKED) when any revocation applies. */
  assertNotRevoked(claims: ScopeTokenClaims, rawTarget?: string, capability?: string): void {
    const signal = this.check(claims, rawTarget, capability);
    if (signal !== null) {
      throw new PepError("REVOKED", signal.reason, { kind: signal.kind });
    }
  }

  get size(): number {
    return (
      (this.global ? 1 : 0) + this.roes.size + this.targets.size + this.capabilities.size
    );
  }
}

/**
 * Decode a `control.kill` broadcast payload (CORE NATS, no JetStream stream,
 * doc 01 §8.1). Contract form: an Envelope whose Any payload is a gatekeeper
 * RevocationEvent (Ruling C11: the Orchestrator maps revocations to
 * control.kill). Fail-SAFE: anything unparseable is treated as a GLOBAL kill.
 */
export function decodeControlKill(data: Uint8Array): RevocationEvent | { global: true } {
  try {
    const envelope = fromBinary(EnvelopeSchema, data);
    if (envelope.payload) {
      const event = anyUnpack(envelope.payload, RevocationEventSchema);
      if (event) return event;
    }
  } catch {
    // fall through to fail-safe global kill
  }
  return { global: true };
}
