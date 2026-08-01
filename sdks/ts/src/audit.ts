/**
 * Audit helpers (doc 01 §5.9/§10.4, Ruling A.4).
 *
 * - `targetTouchedEvent` builds the per-probe TARGET_TOUCHED audit record —
 *   the AUTHORITATIVE cross-check for scope-bound watch tokens (a checkpoint
 *   `targets_touched: ["scope:sha256:…"]` entry is accepted only alongside
 *   these records).
 * - `scopeHashCheckpoint` (from jcs.ts) produces that checkpoint form.
 * - Events are published on `audit.events` (durable, never sampled).
 *
 * The audit of record for authorization state lives in gatekeeper's
 * audit-service (Ruling B); these events feed the command layer's operational
 * chain (aegisbastion.platform.v1.AuditEvent).
 */

import { create, toJson } from "@bufbuild/protobuf";
import { timestampNow } from "@bufbuild/protobuf/wkt";
import type { JsonObject } from "@bufbuild/protobuf";
import {
  AuditActorSchema,
  AuditEventSchema,
  AuditEventType,
  AuditSubjectSchema,
  type AuditEvent,
} from "@aegisbastion/gen/aegisbastion/platform/v1/audit_pb.js";
import { auditChainHash, jcs, scopeHashCheckpoint, sha256JcsHex } from "./jcs.js";
import { ulid } from "./ulid.js";

export { scopeHashCheckpoint, auditChainHash, jcs, sha256JcsHex };

export interface AuditEventInput {
  type: AuditEventType;
  actor: { kind: string; id: string };
  subject: { missionId?: string; taskId?: string; roeId?: string };
  payload: JsonObject;
  /** Chain ordering assigned by the caller's local emitter (0 = unset). */
  seq?: bigint | number;
  /** Previous chain hash ("sha256:…"); "" for the genesis event. */
  prevHash?: string;
}

/**
 * Build a hash-chained platform AuditEvent (doc 01 §5.9):
 * hash = "sha256:" + sha256(prev_hash || JCS(event minus hash)).
 */
export function buildAuditEvent(input: AuditEventInput): AuditEvent {
  const event = create(AuditEventSchema, {
    eventId: `aud_${ulid()}`,
    seq: BigInt(input.seq ?? 0),
    ts: timestampNow(),
    type: input.type,
    actor: create(AuditActorSchema, input.actor),
    subject: create(AuditSubjectSchema, {
      missionId: input.subject.missionId ?? "",
      taskId: input.subject.taskId ?? "",
      roeId: input.subject.roeId ?? "",
    }),
    payload: input.payload,
    prevHash: input.prevHash ?? "",
    hash: "",
  });
  const canonical = toJson(AuditEventSchema, event);
  event.hash = auditChainHash(canonical, event.prevHash);
  return event;
}

/**
 * Build the per-probe TARGET_TOUCHED record (Ruling A.4 — the authoritative
 * cross-check). One record per probe, emitted at touch time.
 */
export function targetTouchedEvent(input: {
  agentId: string;
  taskId: string;
  missionId: string;
  roeId: string;
  target: string;
  tokenJti: string;
  capability: string;
  seq?: bigint | number;
  prevHash?: string;
}): AuditEvent {
  return buildAuditEvent({
    type: AuditEventType.TARGET_TOUCHED,
    actor: { kind: "agent", id: input.agentId },
    subject: { missionId: input.missionId, taskId: input.taskId, roeId: input.roeId },
    payload: {
      target: input.target,
      token_jti: input.tokenJti,
      capability: input.capability,
    },
    ...(input.seq !== undefined ? { seq: input.seq } : {}),
    ...(input.prevHash !== undefined ? { prevHash: input.prevHash } : {}),
  });
}

/**
 * Local audit emitter: keeps the agent-side hash chain (seq + prev_hash) and
 * hands each event to a sink (typically BusClient.publish on audit.events).
 * Sinks are durable and never sampled (doc 01 §8.1); when the sink throws,
 * the error propagates — doc 11 §7: PEPs spool execution events and halt
 * module activity when the spool is full. The sink decides spooling policy.
 */
export class AuditEmitter {
  private seq = 0n;
  private prevHash = "";

  constructor(private readonly sink: (event: AuditEvent) => Promise<void>) {}

  async emit(input: AuditEventInput): Promise<AuditEvent> {
    const event = buildAuditEvent({ ...input, seq: ++this.seq, prevHash: this.prevHash });
    await this.sink(event);
    this.prevHash = event.hash;
    return event;
  }

  /** Emit one per-probe TARGET_TOUCHED record. */
  async targetTouched(input: {
    agentId: string;
    taskId: string;
    missionId: string;
    roeId: string;
    target: string;
    tokenJti: string;
    capability: string;
  }): Promise<AuditEvent> {
    return this.emit({
      type: AuditEventType.TARGET_TOUCHED,
      actor: { kind: "agent", id: input.agentId },
      subject: { missionId: input.missionId, taskId: input.taskId, roeId: input.roeId },
      payload: {
        target: input.target,
        token_jti: input.tokenJti,
        capability: input.capability,
      },
    });
  }
}
