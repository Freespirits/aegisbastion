/**
 * Bus envelope helpers (doc 01 §8.2). Every JetStream message is an
 * `aegisbastion.platform.v1.Envelope`: event_id (ULID), type (fully-qualified
 * payload type), ts, mission_id, trace_context, protobuf Any payload.
 * Consumers MUST be idempotent on event_id / task_id.
 */

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import type { DescMessage, MessageShape } from "@bufbuild/protobuf";
import { anyPack, timestampNow } from "@bufbuild/protobuf/wkt";
import {
  EnvelopeSchema,
  type Envelope,
} from "@aegisbastion/gen/aegisbastion/platform/v1/bus_pb.js";
import {
  TraceContextSchema,
  type TraceContext,
} from "@aegisbastion/gen/aegisbastion/platform/v1/types_pb.js";
import { ulid } from "./ulid.js";

export interface EnvelopeOptions {
  /** Owning mission (empty for platform-internal messages). */
  missionId?: string;
  /** W3C trace context propagated from the triggering assignment/event. */
  traceContext?: { traceparent: string; tracestate?: string };
}

/** Build an Envelope wrapping a typed payload message. */
export function newEnvelope<Desc extends DescMessage>(
  payloadSchema: Desc,
  payload: MessageShape<Desc>,
  opts: EnvelopeOptions = {},
): Envelope {
  const trace: TraceContext | undefined = opts.traceContext
    ? create(TraceContextSchema, {
        traceparent: opts.traceContext.traceparent,
        tracestate: opts.traceContext.tracestate ?? "",
      })
    : undefined;
  return create(EnvelopeSchema, {
    eventId: ulid(),
    type: payloadSchema.typeName,
    ts: timestampNow(),
    missionId: opts.missionId ?? "",
    ...(trace ? { traceContext: trace } : {}),
    payload: anyPack(payloadSchema, payload),
  });
}

/** Serialize an Envelope to protobuf wire bytes. */
export function encodeEnvelope(envelope: Envelope): Uint8Array {
  return toBinary(EnvelopeSchema, envelope);
}

/** Parse an Envelope from protobuf wire bytes. Throws on malformed input. */
export function decodeEnvelope(bytes: Uint8Array): Envelope {
  return fromBinary(EnvelopeSchema, bytes);
}

/**
 * Bounded idempotency set for event_id / task_id dedup (doc 01 §8.2: duplicate
 * delivery is expected under at-least-once). In-memory, insertion-ordered,
 * evicts oldest beyond capacity — redelivery-safe consumers stay cheap.
 */
export class IdempotencySet {
  private readonly seen = new Set<string>();
  constructor(private readonly capacity = 10_000) {}

  /** Returns true the first time a key is observed, false on duplicates. */
  firstSeen(key: string): boolean {
    if (!key) return true;
    if (this.seen.has(key)) return false;
    if (this.seen.size >= this.capacity) {
      const oldest = this.seen.values().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    this.seen.add(key);
    return true;
  }

  get size(): number {
    return this.seen.size;
  }
}
