/**
 * JetStream bus client (doc 01 §8, Ruling C3 — JetStream is the canonical
 * platform bus). Wraps: envelope publishing, the agent's task.assign consumer,
 * module event publishers (*.alert / monitor.changes / detect.findings / …),
 * the tasks.revocations.v1 subscription, and control.kill (CORE NATS
 * broadcast — NO JetStream stream, doc 01 §8.1).
 *
 * Consumers are idempotent on event_id / task_id (doc 01 §8.2) via a bounded
 * dedup set; assignment handlers ack only after successful handling (nak with
 * delay otherwise, so redelivery on lease expiry works per doc 01 §8.1).
 */

import { connect, type NatsConnection, type ConnectionOptions } from "@nats-io/transport-node";
import {
  AckPolicy,
  DeliverPolicy,
  jetstream,
  jetstreamManager,
  type Consumer,
  type ConsumerMessages,
  type JetStreamClient,
  type PubAck,
} from "@nats-io/jetstream";
import { anyUnpack } from "@bufbuild/protobuf/wkt";
import { TaskAssignmentSchema, type TaskAssignment } from "@aegisbastion/gen/aegisbastion/platform/v1/task_pb.js";
import {
  RevocationEventSchema,
  type RevocationEvent,
} from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/revocation_pb.js";
import { encodeEnvelope, decodeEnvelope, IdempotencySet } from "./envelope.js";
import type { EnvelopeOptions } from "./envelope.js";
import { newEnvelope } from "./envelope.js";
import { SUBJECTS } from "./subjects.js";
import type { DescMessage, MessageShape } from "@bufbuild/protobuf";

/** JetStream stream names, as bootstrapped by deploy/jetstream-bootstrap. */
export const STREAMS = {
  taskAssign: "TASK_ASSIGN",
  gatekeeper: "GATEKEEPER",
} as const;

export interface BusClientOptions {
  /** e.g. "nats://localhost:4222" or ["nats://nats:4222"]. */
  servers: string | string[];
  /** NATS connection extras (credentials, TLS, name). */
  connection?: Omit<ConnectionOptions, "servers">;
}

export interface AssignmentDelivery {
  envelopeId: string;
  assignment: TaskAssignment;
  /** Trace context propagated from the Orchestrator's envelope. */
  traceContext?: { traceparent: string; tracestate?: string };
}

export class BusClient {
  private constructor(
    readonly nc: NatsConnection,
    readonly js: JetStreamClient,
  ) {}

  static async connect(opts: BusClientOptions): Promise<BusClient> {
    const nc = await connect({ servers: opts.servers, ...opts.connection });
    return new BusClient(nc, jetstream(nc));
  }

  async close(): Promise<void> {
    await this.nc.drain();
  }

  /** Publish a typed payload on a subject inside the platform envelope. */
  async publish<Desc extends DescMessage>(
    subject: string,
    payloadSchema: Desc,
    payload: MessageShape<Desc>,
    opts: EnvelopeOptions = {},
  ): Promise<PubAck> {
    const envelope = newEnvelope(payloadSchema, payload, opts);
    return this.js.publish(subject, encodeEnvelope(envelope));
  }

  /** Publish a pre-built envelope (e.g. audit events). */
  async publishEnvelope(subject: string, envelopeBytes: Uint8Array): Promise<PubAck> {
    return this.js.publish(subject, envelopeBytes);
  }

  /**
   * Consume task assignments from `task.assign.{agentId}` (WorkQueue stream,
   * ack-required, redelivery on lease expiry — doc 01 §8.1). The handler MUST
   * be redelivery-safe; duplicates on task_id are filtered here, and the
   * Orchestrator-side consumer is idempotent as well (doc 01 §8.2).
   *
   * Ack semantics: ack after the handler resolves; nak(5s) when it throws so
   * the Orchestrator redelivers per the task lease.
   */
  async consumeAssignments(
    agentId: string,
    handler: (delivery: AssignmentDelivery) => Promise<void>,
    opts: { durableName?: string; signal?: AbortSignal } = {},
  ): Promise<{ stop: () => Promise<void> }> {
    const jsm = await jetstreamManager(this.nc);
    const durable = opts.durableName ?? `agent-${agentId}`;
    await jsm.consumers.add(STREAMS.taskAssign, {
      durable_name: durable,
      filter_subject: SUBJECTS.taskAssign(agentId),
      ack_policy: AckPolicy.Explicit,
      deliver_policy: DeliverPolicy.All,
      // Orchestrator lease-expiry redelivery relies on the ack wait (doc 01
      // §6.3); 30 s matches the Registry heartbeat TTL window.
      ack_wait: 30_000_000_000, // nanoseconds
      max_deliver: 5,
    });
    const consumer: Consumer = await this.js.consumers.get(STREAMS.taskAssign, durable);
    const messages: ConsumerMessages = await consumer.consume();
    const dedup = new IdempotencySet();

    const loop = (async () => {
      for await (const msg of messages) {
        if (opts.signal?.aborted) break;
        try {
          const envelope = decodeEnvelope(msg.data);
          if (!dedup.firstSeen(envelope.eventId)) {
            msg.ack();
            continue;
          }
          const assignment = envelope.payload
            ? anyUnpack(envelope.payload, TaskAssignmentSchema)
            : undefined;
          if (!assignment) {
            // Unknown payload type on the assignment subject: term it — it can
            // never become processable, and redelivery loops starve the queue.
            msg.term("unrecognized assignment payload");
            continue;
          }
          await handler({
            envelopeId: envelope.eventId,
            assignment,
            ...(envelope.traceContext
              ? {
                  traceContext: {
                    traceparent: envelope.traceContext.traceparent,
                    tracestate: envelope.traceContext.tracestate,
                  },
                }
              : {}),
          });
          msg.ack();
        } catch {
          msg.nak(5_000);
        }
      }
    })();

    return {
      stop: async () => {
        messages.stop();
        await loop.catch(() => {});
      },
    };
  }

  /**
   * Subscribe to `tasks.revocations.v1` (durable GATEKEEPER stream). The
   * handler is invoked once per RevocationEvent, deduped on event_id.
   */
  async subscribeRevocations(
    agentId: string,
    handler: (event: RevocationEvent) => void,
  ): Promise<{ stop: () => Promise<void> }> {
    const jsm = await jetstreamManager(this.nc);
    const durable = `revocations-${agentId}`;
    await jsm.consumers.add(STREAMS.gatekeeper, {
      durable_name: durable,
      filter_subject: SUBJECTS.tasksRevocations,
      ack_policy: AckPolicy.Explicit,
      deliver_policy: DeliverPolicy.All,
      ack_wait: 30_000_000_000,
      max_deliver: 10,
    });
    const consumer = await this.js.consumers.get(STREAMS.gatekeeper, durable);
    const messages = await consumer.consume();
    const dedup = new IdempotencySet();

    const loop = (async () => {
      for await (const msg of messages) {
        try {
          const envelope = decodeEnvelope(msg.data);
          if (dedup.firstSeen(envelope.eventId) && envelope.payload) {
            const event = anyUnpack(envelope.payload, RevocationEventSchema);
            if (event) handler(event);
          }
          msg.ack();
        } catch {
          msg.nak(1_000);
        }
      }
    })();

    return {
      stop: async () => {
        messages.stop();
        await loop.catch(() => {});
      },
    };
  }

  /**
   * Subscribe to `control.kill` — a CORE NATS broadcast with NO JetStream
   * stream (doc 01 §8.1). Agents must halt target contact within 5 s
   * (doc 01 §10.5). Raw payload bytes are handed to the caller (see
   * decodeControlKill in revocation.ts).
   */
  subscribeKill(handler: (data: Uint8Array) => void): { stop: () => Promise<void> } {
    const sub = this.nc.subscribe(SUBJECTS.controlKill);
    const loop = (async () => {
      for await (const msg of sub) {
        handler(msg.data);
      }
    })();
    return {
      stop: async () => {
        sub.unsubscribe();
        await loop.catch(() => {});
      },
    };
  }
}
