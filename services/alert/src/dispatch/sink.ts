/**
 * Delivery sink abstraction — what makes deliveries MOCKABLE. The dispatcher
 * always writes the recorded outbox (alert.deliveries + payload snapshots);
 * whether bytes actually leave the process is the sink's decision:
 *   - RecordedSink: captures every send (tests, HERALD_DELIVERY_MODE=record).
 *   - LiveSink: fan-out to the five channel adapters (slack, teams,
 *     splunk-hec, syslog, webhook).
 */

import type { AlertEvent, Delivery, EgressEntry, Incident } from "../types.js";

export interface SendRequest {
  delivery: Delivery;
  incident: Incident;
  /** Member alerts, ALREADY redacted for this target (§13.3). */
  alerts: AlertEvent[];
  /** Rendered human text (handlebars, sandboxed). */
  text: string;
  /** Org egress policy entry that authorized this destination (§13.2). */
  egressEntry: EgressEntry | null;
  /** Signed ack-callback link for interactive channels (§9/§12). */
  ackUrl?: string;
}

export interface SendResult {
  ok: boolean;
  providerResponseCode?: number;
  latencyMs?: number;
  error?: string;
  /** Provider asked us to slow down (429 Retry-After). */
  retryAfterMs?: number;
  /** The exact payload sent (recorded into the outbox). */
  payloadSnapshot?: unknown;
}

export interface DeliverySink {
  readonly mode: string;
  send(req: SendRequest): Promise<SendResult>;
  close(): Promise<void>;
}

/** Test/dev sink: every send recorded, nothing leaves the process. */
export class RecordedSink implements DeliverySink {
  readonly mode = "record";
  readonly sent: SendRequest[] = [];
  /** Test hook: force failures for specific channels. */
  failChannels = new Set<string>();

  async send(req: SendRequest): Promise<SendResult> {
    this.sent.push(structuredClone(req));
    if (this.failChannels.has(req.delivery.channel)) {
      return { ok: false, error: `recorded failure for ${req.delivery.channel}` };
    }
    return { ok: true, providerResponseCode: 200, latencyMs: 0, payloadSnapshot: { text: req.text } };
  }

  async close(): Promise<void> {}
}
