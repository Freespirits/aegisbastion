/**
 * The MVP-A default hub transport: INERT (doc 00 §4 — MVP-A ships the
 * standalone library; the hub loop is MVP-B). All sends are dropped with
 * counters (observability for embedders), push handlers are accepted but
 * never fire, and NOTHING is transmitted — the zero-external-transmission
 * rule (doc 07 §7) holds by construction.
 *
 * Kept in its own module (no `@aegisbastion/agent-sdk` imports, even dynamic)
 * so the browser/MV3 bundles can depend on it without pulling hub code.
 */

import type {
  AgentHeartbeatPayload,
  FindingReportPayload,
  ScanRejectedPayload,
  ScanResultPayload,
} from "./messages.js";
import type { DeploymentMode } from "./scan-gate.js";
import type { HubPushHandlers, HubTransport } from "./transport.js";

export class InertHubTransport implements HubTransport {
  readonly live = false;
  private dropped = { heartbeat: 0, scanResult: 0, scanRejected: 0, findingReport: 0 };

  constructor(readonly mode: DeploymentMode) {}

  async start(_handlers: HubPushHandlers): Promise<void> {}
  async stop(): Promise<void> {}

  async sendHeartbeat(_p: AgentHeartbeatPayload): Promise<void> {
    this.dropped.heartbeat++;
  }
  async sendScanResult(_p: ScanResultPayload): Promise<void> {
    this.dropped.scanResult++;
  }
  async sendScanRejected(_p: ScanRejectedPayload): Promise<void> {
    this.dropped.scanRejected++;
  }
  async sendFindingReport(_r: FindingReportPayload): Promise<void> {
    this.dropped.findingReport++;
  }

  /** Test/diagnostic introspection. */
  droppedCounts(): Readonly<typeof this.dropped> {
    return { ...this.dropped };
  }
}
