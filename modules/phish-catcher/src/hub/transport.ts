/**
 * The hub transport seam (doc 07 §5.1, Ruling C10; doc 00 §4).
 *
 * MVP-A ships Phish-Catcher as a STANDALONE library — the hub loop is MVP-B.
 * This file defines the seam so the platform TS agent SDK
 * (`@aegisbastion/agent-sdk` — bus / `StreamTasks`, doc 01 §8.3/§9.1) drops in
 * cleanly: `HubTransport` is the interface, `InertHubTransport` (hub/inert.ts)
 * is the default (zero egress, zero hub coupling), and the SDK-backed
 * adapter loads only behind the feature flag (`enabled: true`, i.e.
 * PHISH_HUB=on).
 *
 * There is NO bespoke WebSocket `/v1/agent-bus` endpoint (Ruling C10).
 */

import type {
  AgentHeartbeatPayload,
  FindingReportPayload,
  ScanRejectedPayload,
  ScanRequestPayload,
  ScanResultPayload,
} from "./messages.js";
import type { DeploymentMode } from "./scan-gate.js";
import { InertHubTransport } from "./inert.js";

export { InertHubTransport } from "./inert.js";

export interface HubPushHandlers {
  /** policy.push — new signed PolicyConfig (doc 07 §4.3). */
  onPolicyPush?: (raw: unknown) => void | Promise<void>;
  /** intel.push — new signed IntelBundle (doc 07 §4.4). */
  onIntelPush?: (raw: unknown) => void | Promise<void>;
  /** scan.request — node batch mode only (§5.2). */
  onScanRequest?: (req: ScanRequestPayload) => void | Promise<void>;
}

export interface HubTransport {
  readonly mode: DeploymentMode;
  /** True when this transport can actually reach the hub. */
  readonly live: boolean;
  start(handlers: HubPushHandlers): Promise<void>;
  stop(): Promise<void>;
  sendHeartbeat(payload: AgentHeartbeatPayload): Promise<void>;
  sendScanResult(payload: ScanResultPayload): Promise<void>;
  sendScanRejected(payload: ScanRejectedPayload): Promise<void>;
  sendFindingReport(report: FindingReportPayload): Promise<void>;
}

export interface HubTransportConfig {
  /** Feature flag — PHISH_HUB=on. Anything else ⇒ inert (MVP-A default). */
  enabled?: boolean;
  mode: DeploymentMode;
  /** Wiring for the SDK adapter (required when enabled). */
  agentSdk?: Record<string, unknown>;
}

/**
 * Transport factory. Inert unless explicitly enabled; the SDK adapter is
 * dynamically imported so the standalone build never loads hub code at
 * runtime. (Node-side only: browser bundles use `InertHubTransport`
 * directly so no hub code enters the extension package, §7.1.)
 */
export async function createHubTransport(config: HubTransportConfig): Promise<HubTransport> {
  if (config.enabled !== true) return new InertHubTransport(config.mode);
  const { AgentSdkHubTransport } = await import("./agent-sdk-transport.js");
  const wiring = { mode: config.mode, ...(config.agentSdk ?? {}) } as ConstructorParameters<typeof AgentSdkHubTransport>[0];
  return new AgentSdkHubTransport(wiring);
}
