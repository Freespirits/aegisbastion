/**
 * Hub message contracts (doc 07 §5.2, agent ↔ commander). Transport is the
 * platform-standard bus envelope (doc 01 §8.2) carried by the platform TS
 * agent SDK (Ruling C10) — this module defines only the payload shapes.
 * Browser-mode agents MUST reject `scan.request` unconditionally with
 * `UNSUPPORTED_IN_MODE` (§5.2).
 */

/** §5.2 scan.request rejection reason codes (normative). */
export type ScanRejectReason =
  | "SCOPE_DENIED"
  | "ROE_INVALID"
  | "RATE_CAPPED"
  | "UNSUPPORTED_IN_MODE";

export interface AgentRegisterPayload {
  capabilities: ["phish.email", "phish.page", "phish.url"];
  libVersion: string;
  bundleVersion: string;
  policyVersion: number;
  deploymentMode: "node-batch" | "browser-extension" | "browser-embed";
}

/** Heartbeat counters only — never content (§5.2). */
export interface AgentHeartbeatPayload {
  bundleVersion: string;
  policyVersion: number;
  counters: {
    analyzed: number;
    clean: number;
    suspicious: number;
    malicious: number;
    reportsQueued: number;
  };
}

export interface ScanRequestPayload {
  scopeId: string;
  /** e.g. "s3://…/*.eml" — resolved by the hub-side artifact service (MVP-B). */
  inputRefs: string[];
  rateCapPerMin?: number;
  /** Gatekeeper Scope Token (doc 11 §3.2) — REQUIRED (§8.2). */
  scopeToken?: string;
  /** Task binding for the token's task_id claim. */
  taskId?: string;
  /** RoE reference echoed back on scan.result (§5.2). */
  roeRef?: string;
}

export interface ScanResultPayload {
  scopeId: string;
  roeRef?: string;
  aggregate: {
    items: number;
    clean: number;
    suspicious: number;
    malicious: number;
  };
  reports: FindingReportPayload[];
}

export interface ScanRejectedPayload {
  scopeId: string;
  reason: ScanRejectReason;
}

/**
 * §5.4 redacted finding report (consent-gated). URLs are salted SHA-256,
 * sender/message-id hashed, body/subject/attachment content NEVER present.
 */
export interface FindingReportPayload {
  schemaVersion: 1;
  reportId: string;
  ts: string;
  kind: "email" | "page" | "url";
  verdict: "clean" | "suspicious" | "malicious";
  score: number;
  ruleIds: string[];
  urlHashes: string[];
  senderHash?: string;
  messageIdHash?: string;
  attachments?: { sha256: string; contentType: string }[];
  clientMeta: { libVersion: string; bundleVersion: string; policyVersion: number };
  /** Set by the consent gate (§7.4) — org policy or per-item user action. */
  consent: "org-policy" | "user-item" | "user-toggle";
}

/** §5.2 message types (carried in the doc 01 §8.2 envelope `type` field). */
export const HUB_MESSAGE_TYPES = {
  agentRegister: "agent.register",
  agentHeartbeat: "agent.heartbeat",
  policyPush: "policy.push",
  intelPush: "intel.push",
  scanRequest: "scan.request",
  scanResult: "scan.result",
  scanRejected: "scan.rejected",
  findingReport: "finding.report",
} as const;

export type HubMessageType = (typeof HUB_MESSAGE_TYPES)[keyof typeof HUB_MESSAGE_TYPES];
