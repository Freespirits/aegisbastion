/**
 * Canonical bus subjects (doc 01 §8.1; doc 11 §9 item 9). JetStream is the
 * canonical platform bus (Ruling C3). `control.kill` is a CORE NATS broadcast
 * with NO JetStream stream (doc 01 §8.1); everything else listed here is a
 * durable JetStream subject.
 */

export const SUBJECTS = {
  /** Orchestrator → specific agent (WorkQueue, ack-required). */
  taskAssign: (agentId: string) => `task.assign.${agentId}`,
  /** agents → Orchestrator (durable, at-least-once, idempotent on task_id). */
  taskResult: "task.result",
  /** agents → Registry (ephemeral, 10 s cadence). */
  agentHeartbeat: "agent.heartbeat",
  /** Orchestrator → commanders, UI (durable). */
  missionEvents: "mission.events",
  /** Monitor agent → commanders (durable). */
  monitorChanges: "monitor.changes",
  /** Monitor new-asset candidates (doc 03 §5). */
  monitorAssetsNew: "monitor.assets.new",
  /** Monitor alerts in AlertEvent v1 form (doc 03 §5.3 mapping). */
  monitorAlert: "monitor.alert",
  /** Detect findings, full stream (doc 04 §4.3). */
  detectFindings: "detect.findings",
  /** Detect alerts in AlertEvent v1 form (Ruling C8 mapping). */
  detectAlert: "detect.alert",
  /** Orchestrator → all agents. CORE NATS broadcast only — no JetStream. */
  controlKill: "control.kill",
  /** all services → Audit Service (durable, never sampled). */
  auditEvents: "audit.events",
  /** Alert agent ↔ notifier integrations (durable). */
  alertOutbound: "alert.outbound",
  // Gatekeeper bus contracts (doc 11 §9 item 9).
  authzDecisions: "authz.decisions.v1",
  authzDenials: "authz.denials.v1",
  roeEvents: "roe.events.v1",
  /** Revocation broadcast consumed by every PEP (kill ≤ 5 s SLA). */
  tasksRevocations: "tasks.revocations.v1",
  authzApprovals: "authz.approvals.v1",
  auditAnomalies: "audit.anomalies.v1",
  /** Phish-Catcher intel feed bundles (doc 01 §9.2). */
  intelFeedsPhishing: "intel.feeds.phishing",
} as const;
