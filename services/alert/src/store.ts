/**
 * Persistence interface for herald. The pipeline only ever talks to this
 * interface: PostgresStore (services/alert/src/db/pgstore.ts) in production,
 * MemoryStore (db/memory.ts) in unit tests. Table shapes are
 * db/migrations/000005_alert.up.sql.
 */

import type {
  AlertEvent,
  AlertRow,
  AuditRecord,
  Delivery,
  EgressEntry,
  EscalationPolicy,
  Incident,
  RoutingPolicy,
  AuthzStatus,
  AlertState,
  DeliveryStatus,
  Channel,
} from "./types.js";

export interface StoredAlert extends AlertRow {
  event: AlertEvent;
  receivedAt: Date;
  authzClaims?: Record<string, unknown>;
}

export interface DedupOutcome {
  verdict: "new" | "duplicate" | "renotify";
  /** Occurrence counter AFTER this touch (1 = first sighting). */
  count: number;
  /** event_id of the alert that first claimed the fingerprint. */
  firstAlertId: string;
  degraded: boolean;
}

export interface DeliveryAttemptResult {
  ok: boolean;
  providerResponseCode?: number;
  latencyMs?: number;
  error?: string;
  /** Final status after this attempt (sent | failed-retryable | dlq decided by caller). */
  status: DeliveryStatus;
  nextAttemptAt?: Date;
  payloadSnapshot?: unknown;
}

export interface AlertFilter {
  orgId?: string;
  state?: AlertState;
  severityGte?: string;
  incidentId?: string;
  limit?: number;
  cursor?: string; // event_id to continue after (received_at desc, event_id desc)
}

export interface IncidentFilter {
  orgId?: string;
  state?: string;
  severityGte?: string;
  limit?: number;
  cursor?: string;
}

export interface DeliveryFilter {
  orgId?: string;
  incidentId?: string;
  alertId?: string;
  channel?: Channel;
  status?: DeliveryStatus;
  limit?: number;
}

export interface Store {
  // --- alerts (idempotent on event_id, doc 05 §3.2 step 2) ---
  insertAlertIfNew(row: StoredAlert): Promise<"inserted" | "duplicate">;
  getAlert(eventId: string): Promise<StoredAlert | null>;
  listAlerts(filter: AlertFilter): Promise<StoredAlert[]>;
  setAlertState(eventId: string, state: AlertState): Promise<void>;
  setAlertAuthz(
    eventId: string,
    status: AuthzStatus,
    claims?: Record<string, unknown>,
    retryAt?: Date | null,
  ): Promise<void>;
  setAlertIncident(eventId: string, incidentId: string): Promise<void>;
  setAlertDedup(eventId: string, verdict: "new" | "duplicate" | "renotify", degraded: boolean): Promise<void>;
  /** Alerts held on authz-verification outage whose retry time has come (§12). */
  dueAuthzRetries(now: Date): Promise<StoredAlert[]>;

  // --- dedup state (§7.1; fail-open handled by callers catching errors) ---
  dedupTouch(
    fingerprint: string,
    orgId: string,
    alertId: string,
    windowSeconds: number,
    renotifyEvery: number,
    now: Date,
  ): Promise<DedupOutcome>;

  // --- incidents / correlation (§5.3, §7.2) ---
  findOpenIncident(orgId: string, correlationKey: string): Promise<Incident | null>;
  insertIncident(incident: Incident): Promise<void>;
  getIncident(incidentId: string): Promise<Incident | null>;
  listIncidents(filter: IncidentFilter): Promise<Incident[]>;
  attachAlertToIncident(incidentId: string, event: AlertEvent, now: Date): Promise<void>;
  incidentAlerts(incidentId: string): Promise<string[]>;
  ackIncident(
    incidentId: string,
    by: string,
    note: string,
    nonce: string,
    now: Date,
  ): Promise<"acked" | "already" | "notfound" | "nonce_used">;
  resolveIncident(incidentId: string, now: Date): Promise<void>;
  setIncidentEscalation(
    incidentId: string,
    escalation: Incident["escalation"],
    state?: "open" | "escalated",
    exhausted?: boolean,
  ): Promise<void>;
  dueEscalations(now: Date): Promise<Incident[]>;

  // --- policies (§5.4/§5.5/§13.2) ---
  routingPolicies(orgId: string): Promise<RoutingPolicy[]>;
  getRoutingPolicy(policyId: string): Promise<RoutingPolicy | null>;
  putRoutingPolicy(policy: RoutingPolicy): Promise<void>;
  escalationPolicy(orgId: string, policyId: string): Promise<EscalationPolicy | null>;
  putEscalationPolicy(policy: EscalationPolicy): Promise<void>;
  egressPolicy(orgId: string): Promise<EgressEntry[] | null>;
  putEgressPolicy(orgId: string, entries: EgressEntry[], updatedBy: string): Promise<void>;

  // --- deliveries (§5.6 recorded outbox) ---
  insertDelivery(delivery: Delivery, payloadSnapshot: unknown): Promise<void>;
  dueDeliveries(now: Date, limit: number): Promise<Delivery[]>;
  recordDeliveryAttempt(deliveryId: string, result: DeliveryAttemptResult): Promise<void>;
  listDeliveries(filter: DeliveryFilter): Promise<Delivery[]>;
  deliveryStatusCounts(orgId?: string): Promise<Record<DeliveryStatus, number>>;

  // --- audit spool (§5.8; append-only) ---
  appendAudit(record: AuditRecord): Promise<string>;
  markAuditForwarded(auditId: string, at: Date): Promise<void>;

  close(): Promise<void>;
}
