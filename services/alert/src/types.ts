/**
 * Domain types for herald (doc 05). TS mirrors of the JSON contracts in
 * schemas/alert/v1 (AlertEvent v1 + CloudEvents envelope) and of the Postgres
 * rows in db/migrations/000005_alert.up.sql. The JSON Schemas remain the
 * source of truth (validated at ingress); these types are the in-service view.
 */

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Ascending rank for comparisons (info=1 … critical=5). */
export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s) + 1;
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return severityRank(a) >= severityRank(b) ? a : b;
}

export type Confidence = "confirmed" | "probable" | "possible";
export type Category =
  | "vuln"
  | "exposure"
  | "config-drift"
  | "new-asset"
  | "phishing"
  | "ai-exploit"
  | "stress-test"
  | "operational";
export type SourceModule =
  | "detect"
  | "monitor"
  | "discover"
  | "ddos-engine"
  | "ai-redteam"
  | "phish-catcher"
  | "commander";
export type PiiClassification = "none" | "pii" | "pci" | "hipaa";
export type AssetCriticality = "critical" | "high" | "medium" | "low";

export interface AlertAsset {
  asset_id: string;
  kind: "domain" | "subdomain" | "ip" | "cloud-resource" | "email" | "ai-agent";
  identifier: string;
  criticality?: AssetCriticality;
  owner_group?: string;
}

/** AlertEvent v1 (schemas/alert/v1/alert-event.schema.json), validated by ajv at ingress. */
export interface AlertEvent {
  schema_version: "1.0";
  event_id: string;
  org_id: string;
  source_module: SourceModule;
  source_event_id: string;
  engagement_id?: string;
  authorization_token_id?: string;
  fingerprint_hint?: string;
  title: string;
  description?: string;
  severity: Severity;
  confidence: Confidence;
  category: Category;
  asset: AlertAsset;
  evidence?: { scanner?: string; proof?: unknown; references?: string[] };
  pii_classification?: PiiClassification;
  occurred_at: string;
  dedup_window_seconds?: number;
  renotify_every?: number;
  requires_ack?: boolean;
  labels?: Record<string, string>;
}

/** CloudEvents 1.0 JSON-mode envelope (doc 05 §5.1). */
export interface AlertEnvelope {
  specversion: "1.0";
  id: string;
  source: string;
  type: "com.aegisbastion.alert.v1";
  subject?: string;
  time: string;
  datacontenttype: "application/json";
  data: AlertEvent;
}

/** What herald needs to know about one ingested alert beyond the event itself. */
export interface IngressContext {
  /** The compact gatekeeper Scope Token JWT (doc 05 §5.7 `authorization_token`). */
  authorizationToken?: string;
  /** CloudEvents envelope metadata when the alert arrived by bus. */
  envelopeSource?: string;
  /** REST ingress idempotency key. */
  idempotencyKey?: string;
  /** Ingest wall-clock — `occurred_at` ±24 h tolerance anchor (§5.2). */
  receivedAt: Date;
}

export type AlertState = "open" | "acknowledged" | "resolved" | "suppressed";
export type IncidentState = "open" | "acknowledged" | "escalated" | "resolved" | "suppressed";
export type DedupVerdict = "new" | "duplicate" | "renotify";
export type AuthzStatus = "none" | "pending" | "verified" | "held" | "rejected";

export interface AlertRow {
  eventId: string;
  orgId: string;
  state: AlertState;
  effectiveSeverity: Severity;
  dedupVerdict: DedupVerdict;
  dedupDegraded: boolean;
  authzStatus: AuthzStatus;
  incidentId?: string;
}

export interface IncidentEscalation {
  policy_id?: string;
  current_step?: number;
  /** When the policy attached (step wait_seconds are cumulative from here). */
  attached_at?: string; // RFC 3339
  last_fired_at?: string; // RFC 3339
  next_fire_at?: string; // RFC 3339
  repeat_count?: number;
}

export interface Incident {
  incidentId: string;
  orgId: string;
  state: IncidentState;
  title: string;
  severity: Severity;
  category: Category;
  sourceModule: SourceModule;
  asset: AlertAsset;
  labels: Record<string, string>;
  correlationKey: string;
  alertCount: number;
  requiresAck: boolean;
  firstSeenAt: Date;
  lastSeenAt: Date;
  ack?: { by: string; at: string; note: string };
  escalation: IncidentEscalation;
  escalationExhausted: boolean;
}

export type Channel = "slack" | "teams" | "splunk-hec" | "syslog" | "webhook";
export const CHANNELS: readonly Channel[] = ["slack", "teams", "splunk-hec", "syslog", "webhook"];

export interface ChannelTarget {
  channel: Channel;
  destination: string;
  template?: string;
  mention?: string;
  /** §13.3: only targets flagged full receive unredacted evidence. */
  evidence_grade?: "full" | "redacted";
}

export interface RoutingMatch {
  severity_gte?: Severity;
  categories?: Category[];
  asset_criticality_gte?: AssetCriticality;
  source_modules?: SourceModule[];
  labels_any?: Record<string, string>;
}

export interface RoutingPolicy {
  policyId: string;
  orgId: string;
  priority: number;
  enabled: boolean;
  match: RoutingMatch;
  targets: ChannelTarget[];
  escalationPolicyId?: string;
  suppressIfAcknowledgedWithin?: number;
  createdBy: string;
  createdAt: Date;
}

export interface EscalationStep {
  step: number;
  wait_seconds: number;
  targets: ChannelTarget[];
}

export interface EscalationPolicy {
  policyId: string;
  orgId: string;
  steps: EscalationStep[];
  repeatLastStepEverySeconds: number;
  maxRepeats: number;
  stopOn: string[];
}

export type DeliveryStatus = "pending" | "sent" | "failed" | "dlq";
export type DeliveryUrgency = "low" | "normal" | "high" | "critical";

export interface Delivery {
  deliveryId: string;
  orgId: string;
  incidentId: string;
  alertIds: string[];
  channel: Channel;
  destination: string;
  template: string;
  urgency: DeliveryUrgency;
  status: DeliveryStatus;
  attemptCount: number;
  maxAttempts: number;
  idempotencyKey: string;
  escalationStep?: number;
  nextAttemptAt: Date;
  sentAt?: Date;
  error?: string;
}

export interface EgressEntry {
  channel: Channel;
  /** Exact host, host:port, "#slack-channel", or syslog "host:port" pattern. */
  pattern: string;
  /** §13.4: admin-flagged internal destinations bypass the SSRF private-range block. */
  internal?: boolean;
  evidence_grade?: "full" | "redacted";
  /** Reference name of the per-endpoint webhook secret (§13.5). */
  secret_ref?: string;
}

export interface AuditRecord {
  orgId: string;
  actor: { kind: "service" | "commander" | "user"; id: string };
  action:
    | "ingest"
    | "ingest_reject"
    | "dedup_suppress"
    | "correlate"
    | "route"
    | "deliver"
    | "deliver_failed"
    | "dlq"
    | "ack"
    | "escalate"
    | "resolve"
    | "policy_create"
    | "policy_update"
    | "egress_update"
    | "authz_reject"
    | "authz_hold"
    | "notify";
  entityIds: Record<string, string>;
  decisionDetail: Record<string, unknown>;
  requestHash: string;
}
