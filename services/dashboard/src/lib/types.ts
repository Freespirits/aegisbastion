// Shared wire types (subset of the owning services' contracts, used by the
// UI). Field names match what the services actually emit:
//   - gatekeeper admin-api: protojson with UseProtoNames (snake_case)
//   - data-platform GraphQL: camelCase per internal/queryapi/schema.graphqls

// --- gatekeeper (doc 11 §3.1, protojson snake_case) -------------------------

export interface Roe {
  roe_id: string;
  org_id: string;
  name: string;
  status: string; // ROE_STATUS_*
  created_by: string;
  scope?: {
    asset_group_ids?: string[];
    domains?: string[];
    cidrs?: string[];
    cloud_accounts?: string[];
    explicit_excludes?: string[];
  };
  constraints?: {
    max_risk_class?: string; // RISK_CLASS_R*
    allowed_capabilities?: string[];
    rate_caps?: Record<string, { rps?: number; max_concurrent?: number }>;
    blackout_windows?: { rrule: string; tz: string }[];
    requires_approval_for?: string[];
  };
  valid_from?: string;
  valid_until?: string;
  version?: string; // uint64 → protojson string
  updated_at?: string;
}

export interface Approval {
  approval_id: string;
  roe_id: string;
  roe_version?: string;
  capability: string;
  risk_class?: string;
  targets?: string[];
  requester: string;
  state: string; // APPROVAL_STATE_*
  decisions?: { approver: string; approved: boolean; at?: string; note?: string }[];
  created_at?: string;
  expires_at?: string;
}

// --- platform-core (doc 01 §5.1, protojson) ---------------------------------

export interface Mission {
  mission_id: string;
  name: string;
  owning_commander?: string; // COMMANDER_*
  objective: string;
  roe_id: string;
  roe_version?: string;
  priority?: string;
  labels?: Record<string, string>;
  created_by?: string;
  created_at?: string;
  state?: string; // MISSION_STATE_*
}

// --- data-platform GraphQL (doc 09 §5, camelCase) ---------------------------

export interface GqlPageInfo {
  hasNextPage: boolean;
  endCursor: string | null;
  totalCount: number;
}

export interface GqlAsset {
  uid: string;
  type: string;
  value: string;
  attributes: unknown;
  confidence: number;
  status: string;
  firstSeen: string;
  lastSeen: string;
  roeId: string;
}

export interface GqlEdge {
  edgeId: string;
  src: string;
  dst: string;
  rel: string;
  firstSeen: string;
  lastSeen: string;
}

export interface GqlFinding {
  findingId: string;
  assetUid: string;
  module: string;
  checkId: string;
  title: string;
  severity: string;
  state: string;
  validation: unknown;
  risk: unknown;
  evidenceRef: string | null;
  occurrence: number;
  firstSeen: string;
  lastSeen: string;
  taskId: string | null;
  sensitive: boolean;
  createdAt: string;
  updatedAt: string;
  transitions: {
    fromState: string | null;
    toState: string;
    actor: unknown;
    note: string | null;
    ts: string;
  }[];
}

export interface GraphQLResponse<T> {
  data?: T;
  errors?: { message: string }[];
}

// --- doc 04 §7.3 lifecycle state machine, persisted by 09 -------------------
// (mirrors services/data-platform/internal/lifecycle; the dp API enforces the
// edges authoritatively — this map only drives which transition buttons render)

export const FINDING_STATES = [
  "new",
  "triaged",
  "validating",
  "confirmed_open",
  "remediation_claimed",
  "verified_closed",
  "false_positive",
  "accepted_risk",
  "reopened",
] as const;

export type FindingState = (typeof FINDING_STATES)[number];

export const FINDING_TRANSITIONS: Record<string, FindingState[]> = {
  new: ["triaged"],
  triaged: ["validating", "false_positive"],
  validating: ["confirmed_open", "accepted_risk"],
  confirmed_open: ["remediation_claimed"],
  remediation_claimed: ["verified_closed", "reopened"],
  reopened: ["confirmed_open"],
  verified_closed: [],
  false_positive: [],
  accepted_risk: [],
};
