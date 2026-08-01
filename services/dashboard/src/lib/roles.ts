// Role → workspace-affordance mapping (doc 10 §7.2). The roles themselves are
// owned and enforced by gatekeeper rbac-service (doc 11 §3.5); this module only
// maps them onto UI affordances and stores nothing locally. Server-side API
// routes re-check these mappings as defense in depth — the authoritative
// enforcement is always downstream (gatekeeper/policy pipeline, dp TPEL).

/** Gatekeeper's eight seeded roles (doc 11 §3.5). */
export const GATEKEEPER_ROLES = [
  "platform-admin",
  "grc-verifier",
  "roe-author",
  "offensive-approver",
  "commander-svc",
  "module-svc",
  "auditor",
  "operator",
] as const;

export type GatekeeperRole = (typeof GATEKEEPER_ROLES)[number];

/** Workspace affordances the UI and BFF gate on. */
export type Capability =
  | "read" // assets, findings, missions, RoE metadata — any authenticated user
  | "findings.triage" // finding lifecycle transitions
  | "tasks.launch" // gated task/mission launch via the Mission API
  | "missions.control" // pause/resume/kill
  | "roe.author" // create RoE drafts
  | "roe.approve" // approve/activate/suspend/revoke RoE, decide approvals
  | "audit.view" // audit-trail viewers
  | "alert-rules.manage"; // herald routing-policy CRUD (client only, Ruling C7)

const ROLE_CAPS: Record<string, Capability[]> = {
  "platform-admin": [
    "read",
    "findings.triage",
    "tasks.launch",
    "missions.control",
    "roe.author",
    "roe.approve",
    "audit.view",
    "alert-rules.manage",
  ],
  operator: ["read", "findings.triage", "tasks.launch", "missions.control", "alert-rules.manage"],
  "roe-author": ["read", "roe.author"],
  "offensive-approver": ["read", "roe.approve"],
  "grc-verifier": ["read", "roe.approve"],
  auditor: ["read", "audit.view"],
  "commander-svc": ["read"],
  "module-svc": ["read"],
};

/** Union of capabilities granted by a set of gatekeeper roles. */
export function capabilitiesOf(roles: string[]): Set<Capability> {
  const out = new Set<Capability>(["read"]);
  for (const r of roles) {
    for (const c of ROLE_CAPS[r] ?? []) out.add(c);
  }
  return out;
}

export function hasCapability(roles: string[], cap: Capability): boolean {
  return capabilitiesOf(roles).has(cap);
}
