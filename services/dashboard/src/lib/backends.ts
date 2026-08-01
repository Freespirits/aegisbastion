// Typed server-side clients for the owning platform services (doc 10 §10 step
// 1: client façades before endpoints). Every call is made from a route
// handler or server component with the SESSION-derived identity injected as
// the platform identity header — never with a browser-supplied identity.
//
// Surfaces consumed (all verified against the running services):
//   gatekeeper admin REST :8080  /v1/roe*, /v1/approvals*, /v1/rbac/grants
//                                (protojson, snake_case; services/gatekeeper/internal/admin)
//   platform-core REST    :8081  /v1/missions*, /v1/roe/approve|revoke
//                                (X-Operator-Id identity; internal/missionapi/rest.go)
//   data-platform         :8082  POST /v1/query (GraphQL), POST /v1/findings/{id}/transitions
//                                (X-DP-Principal / X-DP-Tenant TPEL shim; internal/httpapi)
//   herald control API    :8083  /v1/policies/routing, /v1/routes/test, /v1/deliveries
//                                (doc 05 §4.1 — client only, Ruling C7)

import { env } from "@/env";
import { backendFetch } from "@/lib/http";
import type { Session } from "@/lib/session";

const JSON_HEADERS = { "content-type": "application/json" };

// ---------------------------------------------------------------------------
// gatekeeper (doc 11 — the single PDP; this dashboard decides nothing, Ruling B)
// ---------------------------------------------------------------------------

export const gatekeeper = {
  url(path: string): string {
    return `${env().gatekeeperUrl}${path}`;
  },
  listRoes(orgId: string, status?: string, pageToken?: string) {
    const q = new URLSearchParams({ org_id: orgId });
    if (status) q.set("status", status);
    if (pageToken) q.set("page_token", pageToken);
    return backendFetch("gatekeeper", this.url(`/v1/roe?${q}`));
  },
  getRoe(roeId: string) {
    return backendFetch("gatekeeper", this.url(`/v1/roe/${encodeURIComponent(roeId)}`));
  },
  createRoe(roe: Record<string, unknown>) {
    return backendFetch("gatekeeper", this.url("/v1/roe"), {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(roe),
    });
  },
  roeAction(roeId: string, action: "activate" | "suspend" | "revoke", body: unknown) {
    return backendFetch("gatekeeper", this.url(`/v1/roe/${encodeURIComponent(roeId)}/${action}`), {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body ?? {}),
    });
  },
  listApprovals(opts: { state?: string; roeId?: string; pageToken?: string }) {
    const q = new URLSearchParams();
    if (opts.state) q.set("state", opts.state);
    if (opts.roeId) q.set("roe_id", opts.roeId);
    if (opts.pageToken) q.set("page_token", opts.pageToken);
    const suffix = q.size ? `?${q}` : "";
    return backendFetch("gatekeeper", this.url(`/v1/approvals${suffix}`));
  },
  decideApproval(approvalId: string, decision: { approver: string; approved: boolean; note?: string }) {
    return backendFetch("gatekeeper", this.url(`/v1/approvals/${encodeURIComponent(approvalId)}/decide`), {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(decision),
    });
  },
  listRbacGrants(orgId: string) {
    return backendFetch("gatekeeper", this.url(`/v1/rbac/grants?org_id=${encodeURIComponent(orgId)}`));
  },
};

interface RbacBinding {
  // gatekeeper's admin REST serializes Go structs with capitalized keys.
  Principal?: string;
  Role?: string;
  RevokedAt?: string | null;
  ExpiresAt?: string | null;
  principal?: string;
  role?: string;
  revoked_at?: string | null;
  expires_at?: string | null;
}

/**
 * Resolve a principal's active gatekeeper roles (doc 11 §3.5). Returns null
 * when gatekeeper is unreachable — callers decide the fallback posture
 * (login falls back to configured dev roles; API routes fail closed).
 */
export async function resolveRoles(orgId: string, principalName: string): Promise<string[] | null> {
  try {
    const { res } = await gatekeeper.listRbacGrants(orgId);
    if (!res.ok) return null;
    const body = (await res.json()) as { bindings?: RbacBinding[] };
    const now = Date.now();
    const roles = new Set<string>();
    for (const b of body.bindings ?? []) {
      const principal = b.Principal ?? b.principal;
      const role = b.Role ?? b.role;
      const revokedAt = b.RevokedAt ?? b.revoked_at;
      const expiresAt = b.ExpiresAt ?? b.expires_at;
      if (principal !== principalName || !role) continue;
      if (revokedAt) continue;
      if (expiresAt && Date.parse(expiresAt) <= now) continue;
      roles.add(role);
    }
    return [...roles];
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// platform-core Mission API (doc 01 §7.3; X-Operator-Id identity shim)
// ---------------------------------------------------------------------------

function operatorHeaders(s: Session): Record<string, string> {
  return { ...JSON_HEADERS, "x-operator-id": s.sub };
}

export const platformCore = {
  url(path: string): string {
    return `${env().platformCoreUrl}${path}`;
  },
  createMission(s: Session, req: Record<string, unknown>) {
    return backendFetch("platform-core", this.url("/v1/missions"), {
      method: "POST",
      headers: operatorHeaders(s),
      body: JSON.stringify(req),
    });
  },
  getMission(s: Session, missionId: string) {
    return backendFetch("platform-core", this.url(`/v1/missions/${encodeURIComponent(missionId)}`), {
      headers: operatorHeaders(s),
    });
  },
  missionAction(s: Session, missionId: string, action: "pause" | "resume" | "kill", body?: unknown) {
    return backendFetch(
      "platform-core",
      this.url(`/v1/missions/${encodeURIComponent(missionId)}/${action}`),
      {
        method: "POST",
        headers: operatorHeaders(s),
        body: JSON.stringify(body ?? {}),
      },
    );
  },
  missionAudit(s: Session, missionId: string, afterSeq?: string) {
    const q = afterSeq ? `?after_seq=${encodeURIComponent(afterSeq)}` : "";
    return backendFetch(
      "platform-core",
      this.url(`/v1/missions/${encodeURIComponent(missionId)}/audit${q}`),
      { headers: operatorHeaders(s) },
    );
  },
};

// ---------------------------------------------------------------------------
// data-platform (doc 09 — system of record for assets/findings, Ruling C4)
// ---------------------------------------------------------------------------

function dpHeaders(s: Session): Record<string, string> {
  const h: Record<string, string> = { ...JSON_HEADERS, "x-dp-principal": s.sub };
  if (env().tenantId) h["x-dp-tenant"] = env().tenantId;
  return h;
}

export const dataPlatform = {
  url(path: string): string {
    return `${env().dataPlatformUrl}${path}`;
  },
  graphql(s: Session, query: string, variables?: Record<string, unknown>) {
    return backendFetch("data-platform", this.url("/v1/query"), {
      method: "POST",
      headers: dpHeaders(s),
      body: JSON.stringify({ query, variables: variables ?? {} }),
    });
  },
  findingTransition(s: Session, findingId: string, body: { to_state: string; note?: string; task_id?: string }) {
    return backendFetch(
      "data-platform",
      this.url(`/v1/findings/${encodeURIComponent(findingId)}/transitions`),
      { method: "POST", headers: dpHeaders(s), body: JSON.stringify(body) },
    );
  },
};

// ---------------------------------------------------------------------------
// herald (doc 05 §4.1 control API — alert-rules UI is a CLIENT ONLY; this
// module never dispatches a notification, Ruling C7)
//
// Policy mutations are herald:admin routes (doc 05 §13.7): herald reads the
// caller from the X-AegisBastion-Actor header and 403s anything not in
// HERALD_ADMIN_ACTORS. Forward the SESSION-derived principal (same rule as
// every backend here) — never a browser-supplied identity. The operator
// principal must additionally be listed in herald's HERALD_ADMIN_ACTORS at
// deploy time for mutations to pass.
// ---------------------------------------------------------------------------

function actorHeaders(s: Session): Record<string, string> {
  return { ...JSON_HEADERS, "x-aegisbastion-actor": s.sub };
}

export const herald = {
  url(path: string): string {
    return `${env().heraldUrl}${path}`;
  },
  listRoutingPolicies() {
    return backendFetch("herald", this.url("/v1/policies/routing"));
  },
  createRoutingPolicy(s: Session, policy: Record<string, unknown>) {
    return backendFetch("herald", this.url("/v1/policies/routing"), {
      method: "POST",
      headers: actorHeaders(s),
      body: JSON.stringify(policy),
    });
  },
  testRoute(sampleEvent: Record<string, unknown>) {
    return backendFetch("herald", this.url("/v1/routes/test"), {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(sampleEvent),
    });
  },
  deliveries(ruleId?: string) {
    const q = ruleId ? `?rule_id=${encodeURIComponent(ruleId)}` : "";
    return backendFetch("herald", this.url(`/v1/deliveries${q}`));
  },
};
