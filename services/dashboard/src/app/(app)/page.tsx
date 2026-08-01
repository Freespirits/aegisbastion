import { StatusPills } from "@/components/StatusPills";
import { getSession } from "@/lib/session";
import { capabilitiesOf } from "@/lib/roles";

export default async function OverviewPage() {
  const session = await getSession();
  const caps = session ? [...capabilitiesOf(session.roles)] : [];
  return (
    <>
      <h1 className="page-title">Overview</h1>
      <p className="page-sub">
        Platform status and your effective workspace affordances. Authorization decisions are
        gatekeeper&apos;s (Ruling B) — this console renders and enforces its gates, it never
        decides.
      </p>

      <div className="panel">
        <h3>Backend status</h3>
        <StatusPills />
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <h3>Session</h3>
          <dl className="kv">
            <dt>Principal</dt>
            <dd className="mono">{session?.sub}</dd>
            <dt>Org</dt>
            <dd className="mono">{session?.orgId}</dd>
            <dt>Gatekeeper roles</dt>
            <dd>{session?.roles.length ? session.roles.join(", ") : "none (read-only)"}</dd>
            <dt>Affordances</dt>
            <dd>{caps.join(", ")}</dd>
          </dl>
          <p className="muted small mt">
            Roles are assigned by gatekeeper rbac-service (doc 11 §3.5) and re-resolved at login;
            the dashboard stores no role data locally (doc 10 §7.2).
          </p>
        </div>
        <div className="panel">
          <h3>The gate, made visible</h3>
          <p className="small">
            Task launch path (doc 10 §2.2 Flow B): dashboard → Mission API → dispatch PEP →
            gatekeeper policy-service (hard-coded pipeline: RoE active → scope (exclusions win) →
            capability/risk class → legal artifact → four-eyes → blackout windows →
            jurisdiction/data class → rate caps → audit). A denial returns gatekeeper&apos;s
            machine-readable reason codes verbatim.
          </p>
          <p className="small muted">
            Sensitive actions (RoE create/revoke, offensive approvals, launches, mission
            resume/kill) require a ≤5-min step-up assertion (doc 10 §7.2; placeholder ceremony at
            MVP-A).
          </p>
        </div>
      </div>
    </>
  );
}
