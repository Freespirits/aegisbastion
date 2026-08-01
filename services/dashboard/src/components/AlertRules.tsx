"use client";

import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "@/lib/client";

interface RoutingPolicy {
  policy_id?: string;
  org_id?: string;
  priority?: number;
  enabled?: boolean;
  match?: Record<string, unknown>;
  targets?: { channel: string; destination: string; template?: string }[];
  escalation_policy_id?: string;
  created_by?: string;
}

/**
 * Alert-rules UI — a CLIENT of herald's (doc 05) control API only (Ruling C7:
 * this module never dispatches a notification; herald owns routing, delivery,
 * signing, retry/DLQ end-to-end). List/create routing policies, dry-run a
 * route, render herald's delivery log.
 */
export function AlertRules({ capabilities, orgId }: { capabilities: string[]; orgId: string }) {
  const canManage = capabilities.includes("alert-rules.manage");
  const [policies, setPolicies] = useState<RoutingPolicy[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [severityGte, setSeverityGte] = useState("high");
  const [channel, setChannel] = useState("slack");
  const [destination, setDestination] = useState("#sec-critical");
  const [priority, setPriority] = useState("100");
  const [createError, setCreateError] = useState<string | null>(null);

  const [testJson, setTestJson] = useState(
    JSON.stringify(
      {
        specversion: "1.0",
        id: "evt_test",
        source: "//aegisbastion/detect",
        type: "com.aegisbastion.alert.v1",
        data: { severity: "high", category: "vuln", title: "route test" },
      },
      null,
      2,
    ),
  );
  const [testResult, setTestResult] = useState<string | null>(null);

  const [deliveries, setDeliveries] = useState<unknown[] | null>(null);
  const [deliveriesError, setDeliveriesError] = useState<string | null>(null);

  const heraldDown = (err: unknown) =>
    err instanceof ApiError && err.status === 503
      ? "herald unavailable — alert-rules are read from its control API (doc 05 §4.1); retry later"
      : err instanceof Error
        ? err.message
        : String(err);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api<RoutingPolicy[] | { policies?: RoutingPolicy[] }>("/api/alert-rules");
      setPolicies(Array.isArray(res) ? res : (res.policies ?? []));
    } catch (err) {
      setError(heraldDown(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function create() {
    setCreateError(null);
    try {
      await api("/api/alert-rules", {
        method: "POST",
        body: {
          org_id: orgId,
          priority: Number(priority) || 100,
          enabled: true,
          match: { severity_gte: severityGte },
          targets: [{ channel, destination }],
        },
      });
      await load();
    } catch (err) {
      setCreateError(heraldDown(err));
    }
  }

  async function testRoute() {
    setTestResult(null);
    try {
      const sample = JSON.parse(testJson) as Record<string, unknown>;
      const res = await api("/api/alert-rules/test", { method: "POST", body: sample });
      setTestResult(JSON.stringify(res, null, 2));
    } catch (err) {
      setTestResult(heraldDown(err));
    }
  }

  async function loadDeliveries() {
    setDeliveriesError(null);
    try {
      const res = await api<unknown[] | { deliveries?: unknown[] }>("/api/alert-rules/deliveries");
      setDeliveries(Array.isArray(res) ? res : (res.deliveries ?? []));
    } catch (err) {
      setDeliveriesError(heraldDown(err));
    }
  }

  return (
    <>
      <div className="panel">
        <h3>Routing policies (herald control API)</h3>
        {error ? (
          <div className="error-box" role="alert">
            {error}
          </div>
        ) : loading ? (
          <div className="muted small">loading policies…</div>
        ) : (
          <table className="data" aria-label="routing policies">
            <thead>
              <tr>
                <th>Policy</th>
                <th>Priority</th>
                <th>Enabled</th>
                <th>Match</th>
                <th>Targets</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p, i) => (
                <tr key={p.policy_id ?? i} style={{ cursor: "default" }}>
                  <td className="mono small">{p.policy_id ?? "—"}</td>
                  <td>{p.priority ?? "—"}</td>
                  <td>{p.enabled === false ? "no" : "yes"}</td>
                  <td className="mono small">{JSON.stringify(p.match ?? {})}</td>
                  <td className="mono small">
                    {(p.targets ?? []).map((t) => `${t.channel}:${t.destination}`).join(", ")}
                  </td>
                </tr>
              ))}
              {policies.length === 0 ? (
                <tr>
                  <td colSpan={5} className="muted">
                    no routing policies
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        )}
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <h3>New routing policy</h3>
          {!canManage ? (
            <p className="muted small" data-testid="alert-rules-denied">
              your roles do not include the alert-rules.manage affordance.
            </p>
          ) : (
            <>
              <div className="form-row">
                <label className="field">
                  Severity floor
                  <select value={severityGte} onChange={(e) => setSeverityGte(e.target.value)}>
                    {["critical", "high", "medium", "low", "info"].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  Priority
                  <input value={priority} onChange={(e) => setPriority(e.target.value)} />
                </label>
              </div>
              <div className="form-row">
                <label className="field">
                  Channel
                  <select value={channel} onChange={(e) => setChannel(e.target.value)}>
                    <option value="slack">slack</option>
                    <option value="webhook">webhook (generic signed)</option>
                  </select>
                </label>
                <label className="field">
                  Destination
                  <input value={destination} onChange={(e) => setDestination(e.target.value)} />
                </label>
              </div>
              {createError ? (
                <div className="error-box mb" role="alert">
                  {createError}
                </div>
              ) : null}
              <button type="button" className="primary" onClick={() => void create()}>
                create policy
              </button>
              <p className="muted small mt">
                Delivery, HMAC signing, SSRF guards, retry/DLQ: herald&apos;s domain (doc 05
                §6/§13.4) — never this module&apos;s (Ruling C7).
              </p>
            </>
          )}
        </div>

        <div className="panel">
          <h3>Route dry-run (no delivery)</h3>
          <label className="field">
            Sample AlertEvent v1 (JSON)
            <textarea rows={8} className="mono" value={testJson} onChange={(e) => setTestJson(e.target.value)} />
          </label>
          <button type="button" onClick={() => void testRoute()} disabled={!canManage}>
            test route
          </button>
          {testResult ? <pre className="small mono mt">{testResult}</pre> : null}
        </div>
      </div>

      <div className="panel">
        <div className="spread">
          <h3 style={{ margin: 0 }}>Delivery log (herald data)</h3>
          <button type="button" onClick={() => void loadDeliveries()}>
            load deliveries
          </button>
        </div>
        {deliveriesError ? (
          <div className="error-box mt" role="alert">
            {deliveriesError}
          </div>
        ) : deliveries ? (
          <pre className="small mono mt">{JSON.stringify(deliveries, null, 2)}</pre>
        ) : (
          <p className="muted small mt">not loaded</p>
        )}
      </div>
    </>
  );
}
