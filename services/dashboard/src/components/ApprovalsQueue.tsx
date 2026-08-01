"use client";

import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "@/lib/client";
import { StepUpGate } from "@/components/StepUpGate";
import type { Approval } from "@/lib/types";

/**
 * Plan-approval queue (doc 10 §3.2/§9): pending four-eyes approvals from
 * gatekeeper approval-service (doc 11 §2.1.8). Plans containing offensive
 * steps cannot be approved without gatekeeper recording the approval against
 * a valid RoE covering every target — the decide call enforces SoD
 * (approver ≠ author ≠ requester, two distinct approvers for GRANTED).
 * Deciding is step-up gated (doc 10 §7.2).
 */
export function ApprovalsQueue({
  capabilities,
  principal,
}: {
  capabilities: string[];
  principal: string;
}) {
  const canDecide = capabilities.includes("roe.approve");
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [stateFilter, setStateFilter] = useState("pending");
  const [actionError, setActionError] = useState<Record<string, string>>({});
  const [notes, setNotes] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const q = stateFilter ? `?state=${encodeURIComponent(stateFilter)}` : "";
      const res = await api<{ approvals?: Approval[] }>(`/api/approvals${q}`);
      setApprovals(res.approvals ?? []);
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 503
          ? "gatekeeper unavailable — approvals fail closed (doc 10 §8)"
          : err instanceof Error
            ? err.message
            : String(err),
      );
    } finally {
      setLoading(false);
    }
  }, [stateFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  async function decide(a: Approval, approved: boolean) {
    setActionError((prev) => ({ ...prev, [a.approval_id]: "" }));
    try {
      await api(`/api/approvals/${encodeURIComponent(a.approval_id)}/decide`, {
        method: "POST",
        body: { approved, ...(notes[a.approval_id]?.trim() ? { note: notes[a.approval_id].trim() } : {}) },
      });
      await load();
    } catch (err) {
      // SoD violations come back from gatekeeper verbatim (e.g. approver is
      // the RoE author or the requester, or a duplicate approver).
      setActionError((prev) => ({
        ...prev,
        [a.approval_id]: err instanceof Error ? err.message : String(err),
      }));
    }
  }

  return (
    <div className="panel">
      <div className="spread mb">
        <h3 style={{ margin: 0 }}>Four-eyes approval queue (gatekeeper approval-service)</h3>
        <label className="field" style={{ margin: 0, minWidth: 160 }}>
          State
          <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
            <option value="pending">pending</option>
            <option value="granted">granted</option>
            <option value="rejected">rejected</option>
            <option value="expired">expired</option>
            <option value="">all</option>
          </select>
        </label>
      </div>
      {error ? (
        <div className="error-box" role="alert">
          {error}
        </div>
      ) : loading ? (
        <div className="muted small">loading approvals…</div>
      ) : (
        <table className="data" aria-label="approvals">
          <thead>
            <tr>
              <th>Approval</th>
              <th>Capability / risk</th>
              <th>Targets</th>
              <th>Requester</th>
              <th>Votes</th>
              <th>Expires</th>
              <th>Decide</th>
            </tr>
          </thead>
          <tbody>
            {approvals.map((a) => {
              const grants = (a.decisions ?? []).filter((d) => d.approved).length;
              const isRequester = a.requester === principal;
              return (
                <tr key={a.approval_id} style={{ cursor: "default" }}>
                  <td>
                    <span className="mono small">{a.approval_id}</span>
                    <div className="muted small mono">roe {a.roe_id} v{a.roe_version ?? "?"}</div>
                    <span className="pill">{a.state.replace("APPROVAL_STATE_", "")}</span>
                  </td>
                  <td>
                    <span className="mono small">{a.capability}</span>
                    <div className="small">{(a.risk_class ?? "").replace("RISK_CLASS_", "")}</div>
                  </td>
                  <td className="mono small">{(a.targets ?? []).join(", ")}</td>
                  <td className="mono small">
                    {a.requester}
                    {isRequester ? <div className="pill warn">you — SoD bars your vote</div> : null}
                  </td>
                  <td>
                    {grants}/2 distinct
                    <div className="muted small">
                      {(a.decisions ?? []).map((d) => `${d.approver}:${d.approved ? "✓" : "✗"}`).join(" ")}
                    </div>
                  </td>
                  <td className="muted small">
                    {a.expires_at ? new Date(a.expires_at).toLocaleString() : "—"}
                  </td>
                  <td>
                    {a.state === "APPROVAL_STATE_PENDING" && canDecide ? (
                      <div className="row">
                        <input
                          style={{ minWidth: 120 }}
                          placeholder="note"
                          value={notes[a.approval_id] ?? ""}
                          onChange={(e) =>
                            setNotes((prev) => ({ ...prev, [a.approval_id]: e.target.value }))
                          }
                        />
                        <StepUpGate action={() => decide(a, true)}>
                          {(trigger) => (
                            <button type="button" disabled={isRequester} onClick={trigger}>
                              approve
                            </button>
                          )}
                        </StepUpGate>
                        <StepUpGate action={() => decide(a, false)}>
                          {(trigger) => (
                            <button type="button" className="danger" onClick={trigger}>
                              reject
                            </button>
                          )}
                        </StepUpGate>
                      </div>
                    ) : a.state === "APPROVAL_STATE_PENDING" ? (
                      <span className="muted small" data-testid="decide-denied">
                        offensive-approver role required
                      </span>
                    ) : (
                      <span className="muted small">—</span>
                    )}
                    {actionError[a.approval_id] ? (
                      <div className="error-box mt small" role="alert">
                        {actionError[a.approval_id]}
                      </div>
                    ) : null}
                  </td>
                </tr>
              );
            })}
            {approvals.length === 0 ? (
              <tr>
                <td colSpan={7} className="muted">
                  no approvals in this state
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      )}
      <p className="muted small mt">
        Approvals expire 72 h after creation and bind to a target superset; executed targets must be
        a subset (doc 11 §3.3 step 7). Two DISTINCT offensive-approver grants are required for
        GRANTED.
      </p>
    </div>
  );
}
