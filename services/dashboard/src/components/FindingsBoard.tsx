"use client";

import { useCallback, useEffect, useState } from "react";
import { api, ApiError, gql } from "@/lib/client";
import { FINDINGS_QUERY } from "@/lib/queries";
import {
  FINDING_STATES,
  FINDING_TRANSITIONS,
  type FindingState,
  type GqlFinding,
  type GqlPageInfo,
} from "@/lib/types";

interface FindingsData {
  findings: { nodes: GqlFinding[]; pageInfo: GqlPageInfo };
}

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];

function severityClass(sev: string): string {
  return `sev-${sev.toLowerCase()}`;
}

/**
 * Findings triage queue (doc 10 §1/§9: triage, state machine, severity/risk
 * display, evidence links). Reads via data-platform GraphQL; lifecycle
 * transitions via its REST mutation (doc 04 §7.3 edges enforced by 09).
 * Transition buttons are RBAC-gated (findings.triage affordance) — the dp API
 * re-enforces authoritatively (TPEL TransitionRoles).
 */
export function FindingsBoard({ capabilities }: { capabilities: string[] }) {
  const canTriage = capabilities.includes("findings.triage");
  const [severity, setSeverity] = useState("");
  const [state, setState] = useState("");
  const [findings, setFindings] = useState<GqlFinding[]>([]);
  const [pageInfo, setPageInfo] = useState<GqlPageInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<GqlFinding | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [note, setNote] = useState("");

  const load = useCallback(
    async (after?: string) => {
      setLoading(true);
      setError(null);
      try {
        const filter: Record<string, unknown> = {};
        if (severity) filter.severities = [severity];
        if (state) filter.states = [state];
        const data = await gql<FindingsData>(FINDINGS_QUERY, {
          filter: Object.keys(filter).length ? filter : null,
          first: 50,
          after: after ?? null,
        });
        setFindings(data.findings.nodes);
        setPageInfo(data.findings.pageInfo);
      } catch (err) {
        setError(
          err instanceof ApiError && err.status === 503
            ? "data-platform unavailable (503) — findings reads fail until it recovers (doc 10 §8)"
            : err instanceof Error
              ? err.message
              : String(err),
        );
      } finally {
        setLoading(false);
      }
    },
    [severity, state],
  );

  useEffect(() => {
    void load();
  }, [load]);

  async function transition(finding: GqlFinding, toState: FindingState) {
    setActionError(null);
    try {
      await api(`/api/findings/${encodeURIComponent(finding.findingId)}/transitions`, {
        method: "POST",
        body: { to_state: toState, ...(note.trim() ? { note: note.trim() } : {}) },
      });
      setNote("");
      setSelected(null);
      await load();
    } catch (err) {
      // doc 10 §4.4: problem+json reason codes are surfaced verbatim.
      setActionError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <>
      <div className="panel">
        <div className="form-row">
          <label className="field">
            Severity
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s || "all"}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Lifecycle state
            <select value={state} onChange={(e) => setState(e.target.value)}>
              <option value="">all</option>
              {FINDING_STATES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
        </div>
        {error ? (
          <div className="error-box" role="alert">
            {error}
          </div>
        ) : null}
        {loading ? (
          <div className="muted small">loading findings…</div>
        ) : (
          <>
            <table className="data" aria-label="findings">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Module</th>
                  <th>State</th>
                  <th>Occurrences</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr
                    key={f.findingId}
                    className={selected?.findingId === f.findingId ? "selected" : ""}
                    onClick={() => {
                      setSelected(f);
                      setActionError(null);
                    }}
                  >
                    <td className={severityClass(f.severity)}>{f.severity}</td>
                    <td>{f.title}</td>
                    <td>{f.module}</td>
                    <td>
                      <span className="pill">{f.state}</span>
                    </td>
                    <td>{f.occurrence}</td>
                    <td className="muted small">{new Date(f.lastSeen).toLocaleString()}</td>
                  </tr>
                ))}
                {findings.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="muted">
                      no findings match the filter
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
            <div className="spread mt">
              <span className="muted small">
                {pageInfo ? `${pageInfo.totalCount} findings in this tenant` : ""}
              </span>
              {pageInfo?.hasNextPage && pageInfo.endCursor ? (
                <button type="button" onClick={() => void load(pageInfo.endCursor ?? undefined)}>
                  next page
                </button>
              ) : null}
            </div>
          </>
        )}
      </div>

      {selected ? (
        <div className="panel" data-testid="finding-detail">
          <div className="spread">
            <h3>{selected.title}</h3>
            <button type="button" onClick={() => setSelected(null)}>
              close
            </button>
          </div>
          <dl className="kv">
            <dt>finding id</dt>
            <dd className="mono">{selected.findingId}</dd>
            <dt>severity / state</dt>
            <dd>
              <span className={severityClass(selected.severity)}>{selected.severity}</span> ·{" "}
              <span className="pill">{selected.state}</span>
              {selected.sensitive ? <span className="pill warn">sensitive</span> : null}
            </dd>
            <dt>asset</dt>
            <dd className="mono">{selected.assetUid}</dd>
            <dt>module / check</dt>
            <dd className="mono">
              {selected.module} / {selected.checkId}
            </dd>
            <dt>validation</dt>
            <dd className="mono small">{JSON.stringify(selected.validation)}</dd>
            <dt>risk</dt>
            <dd className="mono small">{JSON.stringify(selected.risk)}</dd>
            <dt>evidence</dt>
            <dd className="mono small">
              {selected.sensitive
                ? "classified digest only — raw evidence is sealed per-tenant by 09 and double-audited (doc 10 §7.3)"
                : (selected.evidenceRef ?? "—")}
            </dd>
            <dt>task</dt>
            <dd className="mono">{selected.taskId ?? "—"}</dd>
          </dl>

          <h3 className="mt">Lifecycle history (doc 04 §7.3)</h3>
          {selected.transitions.length ? (
            <table className="data">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Transition</th>
                  <th>Actor</th>
                  <th>Note</th>
                </tr>
              </thead>
              <tbody>
                {selected.transitions.map((t, i) => (
                  <tr key={i} style={{ cursor: "default" }}>
                    <td className="muted small">{new Date(t.ts).toLocaleString()}</td>
                    <td className="mono small">
                      {t.fromState ?? "∅"} → {t.toState}
                    </td>
                    <td className="mono small">{JSON.stringify(t.actor)}</td>
                    <td className="small">{t.note ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="muted small">no transitions recorded</p>
          )}

          <h3 className="mt">Transition</h3>
          {!canTriage ? (
            <p className="muted small" data-testid="triage-denied">
              your roles ({capabilities.includes("read") ? "read-only" : "none"}) do not include the
              findings.triage affordance — ask a platform-admin for the operator role (gatekeeper
              rbac-service)
            </p>
          ) : null}
          <label className="field">
            Note (optional)
            <input value={note} onChange={(e) => setNote(e.target.value)} disabled={!canTriage} />
          </label>
          <div className="row">
            {(FINDING_TRANSITIONS[selected.state] ?? []).map((to) => (
              <button
                key={to}
                type="button"
                disabled={!canTriage}
                title={canTriage ? `transition to ${to}` : "requires the findings.triage affordance"}
                onClick={() => void transition(selected, to)}
              >
                → {to}
              </button>
            ))}
            {(FINDING_TRANSITIONS[selected.state] ?? []).length === 0 ? (
              <span className="muted small">terminal state — no outgoing transitions</span>
            ) : null}
          </div>
          {actionError ? (
            <div className="error-box mt" role="alert">
              {actionError}
            </div>
          ) : null}
        </div>
      ) : null}
    </>
  );
}
