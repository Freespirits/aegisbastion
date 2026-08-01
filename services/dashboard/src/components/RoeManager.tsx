"use client";

import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "@/lib/client";
import { StepUpGate } from "@/components/StepUpGate";
import type { Roe } from "@/lib/types";

function statusPill(status: string): string {
  switch (status) {
    case "ROE_STATUS_ACTIVE":
      return "pill ok";
    case "ROE_STATUS_PENDING_APPROVAL":
    case "ROE_STATUS_SUSPENDED":
      return "pill warn";
    case "ROE_STATUS_REVOKED":
    case "ROE_STATUS_EXPIRED":
      return "pill crit";
    default:
      return "pill";
  }
}

const RISK_CLASSES = [
  "RISK_CLASS_R0",
  "RISK_CLASS_R1",
  "RISK_CLASS_R2",
  "RISK_CLASS_R3",
] as const;

/**
 * RoE management (doc 10 §9: create/revoke via gatekeeper admin-api including
 * the preflight dry-run scope checker). NO local RoE storage (Ruling B) —
 * every read/write is a gatekeeper call. Create + lifecycle actions are
 * step-up gated (doc 10 §7.2); records permitting R2/R3 require a verified
 * legal artifact (Ruling B.4) which roe-service enforces at activation.
 */
export function RoeManager({ capabilities }: { capabilities: string[] }) {
  const canAuthor = capabilities.includes("roe.author");
  const canApprove = capabilities.includes("roe.approve");
  const [roes, setRoes] = useState<Roe[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Roe | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [reason, setReason] = useState("");

  // create form
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [validFrom, setValidFrom] = useState("");
  const [validUntil, setValidUntil] = useState("");
  const [domains, setDomains] = useState("");
  const [cidrs, setCidrs] = useState("");
  const [excludes, setExcludes] = useState("");
  const [maxRisk, setMaxRisk] = useState<(typeof RISK_CLASSES)[number]>("RISK_CLASS_R1");
  const [capabilities_, setCapabilities_] = useState("");
  const [legalKind, setLegalKind] = useState("");
  const [legalHash, setLegalHash] = useState("");
  const [legalUri, setLegalUri] = useState("");
  const [legalVerifier, setLegalVerifier] = useState("");

  const needsLegal = maxRisk === "RISK_CLASS_R2" || maxRisk === "RISK_CLASS_R3";

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api<{ roes?: Roe[] }>("/api/roe");
      setRoes(res.roes ?? []);
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 503
          ? "gatekeeper unavailable — RoE operations fail closed (doc 10 §8)"
          : err instanceof Error
            ? err.message
            : String(err),
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function create() {
    setActionError(null);
    const split = (s: string) =>
      s
        .split(/[\n,]+/)
        .map((x) => x.trim())
        .filter(Boolean);
    const roe: Record<string, unknown> = {
      name: name.trim(),
      scope: {
        domains: split(domains),
        cidrs: split(cidrs),
        explicit_excludes: split(excludes),
      },
      constraints: {
        max_risk_class: maxRisk,
        allowed_capabilities: split(capabilities_),
      },
    };
    if (validFrom) roe.valid_from = new Date(validFrom).toISOString();
    if (validUntil) roe.valid_until = new Date(validUntil).toISOString();
    if (needsLegal) {
      roe.legal_artifact = {
        kind: legalKind.trim(),
        document_sha256: legalHash.trim(),
        storage_uri: legalUri.trim(),
        verified_by: legalVerifier.trim(),
      };
    }
    try {
      await api("/api/roe", { method: "POST", body: roe });
      setShowCreate(false);
      setName("");
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    }
  }

  async function action(roe: Roe, act: "activate" | "suspend" | "revoke") {
    setActionError(null);
    const body =
      act === "activate"
        ? { version: Number(roe.version ?? "1") }
        : { reason: reason || `${act} from dashboard` };
    try {
      await api(`/api/roe/${encodeURIComponent(roe.roe_id)}/${act}`, { method: "POST", body });
      setReason("");
      await load();
      const refreshed = await api<{ roe: Roe }>(`/api/roe/${encodeURIComponent(roe.roe_id)}`);
      setSelected(refreshed.roe);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <>
      <div className="panel">
        <div className="spread mb">
          <h3 style={{ margin: 0 }}>Rules of Engagement (gatekeeper roe-service)</h3>
          {canAuthor ? (
            <button type="button" onClick={() => setShowCreate((v) => !v)}>
              {showCreate ? "hide create form" : "new RoE draft"}
            </button>
          ) : (
            <span className="muted small" data-testid="author-denied">
              roe-author role required to create
            </span>
          )}
        </div>

        {showCreate && canAuthor ? (
          <div className="panel" style={{ background: "var(--bg-raised)" }}>
            <h3>Create RoE draft (step-up required)</h3>
            <div className="form-row">
              <label className="field">
                Engagement name
                <input value={name} onChange={(e) => setName(e.target.value)} />
              </label>
              <label className="field">
                Max risk class (doc 01 §5.3)
                <select value={maxRisk} onChange={(e) => setMaxRisk(e.target.value as typeof maxRisk)}>
                  {RISK_CLASSES.map((r) => (
                    <option key={r} value={r}>
                      {r.replace("RISK_CLASS_", "")}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="form-row">
              <label className="field">
                Valid from (UTC)
                <input type="datetime-local" value={validFrom} onChange={(e) => setValidFrom(e.target.value)} />
              </label>
              <label className="field">
                Valid until (≤ 90 days from start)
                <input type="datetime-local" value={validUntil} onChange={(e) => setValidUntil(e.target.value)} />
              </label>
            </div>
            <div className="form-row">
              <label className="field">
                Scope domains (one per line)
                <textarea rows={2} value={domains} onChange={(e) => setDomains(e.target.value)} placeholder={"acme.com\n*.acme.com"} />
              </label>
              <label className="field">
                Scope CIDRs
                <textarea rows={2} value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder="203.0.113.0/24" />
              </label>
              <label className="field">
                Explicit excludes (ALWAYS win)
                <textarea rows={2} value={excludes} onChange={(e) => setExcludes(e.target.value)} placeholder="prod-db.acme.com" />
              </label>
            </div>
            <label className="field">
              Allowed capabilities (one per line, e.g. detect.scan.web, monitor.watch)
              <textarea rows={2} value={capabilities_} onChange={(e) => setCapabilities_(e.target.value)} />
            </label>
            {needsLegal ? (
              <>
                <div className="banner">
                  R2/R3 requires a signed legal artifact verified by a grc-verifier (Ruling B.4);
                  roe-service refuses activation without it.
                </div>
                <div className="form-row">
                  <label className="field">
                    Artifact kind
                    <input value={legalKind} onChange={(e) => setLegalKind(e.target.value)} placeholder="signed_loa" />
                  </label>
                  <label className="field">
                    Document SHA-256 (hex)
                    <input value={legalHash} onChange={(e) => setLegalHash(e.target.value)} />
                  </label>
                </div>
                <div className="form-row">
                  <label className="field">
                    Immutable storage URI
                    <input value={legalUri} onChange={(e) => setLegalUri(e.target.value)} placeholder="blob://immutable/legal/acme-loa.pdf" />
                  </label>
                  <label className="field">
                    Verified by (grc-verifier identity)
                    <input value={legalVerifier} onChange={(e) => setLegalVerifier(e.target.value)} />
                  </label>
                </div>
              </>
            ) : null}
            {actionError ? (
              <div className="error-box mb" role="alert">
                {actionError}
              </div>
            ) : null}
            <StepUpGate action={create}>
              {(trigger) => (
                <button className="primary" type="button" disabled={!name.trim()} onClick={trigger}>
                  create draft
                </button>
              )}
            </StepUpGate>
          </div>
        ) : null}

        {error ? (
          <div className="error-box" role="alert">
            {error}
          </div>
        ) : loading ? (
          <div className="muted small">loading RoEs…</div>
        ) : (
          <table className="data" aria-label="rules of engagement">
            <thead>
              <tr>
                <th>Name</th>
                <th>Status</th>
                <th>Max risk</th>
                <th>Window</th>
                <th>Version</th>
              </tr>
            </thead>
            <tbody>
              {roes.map((r) => (
                <tr
                  key={r.roe_id}
                  className={selected?.roe_id === r.roe_id ? "selected" : ""}
                  onClick={() => {
                    setSelected(r);
                    setActionError(null);
                  }}
                >
                  <td>
                    {r.name}
                    <div className="muted small mono">{r.roe_id}</div>
                  </td>
                  <td>
                    <span className={statusPill(r.status)}>{r.status.replace("ROE_STATUS_", "")}</span>
                  </td>
                  <td>{r.constraints?.max_risk_class?.replace("RISK_CLASS_", "") ?? "?"}</td>
                  <td className="muted small">
                    {r.valid_from ? new Date(r.valid_from).toLocaleDateString() : "?"} →{" "}
                    {r.valid_until ? new Date(r.valid_until).toLocaleDateString() : "?"}
                  </td>
                  <td className="mono">{r.version ?? "1"}</td>
                </tr>
              ))}
              {roes.length === 0 ? (
                <tr>
                  <td colSpan={5} className="muted">
                    no RoE records in this org
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        )}
      </div>

      {selected ? (
        <div className="panel" data-testid="roe-detail">
          <div className="spread">
            <h3>
              {selected.name}{" "}
              <span className={statusPill(selected.status)}>{selected.status.replace("ROE_STATUS_", "")}</span>
            </h3>
            <button type="button" onClick={() => setSelected(null)}>
              close
            </button>
          </div>
          <dl className="kv">
            <dt>roe id</dt>
            <dd className="mono">{selected.roe_id}</dd>
            <dt>scope domains</dt>
            <dd className="mono small">{(selected.scope?.domains ?? []).join(", ") || "—"}</dd>
            <dt>scope cidrs</dt>
            <dd className="mono small">{(selected.scope?.cidrs ?? []).join(", ") || "—"}</dd>
            <dt>explicit excludes</dt>
            <dd className="mono small">{selected.scope?.explicit_excludes?.join(", ") || "—"}</dd>
            <dt>capabilities</dt>
            <dd className="mono small">{(selected.constraints?.allowed_capabilities ?? []).join(", ") || "—"}</dd>
            <dt>approval required for</dt>
            <dd className="mono small">{(selected.constraints?.requires_approval_for ?? []).join(", ") || "—"}</dd>
            <dt>rate caps</dt>
            <dd className="mono small">{JSON.stringify(selected.constraints?.rate_caps ?? {})}</dd>
          </dl>
          {canApprove ? (
            <>
              <label className="field mt">
                Reason (suspend/revoke)
                <input value={reason} onChange={(e) => setReason(e.target.value)} />
              </label>
              <div className="row">
                <StepUpGate action={() => action(selected, "activate")}>
                  {(trigger) => (
                    <button
                      type="button"
                      disabled={selected.status === "ROE_STATUS_ACTIVE"}
                      title="activate: validates hard rules and resolves the effective target list"
                      onClick={trigger}
                    >
                      activate
                    </button>
                  )}
                </StepUpGate>
                <StepUpGate action={() => action(selected, "suspend")}>
                  {(trigger) => (
                    <button
                      type="button"
                      disabled={selected.status !== "ROE_STATUS_ACTIVE"}
                      onClick={trigger}
                    >
                      suspend
                    </button>
                  )}
                </StepUpGate>
                <StepUpGate action={() => action(selected, "revoke")}>
                  {(trigger) => (
                    <button
                      type="button"
                      className="danger"
                      disabled={
                        selected.status === "ROE_STATUS_REVOKED" ||
                        selected.status === "ROE_STATUS_EXPIRED"
                      }
                      title="permanent — kills all in-flight tasks under this RoE ≤5s (doc 01 §10.5)"
                      onClick={trigger}
                    >
                      revoke
                    </button>
                  )}
                </StepUpGate>
              </div>
            </>
          ) : (
            <p className="muted small mt" data-testid="approve-denied">
              lifecycle actions require the offensive-approver / grc-verifier / platform-admin role.
            </p>
          )}
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
