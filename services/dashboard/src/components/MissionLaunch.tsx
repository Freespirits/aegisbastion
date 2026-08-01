"use client";

import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "@/lib/client";
import { StepUpGate } from "@/components/StepUpGate";
import type { Mission, Roe } from "@/lib/types";

interface PreflightResponse {
  roe_id: string;
  roe_status: string;
  authoritative: false;
  notice: string;
  confirm_token: string | null;
  results: { target: string; verdict: string; matchedBy?: string }[];
}

/**
 * Gated task launch (doc 10 §2.2 Flow B + §7.2):
 *   1. operator picks an ACTIVE RoE and declares the intended targets
 *   2. non-authoritative preflight renders the scope match BEFORE submission
 *      ("No 'run anything against anything' free-text target fields without a
 *      preflight dry-run", doc 10 §7.2)
 *   3. type-to-confirm friction on the scope root (GitHub-style)
 *   4. step-up gated submission to the Mission API — the dispatch PEP's
 *      gatekeeper call is the authoritative decision; denials surface
 *      verbatim with their machine-readable reason codes.
 */
export function MissionLaunch({
  capabilities,
  onCreated,
}: {
  capabilities: string[];
  onCreated: (m: Mission) => void;
}) {
  const canLaunch = capabilities.includes("tasks.launch");
  const [roes, setRoes] = useState<Roe[]>([]);
  const [roeError, setRoeError] = useState<string | null>(null);
  const [roeId, setRoeId] = useState("");
  const [name, setName] = useState("");
  const [objective, setObjective] = useState("");
  const [commander, setCommander] = useState("COMMANDER_HEXSTRIKE");
  const [priority, setPriority] = useState("PRIORITY_P1_OPERATOR");
  const [targetsText, setTargetsText] = useState("");
  const [preflight, setPreflight] = useState<PreflightResponse | null>(null);
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ roes?: Roe[] }>("/api/roe?status=active")
      .then((r) => setRoes(r.roes ?? []))
      .catch((err) =>
        setRoeError(
          err instanceof ApiError && err.status === 503
            ? "gatekeeper unavailable — launches fail closed (doc 10 §8)"
            : err instanceof Error
              ? err.message
              : String(err),
        ),
      );
  }, []);

  const selectedRoe = roes.find((r) => r.roe_id === roeId) ?? null;

  const runPreflight = useCallback(async () => {
    setError(null);
    setPreflight(null);
    const targets = targetsText
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (!roeId || targets.length === 0) {
      setError("select an RoE and enter at least one target to preflight");
      return;
    }
    setBusy(true);
    try {
      const res = await api<PreflightResponse>("/api/preflight", {
        method: "POST",
        body: { roe_id: roeId, targets },
      });
      setPreflight(res);
      setConfirm("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [roeId, targetsText]);

  const allInScope =
    preflight !== null && preflight.results.every((r) => r.verdict === "in_scope");
  const confirmOk =
    !preflight?.confirm_token || confirm.trim().toLowerCase() === preflight.confirm_token.toLowerCase();
  const launchReady =
    canLaunch && !!preflight && allInScope && confirmOk && name.trim() !== "" && objective.trim() !== "";

  async function launch() {
    setError(null);
    setBusy(true);
    try {
      const res = await api<{ mission: Mission }>("/api/missions", {
        method: "POST",
        body: {
          name: name.trim(),
          objective: objective.trim(),
          roe_id: roeId,
          owning_commander: commander,
          priority,
          labels: { targets: targetsText.replace(/\s+/g, " ").trim() },
        },
      });
      onCreated(res.mission);
      setPreflight(null);
      setTargetsText("");
      setConfirm("");
      setName("");
      setObjective("");
    } catch (err) {
      // 403s from the dispatch PEP carry gatekeeper's denial; show verbatim
      // (doc 10 §2.2 Flow B step 3).
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  if (!canLaunch) {
    return (
      <div className="panel">
        <h3>Gated task launch</h3>
        <p className="muted small" data-testid="launch-denied">
          your roles do not include the tasks.launch affordance (operator / platform-admin). Role
          grants live in gatekeeper rbac-service.
        </p>
      </div>
    );
  }

  return (
    <div className="panel">
      <h3>Gated task launch — Mission API (doc 01 §7.3) behind the gatekeeper gate</h3>
      {roeError ? (
        <div className="error-box mb" role="alert">
          {roeError}
        </div>
      ) : null}
      <div className="form-row">
        <label className="field">
          Mission name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="acme q3 surface watch" />
        </label>
        <label className="field">
          Authorizing RoE (ACTIVE only)
          <select value={roeId} onChange={(e) => setRoeId(e.target.value)}>
            <option value="">— select —</option>
            {roes.map((r) => (
              <option key={r.roe_id} value={r.roe_id}>
                {r.name} ({r.roe_id})
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="form-row">
        <label className="field">
          Owning commander
          <select value={commander} onChange={(e) => setCommander(e.target.value)}>
            <option value="COMMANDER_HEXSTRIKE">HexStrike (R0–R3)</option>
            <option value="COMMANDER_CAI">CAI (R0–R2)</option>
          </select>
        </label>
        <label className="field">
          Priority
          <select value={priority} onChange={(e) => setPriority(e.target.value)}>
            <option value="PRIORITY_P1_OPERATOR">P1 operator</option>
            <option value="PRIORITY_P3_PLANNED">P3 planned</option>
            <option value="PRIORITY_P4_BACKGROUND">P4 background</option>
          </select>
        </label>
      </div>
      <label className="field">
        Objective
        <textarea
          rows={2}
          value={objective}
          onChange={(e) => setObjective(e.target.value)}
          placeholder="map and monitor acme.com attack surface"
        />
      </label>
      {selectedRoe ? (
        <p className="small muted">
          Scope: domains [{(selectedRoe.scope?.domains ?? []).join(", ") || "—"}] cidrs [
          {(selectedRoe.scope?.cidrs ?? []).join(", ") || "—"}] excludes [
          {(selectedRoe.scope?.explicit_excludes ?? []).join(", ") || "—"}] · max risk{" "}
          {selectedRoe.constraints?.max_risk_class ?? "?"} · capabilities [
          {(selectedRoe.constraints?.allowed_capabilities ?? []).join(", ") || "—"}]
        </p>
      ) : null}
      <label className="field">
        Intended targets (one per line) — required for the preflight scope check
        <textarea
          rows={3}
          value={targetsText}
          onChange={(e) => setTargetsText(e.target.value)}
          placeholder="api.acme.com&#10;203.0.113.10"
        />
      </label>
      <div className="row mb">
        <button type="button" onClick={() => void runPreflight()} disabled={busy || !roeId}>
          run preflight scope check
        </button>
        <span className="muted small">non-authoritative UX dry-run (doc 10 §7.1 step 1)</span>
      </div>

      {preflight ? (
        <div className="mb" data-testid="preflight-results">
          <div className={`banner ${allInScope ? "info" : "crit"}`}>
            {preflight.notice} RoE status: {preflight.roe_status}.
          </div>
          <table className="data">
            <thead>
              <tr>
                <th>Target</th>
                <th>Verdict</th>
                <th>Matched by</th>
              </tr>
            </thead>
            <tbody>
              {preflight.results.map((r) => (
                <tr key={r.target} style={{ cursor: "default" }}>
                  <td className="mono">{r.target}</td>
                  <td>
                    <span
                      className={`pill ${r.verdict === "in_scope" ? "ok" : r.verdict === "excluded" ? "crit" : "warn"}`}
                    >
                      {r.verdict}
                    </span>
                  </td>
                  <td className="muted small">{r.matchedBy ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {preflight.confirm_token && allInScope ? (
            <label className="field mt">
              Type <span className="mono">{preflight.confirm_token}</span> to confirm the scope
              root (destructive-action friction, doc 10 §7.2)
              <input value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </label>
          ) : null}
        </div>
      ) : null}

      {error ? (
        <div className="error-box mb" role="alert">
          {error}
        </div>
      ) : null}

      <StepUpGate action={launch}>
        {(trigger) => (
          <button
            className="primary"
            type="button"
            disabled={!launchReady || busy}
            title={
              !preflight
                ? "run the preflight scope check first"
                : !allInScope
                  ? "a single out-of-scope target denies the entire task at dispatch (doc 10 §7.1)"
                  : !confirmOk
                    ? "type the scope root to confirm"
                    : "launch via the Mission API (step-up required)"
            }
            onClick={trigger}
          >
            {busy ? "working…" : "launch mission"}
          </button>
        )}
      </StepUpGate>
    </div>
  );
}
