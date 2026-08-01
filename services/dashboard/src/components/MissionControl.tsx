"use client";

import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "@/lib/client";
import { StepUpGate } from "@/components/StepUpGate";
import type { Mission } from "@/lib/types";

interface AuditEvent {
  seq?: string;
  event_type?: string;
  actor?: string;
  detail?: string;
  occurred_at?: string;
  prev_hash?: string;
  hash?: string;
}

const RECENT_KEY = "aegisbastion.recentMissions";

function statePill(state?: string): string {
  switch (state) {
    case "MISSION_STATE_ACTIVE":
      return "pill ok";
    case "MISSION_STATE_PAUSED":
    case "MISSION_STATE_PLANNER_DEGRADED":
      return "pill warn";
    case "MISSION_STATE_KILLED":
      return "pill crit";
    default:
      return "pill";
  }
}

/**
 * Mission control: lookup, pause / resume / kill (doc 01 §7.3, §10.5) and the
 * mission's hash-chained audit trail. Pause is deliberately NOT step-up
 * gated (a halt must stay fast); resume and kill are (doc 10 §7.2).
 * The Mission API exposes no list endpoint at MVP-A, so the console keeps a
 * UI-local recent-ids list (doc 10 §4.1: UI-local state only).
 */
export function MissionControl({
  capabilities,
  created,
}: {
  capabilities: string[];
  created: Mission | null;
}) {
  const canControl = capabilities.includes("missions.control");
  const canAudit = capabilities.includes("audit.view");
  const [missionId, setMissionId] = useState("");
  const [mission, setMission] = useState<Mission | null>(null);
  const [recent, setRecent] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [killReason, setKillReason] = useState("");
  const [audit, setAudit] = useState<AuditEvent[] | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);

  useEffect(() => {
    try {
      setRecent(JSON.parse(localStorage.getItem(RECENT_KEY) ?? "[]") as string[]);
    } catch {
      setRecent([]);
    }
  }, []);

  useEffect(() => {
    if (created) {
      setMission(created);
      setMissionId(created.mission_id);
      setRecent((prev) => {
        const next = [created.mission_id, ...prev.filter((id) => id !== created.mission_id)].slice(0, 10);
        try {
          localStorage.setItem(RECENT_KEY, JSON.stringify(next));
        } catch {
          /* UI-local only */
        }
        return next;
      });
    }
  }, [created]);

  const load = useCallback(async (id: string) => {
    setError(null);
    setAudit(null);
    try {
      const res = await api<{ mission: Mission }>(`/api/missions/${encodeURIComponent(id)}`);
      setMission(res.mission);
    } catch (err) {
      setMission(null);
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  async function act(action: "pause" | "resume" | "kill") {
    if (!mission) return;
    setError(null);
    try {
      const body = action === "kill" ? { reason: killReason || "operator kill from dashboard" } : {};
      const res = await api<{ mission: Mission }>(
        `/api/missions/${encodeURIComponent(mission.mission_id)}/${action}`,
        { method: "POST", body },
      );
      setMission(res.mission);
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 403
          ? `${err.message} (step-up or role check failed — gatekeeper/Mission API denial shown verbatim)`
          : err instanceof Error
            ? err.message
            : String(err),
      );
    }
  }

  async function loadAudit() {
    if (!mission) return;
    setAuditError(null);
    try {
      const res = await api<{ events?: AuditEvent[] }>(
        `/api/missions/${encodeURIComponent(mission.mission_id)}/audit`,
      );
      setAudit(res.events ?? []);
    } catch (err) {
      setAuditError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="panel">
      <h3>Mission control — pause / resume / kill</h3>
      <div className="row mb">
        <input
          style={{ flex: 1, minWidth: 260 }}
          value={missionId}
          onChange={(e) => setMissionId(e.target.value)}
          placeholder="msn_01J8ZK…"
          aria-label="mission id"
        />
        <button type="button" onClick={() => void load(missionId.trim())} disabled={!missionId.trim()}>
          load
        </button>
      </div>
      {recent.length ? (
        <div className="row mb">
          <span className="muted small">recent:</span>
          {recent.map((id) => (
            <button key={id} type="button" className="small" onClick={() => void load(id)}>
              {id}
            </button>
          ))}
        </div>
      ) : null}
      {error ? (
        <div className="error-box mb" role="alert">
          {error}
        </div>
      ) : null}

      {mission ? (
        <>
          <dl className="kv">
            <dt>mission</dt>
            <dd className="mono">
              {mission.mission_id} — {mission.name}
            </dd>
            <dt>state</dt>
            <dd>
              <span className={statePill(mission.state)} data-testid="mission-state">
                {mission.state ?? "UNKNOWN"}
              </span>
            </dd>
            <dt>objective</dt>
            <dd>{mission.objective}</dd>
            <dt>RoE</dt>
            <dd className="mono">
              {mission.roe_id} (v{mission.roe_version ?? "?"})
            </dd>
            <dt>commander</dt>
            <dd>{mission.owning_commander ?? "—"}</dd>
            <dt>created</dt>
            <dd className="small">
              {mission.created_at ? new Date(mission.created_at).toLocaleString() : "—"} by{" "}
              <span className="mono">{mission.created_by ?? "—"}</span>
            </dd>
          </dl>

          <div className="row mt">
            <button
              type="button"
              disabled={!canControl || mission.state !== "MISSION_STATE_ACTIVE"}
              title={canControl ? "halt new dispatches (not step-up gated — a halt must stay fast)" : "requires the missions.control affordance"}
              onClick={() => void act("pause")}
            >
              pause
            </button>
            <StepUpGate action={() => act("resume")}>
              {(trigger) => (
                <button
                  type="button"
                  disabled={!canControl || mission.state !== "MISSION_STATE_PAUSED"}
                  title="resume dispatching (step-up required, doc 10 §7.2)"
                  onClick={trigger}
                >
                  resume
                </button>
              )}
            </StepUpGate>
            <input
              value={killReason}
              onChange={(e) => setKillReason(e.target.value)}
              placeholder="kill reason (recorded in KILL_SWITCH audit)"
              style={{ minWidth: 240 }}
            />
            <StepUpGate action={() => act("kill")}>
              {(trigger) => (
                <button
                  type="button"
                  className="danger"
                  disabled={
                    !canControl ||
                    mission.state === "MISSION_STATE_KILLED" ||
                    mission.state === "MISSION_STATE_COMPLETED"
                  }
                  title="engage the per-mission kill switch (terminal; step-up required)"
                  onClick={trigger}
                >
                  kill
                </button>
              )}
            </StepUpGate>
            {canAudit ? (
              <button type="button" onClick={() => void loadAudit()}>
                audit trail
              </button>
            ) : null}
          </div>
          {!canControl ? (
            <p className="muted small mt" data-testid="control-denied">
              your roles do not include the missions.control affordance — controls are read-only for
              you.
            </p>
          ) : null}
        </>
      ) : null}

      {auditError ? (
        <div className="error-box mt" role="alert">
          {auditError}
        </div>
      ) : null}
      {audit ? (
        <table className="data mt" aria-label="mission audit trail">
          <thead>
            <tr>
              <th>seq</th>
              <th>event</th>
              <th>actor</th>
              <th>when</th>
              <th>hash</th>
            </tr>
          </thead>
          <tbody>
            {audit.map((e, i) => (
              <tr key={i} style={{ cursor: "default" }}>
                <td className="mono small">{e.seq ?? i}</td>
                <td className="mono small">{e.event_type ?? "—"}</td>
                <td className="mono small">{e.actor ?? "—"}</td>
                <td className="muted small">{e.occurred_at ? new Date(e.occurred_at).toLocaleString() : "—"}</td>
                <td className="mono small muted" title={e.hash}>
                  {e.hash ? `${e.hash.slice(0, 12)}…` : "—"}
                </td>
              </tr>
            ))}
            {audit.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
                  no audit events yet
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      ) : null}
    </div>
  );
}
