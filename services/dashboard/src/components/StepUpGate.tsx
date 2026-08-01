"use client";

import { useCallback, useState } from "react";

/**
 * Step-up gate for sensitive actions (doc 10 §7.2: WebAuthn re-auth ≤5 min
 * old for RoE create/revoke, offensive plan approvals, offensive launches,
 * commander resume). PLACEHOLDER ceremony: the modal acknowledges instead of
 * performing a real WebAuthn assertion; the 5-minute server-side window and
 * the mandatory checks on the API routes are real. The server still rejects
 * sensitive calls without a fresh step-up, so bypassing this modal in the
 * browser achieves nothing.
 */
export function StepUpGate({
  action,
  children,
}: {
  action: () => void | Promise<void>;
  children: (trigger: () => void) => React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/stepup", { cache: "no-store" });
      const status = res.ok ? await res.json() : { active: false };
      if (status.active) {
        await action();
      } else {
        setOpen(true);
      }
    } finally {
      setBusy(false);
    }
  }, [action]);

  async function acknowledge() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/stepup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ acknowledge: true }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body?.detail ?? `step-up failed (HTTP ${res.status})`);
        return;
      }
      setOpen(false);
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {children(() => void run())}
      {open ? (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Step-up authentication">
          <div className="modal">
            <h3>Step-up authentication required</h3>
            <p className="muted">
              This is a sensitive action (doc 10 §7.2). Production requires a WebAuthn
              re-authentication ≤ 5 minutes old. This MVP build ships the placeholder ceremony:
              confirming below starts the same 5-minute server-side window the real ceremony will.
            </p>
            {error ? (
              <div className="error-box mb" role="alert">
                {error}
              </div>
            ) : null}
            <div className="row">
              <button className="primary" onClick={acknowledge} disabled={busy} type="button">
                {busy ? "Verifying…" : "Confirm step-up (placeholder)"}
              </button>
              <button onClick={() => setOpen(false)} disabled={busy} type="button">
                Cancel
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
