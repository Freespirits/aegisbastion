"use client";

import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

/**
 * Login form: OIDC SSO button (when configured) plus the dev static-token
 * shim behind DEV_AUTH_ENABLED (doc 10 MVP-A). No credentials are stored in
 * the browser — the BFF sets a sealed httpOnly session cookie.
 */
export function LoginForm({
  oidcEnabled,
  devAuthEnabled,
}: {
  oidcEnabled: boolean;
  devAuthEnabled: boolean;
}) {
  const router = useRouter();
  const params = useSearchParams();
  const [principal, setPrincipal] = useState("op_jane@example.com");
  const [orgId, setOrgId] = useState("");
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(
    params.get("error") ? `SSO failed: ${params.get("error")}` : null,
  );
  const [busy, setBusy] = useState(false);

  async function devLogin(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/dev-login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          principal,
          token,
          ...(orgId.trim() ? { org_id: orgId.trim() } : {}),
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body?.detail ?? body?.title ?? `login failed (HTTP ${res.status})`);
        return;
      }
      router.push(params.get("next") ?? "/");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-card">
      <h1>
        AegisBastion <span style={{ color: "var(--accent)" }}>Operator Dashboard</span>
      </h1>
      <p className="sub">
        Every offensive operation behind this console is gated by gatekeeper — signed RoE, scope,
        tokens, audit. (doc 10 §1)
      </p>

      {error ? (
        <div className="error-box mb" role="alert">
          {error}
        </div>
      ) : null}

      {oidcEnabled ? (
        <p>
          <a className="button" href="/api/auth/oidc/start">
            <button className="primary" style={{ width: "100%" }} type="button">
              Sign in with SSO (OIDC)
            </button>
          </a>
        </p>
      ) : null}

      {devAuthEnabled ? (
        <form onSubmit={devLogin}>
          {oidcEnabled ? <p className="muted small">— or dev shim —</p> : null}
          <label className="field">
            Operator identity
            <input
              value={principal}
              onChange={(e) => setPrincipal(e.target.value)}
              name="principal"
              autoComplete="username"
              required
            />
          </label>
          <label className="field">
            Org id (optional — defaults to configured org)
            <input value={orgId} onChange={(e) => setOrgId(e.target.value)} name="org_id" />
          </label>
          <label className="field">
            Dev token
            <input
              value={token}
              onChange={(e) => setToken(e.target.value)}
              name="token"
              type="password"
              autoComplete="off"
            />
          </label>
          <button className="primary" style={{ width: "100%" }} disabled={busy} type="submit">
            {busy ? "Signing in…" : "Sign in (dev shim)"}
          </button>
          <p className="muted small mt">
            Dev mode: roles resolve from gatekeeper rbac-service when reachable, else the configured
            fallback roles.
          </p>
        </form>
      ) : null}

      {!oidcEnabled && !devAuthEnabled ? (
        <div className="banner crit">No login method configured. Set OIDC_* or DEV_AUTH_ENABLED.</div>
      ) : null}
    </div>
  );
}
