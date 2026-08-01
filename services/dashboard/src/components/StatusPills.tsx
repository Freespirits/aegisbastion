"use client";

import { useEffect, useState } from "react";

interface Health {
  ok: boolean;
  backends: Record<string, { ok: boolean; detail: string }>;
}

/** Backend status pills (doc 10 §3.4 kill-switch bar analogue + §8 degraded banners). */
export function StatusPills() {
  const [health, setHealth] = useState<Health | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    async function tick() {
      try {
        const res = await fetch("/api/health", { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const body = (await res.json()) as Health;
        if (!stop) {
          setHealth(body);
          setErr(null);
        }
      } catch (e) {
        if (!stop) setErr(e instanceof Error ? e.message : String(e));
      }
    }
    void tick();
    const t = setInterval(tick, 15_000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);

  if (err) return <div className="banner crit">health probe failed: {err}</div>;
  if (!health) return <div className="muted small">probing backends…</div>;
  return (
    <div className="row" aria-label="backend status">
      {Object.entries(health.backends).map(([name, b]) => (
        <span key={name} className={`pill ${b.ok ? "ok" : "crit"}`} title={b.detail}>
          {name}: {b.ok ? "up" : "down"}
        </span>
      ))}
      {!health.ok ? (
        <span className="muted small">
          degraded — offensive launches fail closed while gatekeeper is unreachable (doc 10 §8)
        </span>
      ) : null}
    </div>
  );
}
