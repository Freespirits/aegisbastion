// Aggregated backend health for the overview status pills. Degraded backends
// surface as red pills; the dashboard itself stays up (doc 10 §8).

import { env } from "@/env";
import { requireSession } from "@/lib/guard";
import { NextResponse } from "next/server";

async function probe(name: string, url: string): Promise<[string, { ok: boolean; detail: string }]> {
  try {
    const res = await fetch(`${url}/healthz`, { cache: "no-store", signal: AbortSignal.timeout(3000) });
    return [name, { ok: res.ok, detail: `HTTP ${res.status}` }];
  } catch (err) {
    return [name, { ok: false, detail: err instanceof Error ? err.message : String(err) }];
  }
}

export async function GET() {
  const g = await requireSession();
  if (!g.ok) return g.response;
  const e = env();
  const entries = await Promise.all([
    probe("gatekeeper", e.gatekeeperUrl),
    probe("platform-core", e.platformCoreUrl),
    probe("data-platform", e.dataPlatformUrl),
    probe("herald", e.heraldUrl),
  ]);
  const backends = Object.fromEntries(entries);
  return NextResponse.json({
    ok: Object.values(backends).every((b) => b.ok),
    backends,
  });
}
