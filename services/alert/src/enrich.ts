/**
 * Asset enrichment (doc 05 §3.1 C2): asset criticality + owner from the data
 * platform Query API (doc 09 §5, GraphQL `POST /v1/query`), read-through
 * cache with 5-min TTL. Fail-SOFT: enrichment never blocks an alert — if the
 * data platform is absent or errors, the producer-supplied criticality stands
 * and the alert is stamped `enriched: false` (its severity floor rule simply
 * doesn't apply).
 *
 * The data-platform contract (services/data-platform, Ruling C4 — the built
 * service wins over doc 05's assumed shape):
 *  - TPEL resolves the tenant from the caller credential, NEVER from the
 *    query (doc 09 §2.3): herald presents `X-DP-Principal` (a tenancy.grants
 *    principal with role `service_alert`), plus `X-DP-Tenant` when that
 *    principal holds grants in several tenants. org_id is NOT a dp tenant id.
 *  - Assets are keyed by a UUIDv7 `uid`; `criticality` / `owner_group` are
 *    producer-set entries inside the Asset `attributes` JSON.
 *  - Lookup: `asset(uid:)` when the alert's asset_id is a dp uuid, else an
 *    exact-`value` match via `assets(filter: { valuePrefix: … })`.
 */

import { maxSeverity, type AlertAsset, type AlertEvent, type Severity } from "./types.js";

export interface AssetInfo {
  criticality?: AlertAsset["criticality"];
  owner_group?: string;
}

export interface AssetLookup {
  lookup(orgId: string, asset: AlertAsset): Promise<AssetInfo | null>;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CRITICALITIES = ["critical", "high", "medium", "low"] as const;

export interface DpQueryOptions {
  /** TPEL principal (X-DP-Principal); must hold a tenancy grant (role service_alert). */
  principal?: string;
  /** X-DP-Tenant disambiguation when the principal holds several tenant grants. */
  tenant?: string;
  timeoutMs?: number;
}

interface DpAssetNode {
  uid?: string;
  value?: string;
  attributes?: Record<string, unknown>;
}

/** GraphQL client for doc 09's Query API (tenant-scoped via TPEL headers). */
export class GraphQlAssetLookup implements AssetLookup {
  private readonly principal: string;
  private readonly tenant: string | undefined;
  private readonly timeoutMs: number;

  constructor(
    private readonly baseUrl: string,
    opts: DpQueryOptions = {},
  ) {
    this.principal = opts.principal ?? "herald";
    this.tenant = opts.tenant;
    this.timeoutMs = opts.timeoutMs ?? 3_000;
  }

  async lookup(_orgId: string, asset: AlertAsset): Promise<AssetInfo | null> {
    // The dp tenant comes from the principal's grants (TPEL), not org_id.
    if (UUID_RE.test(asset.asset_id)) {
      const byUid = await this.byUid(asset.asset_id);
      if (byUid) return byUid;
    }
    return this.byIdentifier(asset.identifier);
  }

  private async gql(query: string, variables: Record<string, unknown>): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl.replace(/\/$/, "")}/v1/query`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        "x-dp-principal": this.principal,
        ...(this.tenant ? { "x-dp-tenant": this.tenant } : {}),
      },
      body: JSON.stringify({ query, variables }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) throw new Error(`dp query failed: HTTP ${res.status}`);
    const body = (await res.json()) as { data?: Record<string, unknown>; errors?: { message?: string }[] };
    if (body.errors?.length) throw new Error(`dp graphql error: ${body.errors[0]?.message ?? "unknown"}`);
    return body.data ?? {};
  }

  private async byUid(uid: string): Promise<AssetInfo | null> {
    const data = await this.gql(
      `query ($id: ID!) { asset(uid: $id) { uid value attributes } }`,
      { id: uid },
    );
    return infoFromDpAsset(data.asset as DpAssetNode | null);
  }

  private async byIdentifier(identifier: string): Promise<AssetInfo | null> {
    const data = await this.gql(
      `query ($v: String!) { assets(filter: { valuePrefix: $v }, first: 10) { nodes { uid value attributes } } }`,
      { v: identifier },
    );
    const nodes = ((data.assets as { nodes?: DpAssetNode[] } | undefined)?.nodes ?? []).filter(
      (n): n is DpAssetNode => n !== null && typeof n === "object",
    );
    return infoFromDpAsset(nodes.find((n) => n.value === identifier) ?? null);
  }
}

/** criticality/owner_group ride in the Asset attributes JSON (producer-set). */
function infoFromDpAsset(node: DpAssetNode | null | undefined): AssetInfo | null {
  if (!node || typeof node !== "object") return null;
  const attrs = (node.attributes ?? {}) as Record<string, unknown>;
  const criticality =
    typeof attrs.criticality === "string" &&
    (CRITICALITIES as readonly string[]).includes(attrs.criticality)
      ? (attrs.criticality as AssetInfo["criticality"])
      : undefined;
  const ownerGroup = typeof attrs.owner_group === "string" && attrs.owner_group !== "" ? attrs.owner_group : undefined;
  if (criticality === undefined && ownerGroup === undefined) return null;
  return { ...(criticality !== undefined ? { criticality } : {}), ...(ownerGroup !== undefined ? { owner_group: ownerGroup } : {}) };
}

export class AssetCache {
  private readonly cache = new Map<string, { at: number; info: AssetInfo | null }>();

  constructor(
    private readonly lookup: AssetLookup | null,
    private readonly ttlMs: number,
  ) {}

  async get(orgId: string, asset: AlertAsset): Promise<{ info: AssetInfo | null; enriched: boolean }> {
    if (!this.lookup) return { info: null, enriched: false };
    const key = `${orgId}/${asset.asset_id}`;
    const hit = this.cache.get(key);
    if (hit && Date.now() - hit.at < this.ttlMs) return { info: hit.info, enriched: true };
    try {
      const info = await this.lookup.lookup(orgId, asset);
      this.cache.set(key, { at: Date.now(), info });
      return { info, enriched: true };
    } catch {
      // Fail-soft per module header: serve a stale entry if we have one.
      if (hit) return { info: hit.info, enriched: true };
      return { info: null, enriched: false };
    }
  }
}

/**
 * Effective severity (doc 05 §8): max(producer severity, asset-criticality
 * floor). The ratified floor rule (§3.2 step 3): ANY confirmed exposure/vuln
 * on a `critical` asset floors severity at `high`.
 */
export function effectiveSeverity(event: AlertEvent, asset: AlertAsset): Severity {
  let severity: Severity = event.severity;
  if (
    asset.criticality === "critical" &&
    event.confidence === "confirmed" &&
    (event.category === "vuln" || event.category === "exposure")
  ) {
    severity = maxSeverity(severity, "high");
  }
  return severity;
}

/** Apply enrichment to the event's asset (mutates a copy) + compute severity. */
export async function enrichEvent(
  event: AlertEvent,
  cache: AssetCache,
): Promise<{ event: AlertEvent; effectiveSeverity: Severity; enriched: boolean }> {
  const { info, enriched } = await cache.get(event.org_id, event.asset);
  const asset: AlertAsset = {
    ...event.asset,
    ...(info?.criticality !== undefined ? { criticality: info.criticality } : {}),
    ...(info?.owner_group !== undefined ? { owner_group: info.owner_group } : {}),
  };
  const enrichedEvent: AlertEvent = { ...event, asset };
  return { event: enrichedEvent, effectiveSeverity: effectiveSeverity(enrichedEvent, asset), enriched };
}
