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
import { maxSeverity } from "./types.js";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CRITICALITIES = ["critical", "high", "medium", "low"];
/** GraphQL client for doc 09's Query API (tenant-scoped via TPEL headers). */
export class GraphQlAssetLookup {
    baseUrl;
    principal;
    tenant;
    timeoutMs;
    constructor(baseUrl, opts = {}) {
        this.baseUrl = baseUrl;
        this.principal = opts.principal ?? "herald";
        this.tenant = opts.tenant;
        this.timeoutMs = opts.timeoutMs ?? 3_000;
    }
    async lookup(_orgId, asset) {
        // The dp tenant comes from the principal's grants (TPEL), not org_id.
        if (UUID_RE.test(asset.asset_id)) {
            const byUid = await this.byUid(asset.asset_id);
            if (byUid)
                return byUid;
        }
        return this.byIdentifier(asset.identifier);
    }
    async gql(query, variables) {
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
        if (!res.ok)
            throw new Error(`dp query failed: HTTP ${res.status}`);
        const body = (await res.json());
        if (body.errors?.length)
            throw new Error(`dp graphql error: ${body.errors[0]?.message ?? "unknown"}`);
        return body.data ?? {};
    }
    async byUid(uid) {
        const data = await this.gql(`query ($id: ID!) { asset(uid: $id) { uid value attributes } }`, { id: uid });
        return infoFromDpAsset(data.asset);
    }
    async byIdentifier(identifier) {
        const data = await this.gql(`query ($v: String!) { assets(filter: { valuePrefix: $v }, first: 10) { nodes { uid value attributes } } }`, { v: identifier });
        const nodes = (data.assets?.nodes ?? []).filter((n) => n !== null && typeof n === "object");
        return infoFromDpAsset(nodes.find((n) => n.value === identifier) ?? null);
    }
}
/** criticality/owner_group ride in the Asset attributes JSON (producer-set). */
function infoFromDpAsset(node) {
    if (!node || typeof node !== "object")
        return null;
    const attrs = (node.attributes ?? {});
    const criticality = typeof attrs.criticality === "string" &&
        CRITICALITIES.includes(attrs.criticality)
        ? attrs.criticality
        : undefined;
    const ownerGroup = typeof attrs.owner_group === "string" && attrs.owner_group !== "" ? attrs.owner_group : undefined;
    if (criticality === undefined && ownerGroup === undefined)
        return null;
    return { ...(criticality !== undefined ? { criticality } : {}), ...(ownerGroup !== undefined ? { owner_group: ownerGroup } : {}) };
}
export class AssetCache {
    lookup;
    ttlMs;
    cache = new Map();
    constructor(lookup, ttlMs) {
        this.lookup = lookup;
        this.ttlMs = ttlMs;
    }
    async get(orgId, asset) {
        if (!this.lookup)
            return { info: null, enriched: false };
        const key = `${orgId}/${asset.asset_id}`;
        const hit = this.cache.get(key);
        if (hit && Date.now() - hit.at < this.ttlMs)
            return { info: hit.info, enriched: true };
        try {
            const info = await this.lookup.lookup(orgId, asset);
            this.cache.set(key, { at: Date.now(), info });
            return { info, enriched: true };
        }
        catch {
            // Fail-soft per module header: serve a stale entry if we have one.
            if (hit)
                return { info: hit.info, enriched: true };
            return { info: null, enriched: false };
        }
    }
}
/**
 * Effective severity (doc 05 §8): max(producer severity, asset-criticality
 * floor). The ratified floor rule (§3.2 step 3): ANY confirmed exposure/vuln
 * on a `critical` asset floors severity at `high`.
 */
export function effectiveSeverity(event, asset) {
    let severity = event.severity;
    if (asset.criticality === "critical" &&
        event.confidence === "confirmed" &&
        (event.category === "vuln" || event.category === "exposure")) {
        severity = maxSeverity(severity, "high");
    }
    return severity;
}
/** Apply enrichment to the event's asset (mutates a copy) + compute severity. */
export async function enrichEvent(event, cache) {
    const { info, enriched } = await cache.get(event.org_id, event.asset);
    const asset = {
        ...event.asset,
        ...(info?.criticality !== undefined ? { criticality: info.criticality } : {}),
        ...(info?.owner_group !== undefined ? { owner_group: info.owner_group } : {}),
    };
    const enrichedEvent = { ...event, asset };
    return { event: enrichedEvent, effectiveSeverity: effectiveSeverity(enrichedEvent, asset), enriched };
}
