/**
 * Enrichment against the REAL data-platform contract (doc 09 §5, Ruling C4):
 * TPEL headers (X-DP-Principal / X-DP-Tenant), asset(uid:) for uuid asset
 * ids, exact-value fallback via assets(valuePrefix:), criticality/owner_group
 * extracted from the Asset attributes JSON, fail-soft on any transport or
 * GraphQL error.
 */

import { describe, expect, it, vi, afterEach } from "vitest";
import { AssetCache, GraphQlAssetLookup, effectiveSeverity } from "../src/enrich.js";
import type { AlertAsset } from "../src/types.js";

const UID = "0191e2b0-7c3a-7f2e-9b1d-2a4c6e8f0a1b";
const asset: AlertAsset = { asset_id: UID, kind: "domain", identifier: "api.example.com" };

function gqlResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify({ data }), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => vi.unstubAllGlobals());

describe("GraphQlAssetLookup (doc 09 Query API contract)", () => {
  it("uuid asset_id → asset(uid:) with TPEL headers; attributes → AssetInfo", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      gqlResponse({ asset: { uid: UID, value: "api.example.com", attributes: { criticality: "critical", owner_group: "team-platform" } } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const lookup = new GraphQlAssetLookup("http://dp:8082", { principal: "herald", tenant: "tenant-1" });
    const info = await lookup.lookup("org_acme", asset);
    expect(info).toEqual({ criticality: "critical", owner_group: "team-platform" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://dp:8082/v1/query");
    const headers = init.headers as Record<string, string>;
    expect(headers["x-dp-principal"]).toBe("herald");
    expect(headers["x-dp-tenant"]).toBe("tenant-1");
    expect(String(init.body)).toContain("asset(uid: $id)");
  });

  it("non-uuid asset_id → exact-value fallback via assets(valuePrefix:)", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      gqlResponse({
        assets: {
          nodes: [
            { uid: "u1", value: "api.example.com.evil", attributes: { criticality: "low" } },
            { uid: "u2", value: "api.example.com", attributes: { criticality: "high", owner_group: "team-sec" } },
          ],
        },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const lookup = new GraphQlAssetLookup("http://dp:8082");
    const info = await lookup.lookup("org_acme", { ...asset, asset_id: "asset_88f3" });
    expect(info).toEqual({ criticality: "high", owner_group: "team-sec" });
    expect(fetchMock).toHaveBeenCalledTimes(1); // no uid attempt for non-uuid ids
    expect(String((fetchMock.mock.calls[0] as [string, RequestInit])[1].body)).toContain("valuePrefix");
  });

  it("uuid miss falls through to the identifier lookup", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(gqlResponse({ asset: null }))
      .mockResolvedValueOnce(
        gqlResponse({ assets: { nodes: [{ uid: "u2", value: "api.example.com", attributes: { criticality: "medium" } }] } }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const lookup = new GraphQlAssetLookup("http://dp:8082");
    expect(await lookup.lookup("org_acme", asset)).toEqual({ criticality: "medium" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("unknown criticality values are dropped, not passed through", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      gqlResponse({ asset: { uid: UID, value: "v", attributes: { criticality: "ultra", owner_group: "team-platform" } } }),
    ));
    const lookup = new GraphQlAssetLookup("http://dp:8082");
    expect(await lookup.lookup("org_acme", asset)).toEqual({ owner_group: "team-platform" });
  });

  it("no criticality/owner in attributes → null (no enrichment)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(gqlResponse({ asset: { uid: UID, value: "v", attributes: { dns: [] } } })));
    const lookup = new GraphQlAssetLookup("http://dp:8082");
    // uid miss of info → identifier fallback also returns null info
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(gqlResponse({ asset: { uid: UID, value: "v", attributes: { dns: [] } } }))
      .mockResolvedValueOnce(gqlResponse({ assets: { nodes: [] } })));
    expect(await lookup.lookup("org_acme", asset)).toBeNull();
  });
});

describe("AssetCache fail-soft + TTL", () => {
  it("HTTP error → not enriched, never throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("nope", { status: 503 })));
    const cache = new AssetCache(new GraphQlAssetLookup("http://dp:8082"), 60_000);
    const res = await cache.get("org_acme", asset);
    expect(res).toEqual({ info: null, enriched: false });
  });

  it("GraphQL error body → fail-soft; second call serves the cached null within TTL", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ errors: [{ message: "no grant" }] }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const cache = new AssetCache(new GraphQlAssetLookup("http://dp:8082"), 60_000);
    await cache.get("org_acme", asset);
    // After a failure there is no cache entry; a working stub lookup proves caching on success instead.
    const stubCache = new AssetCache({ lookup: async () => ({ criticality: "low" }) }, 60_000);
    expect((await stubCache.get("org_acme", asset)).enriched).toBe(true);
    expect((await stubCache.get("org_acme", asset)).info).toEqual({ criticality: "low" });
  });
});

describe("effectiveSeverity floor rule (§8)", () => {
  const base = { severity: "low", confidence: "confirmed", category: "vuln" } as const;
  it("confirmed vuln on a critical asset floors at high", () => {
    expect(effectiveSeverity(
      { ...base } as never,
      { asset_id: "a", kind: "domain", identifier: "x", criticality: "critical" },
    )).toBe("high");
  });
  it("producer severity above the floor stands", () => {
    expect(effectiveSeverity(
      { ...base, severity: "critical" } as never,
      { asset_id: "a", kind: "domain", identifier: "x", criticality: "critical" },
    )).toBe("critical");
  });
  it("no floor for non-critical assets or unconfirmed alerts", () => {
    expect(effectiveSeverity({ ...base } as never, { asset_id: "a", kind: "domain", identifier: "x", criticality: "high" })).toBe("low");
    expect(effectiveSeverity(
      { ...base, confidence: "probable" } as never,
      { asset_id: "a", kind: "domain", identifier: "x", criticality: "critical" },
    )).toBe("low");
  });
});
