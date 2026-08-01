"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useState } from "react";
import { ApiError, gql } from "@/lib/client";
import { ASSET_NEIGHBORHOOD_QUERY, ASSETS_QUERY } from "@/lib/queries";
import type { GqlAsset, GqlEdge, GqlPageInfo } from "@/lib/types";

// Cytoscape is client-only (doc 10 §5); load it lazily.
const SurfaceGraph = dynamic(
  () => import("@/components/SurfaceGraph").then((m) => m.SurfaceGraph),
  { ssr: false, loading: () => <div className="graph-box muted small">loading graph…</div> },
);

interface AssetsData {
  assets: { nodes: GqlAsset[]; pageInfo: GqlPageInfo };
}

interface NeighborhoodData {
  assetNeighborhood: { root: GqlAsset; assets: GqlAsset[]; edges: GqlEdge[] };
}

const ASSET_TYPES = ["", "domain", "subdomain", "ip", "service", "certificate", "cloud"];

/**
 * Attack-surface map (doc 10 MVP-A: asset list + detail + Cytoscape graph,
 * read from doc 09's Query API — Ruling C4: 09 is the system of record).
 */
export function AssetsExplorer() {
  const [typeFilter, setTypeFilter] = useState("");
  const [prefix, setPrefix] = useState("");
  const [assets, setAssets] = useState<GqlAsset[]>([]);
  const [pageInfo, setPageInfo] = useState<GqlPageInfo | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [selected, setSelected] = useState<GqlAsset | null>(null);
  const [hood, setHood] = useState<NeighborhoodData["assetNeighborhood"] | null>(null);
  const [hoodError, setHoodError] = useState<string | null>(null);

  const load = useCallback(
    async (after?: string) => {
      setLoading(true);
      setError(null);
      try {
        const filter: Record<string, unknown> = {};
        if (typeFilter) filter.types = [typeFilter];
        if (prefix.trim()) filter.valuePrefix = prefix.trim();
        const data = await gql<AssetsData>(ASSETS_QUERY, {
          filter: Object.keys(filter).length ? filter : null,
          first: 50,
          after: after ?? null,
        });
        setAssets(data.assets.nodes);
        setPageInfo(data.assets.pageInfo);
      } catch (err) {
        setError(
          err instanceof ApiError && err.status === 503
            ? "data-platform unavailable (503) — assets reads fail until it recovers (doc 10 §8)"
            : err instanceof Error
              ? err.message
              : String(err),
        );
      } finally {
        setLoading(false);
      }
    },
    [typeFilter, prefix],
  );

  useEffect(() => {
    setCursor(undefined);
    void load();
  }, [load]);

  const openNeighborhood = useCallback(async (asset: GqlAsset) => {
    setSelected(asset);
    setHood(null);
    setHoodError(null);
    try {
      const data = await gql<NeighborhoodData>(ASSET_NEIGHBORHOOD_QUERY, { uid: asset.uid, depth: 3 });
      setHood(data.assetNeighborhood);
    } catch (err) {
      setHoodError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  return (
    <>
      <div className="panel">
        <div className="form-row">
          <label className="field">
            Asset type
            <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
              {ASSET_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t || "all"}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Value prefix
            <input
              value={prefix}
              onChange={(e) => setPrefix(e.target.value)}
              placeholder="e.g. api.example"
            />
          </label>
        </div>
        {error ? (
          <div className="error-box" role="alert">
            {error}
          </div>
        ) : null}
        {loading ? (
          <div className="muted small">loading assets…</div>
        ) : (
          <>
            <table className="data" aria-label="assets">
              <thead>
                <tr>
                  <th>Value</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Confidence</th>
                  <th>First seen</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a) => (
                  <tr
                    key={a.uid}
                    className={selected?.uid === a.uid ? "selected" : ""}
                    onClick={() => void openNeighborhood(a)}
                  >
                    <td className="mono">{a.value}</td>
                    <td>{a.type}</td>
                    <td>{a.status}</td>
                    <td>{a.confidence.toFixed(2)}</td>
                    <td className="muted small">{new Date(a.firstSeen).toLocaleString()}</td>
                    <td className="muted small">{new Date(a.lastSeen).toLocaleString()}</td>
                  </tr>
                ))}
                {assets.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="muted">
                      no assets match — Discover (02) publishes assets into the data platform (09)
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
            <div className="spread mt">
              <span className="muted small">
                {pageInfo ? `${pageInfo.totalCount} assets in this tenant` : ""}
              </span>
              {pageInfo?.hasNextPage && pageInfo.endCursor ? (
                <button
                  type="button"
                  onClick={() => {
                    const next = pageInfo.endCursor ?? undefined;
                    setCursor(next);
                    void load(next);
                  }}
                >
                  next page
                </button>
              ) : null}
            </div>
          </>
        )}
      </div>

      {selected ? (
        <div className="panel">
          <div className="spread">
            <h3>
              Neighborhood of <span className="mono">{selected.value}</span>
            </h3>
            <button type="button" onClick={() => setSelected(null)}>
              close
            </button>
          </div>
          <dl className="kv mb">
            <dt>uid</dt>
            <dd className="mono">{selected.uid}</dd>
            <dt>type / status</dt>
            <dd>
              {selected.type} / {selected.status}
            </dd>
            <dt>RoE</dt>
            <dd className="mono">{selected.roeId || "—"}</dd>
            <dt>attributes</dt>
            <dd className="mono small">{JSON.stringify(selected.attributes)}</dd>
          </dl>
          {hoodError ? (
            <div className="error-box" role="alert">
              {hoodError}
            </div>
          ) : hood ? (
            <SurfaceGraph
              root={hood.root}
              assets={hood.assets}
              edges={hood.edges}
              onSelect={(uid) => {
                const next = hood.assets.find((a) => a.uid === uid);
                if (next) void openNeighborhood(next);
              }}
            />
          ) : (
            <div className="muted small">loading neighborhood…</div>
          )}
        </div>
      ) : null}
    </>
  );
}
