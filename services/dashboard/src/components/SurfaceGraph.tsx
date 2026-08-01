"use client";

import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import type { GqlAsset, GqlEdge } from "@/lib/types";

const TYPE_COLORS: Record<string, string> = {
  domain: "#4da3ff",
  subdomain: "#6fb7ff",
  ip: "#e2b93b",
  service: "#34c98e",
  certificate: "#b78bff",
  cloud: "#ef8f4d",
};

function colorFor(type: string): string {
  return TYPE_COLORS[type.toLowerCase()] ?? "#8b98a9";
}

/**
 * Attack-surface graph (doc 10 §2.1: Cytoscape.js) over data-platform's
 * assetNeighborhood adjacency query (doc 09 §5, depth ≤ 4).
 */
export function SurfaceGraph({
  root,
  assets,
  edges,
  onSelect,
}: {
  root: GqlAsset;
  assets: GqlAsset[];
  edges: GqlEdge[];
  onSelect?: (uid: string) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  useEffect(() => {
    if (!ref.current) return;
    const byUid = new Map(assets.map((a) => [a.uid, a]));
    const elements: cytoscape.ElementDefinition[] = [];
    const seen = new Set<string>();
    for (const a of [root, ...assets]) {
      if (seen.has(a.uid)) continue;
      seen.add(a.uid);
      elements.push({
        data: { id: a.uid, label: a.value },
        classes: a.uid === root.uid ? "root" : "",
        style: { "background-color": colorFor(a.type) },
      });
    }
    for (const e of edges) {
      if (!byUid.has(e.src) && e.src !== root.uid) continue;
      if (!byUid.has(e.dst) && e.dst !== root.uid) continue;
      elements.push({ data: { id: e.edgeId, source: e.src, target: e.dst, label: e.rel } });
    }
    const cy = cytoscape({
      container: ref.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-size": 9,
            color: "#dbe4ee",
            "text-margin-y": 10,
            "text-background-color": "#0b0f14",
            "text-background-opacity": 0.7,
            "text-background-padding": "2px",
            width: 14,
            height: 14,
          },
        },
        {
          selector: "node.root",
          style: { width: 22, height: 22, "border-width": 2, "border-color": "#ffffff" },
        },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": "#263244",
            label: "data(label)",
            "font-size": 7,
            color: "#8b98a9",
            "curve-style": "bezier",
          },
        },
      ],
      layout: { name: "cose", animate: false, nodeRepulsion: 8000, idealEdgeLength: 90 },
    });
    cy.on("tap", "node", (evt) => {
      const id = evt.target.id() as string;
      onSelectRef.current?.(id);
    });
    return () => cy.destroy();
  }, [root, assets, edges]);

  return <div ref={ref} className="graph-box" data-testid="surface-graph" />;
}
