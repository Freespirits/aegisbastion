/**
 * Inline risk badge (doc 07 §6.3): rendered next to the message header by
 * the content script. Shadow DOM isolation; no images, no network — colors
 * and text only. Shows "intel outdated" when the bundle is stale (§9
 * degraded_mode).
 */

import type { Verdict, VerdictLabel } from "../core/verdict.js";

const HOST_ID = "aegisbastion-phish-badge";

const COLORS: Record<VerdictLabel, { bg: string; fg: string; label: string }> = {
  clean: { bg: "#e6f6ec", fg: "#1c7c3c", label: "Clean" },
  suspicious: { bg: "#fdf3e0", fg: "#9a6a00", label: "Suspicious" },
  malicious: { bg: "#fde7e7", fg: "#b42318", label: "Malicious" },
};

/** Create or update the badge. Returns the host element. */
export function renderBadge(
  doc: Document,
  verdict: Verdict,
  opts: { degraded?: boolean; anchor?: Element | null } = {},
): HTMLElement {
  let host = doc.getElementById(HOST_ID) as HTMLElement | null;
  if (!host) {
    host = doc.createElement("div");
    host.id = HOST_ID;
    const parent = opts.anchor ?? doc.body ?? doc.documentElement;
    parent.appendChild(host);
    host.attachShadow({ mode: "closed" });
  }
  const shadow = host.shadowRoot;
  if (!shadow) return host;

  const c = COLORS[verdict.verdict];
  const topExplanations = verdict.explanations.slice(0, 3);
  shadow.textContent = "";
  const style = doc.createElement("style");
  style.textContent = `
    .wrap { position: fixed; top: 12px; right: 12px; z-index: 2147483646;
            font: 12px/1.4 system-ui, sans-serif; max-width: 300px; }
    .pill { display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px;
            border-radius: 999px; font-weight: 600; background: ${c.bg}; color: ${c.fg};
            box-shadow: 0 1px 4px rgba(0,0,0,.18); cursor: default; }
    .detail { margin-top: 6px; background: #fff; border: 1px solid #e3e8ee; border-radius: 8px;
              padding: 8px 10px; color: #17202a; display: none; }
    .wrap:hover .detail { display: block; }
    .detail ul { margin: 4px 0 0; padding-left: 16px; }
    .stale { color: #9a6a00; font-size: 11px; }
  `;
  const wrap = doc.createElement("div");
  wrap.className = "wrap";
  const pill = doc.createElement("div");
  pill.className = "pill";
  pill.textContent = `Phish-Catcher: ${c.label} (${verdict.score})`;
  const detail = doc.createElement("div");
  detail.className = "detail";
  const title = doc.createElement("strong");
  title.textContent = `Score ${verdict.score}/100${verdict.hardFail ? " — hard-fail rule triggered" : ""}`;
  detail.appendChild(title);
  if (opts.degraded === true) {
    const stale = doc.createElement("div");
    stale.className = "stale";
    stale.textContent = "intel outdated — reputation checks degraded";
    detail.appendChild(stale);
  }
  if (topExplanations.length > 0) {
    const ul = doc.createElement("ul");
    for (const e of topExplanations) {
      const li = doc.createElement("li");
      li.textContent = e;
      ul.appendChild(li);
    }
    detail.appendChild(ul);
  }
  wrap.appendChild(pill);
  wrap.appendChild(detail);
  shadow.appendChild(style);
  shadow.appendChild(wrap);
  return host;
}

/** Remove the badge (e.g. navigating to a non-message view). */
export function removeBadge(doc: Document): void {
  doc.getElementById(HOST_ID)?.remove();
}
