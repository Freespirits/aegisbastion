/**
 * Popup (doc 07 §6.3): current-tab verdict + top explanations, the
 * "report this phish" consent action, and a paste-a-URL checker. Verdicts
 * come from the service worker (owner of the intel bundle).
 */

import type { ExtResponse, ExtState } from "./messages.js";
import type { Verdict } from "../core/verdict.js";

function send(msg: unknown): Promise<ExtResponse> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (r: ExtResponse) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message ?? "sendMessage failed" });
        return;
      }
      resolve(r);
    });
  });
}

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) throw new Error(`missing element #${id}`);
  return e as T;
}

function renderVerdict(verdict: Verdict | null, state: ExtState | null): void {
  const pill = el<HTMLSpanElement>("verdict-pill");
  const score = document.querySelector("#score");
  const meta = el<HTMLDivElement>("meta");
  const explanations = el<HTMLOListElement>("explanations");
  explanations.textContent = "";

  if (!verdict) {
    pill.className = "unknown";
    pill.textContent = "—";
    if (score) score.innerHTML = "— <small>/ 100</small>";
    meta.textContent = "No page analysis yet — open a message in Gmail/Outlook Web, or check a URL below.";
    return;
  }
  pill.className = verdict.verdict;
  pill.textContent = verdict.verdict;
  if (score) score.innerHTML = `${verdict.score} <small>/ 100${verdict.hardFail ? " · hard-fail" : ""}</small>`;
  const bits = [
    `bundle ${verdict.clientMeta.bundleVersion}`,
    `policy v${verdict.clientMeta.policyVersion}`,
    `${verdict.timingMs} ms`,
  ];
  if (state?.degraded === true) bits.push("intel outdated");
  meta.textContent = bits.join(" · ");
  for (const e of verdict.explanations.slice(0, 5)) {
    const li = document.createElement("li");
    li.textContent = e;
    explanations.appendChild(li);
  }
}

async function activeTabId(): Promise<number | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return typeof tab?.id === "number" ? tab.id : null;
}

async function refresh(): Promise<void> {
  const stateRes = await send({ type: "get-state" });
  const state = stateRes.ok && "state" in stateRes ? stateRes.state : null;
  const tabId = await activeTabId();
  if (tabId === null) {
    renderVerdict(null, state);
    return;
  }
  const res = await send({ type: "get-tab-verdict", tabId });
  renderVerdict(res.ok && "tabVerdict" in res ? res.tabVerdict?.verdict ?? null : null, state);
}

async function init(): Promise<void> {
  await refresh();

  el<HTMLButtonElement>("report-btn").addEventListener("click", async () => {
    // Explicit per-item consent (doc 07 §7.4) → redacted finding.report (§5.4).
    const tabId = await activeTabId();
    if (tabId === null) return;
    const res = await send({ type: "report-finding", tabId });
    el<HTMLDivElement>("report-status").textContent = res.ok
      ? "Thank you — a redacted report was queued (no content leaves this device unhashed)."
      : `Report failed: ${"error" in res ? res.error : "unknown"}`;
  });

  // The report button enables once any non-clean verdict exists for the tab.
  const tabId = await activeTabId();
  if (tabId !== null) {
    const res = await send({ type: "get-tab-verdict", tabId });
    const v = res.ok && "tabVerdict" in res ? res.tabVerdict?.verdict : null;
    el<HTMLButtonElement>("report-btn").disabled = !v || v.verdict === "clean";
  }

  el<HTMLButtonElement>("options-btn").addEventListener("click", () => {
    void chrome.runtime.openOptionsPage();
  });

  el<HTMLFormElement>("url-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const input = el<HTMLInputElement>("url-input").value.trim();
    if (input === "") return;
    const res = await send({ type: "analyze-url", url: input });
    if (res.ok && "verdict" in res) {
      const stateRes = await send({ type: "get-state" });
      renderVerdict(res.verdict, stateRes.ok && "state" in stateRes ? stateRes.state : null);
    }
  });
}

void init();
