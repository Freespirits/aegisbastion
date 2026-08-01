/**
 * Options page (doc 07 §6.3): telemetry opt-in (default OFF), local
 * brand-list additions, signed bundle/policy application against pinned hub
 * keys, and dev mode (unsigned policies — compiled out unless PHISH_DEV=on).
 */

import type { ExtResponse } from "./messages.js";

declare const __PHISH_DEV__: boolean;

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

function status(text: string): void {
  el<HTMLSpanElement>("status").textContent = text;
}

async function init(): Promise<void> {
  if (__PHISH_DEV__ === true) {
    el<HTMLFieldSetElement>("dev-section").style.display = "block";
  }

  const res = await send({ type: "get-state" });
  if (res.ok && "state" in res) {
    el<HTMLInputElement>("telemetry-enabled").checked = res.state.telemetryEnabled;
    el<HTMLInputElement>("dev-mode").checked = res.state.devMode;
    el<HTMLTextAreaElement>("local-brands").value = res.state.localBrands.join("\n");
    el<HTMLParagraphElement>("intel-state").textContent =
      `Bundle: ${res.state.bundleVersion} · policy v${res.state.policyVersion} · ` +
      `${res.state.degraded ? "DEGRADED (stale intel)" : "fresh"} · ${res.state.reportsQueued} reports queued · ` +
      `${res.state.pins.length} pinned key(s)`;
  }

  el<HTMLButtonElement>("save-btn").addEventListener("click", async () => {
    const telemetry = el<HTMLInputElement>("telemetry-enabled").checked;
    const domains = el<HTMLTextAreaElement>("local-brands").value
      .split(/\r?\n/)
      .map((d) => d.trim())
      .filter((d) => d !== "");
    await send({ type: "set-telemetry", enabled: telemetry });
    const r = await send({ type: "set-local-brands", domains });
    if (__PHISH_DEV__ === true) {
      await send({ type: "set-dev-mode", enabled: el<HTMLInputElement>("dev-mode").checked });
    }
    status(r.ok ? "Saved." : `Error: ${"error" in r ? r.error : "unknown"}`);
    setTimeout(() => status(""), 3000);
  });

  el<HTMLInputElement>("bundle-file").addEventListener("change", async () => {
    const file = el<HTMLInputElement>("bundle-file").files?.[0];
    if (!file) return;
    let doc: unknown;
    try {
      doc = JSON.parse(await file.text());
    } catch {
      status("Not a JSON document.");
      return;
    }
    const pin = el<HTMLInputElement>("pin-input").value.trim();
    const r = await send({ type: "apply-intel", document: doc, pin });
    status(r.ok ? "Intel applied (signature verified)." : `Rejected: ${"error" in r ? r.error : "unknown"}`);
  });
}

void init();
