/**
 * MV3 background service worker (doc 07 §6.3): owns the intel bundle +
 * policy in memory (one copy), verifies/persists updates, runs analyses for
 * content scripts and the popup, and manages the consent-gated,
 * redacted-report queue. No persistent background page (MV3); state
 * rehydrates from IndexedDB on wake.
 *
 * Zero external transmission (§7): this worker performs NO network I/O in
 * MVP-A — bundle/policy arrive via the extension-update channel (applied
 * from the options page), and report flush is inert until the MVP-B hub
 * transport (src/hub/) is enabled by enterprise enrollment.
 */

import { PhishCatcher } from "../index.js";
import { IntelStore } from "../intel/store.js";
import { extractPageEvidence } from "../dom/page-context.js";
import { evidenceFromPage } from "../core/normalize.js";
import type { Evidence } from "../core/evidence.js";
import type { Verdict } from "../core/verdict.js";
import { redactFindingReport } from "../hub/redact.js";
import type { FindingReportPayload } from "../hub/messages.js";
import { InertHubTransport } from "../hub/inert.js";
import type { HubTransport } from "../hub/transport.js";
import { bytesToBase64url } from "../intel/base64.js";
import {
  idbDrainReports,
  idbEnqueueReport,
  idbGet,
  idbReportCount,
  idbSet,
} from "./idb.js";
import {
  isExtRequest,
  type ExtResponse,
  type ExtState,
  type TabVerdictState,
} from "./messages.js";

declare const __PHISH_DEV__: boolean;

interface TabAnalysis {
  verdict: Verdict;
  evidence: Evidence;
  url: string;
  analyzedAt: string;
}

const tabAnalyses = new Map<number, TabAnalysis>();

let store = new IntelStore({ pinnedKeys: [] });
let catcher = new PhishCatcher({ intel: store, policy: store.policy() });
let transport: HubTransport | null = null;
let localBrands: string[] = [];
let pins: string[] = [];
let telemetryEnabled = false;
let devMode = false;

const SALT_ROTATE_MS = 24 * 60 * 60 * 1000;

async function reportSalt(): Promise<string> {
  const [salt, ts] = await Promise.all([idbGet<string>("reportSalt"), idbGet<number>("reportSaltTs")]);
  const now = Date.now();
  if (salt && ts && now - ts < SALT_ROTATE_MS) return salt;
  const fresh = bytesToBase64url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  await idbSet("reportSalt", fresh);
  await idbSet("reportSaltTs", now);
  return fresh;
}

/** Rebuild the intel store (pins/local brands changed) and re-apply intel. */
async function rebuildStore(): Promise<void> {
  store = new IntelStore({ pinnedKeys: pins });
  store.addLocalBrands(localBrands);
  const [bundleDoc, policyDoc] = await Promise.all([idbGet<unknown>("bundle"), idbGet<unknown>("policy")]);
  if (bundleDoc !== undefined) await store.applyBundle(bundleDoc);
  if (policyDoc !== undefined) await store.applyPolicy(policyDoc);
  catcher = new PhishCatcher({ intel: store, policy: store.policy() });
}

/** Rehydrate on wake (budget <100 ms, §6.3) + feature-flagged transport. */
async function init(): Promise<void> {
  const [storedPins, storedBrands, telemetry, dev] = await Promise.all([
    idbGet<string[]>("pins"),
    idbGet<string[]>("localBrands"),
    idbGet<boolean>("telemetryEnabled"),
    idbGet<boolean>("devMode"),
  ]);
  pins = storedPins ?? [];
  localBrands = storedBrands ?? [];
  telemetryEnabled = telemetry ?? false;
  // Dev mode (unsigned local policy overrides, §3.3) is compiled out of
  // production builds by the __PHISH_DEV__ define (tsup.ext.config.ts).
  devMode = __PHISH_DEV__ === true && (dev ?? false);
  await rebuildStore();
  // MVP-A: the transport is INERT (doc 00 §4 — hub loop is MVP-B). Seam:
  // enterprise enrollment (managed storage) will swap this for
  // `createHubTransport({ enabled: true, mode: "browser-extension", … })`
  // from ../hub/transport.js — the browser bundle deliberately ships no hub
  // code (§7.1: only the Node agent carries hub transport).
  transport = new InertHubTransport("browser-extension");
  await transport.start({});
}

const initPromise = init().catch(() => {});

async function state(): Promise<ExtState> {
  return {
    bundleVersion: store.bundleVersion(),
    policyVersion: store.policy().policyVersion,
    degraded: store.degraded(),
    telemetryEnabled,
    reportsQueued: await idbReportCount(),
    devMode,
    pins: [...pins],
    localBrands: [...localBrands],
  };
}

function analyzePageDom(tabId: number | undefined, pageDom: Parameters<typeof extractPageEvidence>[0], expectContent: boolean | undefined): ExtResponse {
  const { page, extractionDegraded } = extractPageEvidence(pageDom, {
    ...(expectContent !== undefined ? { expectContent } : {}),
  });
  const evidence = evidenceFromPage({
    ...page,
    clientMeta: {
      bundleVersion: store.bundleVersion(),
      policyVersion: store.policy().policyVersion,
    },
  });
  const verdict = catcher.analyze(evidence, {
    degradedIntel: store.degraded(),
    extractionDegraded,
  });
  if (typeof tabId === "number") {
    tabAnalyses.set(tabId, { verdict, evidence, url: pageDom.url, analyzedAt: new Date().toISOString() });
  }
  return { ok: true, verdict };
}

async function handle(msg: Parameters<typeof isExtRequest>[0] & object, senderTabId: number | undefined): Promise<ExtResponse> {
  if (!isExtRequest(msg)) return { ok: false, error: "unknown message" };
  switch (msg.type) {
    case "analyze-page":
      return analyzePageDom(msg.tabId ?? senderTabId, msg.page, msg.expectContent);

    case "analyze-url": {
      const verdict = catcher.analyzeUrl(msg.url, {
        clientMeta: { bundleVersion: store.bundleVersion(), policyVersion: store.policy().policyVersion },
        degradedIntel: store.degraded(),
      });
      return { ok: true, verdict };
    }

    case "get-tab-verdict": {
      const a = tabAnalyses.get(msg.tabId);
      const tabVerdict: TabVerdictState | null = a
        ? { verdict: a.verdict, url: a.url, analyzedAt: a.analyzedAt }
        : null;
      return { ok: true, tabVerdict };
    }

    case "get-state":
      return { ok: true, state: await state() };

    case "set-telemetry": {
      // Consumer consent model (§7.4): user toggle; org policy (managed
      // storage) wins in enrolled deployments — handled at enrollment.
      telemetryEnabled = msg.enabled;
      await idbSet("telemetryEnabled", telemetryEnabled);
      return { ok: true };
    }

    case "set-local-brands": {
      localBrands = msg.domains.map((d) => d.toLowerCase()).filter((d) => d.includes("."));
      await idbSet("localBrands", localBrands);
      await rebuildStore();
      return { ok: true };
    }

    case "set-dev-mode": {
      if (__PHISH_DEV__ !== true) return { ok: false, error: "dev mode is compiled out of this build" };
      devMode = msg.enabled;
      await idbSet("devMode", devMode);
      return { ok: true };
    }

    case "apply-intel": {
      const doc = msg.document as Record<string, unknown> | null;
      if (typeof doc !== "object" || doc === null) return { ok: false, error: "not a JSON document" };
      const isBundle = typeof doc.bundleVersion === "string";
      if (typeof msg.pin === "string" && msg.pin !== "" && !pins.includes(msg.pin)) {
        pins = [...pins, msg.pin].slice(-2); // two pinned keys (rotation, §4.4)
        await idbSet("pins", pins);
      }
      if (pins.length === 0 && !devMode) {
        return { ok: false, error: "a pinned hub key is required (signed intel only, §4.3/§4.4)" };
      }
      await rebuildStore();
      if (isBundle) {
        const res = await store.applyBundle(doc);
        if (!res.applied) return { ok: false, error: `bundle rejected: ${res.reason ?? "unknown"}` };
        await idbSet("bundle", doc);
        catcher = new PhishCatcher({ intel: store, policy: store.policy() });
        return { ok: true };
      }
      const res = await store.applyPolicy(doc);
      if (!res.applied) return { ok: false, error: `policy rejected: ${res.reason ?? "unknown"}` };
      await idbSet("policy", doc);
      catcher = new PhishCatcher({ intel: store, policy: store.policy() });
      return { ok: true };
    }

    case "report-finding": {
      // Explicit per-item consent action (§7.4) — allowed even when the
      // telemetry toggle is off. Redaction is non-negotiable (§5.4).
      const a = tabAnalyses.get(msg.tabId);
      if (!a) return { ok: false, error: "no analysis for this tab yet" };
      const salt = await reportSalt();
      const report: FindingReportPayload = redactFindingReport(
        a.evidence,
        a.verdict,
        { urlSalt: salt, consent: "user-item" },
        `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
      );
      await idbEnqueueReport(report);
      if (transport?.live === true) await transport.sendFindingReport(report);
      return { ok: true, report };
    }

    default:
      return { ok: false, error: "unsupported message" };
  }
}

// --- wiring ------------------------------------------------------------------

chrome.runtime.onMessage.addListener((raw: unknown, sender, sendResponse: (r: ExtResponse) => void) => {
  void initPromise.then(async () => {
    try {
      sendResponse(await handle(raw as object, sender.tab?.id));
    } catch (err) {
      sendResponse({ ok: false, error: (err as Error).message });
    }
  });
  return true; // async response
});

// Opportunistic report flush (§5.4): only when a live transport exists
// (MVP-B); in MVP-A the queue persists locally, drop-oldest at 500.
chrome.alarms?.create("report-flush", { periodInMinutes: 5 });
chrome.alarms?.onAlarm.addListener((alarm) => {
  if (alarm.name !== "report-flush") return;
  void initPromise.then(async () => {
    if (transport?.live !== true) return;
    const batch = (await idbDrainReports(500)) as FindingReportPayload[];
    for (const report of batch) {
      await transport.sendFindingReport(report).catch(() => idbEnqueueReport(report));
    }
  });
});
