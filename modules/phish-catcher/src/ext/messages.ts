/**
 * chrome.runtime message contracts between the content script, service
 * worker, popup, and options page (doc 07 §6.3). The service worker owns the
 * intel store + policy (one copy, MV3 memory budget); content scripts ship
 * structural PageDom snapshots for analysis.
 */

import type { PageDom } from "../dom/page-context.js";
import type { Verdict } from "../core/verdict.js";
import type { FindingReportPayload } from "../hub/messages.js";

export type ExtRequest =
  | { type: "analyze-page"; tabId?: number; page: PageDom; expectContent?: boolean }
  | { type: "analyze-url"; url: string }
  | { type: "get-tab-verdict"; tabId: number }
  | { type: "get-state" }
  | { type: "set-telemetry"; enabled: boolean }
  | { type: "set-local-brands"; domains: string[] }
  | { type: "set-dev-mode"; enabled: boolean }
  | { type: "apply-intel"; document: unknown; pin: string }
  | { type: "report-finding"; tabId: number };

export interface TabVerdictState {
  verdict: Verdict;
  url: string;
  analyzedAt: string;
}

export interface ExtState {
  bundleVersion: string;
  policyVersion: number;
  degraded: boolean;
  telemetryEnabled: boolean;
  reportsQueued: number;
  devMode: boolean;
  pins: string[];
  localBrands: string[];
}

export type ExtResponse =
  | { ok: true; verdict: Verdict }
  | { ok: true; tabVerdict: TabVerdictState | null }
  | { ok: true; state: ExtState }
  | { ok: true; report: FindingReportPayload }
  | { ok: true }
  | { ok: false; error: string };

export function isExtRequest(v: unknown): v is ExtRequest {
  return typeof v === "object" && v !== null && typeof (v as { type?: unknown }).type === "string";
}
