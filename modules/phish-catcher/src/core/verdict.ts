/**
 * `Verdict` — the pipeline output (doc 07 §4.2, JSON Schema in
 * schemas/verdict/v1/schema.json). Every verdict carries human-readable
 * `explanations` (i18n-rendered, EN at MVP) — no black-box scores (§3.3).
 */

export const VERDICT_SCHEMA_VERSION = 1 as const;

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type CheckFamily = "url" | "dom" | "content" | "auth" | "reputation";

export interface Finding {
  /** Stable rule id (doc 07 §3.2 normative ids), e.g. "url.idn_homograph". */
  ruleId: string;
  severity: Severity;
  /** 0–100 contribution before the family cap (stamped by the engine). */
  weight: number;
  /** Human-readable detail string (evidence excerpt, never the full body). */
  detail: string;
  /**
   * Machine-readable markers consumed by the normative hard-fail rules
   * (doc 07 §3.3): "exact" (rep.url_blocklisted exact-hash confirm),
   * "brand_host" (dom.password_form_offdomain on a brand-listed domain).
   */
  flags?: string[];
}

export type VerdictLabel = "clean" | "suspicious" | "malicious";

export interface VerdictHints {
  /**
   * Data, not an action (doc 07 §8.5): execution belongs to the
   * orchestrator's separately-authorized sandbox module. Phish-Catcher
   * never fetches.
   */
  sandbox_recommended?: boolean;
}

export interface VerdictMeta {
  /** Set when the intel bundle is stale (doc 07 §9): reputation weight → 0. */
  degradedIntel?: boolean;
  /** Set when DOM extraction self-test failed (doc 07 §9). */
  extractionDegraded?: boolean;
  /** Check id → error message for checks that threw (contained, §2.3). */
  checkErrors?: Record<string, string>;
  [key: string]: unknown;
}

export interface Verdict {
  schemaVersion: typeof VERDICT_SCHEMA_VERSION;
  verdict: VerdictLabel;
  /** 0–100 additive score after per-family caps. */
  score: number;
  familyScores: Record<CheckFamily, number>;
  hardFail: boolean;
  hardFailReasons: string[];
  findings: Finding[];
  /** Top-N contributing findings rendered from i18n templates (EN). */
  explanations: string[];
  hints: VerdictHints[];
  timingMs: number;
  /** Ids of checks that exceeded their time-box (doc 07 §2.3). */
  checkTimeouts: string[];
  clientMeta: import("./evidence.js").ClientMeta;
  meta?: VerdictMeta;
}

export const EMPTY_FAMILY_SCORES: Record<CheckFamily, number> = {
  url: 0,
  dom: 0,
  content: 0,
  auth: 0,
  reputation: 0,
};
