/**
 * Scorer (doc 07 §3.3): per-family weight caps, additive score, hard-fail
 * overrides, threshold mapping, top-N explanations.
 *
 * Hard-fail rules (normative, §3.3):
 *  1. `rep.url_blocklisted` exact match (finding carries the "exact" flag).
 *  2. `dom.password_form_offdomain` on a brand-listed domain (finding carries
 *     the "brand_host" flag — the check computes brand-list membership
 *     against the intel bundle).
 *  3. `auth.dmarc_fail` + `content.credential_request` co-occurrence.
 */

import type { Evidence } from "./evidence.js";
import { explain } from "./i18n.js";
import type { PolicyConfig } from "./policy.js";
import { EMPTY_FAMILY_SCORES, type CheckFamily, type Finding, type Severity, type VerdictLabel } from "./verdict.js";

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface ScoreResult {
  verdict: VerdictLabel;
  score: number;
  familyScores: Record<CheckFamily, number>;
  hardFail: boolean;
  hardFailReasons: string[];
  explanations: string[];
}

/** The normative hard-fail evaluation (doc 07 §3.3). */
export function evaluateHardFails(findings: Finding[]): string[] {
  const reasons: string[] = [];
  const byRule = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byRule.get(f.ruleId) ?? [];
    list.push(f);
    byRule.set(f.ruleId, list);
  }
  for (const f of byRule.get("rep.url_blocklisted") ?? []) {
    if (f.flags?.includes("exact")) {
      reasons.push("rep.url_blocklisted exact match");
      break;
    }
  }
  for (const f of byRule.get("dom.password_form_offdomain") ?? []) {
    if (f.flags?.includes("brand_host")) {
      reasons.push("dom.password_form_offdomain on a brand-listed domain");
      break;
    }
  }
  if (byRule.has("auth.dmarc_fail") && byRule.has("content.credential_request")) {
    reasons.push("auth.dmarc_fail + content.credential_request co-occurrence");
  }
  return reasons;
}

export function scoreFindings(
  findings: Finding[],
  _ev: Evidence,
  policy: PolicyConfig,
  explanationCount = 5,
): ScoreResult {
  const familyScores: Record<CheckFamily, number> = { ...EMPTY_FAMILY_SCORES };
  for (const f of findings) {
    const family = f.ruleId.split(".")[0] as CheckFamily;
    if (!(family in familyScores)) continue;
    familyScores[family] += f.weight;
  }
  let score = 0;
  for (const fam of Object.keys(familyScores) as CheckFamily[]) {
    const cap = policy.familyCaps[fam];
    familyScores[fam] = Math.min(familyScores[fam], cap);
    score += familyScores[fam];
  }
  score = Math.min(100, score);

  const hardFailReasons = evaluateHardFails(findings);
  const hardFail = hardFailReasons.length > 0;

  let verdict: VerdictLabel;
  if (hardFail || score >= policy.thresholds.malicious) verdict = "malicious";
  else if (score >= policy.thresholds.suspicious) verdict = "suspicious";
  else verdict = "clean";

  const ranked = [...findings]
    .filter((f) => f.weight > 0)
    .sort((a, b) => b.weight - a.weight || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  const explanations = ranked.slice(0, explanationCount).map(explain);

  return { verdict, score, familyScores, hardFail, hardFailReasons, explanations };
}
