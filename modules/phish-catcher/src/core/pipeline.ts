/**
 * The check engine (doc 07 §2.2 step 2 + §2.3 performance budget).
 *
 * Runs every enabled, applicable check against the frozen `Evidence`,
 * time-boxed per check (default 10 ms, policy-configurable): a check that
 * overruns is recorded in `checkTimeouts` and well-behaved checks poll the
 * deadline token and return early — the pipeline never blocks. Check
 * exceptions are contained (recorded in `meta.checkErrors`); the pipeline
 * itself never throws.
 */

import { EMPTY_INTEL, type Check, type CheckContext, type CheckRegistry, type Deadline, type IntelReaders } from "./check.js";
import type { Evidence } from "./evidence.js";
import { resolvePolicy, type PolicyConfig } from "./policy.js";
import { scoreFindings } from "./scorer.js";
import { VERDICT_SCHEMA_VERSION, type Finding, type Verdict, type VerdictHints } from "./verdict.js";

export interface AnalyzeOptions {
  /** Policy snapshot; compiled-in safe defaults when absent (doc 07 §9). */
  policy?: PolicyConfig | null;
  /** Intel readers; empty intel when no bundle is applied. */
  intel?: IntelReaders;
  /** Stale-bundle degraded mode (doc 07 §9): reputation family weight → 0. */
  degradedIntel?: boolean;
  /** Extraction self-test failure (doc 07 §9): raw-HTML fallback was used. */
  extractionDegraded?: boolean;
  /** Max explanations (default 5). */
  explanationCount?: number;
}

function now(): number {
  return globalThis.performance?.now() ?? Date.now();
}

class Timebox implements Deadline {
  private readonly start = now();
  constructor(private readonly budgetMs: number) {}
  expired(): boolean {
    return now() - this.start > this.budgetMs;
  }
  remainingMs(): number {
    return Math.max(0, this.budgetMs - (now() - this.start));
  }
}

function applies(check: Check, ev: Evidence): boolean {
  return check.requires.every((field) => ev[field] !== undefined);
}

export class Pipeline {
  constructor(private readonly registry: CheckRegistry) {}

  analyze(ev: Evidence, opts: AnalyzeOptions = {}): Verdict {
    const started = now();
    const policy = resolvePolicy(opts.policy);
    const intel = opts.intel ?? EMPTY_INTEL;
    const degradedIntel = opts.degradedIntel === true;
    const timeboxMs = policy.checkTimeboxMs ?? 10;

    const findings: Finding[] = [];
    const checkTimeouts: string[] = [];
    const checkErrors: Record<string, string> = {};

    for (const check of this.registry.enabled(policy)) {
      if (!applies(check, ev)) continue;
      const deadline = new Timebox(timeboxMs);
      const ctx: CheckContext = { intel, policy, deadline, degradedIntel };
      const t0 = now();
      let emitted;
      try {
        emitted = check.run(ev, ctx);
      } catch (err) {
        // A throwing check must never take the pipeline down (§2.3).
        checkErrors[check.id] = err instanceof Error ? err.message : String(err);
        continue;
      }
      const elapsed = now() - t0;
      if (elapsed > timeboxMs) checkTimeouts.push(check.id);
      for (const f of emitted) {
        const weight =
          policy.weightOverrides[check.id] ?? f.weight ?? check.defaultWeight;
        const stamped: Finding = { ...f, weight };
        // Degraded mode (doc 07 §9): reputation family weight → 0.
        if (degradedIntel && check.family === "reputation") stamped.weight = 0;
        findings.push(stamped);
      }
    }

    const scored = scoreFindings(findings, ev, policy, opts.explanationCount ?? 5);

    const hints: VerdictHints[] = [];
    // §1/§5.3: the client never fetches; it hints the separately-authorized
    // sandbox. URL-only non-clean verdicts and any malicious verdict hint.
    if (scored.verdict === "malicious" || (scored.verdict === "suspicious" && ev.kind === "url")) {
      hints.push({ sandbox_recommended: true });
    }

    const meta: NonNullable<Verdict["meta"]> = {};
    if (degradedIntel) meta.degradedIntel = true;
    if (opts.extractionDegraded) meta.extractionDegraded = true;
    if (Object.keys(checkErrors).length > 0) meta.checkErrors = checkErrors;

    return {
      schemaVersion: VERDICT_SCHEMA_VERSION,
      verdict: scored.verdict,
      score: scored.score,
      familyScores: scored.familyScores,
      hardFail: scored.hardFail,
      hardFailReasons: scored.hardFailReasons,
      findings,
      explanations: scored.explanations,
      hints,
      timingMs: Math.round((now() - started) * 100) / 100,
      checkTimeouts,
      clientMeta: {
        libVersion: ev.clientMeta.libVersion,
        bundleVersion: intel.bundleVersion(),
        policyVersion: policy.policyVersion,
      },
      ...(Object.keys(meta).length > 0 ? { meta } : {}),
    };
  }
}
