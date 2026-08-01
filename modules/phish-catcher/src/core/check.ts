/**
 * The Check contract (doc 07 §3.1) and the check registry.
 *
 * Checks are PURE and SYNCHRONOUS (WASM checks — async, awaited in parallel —
 * are a Later item, §3.2 `content.qr_url`). No check may perform I/O (§12).
 * Third parties may register custom checks, but only from code shipped inside
 * the signed bundle/extension — never dynamic remote code (§3.1; MV3 CSP
 * enforces this too).
 */

import type { Evidence } from "./evidence.js";
import type { PolicyConfig } from "./policy.js";
import type { CheckFamily, Finding } from "./verdict.js";

/** Finding as emitted by a check; the engine stamps weight when absent. */
export type EmittedFinding = Omit<Finding, "weight"> & { weight?: number };

/** Per-check deadline token (doc 07 §2.3): checks poll it in long loops. */
export interface Deadline {
  /** True once the check's time-box has elapsed. */
  expired(): boolean;
  /** Milliseconds remaining (0 once expired). */
  remainingMs(): number;
}

/** Intel readers the checks consume (implemented by phish-intel). */
export interface IntelReaders {
  /** Bloom + exact-hash confirm for a canonicalized domain (host). */
  isDomainBlocklisted(domain: string): boolean;
  /** Bloom + exact-hash confirm for a normalized URL string. */
  isUrlBlocklisted(url: string): boolean;
  /** Bloom + exact-hash confirm for a sender address. */
  isSenderBlocklisted(sender: string): boolean;
  /** Brand domains (lowercase registered domains) from the bundle. */
  brandDomains(): readonly string[];
  /** Ranked TLD risk table (tld → 0–100 risk weight). */
  tldRiskTable(): Readonly<Record<string, number>>;
  /** Extra confusable skeleton entries from the bundle (char → canonical). */
  confusables(): Readonly<Record<string, string>>;
  /**
   * Urgency lexicon overlay from the bundle (doc 07 §3.2: lexicon in bundle
   * for i18n); null → compiled-in EN default.
   */
  urgencyLexicon(): Readonly<Record<string, number>> | null;
  /** Bundle version string carried into clientMeta/verdicts. */
  bundleVersion(): string;
}

/** An IntelReaders with empty intel — used when no bundle is applied. */
export const EMPTY_INTEL: IntelReaders = {
  isDomainBlocklisted: () => false,
  isUrlBlocklisted: () => false,
  isSenderBlocklisted: () => false,
  brandDomains: () => [],
  tldRiskTable: () => ({}),
  confusables: () => ({}),
  urgencyLexicon: () => null,
  bundleVersion: () => "none",
};

export interface CheckContext {
  intel: IntelReaders;
  policy: PolicyConfig;
  deadline: Deadline;
  /**
   * True when the intel bundle is stale (doc 07 §9 degraded_mode): the
   * reputation family weight is zeroed by the engine and this flag lets
   * checks skip expensive reputation work.
   */
  degradedIntel: boolean;
}

export interface Check {
  /** Stable rule id (normative, doc 07 §3.2), e.g. "url.idn_homograph". */
  id: string;
  /** Bumped on logic change (audit trail). */
  version: number;
  family: CheckFamily;
  /** Engine skips the check when Evidence lacks any of these fields. */
  requires: (keyof Evidence)[];
  /** 0–100 contribution before the family cap; policy may override. */
  defaultWeight: number;
  run(ev: Evidence, ctx: CheckContext): EmittedFinding[];
}

export class CheckRegistry {
  private readonly checks = new Map<string, Check>();

  register(check: Check): this {
    const existing = this.checks.get(check.id);
    if (existing && existing.version >= check.version) {
      throw new Error(
        `check ${check.id} already registered at version ${existing.version}; ` +
          `refusing downgrade/re-register to ${check.version}`,
      );
    }
    this.checks.set(check.id, check);
    return this;
  }

  has(id: string): boolean {
    return this.checks.has(id);
  }

  get(id: string): Check | undefined {
    return this.checks.get(id);
  }

  /** Enabled checks for a policy snapshot (disabledChecks honored). */
  enabled(policy: PolicyConfig): Check[] {
    const disabled = new Set(policy.disabledChecks);
    return [...this.checks.values()].filter((c) => !disabled.has(c.id));
  }

  ids(): string[] {
    return [...this.checks.keys()];
  }
}
