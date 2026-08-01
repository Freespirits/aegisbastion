/**
 * IntelStore (phish-intel, doc 07 §2.1): holds the last-good verified bundle
 * + policy, exposes the `IntelReaders` the checks consume, and implements the
 * §9 failure semantics:
 *
 *  - signature invalid / rollback → reject, KEEP LAST GOOD, caller audits
 *    `INTEGRITY_FAILURE`;
 *  - stale bundle (> 14 d / expired) → applied but `degraded()` → true:
 *    heuristic checks continue, reputation family weight → 0 (the pipeline
 *    enforces the zeroing via `degradedIntel`);
 *  - valid fresher bundle → atomically replaces state; `nextKey` rotation
 *    (dual-signed) is adopted as an additional pin (§8.6).
 *  - expired policy → rejected; fall back to last non-expired policy, else
 *    compiled-in safe defaults (§9).
 */

import type { IntelReaders } from "../core/check.js";
import { DEFAULT_POLICY, resolvePolicy, type PolicyConfig } from "../core/policy.js";
import { base64ToBytes, bytesToUtf8, utf8ToBytes } from "./base64.js";
import { blocklistEntry, BloomFilter, ExactHashTable } from "./bloom.js";
import type { IntelBundle } from "./bundle.js";
import { sha256 } from "./sha256.js";
import { verifyIntelBundle, verifyPolicyConfig, type RejectReason, type VerifyOptions } from "./verify.js";
import { normalizeUrlForHash } from "../url/parse.js";

export interface ApplyResult {
  applied: boolean;
  reason?: RejectReason;
  /** §9: integrity OK but the freshness window is exceeded. */
  stale?: boolean;
  /** True when the caller should write an INTEGRITY_FAILURE audit record. */
  integrityFailure?: boolean;
  rotationAdopted?: string;
  errors?: { field: string; message: string }[];
}

interface BundleState {
  version: string;
  bloom: BloomFilter;
  exact: ExactHashTable;
  brands: string[];
  confusables: Record<string, string>;
  tldRisk: Record<string, number>;
  lexicon: Record<string, number> | null;
  stale: boolean;
}

export interface IntelStoreOptions {
  /** base64url raw Ed25519 pinned hub public keys (two for rotation, §4.4). */
  pinnedKeys: readonly string[];
  /** Test hook / deterministic clock. */
  now?: () => Date;
}

export class IntelStore implements IntelReaders {
  private readonly pins: string[];
  private readonly now: () => Date;
  private state: BundleState | null = null;
  private currentPolicy: PolicyConfig | null = null;
  private localBrands: string[] = [];

  constructor(opts: IntelStoreOptions) {
    this.pins = [...opts.pinnedKeys];
    this.now = opts.now ?? (() => new Date());
  }

  /** The current pin set (original pins + adopted rotations). */
  pinnedKeys(): readonly string[] {
    return this.pins;
  }

  /** Verify + apply a signed bundle. Never throws; fail-closed. */
  async applyBundle(raw: unknown): Promise<ApplyResult> {
    const verifyOpts: VerifyOptions = {
      pinnedKeys: this.pins,
      ...(this.state ? { currentBundleVersion: this.state.version } : {}),
      now: this.now(),
    };
    const res = await verifyIntelBundle(raw, verifyOpts);
    if (!res.ok || !res.bundle) {
      // §9: reject, keep last good; INTEGRITY_FAILURE audit is the caller's job.
      return {
        applied: false,
        ...(res.reason !== undefined ? { reason: res.reason } : {}),
        integrityFailure: res.reason === "SIGNATURE_INVALID" || res.reason === "ROLLBACK" || res.reason === "ROTATION_SIGNATURE_INVALID",
        ...(res.errors !== undefined ? { errors: res.errors } : {}),
      };
    }
    const next = this.materialize(res.bundle, res.stale === true);
    if (!next.ok) {
      return { applied: false, reason: "SCHEMA_INVALID", integrityFailure: true, errors: next.errors };
    }
    this.state = next.state;
    let rotationAdopted: string | undefined;
    if (res.rotation && !this.pins.includes(res.rotation.publicKey)) {
      this.pins.push(res.rotation.publicKey);
      rotationAdopted = res.rotation.publicKey;
    }
    return { applied: true, stale: res.stale === true, ...(rotationAdopted !== undefined ? { rotationAdopted } : {}) };
  }

  /** Decode bundle payloads into reader state (malformed payloads = reject). */
  private materialize(
    bundle: IntelBundle,
    stale: boolean,
  ): { ok: true; state: BundleState } | { ok: false; errors: { field: string; message: string }[] } {
    try {
      const bloom = BloomFilter.fromBase64(bundle.blocklistBloom);
      const exact = ExactHashTable.fromBase64(bundle.blocklistExact);
      let confusables: Record<string, string> = {};
      if (bundle.confusablesMap !== undefined && bundle.confusablesMap !== "") {
        const parsed: unknown = JSON.parse(bytesToUtf8(base64ToBytes(bundle.confusablesMap)));
        if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
          for (const [k, v] of Object.entries(parsed)) {
            if (typeof v === "string") confusables[k] = v;
          }
        }
      }
      return {
        ok: true,
        state: {
          version: bundle.bundleVersion,
          bloom,
          exact,
          brands: bundle.brandDomains.map((d) => d.toLowerCase()),
          confusables,
          tldRisk: { ...(bundle.tldRiskTable ?? {}) },
          lexicon: bundle.urgencyLexicon ? { ...bundle.urgencyLexicon } : null,
          stale,
        },
      };
    } catch (err) {
      return {
        ok: false,
        errors: [{ field: "payloads", message: err instanceof Error ? err.message : String(err) }],
      };
    }
  }

  /** Verify + apply a signed PolicyConfig (§4.3, §5.2 policy.push). */
  async applyPolicy(raw: unknown): Promise<ApplyResult> {
    const res = await verifyPolicyConfig(raw, {
      pinnedKeys: this.pins,
      ...(this.currentPolicy ? { currentPolicyVersion: this.currentPolicy.policyVersion } : {}),
      now: this.now(),
    });
    if (!res.ok || !res.policy) {
      return {
        applied: false,
        ...(res.reason !== undefined ? { reason: res.reason } : {}),
        integrityFailure: res.reason === "SIGNATURE_INVALID" || res.reason === "ROLLBACK",
        ...(res.errors !== undefined ? { errors: res.errors } : {}),
      };
    }
    this.currentPolicy = res.policy;
    return { applied: true };
  }

  /** Current policy: last non-expired, else compiled-in safe defaults (§9). */
  policy(): PolicyConfig {
    if (this.currentPolicy && Date.parse(this.currentPolicy.expiresAt) > this.now().getTime()) {
      return resolvePolicy(this.currentPolicy);
    }
    return resolvePolicy(null);
  }

  /** §9 degraded_mode: bundle missing or stale. */
  degraded(): boolean {
    return this.state === null || this.state.stale;
  }

  /** Consumer-side local brand-list additions (options page, §6.3). */
  addLocalBrands(domains: string[]): void {
    for (const d of domains) {
      const lower = d.toLowerCase();
      if (lower.includes(".") && !this.localBrands.includes(lower)) this.localBrands.push(lower);
    }
  }

  // --- IntelReaders ---------------------------------------------------------

  private confirmed(entry: string): boolean {
    if (this.state === null) return false;
    if (!this.state.bloom.has(entry)) return false;
    // Bloom positive → exact-hash confirm removes false positives (§3.2).
    return this.state.exact.hasDigest(sha256(utf8ToBytes(entry)));
  }

  isDomainBlocklisted(domain: string): boolean {
    return this.confirmed(blocklistEntry.domain(domain));
  }

  isUrlBlocklisted(url: string): boolean {
    return this.confirmed(blocklistEntry.url(normalizeUrlForHash(url)));
  }

  isSenderBlocklisted(sender: string): boolean {
    return this.confirmed(blocklistEntry.sender(sender));
  }

  brandDomains(): readonly string[] {
    return [...(this.state?.brands ?? []), ...this.localBrands];
  }

  tldRiskTable(): Readonly<Record<string, number>> {
    return this.state?.tldRisk ?? {};
  }

  confusables(): Readonly<Record<string, string>> {
    return this.state?.confusables ?? {};
  }

  urgencyLexicon(): Readonly<Record<string, number>> | null {
    return this.state?.lexicon ?? null;
  }

  bundleVersion(): string {
    return this.state?.version ?? "none";
  }
}
