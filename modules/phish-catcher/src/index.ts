/**
 * @aegisbastion/phish-catcher — neutral entry (phish-core + phish-url +
 * phish-content + phish-dom checks + phish-intel). No DOM or Node APIs are
 * touched at import time; the runtime-specific entries are `./browser`
 * (live-DOM extraction) and `./node` (.eml intake, CLI, hub transport).
 *
 * Doc 07 §2.1 package layout is mapped onto `src/` subdirectories:
 *   core/     → @aegisbastion/phish-core     (pipeline, registry, scoring, schemas)
 *   url/      → @aegisbastion/phish-url      (parsing, homograph, typosquat, tables)
 *   content/  → @aegisbastion/phish-content  (auth headers, lexicons, attachments)
 *   dom/      → @aegisbastion/phish-dom      (PageContext extraction, DOM checks)
 *   intel/    → @aegisbastion/phish-intel    (signed bundles, Bloom, store)
 *   node/     → @aegisbastion/phish-node     (see ./node entry)
 *   ext/      → @aegisbastion/phish-ext      (see tsup.ext.config.ts)
 *
 * Zero external transmission (doc 07 §7): nothing reachable from this entry
 * performs I/O. Enforced by the dependency-graph gate + the network-mocked
 * attestation test (test/no-egress*.test.ts).
 */

// --- phish-core -------------------------------------------------------------
export {
  CheckRegistry,
  EMPTY_INTEL,
  type Check,
  type CheckContext,
  type Deadline,
  type EmittedFinding,
  type IntelReaders,
} from "./core/check.js";
export {
  EVIDENCE_SCHEMA_VERSION,
  freezeEvidence,
  type AnchorMeta,
  type AttachmentMeta,
  type ClientMeta,
  type Evidence,
  type EvidenceKind,
  type FormEvidence,
  type IframeEvidence,
  type ImageMeta,
  type LinkEvidence,
  type MessageEvidence,
  type MessageHeaders,
  type PageEvidence,
  type UrlEvidence,
} from "./core/evidence.js";
export {
  defaultClientMeta,
  evidenceFromEmail,
  evidenceFromPage,
  withClientMeta,
  type EmailParts,
  type PageParts,
} from "./core/normalize.js";
export { Pipeline, type AnalyzeOptions } from "./core/pipeline.js";
export {
  DEFAULT_POLICY,
  POLICY_SCHEMA_VERSION,
  resolvePolicy,
  validatePolicyConfig,
  type PolicyConfig,
  type PolicyFamilyCaps,
  type PolicyTelemetry,
  type PolicyThresholds,
  type PolicyValidationError,
} from "./core/policy.js";
export { evaluateHardFails, scoreFindings, type ScoreResult } from "./core/scorer.js";
export { explain } from "./core/i18n.js";
export {
  EMPTY_FAMILY_SCORES,
  VERDICT_SCHEMA_VERSION,
  type CheckFamily,
  type Finding,
  type Severity,
  type Verdict,
  type VerdictHints,
  type VerdictLabel,
  type VerdictMeta,
} from "./core/verdict.js";
export { LIB_VERSION } from "./core/version.js";

// --- phish-url ---------------------------------------------------------------
export {
  URL_CHECKS,
  evidenceFromUrl,
  parseUrl,
  collectUrls,
  registeredDomainOf,
  isIpLiteral,
  skeleton,
  damerauLevenshtein,
  shannonEntropy,
  decodeHostLabels,
  decodePunycodeLabel,
  KNOWN_SHORTENERS,
  DEFAULT_TLD_RISK,
} from "./url/checks.js";
export {
  publicSuffixOf,
  isIpv4Literal,
  normalizeUrlForHash,
  domainLikeInText,
  MULTIPART_SUFFIXES,
  type AnchorInstance,
  type ParsedUrl,
  type UrlInstance,
  type UrlRole,
  type UrlSource,
} from "./url/parse.js";
export { extractUrlsFromText, extractAnchorsFromHtml, collectMessageUrls } from "./content/extract.js";

// --- phish-content -----------------------------------------------------------
export {
  CONTENT_CHECKS,
  parseAuthenticationResults,
  parseReceivedSpf,
  authResultFor,
  parseMailbox,
  domainOfAddress,
  htmlToText,
  messageText,
  urgencyScore,
  credentialRequestMatches,
  DEFAULT_URGENCY_LEXICON,
  CREDENTIAL_PATTERNS,
  classifyAttachment,
} from "./content/checks.js";
export type { AttachmentRisk, AttachmentRiskCategory } from "./content/attachments.js";

// --- phish-dom (checks + structural extraction; live-DOM adapter too) -------
export {
  DOM_CHECKS,
  extractPageEvidence,
  isOffOrigin,
  extractFromDocument,
  type ExtractionResult,
  type PageDom,
} from "./dom/checks.js";
export type {
  PageDomForm,
  PageDomIframe,
  PageDomInput,
  PageDomLink,
} from "./dom/page-context.js";

// --- phish-intel -------------------------------------------------------------
export { REP_CHECKS } from "./intel/checks.js";
export {
  BUNDLE_STALE_AFTER_MS,
  BUNDLE_VERSION_RE,
  INTEL_BUNDLE_SCHEMA_VERSION,
  bundleIsStale,
  compareBundleVersions,
  parseBundleVersion,
  validateIntelBundle,
  type BundleValidationError,
  type IntelBundle,
  type KeyRotation,
} from "./intel/bundle.js";
export {
  verifyIntelBundle,
  verifyPolicyConfig,
  type RejectReason,
  type VerifyBundleResult,
  type VerifyOptions,
  type VerifyPolicyResult,
  type VerifiedBundle,
} from "./intel/verify.js";
export { IntelStore, type ApplyResult, type IntelStoreOptions } from "./intel/store.js";
export { BloomFilter, ExactHashTable, blocklistEntry, fnv1a64 } from "./intel/bloom.js";
export {
  generateEd25519Keypair,
  importPinnedPublicKey,
  importPrivateKeyPkcs8,
  signBytes,
  verifyBytes,
  verifyJcs,
  type Ed25519Keypair,
} from "./intel/ed25519.js";
export { jcs } from "./intel/jcs.js";
export { sha256, sha256Hex, toHex, fromHex } from "./intel/sha256.js";
export {
  base64ToBytes,
  bytesToBase64,
  base64urlToBytes,
  bytesToBase64url,
  bytesToUtf8,
  utf8ToBytes,
} from "./intel/base64.js";

// --- assembly ----------------------------------------------------------------

import { CheckRegistry, type IntelReaders } from "./core/check.js";
import type { Evidence } from "./core/evidence.js";
import { evidenceFromEmail, evidenceFromPage, type EmailParts, type PageParts } from "./core/normalize.js";
import { Pipeline, type AnalyzeOptions } from "./core/pipeline.js";
import type { PolicyConfig } from "./core/policy.js";
import type { Verdict } from "./core/verdict.js";
import { URL_CHECKS, evidenceFromUrl } from "./url/checks.js";
import { CONTENT_CHECKS } from "./content/checks.js";
import { DOM_CHECKS } from "./dom/checks.js";
import { REP_CHECKS } from "./intel/checks.js";
import { IntelStore } from "./intel/store.js";
import type { ClientMeta } from "./core/evidence.js";

/** All MVP check rule ids (doc 07 §3.2 minus the three Later checks). */
export const MVP_CHECK_IDS: readonly string[] = [
  ...URL_CHECKS,
  ...CONTENT_CHECKS,
  ...DOM_CHECKS,
  ...REP_CHECKS,
].map((c) => c.id);

/**
 * A registry with every MVP check registered (doc 07 §11: all of §3.2 except
 * `content.qr_url`, `dom.favicon_brand_mismatch`, `rep.cert_age_suspicious`).
 */
export function createDefaultRegistry(): CheckRegistry {
  const registry = new CheckRegistry();
  for (const check of [...URL_CHECKS, ...CONTENT_CHECKS, ...DOM_CHECKS, ...REP_CHECKS]) {
    registry.register(check);
  }
  return registry;
}

export interface PhishCatcherOptions {
  /** Extra/custom checks (signed-bundle/extension code only, doc 07 §3.1). */
  extraChecks?: readonly import("./core/check.js").Check[];
  /** Intel store; when absent, reputation checks see empty intel. */
  intel?: IntelReaders;
  /** Default policy snapshot (compiled-in safe defaults when absent). */
  policy?: PolicyConfig | null;
}

/**
 * The detector facade: one pipeline over the default registry with
 * convenience normalizers for each input kind (doc 07 §2.2).
 */
export class PhishCatcher {
  readonly registry: CheckRegistry;
  readonly pipeline: Pipeline;
  private readonly intel?: IntelReaders;
  private readonly policy?: PolicyConfig | null;

  constructor(opts: PhishCatcherOptions = {}) {
    this.registry = createDefaultRegistry();
    for (const check of opts.extraChecks ?? []) this.registry.register(check);
    this.pipeline = new Pipeline(this.registry);
    if (opts.intel !== undefined) this.intel = opts.intel;
    if (opts.policy !== undefined) this.policy = opts.policy;
  }

  private baseOptions(opts: AnalyzeOptions = {}): AnalyzeOptions {
    return {
      policy: opts.policy ?? this.policy ?? null,
      intel: opts.intel ?? this.intel,
      degradedIntel: opts.degradedIntel ?? this.degraded(),
      ...(opts.extractionDegraded !== undefined ? { extractionDegraded: opts.extractionDegraded } : {}),
      ...(opts.explanationCount !== undefined ? { explanationCount: opts.explanationCount } : {}),
    };
  }

  private degraded(): boolean {
    const intel = this.intel;
    if (intel instanceof IntelStore) return intel.degraded();
    return false;
  }

  /** Analyze a frozen Evidence directly (doc 07 §2.2 step 2–3). */
  analyze(ev: Evidence, opts: AnalyzeOptions = {}): Verdict {
    return this.pipeline.analyze(ev, this.baseOptions(opts));
  }

  /** URL-only path (p95 ≤ 5 ms budget, doc 07 §2.3). */
  analyzeUrl(raw: string, opts: AnalyzeOptions & { clientMeta?: Partial<ClientMeta> } = {}): Verdict {
    const { clientMeta, ...rest } = opts;
    return this.analyze(evidenceFromUrl(raw, clientMeta), rest);
  }

  /** Email path from already-normalized parts. */
  analyzeEmail(parts: EmailParts, opts: AnalyzeOptions = {}): Verdict {
    return this.analyze(evidenceFromEmail(parts), opts);
  }

  /** Page path from already-normalized parts (browser DOM walk: ./browser). */
  analyzePage(parts: PageParts, opts: AnalyzeOptions = {}): Verdict {
    return this.analyze(evidenceFromPage(parts), opts);
  }
}

export function createPhishCatcher(opts: PhishCatcherOptions = {}): PhishCatcher {
  return new PhishCatcher(opts);
}
