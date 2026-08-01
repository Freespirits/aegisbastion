/**
 * Shared test fixtures/helpers: fake intel readers, a single-check runner,
 * signed bundle/policy builders, and evidence builders.
 */

import type { Check, CheckContext, EmittedFinding, IntelReaders } from "../src/core/check.js";
import type { Evidence } from "../src/core/evidence.js";
import { DEFAULT_POLICY, type PolicyConfig } from "../src/core/policy.js";
import { BloomFilter, ExactHashTable, blocklistEntry } from "../src/intel/bloom.js";
import { jcs } from "../src/intel/jcs.js";
import { sha256, toHex } from "../src/intel/sha256.js";
import { utf8ToBytes } from "../src/intel/base64.js";
import { generateEd25519Keypair, importPrivateKeyPkcs8, signBytes, type Ed25519Keypair } from "../src/intel/ed25519.js";
import type { IntelBundle } from "../src/intel/bundle.js";

export function fakeDeadline(budgetMs = 10_000) {
  const start = Date.now();
  return {
    expired: () => Date.now() - start > budgetMs,
    remainingMs: () => Math.max(0, budgetMs - (Date.now() - start)),
  };
}

export function fakeIntel(overrides: Partial<IntelReaders> = {}): IntelReaders {
  return {
    isDomainBlocklisted: () => false,
    isUrlBlocklisted: () => false,
    isSenderBlocklisted: () => false,
    brandDomains: () => ["paypal.com", "example.com", "microsoft.com", "chase.com"],
    tldRiskTable: () => ({}),
    confusables: () => ({}),
    urgencyLexicon: () => null,
    bundleVersion: () => "2026.07.30-1",
    ...overrides,
  };
}

export function runCheck(
  check: Check,
  ev: Evidence,
  intel: IntelReaders = fakeIntel(),
  policy: PolicyConfig = { ...DEFAULT_POLICY, disabledChecks: [], weightOverrides: {} },
): EmittedFinding[] {
  const ctx: CheckContext = { intel, policy, deadline: fakeDeadline(), degradedIntel: false };
  return check.run(ev, ctx);
}

export function ruleIds(findings: readonly { ruleId: string }[]): string[] {
  return [...new Set(findings.map((f) => f.ruleId))];
}

// --- signed bundle/policy builders -------------------------------------------

export interface BundleSpec {
  version?: string;
  issuedAt?: string;
  expiresAt?: string;
  domains?: string[];
  urls?: string[];
  senders?: string[];
  brands?: string[];
  tldRiskTable?: Record<string, number>;
  urgencyLexicon?: Record<string, number>;
  /** §8.6 dual-signed rotation — included IN the signed body. */
  nextKey?: { publicKey: string; signature: string };
}

export async function makeKeypair(): Promise<Ed25519Keypair> {
  return generateEd25519Keypair();
}

/** Build + sign a valid IntelBundle carrying the given blocklist entries. */
export async function buildSignedBundle(keys: Ed25519Keypair, spec: BundleSpec = {}): Promise<IntelBundle> {
  const entries = [
    ...(spec.domains ?? []).map((d) => blocklistEntry.domain(d)),
    ...(spec.urls ?? []).map((u) => blocklistEntry.url(u)),
    ...(spec.senders ?? []).map((s) => blocklistEntry.sender(s)),
  ];
  const bloom = BloomFilter.create(Math.max(8, entries.length));
  for (const e of entries) bloom.add(e);
  const exact = ExactHashTable.fromHexList(entries.map((e) => toHex(sha256(utf8ToBytes(e)))));
  const body: Record<string, unknown> = {
    schemaVersion: 1,
    bundleVersion: spec.version ?? "2026.07.30-1",
    issuedAt: spec.issuedAt ?? new Date(Date.now() - 60_000).toISOString(),
    expiresAt: spec.expiresAt ?? new Date(Date.now() + 7 * 24 * 3600_000).toISOString(),
    blocklistBloom: bloom.toBase64(),
    blocklistExact: exact.toBase64(),
    brandDomains: spec.brands ?? ["paypal.com", "example.com"],
    ...(spec.tldRiskTable ? { tldRiskTable: spec.tldRiskTable } : {}),
    ...(spec.urgencyLexicon ? { urgencyLexicon: spec.urgencyLexicon } : {}),
    ...(spec.nextKey ? { nextKey: spec.nextKey } : {}),
  };
  const priv = await importPrivateKeyPkcs8(keys.privateKeyPkcs8);
  const signature = await signBytes(priv, utf8ToBytes(jcs(body)));
  return { ...body, signature } as unknown as IntelBundle;
}

export async function signDocument(keys: Ed25519Keypair, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const priv = await importPrivateKeyPkcs8(keys.privateKeyPkcs8);
  const signature = await signBytes(priv, utf8ToBytes(jcs(body)));
  return { ...body, signature };
}

/** A valid unsigned policy body (sign via signDocument). */
export function policyBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    policyVersion: 7,
    issuedAt: new Date(Date.now() - 60_000).toISOString(),
    expiresAt: new Date(Date.now() + 30 * 24 * 3600_000).toISOString(),
    thresholds: { malicious: 70, suspicious: 35 },
    familyCaps: { url: 40, dom: 35, content: 30, auth: 35, reputation: 100 },
    disabledChecks: [],
    weightOverrides: {},
    telemetry: { enabled: false, includeUrlHashes: true, includeBodySnippets: false },
    ...overrides,
  };
}
