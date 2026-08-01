/**
 * `IntelBundle` (doc 07 §4.4; JSON Schema in schemas/intel-bundle/v1/):
 * signed, versioned, offline reputation. Bundles are verified against pinned
 * hub public keys (two pinned for rotation), monotonically versioned
 * (rollback rejected), and expiry-checked: a stale bundle flips the library
 * into `degraded_mode` (§9).
 */

export const INTEL_BUNDLE_SCHEMA_VERSION = 1 as const;

/** Staleness bound (§4.4/§9): a bundle older than 14 days → degraded_mode. */
export const BUNDLE_STALE_AFTER_MS = 14 * 24 * 60 * 60 * 1000;

export interface KeyRotation {
  /** base64url raw Ed25519 public key to adopt as a new pin. */
  publicKey: string;
  /**
   * Ed25519 signature (base64url) over JCS({publicKey}) by the SAME key that
   * signed this bundle — the dual-signed (old+new) rotation (§8.6).
   */
  signature: string;
}

export interface IntelBundle {
  schemaVersion: typeof INTEL_BUNDLE_SCHEMA_VERSION;
  /** Monotonic version "YYYY.MM.DD-N" (rollback rejected). */
  bundleVersion: string;
  issuedAt: string;
  expiresAt: string;
  /** base64 Bloom wire format (see bloom.ts). */
  blocklistBloom: string;
  /** base64 sorted 32-byte SHA-256 digests (exact-hash confirm table). */
  blocklistExact: string;
  brandDomains: string[];
  /** base64 UTF-8 JSON {char: canonical} — extends the compiled-in skeleton. */
  confusablesMap?: string;
  tldRiskTable?: Record<string, number>;
  /** Later (§11): DKIM selector/TXT snapshots for local verification. */
  dkimKeyCache?: Record<string, string>;
  /** i18n urgency lexicon overlay (§3.2: lexicon in bundle). */
  urgencyLexicon?: Record<string, number>;
  /** Extra multi-part public suffixes for PSL-lite. */
  publicSuffixes?: string[];
  /** Dual-signed key rotation (§8.6). */
  nextKey?: KeyRotation;
  /** base64url Ed25519 signature over JCS(bundle minus signature). */
  signature: string;
}

export interface BundleValidationError {
  field: string;
  message: string;
}

export const BUNDLE_VERSION_RE = /^(\d{4})\.(\d{2})\.(\d{2})-(\d+)$/;

/** Parse "YYYY.MM.DD-N" into a comparable tuple; null when malformed. */
export function parseBundleVersion(v: string): [number, number, number, number] | null {
  const m = BUNDLE_VERSION_RE.exec(v);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
}

/** -1/0/1 comparison of two bundle versions; null when either is malformed. */
export function compareBundleVersions(a: string, b: string): number | null {
  const pa = parseBundleVersion(a);
  const pb = parseBundleVersion(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 4; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** Fail-closed structural validation (signature check lives in verify.ts). */
export function validateIntelBundle(raw: unknown): BundleValidationError[] {
  const errors: BundleValidationError[] = [];
  const rec = (v: unknown): v is Record<string, unknown> =>
    typeof v === "object" && v !== null && !Array.isArray(v);
  if (!rec(raw)) return [{ field: "$", message: "bundle is not an object" }];
  if (raw.schemaVersion !== INTEL_BUNDLE_SCHEMA_VERSION) {
    errors.push({ field: "schemaVersion", message: `must be ${INTEL_BUNDLE_SCHEMA_VERSION}` });
  }
  if (typeof raw.bundleVersion !== "string" || parseBundleVersion(raw.bundleVersion) === null) {
    errors.push({ field: "bundleVersion", message: "must match YYYY.MM.DD-N" });
  }
  for (const f of ["issuedAt", "expiresAt"] as const) {
    if (typeof raw[f] !== "string" || Number.isNaN(Date.parse(raw[f] as string))) {
      errors.push({ field: f, message: "must be an ISO-8601 timestamp" });
    }
  }
  for (const f of ["blocklistBloom", "signature"] as const) {
    if (typeof raw[f] !== "string" || (raw[f] as string).length === 0) {
      errors.push({ field: f, message: "must be a non-empty base64 string" });
    }
  }
  // The exact-confirm table may legitimately be empty (zero-entry blocklist).
  if (typeof raw.blocklistExact !== "string") {
    errors.push({ field: "blocklistExact", message: "must be a base64 string" });
  }
  if (!Array.isArray(raw.brandDomains) || !raw.brandDomains.every((d) => typeof d === "string" && d.includes("."))) {
    errors.push({ field: "brandDomains", message: "must be an array of domains" });
  }
  if (raw.confusablesMap !== undefined && typeof raw.confusablesMap !== "string") {
    errors.push({ field: "confusablesMap", message: "must be base64" });
  }
  for (const f of ["tldRiskTable", "urgencyLexicon"] as const) {
    if (raw[f] !== undefined) {
      const t = raw[f];
      if (!rec(t) || !Object.values(t).every((v) => typeof v === "number" && v >= 0 && v <= 100)) {
        errors.push({ field: f, message: "must map strings to 0–100 numbers" });
      }
    }
  }
  if (raw.dkimKeyCache !== undefined && !rec(raw.dkimKeyCache)) {
    errors.push({ field: "dkimKeyCache", message: "must be an object" });
  }
  if (raw.publicSuffixes !== undefined && (!Array.isArray(raw.publicSuffixes) || !raw.publicSuffixes.every((s) => typeof s === "string"))) {
    errors.push({ field: "publicSuffixes", message: "must be a string array" });
  }
  if (raw.nextKey !== undefined) {
    if (!rec(raw.nextKey) || typeof raw.nextKey.publicKey !== "string" || typeof raw.nextKey.signature !== "string") {
      errors.push({ field: "nextKey", message: "must carry publicKey + signature" });
    }
  }
  return errors;
}

/**
 * Staleness (§4.4/§9): older than 14 days past issue, or past expiresAt —
 * whichever comes first. Stale bundles still verify (integrity ≠ freshness);
 * the store flips to degraded_mode instead of rejecting.
 */
export function bundleIsStale(bundle: Pick<IntelBundle, "issuedAt" | "expiresAt">, now: Date): boolean {
  const issued = Date.parse(bundle.issuedAt);
  const expires = Date.parse(bundle.expiresAt);
  const t = now.getTime();
  return t > expires || t > issued + BUNDLE_STALE_AFTER_MS;
}
