/**
 * `PolicyConfig` — hub-pushed, signed (doc 07 §4.3; JSON Schema in
 * schemas/policy/v1/schema.json). Thresholds, family caps, per-check
 * enablement, weight overrides, telemetry posture. Unsigned local overrides
 * are allowed only in devMode (§3.3); production policy is verified against
 * pinned hub keys by phish-intel (`verifyPolicy`).
 *
 * Signature: Ed25519 over the JCS-canonical (RFC 8785, doc 01 §10.2) JSON of
 * the policy with the `signature` field removed — the platform's single
 * canonicalization (doc 07 §12: "Do not invent a second canonicalization").
 */

export const POLICY_SCHEMA_VERSION = 1 as const;

export interface PolicyThresholds {
  malicious: number;
  suspicious: number;
}

export interface PolicyFamilyCaps {
  url: number;
  dom: number;
  content: number;
  auth: number;
  reputation: number;
}

export interface PolicyTelemetry {
  enabled: boolean;
  endpoint?: string;
  includeUrlHashes?: boolean;
  includeBodySnippets?: boolean;
}

export interface PolicyConfig {
  schemaVersion: typeof POLICY_SCHEMA_VERSION;
  policyVersion: number;
  issuedAt: string;
  expiresAt: string;
  thresholds: PolicyThresholds;
  familyCaps: PolicyFamilyCaps;
  disabledChecks: string[];
  weightOverrides: Record<string, number>;
  /** Per-check time-box (doc 07 §2.3): default 10 ms, configurable here. */
  checkTimeboxMs?: number;
  telemetry: PolicyTelemetry;
  /** base64url Ed25519 signature over JCS(policy minus signature). */
  signature?: string;
}

/**
 * Compiled-in safe defaults (doc 07 §9 "Policy expiry": fall back to last
 * non-expired policy; if none, compiled-in safe defaults). Telemetry OFF.
 * Values are the doc 07 §3.3 defaults.
 */
export const DEFAULT_POLICY: Readonly<PolicyConfig> = Object.freeze({
  schemaVersion: POLICY_SCHEMA_VERSION,
  policyVersion: 0,
  issuedAt: "1970-01-01T00:00:00Z",
  expiresAt: "9999-12-31T23:59:59Z",
  thresholds: Object.freeze({ malicious: 70, suspicious: 35 }),
  familyCaps: Object.freeze({ url: 40, dom: 35, content: 30, auth: 35, reputation: 100 }),
  disabledChecks: Object.freeze([]) as unknown as string[],
  weightOverrides: Object.freeze({}) as Record<string, number>,
  checkTimeboxMs: 10,
  telemetry: Object.freeze({ enabled: false, includeUrlHashes: false, includeBodySnippets: false }),
});

export interface PolicyValidationError {
  field: string;
  message: string;
}

/** Fail-closed structural validation (signature verification lives in phish-intel). */
export function validatePolicyConfig(raw: unknown): PolicyValidationError[] {
  const errors: PolicyValidationError[] = [];
  const rec = (v: unknown): v is Record<string, unknown> =>
    typeof v === "object" && v !== null && !Array.isArray(v);
  if (!rec(raw)) return [{ field: "$", message: "policy is not an object" }];
  if (raw.schemaVersion !== POLICY_SCHEMA_VERSION) {
    errors.push({ field: "schemaVersion", message: `must be ${POLICY_SCHEMA_VERSION}` });
  }
  if (typeof raw.policyVersion !== "number" || !Number.isInteger(raw.policyVersion) || raw.policyVersion < 0) {
    errors.push({ field: "policyVersion", message: "must be a non-negative integer" });
  }
  for (const f of ["issuedAt", "expiresAt"] as const) {
    if (typeof raw[f] !== "string" || Number.isNaN(Date.parse(raw[f] as string))) {
      errors.push({ field: f, message: "must be an ISO-8601 timestamp" });
    }
  }
  if (!rec(raw.thresholds)) {
    errors.push({ field: "thresholds", message: "must be an object" });
  } else {
    const { malicious, suspicious } = raw.thresholds;
    if (typeof malicious !== "number" || malicious < 0 || malicious > 100) {
      errors.push({ field: "thresholds.malicious", message: "must be 0–100" });
    }
    if (typeof suspicious !== "number" || suspicious < 0 || suspicious > 100) {
      errors.push({ field: "thresholds.suspicious", message: "must be 0–100" });
    }
    if (typeof malicious === "number" && typeof suspicious === "number" && suspicious >= malicious) {
      errors.push({ field: "thresholds", message: "suspicious must be < malicious" });
    }
  }
  if (!rec(raw.familyCaps)) {
    errors.push({ field: "familyCaps", message: "must be an object" });
  } else {
    for (const fam of ["url", "dom", "content", "auth", "reputation"] as const) {
      const v = raw.familyCaps[fam];
      if (typeof v !== "number" || v < 0 || v > 100) {
        errors.push({ field: `familyCaps.${fam}`, message: "must be 0–100" });
      }
    }
  }
  if (!Array.isArray(raw.disabledChecks) || !raw.disabledChecks.every((c) => typeof c === "string")) {
    errors.push({ field: "disabledChecks", message: "must be a string array" });
  }
  if (!rec(raw.weightOverrides)) {
    errors.push({ field: "weightOverrides", message: "must be an object" });
  } else {
    for (const [k, v] of Object.entries(raw.weightOverrides)) {
      if (typeof v !== "number" || v < 0 || v > 100) {
        errors.push({ field: `weightOverrides.${k}`, message: "must be 0–100" });
      }
    }
  }
  if (raw.checkTimeboxMs !== undefined && (typeof raw.checkTimeboxMs !== "number" || raw.checkTimeboxMs <= 0)) {
    errors.push({ field: "checkTimeboxMs", message: "must be a positive number" });
  }
  if (!rec(raw.telemetry) || typeof raw.telemetry.enabled !== "boolean") {
    errors.push({ field: "telemetry.enabled", message: "must be a boolean" });
  }
  if (raw.signature !== undefined && typeof raw.signature !== "string") {
    errors.push({ field: "signature", message: "must be a base64url string" });
  }
  return errors;
}

/** Merge a validated policy over the compiled-in defaults (fill gaps). */
export function resolvePolicy(policy?: PolicyConfig | null): PolicyConfig {
  if (!policy) return { ...DEFAULT_POLICY, disabledChecks: [], weightOverrides: {} };
  return {
    ...DEFAULT_POLICY,
    ...policy,
    thresholds: { ...DEFAULT_POLICY.thresholds, ...policy.thresholds },
    familyCaps: { ...DEFAULT_POLICY.familyCaps, ...policy.familyCaps },
    telemetry: { ...DEFAULT_POLICY.telemetry, ...policy.telemetry },
    disabledChecks: [...policy.disabledChecks],
    weightOverrides: { ...policy.weightOverrides },
  };
}
