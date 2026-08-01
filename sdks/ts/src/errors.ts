/**
 * Error taxonomy for the agent SDK / PEP guardrails.
 *
 * Every guardrail failure is fail-closed (doc 01 §10.1, doc 11 §7): a refusal
 * is expressed by throwing one of these errors, never by returning a boolean
 * that a caller could ignore. `code` values are stable strings so modules can
 * map them onto TaskResultStatus.REJECTED_UNAUTHORIZED and audit payloads.
 */

export type PepErrorCode =
  // Token verification failures (doc 01 §5.5, doc 11 §3.2).
  | "TOKEN_MALFORMED"
  | "TOKEN_SIGNATURE_INVALID"
  | "TOKEN_EXPIRED"
  | "TOKEN_NOT_YET_VALID"
  | "TOKEN_TTL_EXCEEDED"
  | "TOKEN_ISSUER_INVALID"
  | "TOKEN_AUDIENCE_INVALID"
  | "TOKEN_TASK_MISMATCH"
  | "TOKEN_RISK_CLASS_INVALID"
  | "TOKEN_SCOPE_BOUND_MISUSE"
  | "TOKEN_MISSING"
  | "JWKS_UNAVAILABLE"
  // Manifest / scope failures (Ruling A).
  | "MANIFEST_FETCH_FAILED"
  | "MANIFEST_HASH_MISMATCH"
  | "MANIFEST_MALFORMED"
  | "TARGET_NOT_IN_MANIFEST"
  | "TARGET_NOT_IN_SCOPE"
  | "TARGET_EXCLUDED"
  // Runtime guardrails.
  | "RATE_LIMITED"
  | "CONCURRENCY_LIMITED"
  | "REVOKED"
  | "KILLED"
  | "REAUTHORIZATION_DENIED";

export class PepError extends Error {
  readonly code: PepErrorCode;
  /** Structured detail for audit payloads — never contains raw target lists. */
  readonly detail: Record<string, unknown>;

  constructor(code: PepErrorCode, message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = "PepError";
    this.code = code;
    this.detail = detail;
  }
}

export function isPepError(err: unknown): err is PepError {
  return err instanceof PepError;
}
