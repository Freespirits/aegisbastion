/**
 * JCS (JSON Canonicalization Scheme, RFC 8785) — the platform's single
 * canonicalization (doc 01 §10.2; doc 07 §12: "Do not invent a second
 * canonicalization"). Same `canonicalize` package the platform TS SDK uses.
 */
import canonicalize from "canonicalize";

/** Serialize a JSON value in JCS (RFC 8785) canonical form. */
export function jcs(value: unknown): string {
  const out = canonicalize(value as never);
  if (out === undefined) throw new Error("value is not JCS-serializable");
  return out;
}
