/**
 * Authentication-Results (RFC 7601) / Received-SPF parsing (doc 07 §3.2 auth
 * family). The auth family trusts headers ALREADY PRESENT in the message —
 * no live DNS from the client (DNS leaks the lookup target, §3.2).
 */

export type AuthMethod = "spf" | "dkim" | "dmarc";

export interface AuthResult {
  method: AuthMethod;
  /** none | pass | fail | softfail | neutral | temperror | permerror | policy */
  result: string;
  /** Raw property string (e.g. "smtp.mailfrom=bad.com header.d=bad.com"). */
  properties: string;
}

const KNOWN_METHODS = new Set<AuthMethod>(["spf", "dkim", "dmarc"]);

/** Parse the first Authentication-Results header value (methods of interest). */
export function parseAuthenticationResults(header: string | undefined): AuthResult[] {
  if (!header) return [];
  const out: AuthResult[] = [];
  for (const part of header.split(";")) {
    const m = /^\s*([A-Za-z][A-Za-z0-9-]*)\s*=\s*([A-Za-z]+)(.*)$/.exec(part);
    if (!m) continue;
    const method = (m[1] ?? "").toLowerCase();
    if (!KNOWN_METHODS.has(method as AuthMethod)) continue;
    out.push({
      method: method as AuthMethod,
      result: (m[2] ?? "").toLowerCase(),
      properties: (m[3] ?? "").trim(),
    });
  }
  return out;
}

/** Parse a Received-SPF header: first token is the result. */
export function parseReceivedSpf(header: string | undefined): AuthResult | null {
  if (!header) return null;
  const m = /^\s*([A-Za-z]+)/.exec(header);
  if (!m) return null;
  return { method: "spf", result: (m[1] ?? "").toLowerCase(), properties: header };
}

/** Best-known result for a method across both header sources. */
export function authResultFor(
  method: AuthMethod,
  authenticationResults: string | undefined,
  receivedSpf: string | undefined,
): AuthResult | null {
  const fromAR = parseAuthenticationResults(authenticationResults).find((r) => r.method === method);
  if (fromAR) return fromAR;
  if (method === "spf") return parseReceivedSpf(receivedSpf);
  return null;
}

export interface Mailbox {
  displayName: string;
  address: string;
}

/** Parse a From:/Reply-To:/Return-Path: header value into display name + address. */
export function parseMailbox(header: string | undefined): Mailbox | null {
  if (!header) return null;
  const h = header.trim();
  if (h === "" || h === "<>") return null;
  // "Display Name" <addr@dom.tld>
  let m = /^(?:"([^"]*)"|([^<]*?))\s*<([^<>\s]+@[^<>\s]+)>\s*$/.exec(h);
  if (m) {
    return { displayName: (m[1] ?? m[2] ?? "").trim(), address: (m[3] ?? "").toLowerCase() };
  }
  // addr@dom.tld (Display Name)
  m = /^([^\s()<>]+@[^\s()<>]+)\s*\(([^)]*)\)\s*$/.exec(h);
  if (m) {
    return { displayName: (m[2] ?? "").trim(), address: (m[1] ?? "").toLowerCase() };
  }
  // bare addr@dom.tld
  m = /^([^\s<>]+@[^\s<>]+)$/.exec(h);
  if (m) return { displayName: "", address: (m[1] ?? "").toLowerCase() };
  return null;
}

export function domainOfAddress(address: string): string {
  const at = address.lastIndexOf("@");
  return at < 0 ? "" : address.slice(at + 1).toLowerCase();
}
