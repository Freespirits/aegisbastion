/**
 * Canonicalized target scope evaluation (doc 01 §10.1, doc 11 §3.1, Ruling A).
 *
 * Rules:
 *  - Targets and scope entries are canonicalized before matching (lowercase
 *    scheme/host, default ports dropped, trailing root dot stripped, fragments
 *    dropped).
 *  - Wildcard domains use TLS convention: "*.acme.com" matches any host with
 *    one or more leading labels under acme.com, NOT the apex itself; the apex
 *    must be listed separately (as doc 11 §3.1's example RoE does).
 *  - URL/path entries match by longest-prefix on the canonical URL form;
 *    bare hosts match exact-host only; CIDRs match IP targets in range.
 *  - EXCLUSIONS ALWAYS WIN over every include form (doc 01 §5.4, doc 11 §3.1).
 *  - asset_group_ids / cloud_accounts cannot be resolved client-side, so they
 *    never grant inclusion — fail-closed (doc 01 §10.1).
 *  - DNS names are never resolved to IPs client-side (no DNS rebinding games,
 *    and fail-closed: a hostname cannot sneak into a CIDR include).
 */

import { PepError } from "./errors.js";

/** The canonical RoE scope carried by a scope-bound watch-token manifest. */
export interface CanonicalScope {
  domains: string[];
  cidrs: string[];
  explicit_excludes: string[];
  asset_group_ids?: string[];
  cloud_accounts?: string[];
}

export type ScopeVerdict =
  | { allow: true; matchedBy: string }
  | { allow: false; code: "TARGET_EXCLUDED" | "TARGET_NOT_IN_SCOPE"; matchedRule?: string };

// ---------------------------------------------------------------------------
// IP parsing (IPv4 + IPv6, no dependencies)
// ---------------------------------------------------------------------------

export function parseIpv4(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  let v = 0;
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i]);
    if (octet > 255 || (m[i]!.length > 1 && m[i]!.startsWith("0"))) return null;
    v = v * 256 + octet;
  }
  return v >>> 0;
}

/** Parse an IPv6 address (with :: compression and optional embedded IPv4) to 16 bytes. */
export function parseIpv6(s: string): Uint8Array | null {
  let input = s.toLowerCase();
  if (input.startsWith("[") && input.endsWith("]")) input = input.slice(1, -1);
  if (!/^[0-9a-f:.]+$/.test(input)) return null;

  // Embedded IPv4 tail, e.g. "::ffff:203.0.113.7".
  let ipv4Tail: number[] | null = null;
  const lastColon = input.lastIndexOf(":");
  if (lastColon >= 0) {
    const tail = input.slice(lastColon + 1);
    if (tail.includes(".")) {
      const v4 = parseIpv4(tail);
      if (v4 === null) return null;
      ipv4Tail = [(v4 >>> 24) & 0xff, (v4 >>> 16) & 0xff, (v4 >>> 8) & 0xff, v4 & 0xff];
      // Drop the tail but keep the "::" structure intact: when the char before
      // the tail's colon is itself ":", keep that colon too ("::1.2.3.4" → "::").
      input =
        lastColon > 0 && input[lastColon - 1] === ":"
          ? input.slice(0, lastColon + 1)
          : input.slice(0, lastColon);
    }
  }

  const halves = input.split("::");
  if (halves.length > 2) return null;
  const groups: number[] = [];
  const parseHalf = (half: string): number[] | null => {
    if (half === "") return [];
    const parts = half.split(":");
    const out: number[] = [];
    for (const p of parts) {
      if (!/^[0-9a-f]{1,4}$/.test(p)) return null;
      out.push(parseInt(p, 16));
    }
    return out;
  };
  const left = parseHalf(halves[0] ?? "");
  const right = halves.length === 2 ? parseHalf(halves[1] ?? "") : [];
  if (left === null || right === null) return null;
  const tailGroups = ipv4Tail ? 2 : 0;
  if (halves.length === 2) {
    const missing = 8 - left.length - right.length - tailGroups;
    if (missing < 0) return null;
    groups.push(...left, ...new Array<number>(missing).fill(0), ...right);
  } else {
    if (left.length + tailGroups !== 8) return null;
    groups.push(...left);
  }
  if (ipv4Tail) {
    groups.push(((ipv4Tail[0]! << 8) | ipv4Tail[1]!), ((ipv4Tail[2]! << 8) | ipv4Tail[3]!));
  }
  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (groups[i]! >>> 8) & 0xff;
    bytes[i * 2 + 1] = groups[i]! & 0xff;
  }
  return bytes;
}

interface CidrV4 {
  family: 4;
  base: number;
  bits: number;
}
interface CidrV6 {
  family: 6;
  base: Uint8Array;
  bits: number;
}
export type Cidr = CidrV4 | CidrV6;

export function parseCidr(s: string): Cidr | null {
  const slash = s.indexOf("/");
  if (slash < 0) return null;
  const addr = s.slice(0, slash);
  const bitsStr = s.slice(slash + 1);
  if (!/^\d{1,3}$/.test(bitsStr)) return null;
  const bits = Number(bitsStr);
  const v4 = parseIpv4(addr);
  if (v4 !== null) {
    if (bits > 32) return null;
    return { family: 4, base: v4, bits };
  }
  const v6 = parseIpv6(addr);
  if (v6 !== null) {
    if (bits > 128) return null;
    return { family: 6, base: v6, bits };
  }
  return null;
}

export function ipv4InCidr(ip: number, cidr: CidrV4): boolean {
  if (cidr.bits === 0) return true;
  const mask = (~0 << (32 - cidr.bits)) >>> 0;
  return (ip & mask) === (cidr.base & mask);
}

export function ipv6InCidr(ip: Uint8Array, cidr: CidrV6): boolean {
  for (let i = 0; i < 16; i++) {
    const remaining = cidr.bits - i * 8;
    if (remaining <= 0) return true;
    if (remaining >= 8) {
      if (ip[i] !== cidr.base[i]) return false;
    } else {
      const mask = (0xff << (8 - remaining)) & 0xff;
      if ((ip[i]! & mask) !== (cidr.base[i]! & mask)) return false;
      return true;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Target canonicalization (doc 01 §10.1: "evaluated against canonicalized targets")
// ---------------------------------------------------------------------------

export type CanonicalTarget =
  | { kind: "ipv4"; ip: number; canonical: string }
  | { kind: "ipv6"; ip: Uint8Array; canonical: string }
  | { kind: "host"; host: string; canonical: string }
  | { kind: "url"; host: string; canonical: string; urlPrefix: string; hostPath: string };

const DEFAULT_PORTS: Record<string, string> = { "http:": "80", "https:": "443" };

/**
 * Canonicalize a target string. Throws PepError(TARGET_NOT_IN_SCOPE) on
 * unparseable input — malformed targets are never in scope (fail-closed).
 */
export function canonicalizeTarget(raw: string): CanonicalTarget {
  const input = raw.trim().toLowerCase();
  if (input === "") {
    throw new PepError("TARGET_NOT_IN_SCOPE", "empty target string");
  }

  const v4 = parseIpv4(input);
  if (v4 !== null) return { kind: "ipv4", ip: v4, canonical: input };

  if (input.startsWith("[") || /^[0-9a-f:]*:[0-9a-f:.]*$/.test(input)) {
    const v6 = parseIpv6(input);
    if (v6 !== null) return { kind: "ipv6", ip: v6, canonical: input };
  }

  if (input.includes("://")) {
    let url: URL;
    try {
      url = new URL(input);
    } catch {
      throw new PepError("TARGET_NOT_IN_SCOPE", `unparseable URL target: ${raw}`);
    }
    const host = url.hostname.replace(/\.$/, "");
    const port = url.port === DEFAULT_PORTS[url.protocol] ? "" : url.port;
    const portSuffix = port ? `:${port}` : "";
    const path = url.pathname === "/" ? "" : url.pathname;
    const canonical = `${url.protocol}//${host}${portSuffix}${path}${url.search}`;
    return {
      kind: "url",
      host,
      canonical,
      urlPrefix: `${url.protocol}//${host}${portSuffix}${path}`,
      hostPath: `${host}${portSuffix}${path}`,
    };
  }

  // Bare host or host/path form ("api.acme.com/graphql").
  const slash = input.indexOf("/");
  const hostPart = (slash >= 0 ? input.slice(0, slash) : input).replace(/\.$/, "");
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(hostPart)) {
    throw new PepError("TARGET_NOT_IN_SCOPE", `unparseable target: ${raw}`);
  }
  if (slash >= 0) {
    return { kind: "url", host: hostPart, canonical: input, urlPrefix: input, hostPath: input };
  }
  return { kind: "host", host: hostPart, canonical: hostPart };
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

function hostMatchesDomain(host: string, domainEntry: string): boolean {
  const entry = domainEntry.trim().toLowerCase().replace(/\.$/, "");
  if (entry.startsWith("*.")) {
    const suffix = entry.slice(1); // ".acme.com"
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return host === entry;
}

/**
 * Does one scope rule (include or exclude form) match a canonical target?
 * Rule forms: CIDR, bare IP, bare host, wildcard domain, URL/host-path prefix
 * (longest-prefix), or URL with scheme (longest-prefix).
 */
export function ruleMatchesTarget(ruleRaw: string, target: CanonicalTarget): boolean {
  const rule = ruleRaw.trim().toLowerCase();
  if (rule === "") return false;

  const cidr = parseCidr(rule);
  if (cidr !== null) {
    if (target.kind === "ipv4" && cidr.family === 4) return ipv4InCidr(target.ip, cidr);
    if (target.kind === "ipv6" && cidr.family === 6) return ipv6InCidr(target.ip, cidr);
    return false;
  }

  const v4 = parseIpv4(rule);
  if (v4 !== null) return target.kind === "ipv4" && target.ip === v4;

  if (rule.startsWith("[") || /^[0-9a-f:]*:[0-9a-f:.]*$/.test(rule)) {
    const v6 = parseIpv6(rule);
    if (v6 !== null && target.kind === "ipv6") {
      if (target.ip.length !== v6.length) return false;
      return target.ip.every((b, i) => b === v6[i]);
    }
  }

  // URL or host/path rule → longest-prefix on the canonical URL prefix form.
  if (rule.includes("/")) {
    if (target.kind !== "url") return false;
    // A rule WITH a scheme binds to that scheme; a scheme-less rule matches
    // any scheme (compare on host+path only).
    const targetForm = rule.includes("://") ? target.urlPrefix : target.hostPath;
    let prefix: string;
    try {
      const ct = canonicalizeTarget(rule);
      prefix = ct.kind === "url" ? (rule.includes("://") ? ct.urlPrefix : ct.hostPath) : ct.canonical;
    } catch {
      return false;
    }
    return targetForm === prefix || targetForm.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`);
  }

  // Bare host or wildcard domain rule.
  const host = rule.replace(/\.$/, "");
  if (host.startsWith("*.")) {
    if (target.kind === "host" || target.kind === "url") return hostMatchesDomain(target.host, host);
    return false;
  }
  if (target.kind === "host" || target.kind === "url") return target.host === host;
  return false;
}

/**
 * Evaluate one probe target against a canonical scope (Ruling A.5).
 * Exclusions are evaluated FIRST and always win; then includes (domains,
 * CIDRs). Anything unmatched is denied — fail-closed.
 */
export function evaluateTargetInScope(rawTarget: string, scope: CanonicalScope): ScopeVerdict {
  const target = canonicalizeTarget(rawTarget);

  for (const exclusion of scope.explicit_excludes) {
    if (ruleMatchesTarget(exclusion, target)) {
      return { allow: false, code: "TARGET_EXCLUDED", matchedRule: exclusion };
    }
  }

  for (const domain of scope.domains) {
    if ((target.kind === "host" || target.kind === "url") && hostMatchesDomain(target.host, domain)) {
      return { allow: true, matchedBy: domain };
    }
    // Domain entries that are actually URL/path prefixes.
    if (domain.includes("/") && ruleMatchesTarget(domain, target)) {
      return { allow: true, matchedBy: domain };
    }
  }

  for (const cidrRaw of scope.cidrs) {
    const cidr = parseCidr(cidrRaw.trim().toLowerCase());
    if (cidr === null) continue;
    if (target.kind === "ipv4" && cidr.family === 4 && ipv4InCidr(target.ip, cidr)) {
      return { allow: true, matchedBy: cidrRaw };
    }
    if (target.kind === "ipv6" && cidr.family === 6 && ipv6InCidr(target.ip, cidr)) {
      return { allow: true, matchedBy: cidrRaw };
    }
  }

  return { allow: false, code: "TARGET_NOT_IN_SCOPE" };
}

/**
 * Exact-enumerated manifest membership (doc 01 §5.5): the target must equal a
 * manifest entry after canonicalization. No wildcards, no scope expansion.
 */
export function isTargetInManifest(rawTarget: string, manifestTargets: readonly string[]): boolean {
  let target: CanonicalTarget;
  try {
    target = canonicalizeTarget(rawTarget);
  } catch {
    return false; // an unparseable target can never be a manifest member
  }
  for (const entry of manifestTargets) {
    try {
      if (canonicalizeTarget(entry).canonical === target.canonical) return true;
    } catch {
      // A malformed manifest entry can never match — skip it (fail-closed).
    }
  }
  return false;
}
