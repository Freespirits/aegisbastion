// Non-authoritative preflight scope checker (doc 10 §7.1 step 1: "BFF
// pre-flight (UX only) — ... Never authoritative"). gatekeeper's
// policy-service Authorize dry-run is exposed on gRPC only, so at MVP-A the
// dashboard renders the SAME semantics locally from the RoE record fetched
// via the gatekeeper admin-api: doc 01 §10.1 canonicalized matching
// (exact-host / longest-prefix for domains, CIDR containment for IPs) with
// the platform-wide invariant that EXCLUSIONS ALWAYS WIN (docs 01 §5.4,
// 03 §9.2, 11 §3.1). The authoritative decision stays with gatekeeper's
// hard-coded pipeline at dispatch time.

export interface RoeScope {
  asset_group_ids?: string[];
  domains?: string[];
  cidrs?: string[];
  cloud_accounts?: string[];
  explicit_excludes?: string[];
}

export type PreflightVerdict = "in_scope" | "excluded" | "out_of_scope" | "unparseable";

export interface PreflightResult {
  target: string;
  verdict: PreflightVerdict;
  /** Which scope rule decided (for UI display). */
  matchedBy?: string;
}

/** Canonicalize a target to host or IP form (mirrors dp's canonicalizeTarget). */
export function canonicalizeTarget(raw: string): string | null {
  let t = raw.trim();
  if (t === "") return null;
  const schemeIdx = t.indexOf("://");
  if (schemeIdx >= 0) {
    t = t.slice(schemeIdx + 3);
    const end = t.search(/[/?#]/);
    if (end >= 0) t = t.slice(0, end);
    const at = t.lastIndexOf("@");
    if (at >= 0) t = t.slice(at + 1);
  }
  // Strip port (host:port and [v6]:port).
  const bracket = t.match(/^\[(?<host>[^\]]+)\](?::\d+)?$/);
  if (bracket?.groups) {
    t = bracket.groups.host;
  } else {
    const m = t.match(/^(?<host>[^:\s]+):\d+$/);
    if (m?.groups) t = m.groups.host;
  }
  t = t.toLowerCase().replace(/\.$/, "");
  return t === "" ? null : t;
}

export function isIPv4(t: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(t) && t.split(".").every((o) => Number(o) <= 255);
}

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => ((acc << 8) | Number(o)) >>> 0, 0);
}

/** IPv4 CIDR containment. Non-IPv4 CIDRs never match at MVP-A. */
export function cidrContains(cidr: string, ip: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  if (!base || !isIPv4(base) || !isIPv4(ip) || Number.isNaN(bits) || bits < 0 || bits > 32) {
    return false;
  }
  if (bits === 0) return true;
  const mask = (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(base) & mask) === (ipv4ToInt(ip) & mask);
}

/**
 * Domain rule match (doc 01 §10.1): "acme.com" matches itself and any
 * subdomain; "*.acme.com" matches subdomains only. Longest-prefix wins
 * naturally because any matching include puts the target in scope.
 */
export function domainMatches(rule: string, host: string): boolean {
  const r = rule.toLowerCase().replace(/\.$/, "");
  if (r.startsWith("*.")) {
    const suffix = r.slice(2);
    return host.endsWith(`.${suffix}`);
  }
  return host === r || host.endsWith(`.${r}`);
}

/** Does one scope rule (domain/CIDR/exclude entry) cover this target? */
function ruleMatches(rule: string, target: string): boolean {
  const r = rule.trim();
  if (r === "") return false;
  if (r.includes("/")) return cidrContains(r, target);
  if (isIPv4(r)) return target === r;
  return domainMatches(r, target);
}

/**
 * Evaluate targets against an RoE scope. Exclusions are evaluated first and
 * always win; a target with no matching include is out of scope. Empty
 * include sets mean nothing is in scope (fail-closed, mirroring the PDP).
 */
export function evaluateScope(scope: RoeScope, targets: string[]): PreflightResult[] {
  const excludes = scope.explicit_excludes ?? [];
  const domainIncludes = scope.domains ?? [];
  const cidrIncludes = scope.cidrs ?? [];
  return targets.map((raw) => {
    const target = canonicalizeTarget(raw);
    if (!target) return { target: raw, verdict: "unparseable" as const };
    for (const ex of excludes) {
      if (ruleMatches(ex, target)) {
        return { target: raw, verdict: "excluded" as const, matchedBy: `exclusion ${ex}` };
      }
    }
    for (const d of domainIncludes) {
      if (ruleMatches(d, target)) {
        return { target: raw, verdict: "in_scope" as const, matchedBy: `domain ${d}` };
      }
    }
    for (const c of cidrIncludes) {
      if (ruleMatches(c, target)) {
        return { target: raw, verdict: "in_scope" as const, matchedBy: `cidr ${c}` };
      }
    }
    return { target: raw, verdict: "out_of_scope" as const };
  });
}

/** The root scope string used for the type-to-confirm friction (doc 10 §7.2). */
export function scopeConfirmToken(scope: RoeScope): string | null {
  const first = (scope.domains ?? [])[0] ?? (scope.cidrs ?? [])[0] ?? null;
  return first ? first.replace(/^\*\./, "") : null;
}
