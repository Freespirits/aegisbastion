/**
 * Canonicalized scope evaluation matrix (doc 01 §10.1, Ruling A.5):
 * longest-prefix / exact-host matching, wildcard domains, CIDRs, and
 * EXCLUSIONS ALWAYS WIN. Fail-closed on anything unmatched.
 */

import { describe, expect, it } from "vitest";
import {
  canonicalizeTarget,
  evaluateTargetInScope,
  isTargetInManifest,
  parseCidr,
  parseIpv4,
  parseIpv6,
  ipv4InCidr,
  ipv6InCidr,
  type CanonicalScope,
} from "../src/scope.js";

const scope = (over: Partial<CanonicalScope> = {}): CanonicalScope => ({
  domains: [],
  cidrs: [],
  explicit_excludes: [],
  ...over,
});

describe("canonicalizeTarget", () => {
  it("normalizes URLs (case, default port, trailing dot, fragment)", () => {
    expect(canonicalizeTarget("HTTPS://API.Acme.COM:443/graphql#frag").canonical).toBe(
      "https://api.acme.com/graphql",
    );
  });

  it("keeps non-default ports", () => {
    expect(canonicalizeTarget("http://api.acme.com:8080/x").canonical).toBe(
      "http://api.acme.com:8080/x",
    );
  });

  it("parses bare hosts, IPv4, IPv6", () => {
    expect(canonicalizeTarget("Example.COM.").canonical).toBe("example.com");
    expect(canonicalizeTarget("203.0.113.7").kind).toBe("ipv4");
    expect(canonicalizeTarget("::1").kind).toBe("ipv6");
    expect(canonicalizeTarget("[2001:db8::1]").kind).toBe("ipv6");
  });

  it("rejects empty and malformed targets (fail-closed)", () => {
    expect(() => canonicalizeTarget("   ")).toThrow();
    expect(() => canonicalizeTarget("not a host!").canonical).toThrow();
  });
});

describe("IP / CIDR primitives", () => {
  it("IPv4 parse + range checks", () => {
    expect(parseIpv4("203.0.113.7")).not.toBeNull();
    expect(parseIpv4("256.1.1.1")).toBeNull();
    expect(parseIpv4("01.2.3.4")).toBeNull(); // no octal/leading-zero games
    const c = parseCidr("203.0.113.0/24");
    expect(c?.family).toBe(4);
    expect(ipv4InCidr(parseIpv4("203.0.113.50")!, c as never)).toBe(true);
    expect(ipv4InCidr(parseIpv4("203.0.114.1")!, c as never)).toBe(false);
    expect(ipv4InCidr(parseIpv4("1.2.3.4")!, parseCidr("0.0.0.0/0") as never)).toBe(true);
  });

  it("IPv6 parse (compression, embedded v4) + range checks", () => {
    expect(parseIpv6("2001:db8::1")).not.toBeNull();
    expect(parseIpv6("::ffff:203.0.113.7")).not.toBeNull();
    expect(parseIpv6("2001:::1")).toBeNull();
    expect(parseIpv6("2001:db8::1::2")).toBeNull();
    const c = parseCidr("2001:db8::/32");
    expect(c?.family).toBe(6);
    expect(ipv6InCidr(parseIpv6("2001:db8:1::1")!, c as never)).toBe(true);
    expect(ipv6InCidr(parseIpv6("2001:db9::1")!, c as never)).toBe(false);
    const c128 = parseCidr("2001:db8::5/128");
    expect(ipv6InCidr(parseIpv6("2001:db8::5")!, c128 as never)).toBe(true);
    expect(ipv6InCidr(parseIpv6("2001:db8::6")!, c128 as never)).toBe(false);
  });
});

describe("evaluateTargetInScope", () => {
  const acme = scope({
    domains: ["acme.com", "*.acme.com", "acme.io", "*.acme.io"],
    cidrs: ["203.0.113.0/24"],
  });

  it("allows exact-host and wildcard subdomain matches", () => {
    expect(evaluateTargetInScope("acme.com", acme).allow).toBe(true);
    expect(evaluateTargetInScope("api.acme.com", acme).allow).toBe(true);
    expect(evaluateTargetInScope("deep.api.acme.com", acme).allow).toBe(true);
    expect(evaluateTargetInScope("https://shop.acme.io/path", acme).allow).toBe(true);
  });

  it("denies the apex-less wildcard mismatch and unrelated hosts", () => {
    expect(evaluateTargetInScope("notacme.com", acme).allow).toBe(false);
    expect(evaluateTargetInScope("acme.com.evil.io", acme).allow).toBe(false);
    expect(evaluateTargetInScope("sub.acme.io.evil.com", acme).allow).toBe(false);
  });

  it("allows IPs inside CIDRs, denies IPs outside", () => {
    expect(evaluateTargetInScope("203.0.113.50", acme).allow).toBe(true);
    expect(evaluateTargetInScope("203.0.114.50", acme).allow).toBe(false);
  });

  it("does not resolve hostnames into CIDRs (no DNS client-side, fail-closed)", () => {
    const s = scope({ cidrs: ["203.0.113.0/24"] });
    expect(evaluateTargetInScope("acme.com", s).allow).toBe(false);
  });

  it("EXCLUSIONS ALWAYS WIN over every include form", () => {
    const s = scope({
      domains: ["*.acme.com", "acme.com"],
      cidrs: ["203.0.113.0/24"],
      explicit_excludes: ["legacy.acme.com", "203.0.113.50", "203.0.113.64/26"],
    });
    expect(evaluateTargetInScope("legacy.acme.com", s)).toMatchObject({
      allow: false,
      code: "TARGET_EXCLUDED",
    });
    expect(evaluateTargetInScope("203.0.113.50", s)).toMatchObject({
      allow: false,
      code: "TARGET_EXCLUDED",
    });
    expect(evaluateTargetInScope("203.0.113.70", s)).toMatchObject({
      allow: false,
      code: "TARGET_EXCLUDED",
    }); // in 203.0.113.64/26
    expect(evaluateTargetInScope("203.0.113.10", s).allow).toBe(true);
    expect(evaluateTargetInScope("api.acme.com", s).allow).toBe(true);
  });

  it("URL-prefix exclusions win by longest-prefix, regardless of scheme", () => {
    const s = scope({
      domains: ["*.acme.com"],
      explicit_excludes: ["api.acme.com/admin"],
    });
    expect(evaluateTargetInScope("https://api.acme.com/admin/users", s)).toMatchObject({
      allow: false,
      code: "TARGET_EXCLUDED",
    });
    expect(evaluateTargetInScope("http://api.acme.com/admin", s)).toMatchObject({
      allow: false,
      code: "TARGET_EXCLUDED",
    });
    expect(evaluateTargetInScope("https://api.acme.com/public", s).allow).toBe(true);
  });

  it("scheme-bound prefix exclusions bind to their scheme", () => {
    const s = scope({
      domains: ["*.acme.com"],
      explicit_excludes: ["https://api.acme.com/admin"],
    });
    expect(evaluateTargetInScope("https://api.acme.com/admin/x", s).allow).toBe(false);
    expect(evaluateTargetInScope("http://api.acme.com/admin/x", s).allow).toBe(true);
  });

  it("wildcard exclusions cover whole subtrees", () => {
    const s = scope({
      domains: ["*.acme.com", "acme.com"],
      explicit_excludes: ["*.internal.acme.com"],
    });
    expect(evaluateTargetInScope("db.internal.acme.com", s).allow).toBe(false);
    expect(evaluateTargetInScope("web.acme.com", s).allow).toBe(true);
  });

  it("asset_group_ids / cloud_accounts never grant inclusion (fail-closed)", () => {
    const s = scope({ asset_group_ids: ["ag_external_prod"], cloud_accounts: ["azure_sub_1"] });
    expect(evaluateTargetInScope("anything.example.com", s).allow).toBe(false);
  });

  it("denies targets in an empty scope (fail-closed)", () => {
    expect(evaluateTargetInScope("acme.com", scope())).toMatchObject({
      allow: false,
      code: "TARGET_NOT_IN_SCOPE",
    });
  });
});

describe("isTargetInManifest (exact-enumerated form)", () => {
  const manifest = ["https://api.acme.com/graphql", "203.0.113.10", "shop.acme.com"];

  it("matches exact entries after canonicalization", () => {
    expect(isTargetInManifest("HTTPS://API.Acme.COM:443/graphql", manifest)).toBe(true);
    expect(isTargetInManifest("203.0.113.10", manifest)).toBe(true);
    expect(isTargetInManifest("shop.acme.com", manifest)).toBe(true);
  });

  it("rejects non-members, near-misses, and scope expansion attempts", () => {
    expect(isTargetInManifest("https://api.acme.com/admin", manifest)).toBe(false);
    expect(isTargetInManifest("other.acme.com", manifest)).toBe(false);
    expect(isTargetInManifest("203.0.113.11", manifest)).toBe(false);
    expect(isTargetInManifest("*.acme.com", manifest)).toBe(false);
  });

  it("skips malformed manifest entries (fail-closed)", () => {
    expect(isTargetInManifest("acme.com", ["!!!bad!!!", "acme.com"])).toBe(true);
    expect(isTargetInManifest("acme.com", ["!!!bad!!!"])).toBe(false);
  });
});
