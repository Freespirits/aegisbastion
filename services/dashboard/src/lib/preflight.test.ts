import { describe, expect, it } from "vitest";
import {
  canonicalizeTarget,
  cidrContains,
  domainMatches,
  evaluateScope,
  scopeConfirmToken,
} from "@/lib/preflight";

describe("canonicalizeTarget", () => {
  it("reduces URLs to host form", () => {
    expect(canonicalizeTarget("https://user:pw@API.Example.com:8443/path?q=1")).toBe(
      "api.example.com",
    );
  });
  it("strips trailing dot and lowercases", () => {
    expect(canonicalizeTarget("WWW.Example.COM.")).toBe("www.example.com");
  });
  it("keeps IPs and strips ports", () => {
    expect(canonicalizeTarget("203.0.113.10:443")).toBe("203.0.113.10");
    expect(canonicalizeTarget("203.0.113.10")).toBe("203.0.113.10");
  });
  it("rejects empties", () => {
    expect(canonicalizeTarget("   ")).toBeNull();
    expect(canonicalizeTarget("https://")).toBeNull();
  });
});

describe("domainMatches (doc 01 §10.1)", () => {
  it("plain rule matches the host itself and subdomains", () => {
    expect(domainMatches("acme.com", "acme.com")).toBe(true);
    expect(domainMatches("acme.com", "api.acme.com")).toBe(true);
    expect(domainMatches("acme.com", "deep.api.acme.com")).toBe(true);
  });
  it("does not match sibling or suffix-lookalike domains", () => {
    expect(domainMatches("acme.com", "evilacme.com")).toBe(false);
    expect(domainMatches("acme.com", "acme.com.evil.io")).toBe(false);
  });
  it("wildcard matches subdomains only", () => {
    expect(domainMatches("*.acme.com", "api.acme.com")).toBe(true);
    expect(domainMatches("*.acme.com", "acme.com")).toBe(false);
  });
});

describe("cidrContains", () => {
  it("matches IPv4 inside the block", () => {
    expect(cidrContains("203.0.113.0/24", "203.0.113.10")).toBe(true);
    expect(cidrContains("203.0.113.0/24", "203.0.114.1")).toBe(false);
  });
  it("handles /32 and /0", () => {
    expect(cidrContains("203.0.113.10/32", "203.0.113.10")).toBe(true);
    expect(cidrContains("203.0.113.10/32", "203.0.113.11")).toBe(false);
    expect(cidrContains("0.0.0.0/0", "198.51.100.7")).toBe(true);
  });
  it("rejects malformed input fail-closed", () => {
    expect(cidrContains("203.0.113.0/33", "203.0.113.10")).toBe(false);
    expect(cidrContains("not-a-cidr", "203.0.113.10")).toBe(false);
  });
});

describe("evaluateScope — exclusions ALWAYS win (docs 01 §5.4 / 03 §9.2 / 11 §3.1)", () => {
  const scope = {
    domains: ["acme.com"],
    cidrs: ["203.0.113.0/24"],
    explicit_excludes: ["prod-db.acme.com", "203.0.113.99"],
  };

  it("marks in-scope targets", () => {
    const [r] = evaluateScope(scope, ["https://api.acme.com/"]);
    expect(r.verdict).toBe("in_scope");
    expect(r.matchedBy).toContain("acme.com");
  });

  it("an exclude beats a matching include", () => {
    const [host] = evaluateScope(scope, ["prod-db.acme.com"]);
    expect(host.verdict).toBe("excluded");
    const [ip] = evaluateScope(scope, ["203.0.113.99"]);
    expect(ip.verdict).toBe("excluded");
  });

  it("unlisted targets are out of scope (fail-closed)", () => {
    const [r] = evaluateScope(scope, ["other.org"]);
    expect(r.verdict).toBe("out_of_scope");
  });

  it("empty include sets mean nothing is in scope", () => {
    const [r] = evaluateScope({ domains: [], cidrs: [] }, ["acme.com"]);
    expect(r.verdict).toBe("out_of_scope");
  });

  it("flags unparseable targets", () => {
    const [r] = evaluateScope(scope, ["   "]);
    expect(r.verdict).toBe("unparseable");
  });
});

describe("scopeConfirmToken", () => {
  it("uses the first scope root, stripping wildcards", () => {
    expect(scopeConfirmToken({ domains: ["*.acme.com"] })).toBe("acme.com");
    expect(scopeConfirmToken({ cidrs: ["203.0.113.0/24"] })).toBe("203.0.113.0/24");
    expect(scopeConfirmToken({})).toBeNull();
  });
});
