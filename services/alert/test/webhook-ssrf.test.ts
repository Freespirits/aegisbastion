/**
 * Signed webhooks (doc 05 §6/§13.5) + SSRF guard (§13.4).
 * HMAC X-AegisBastion-Signature: t=<ts>,v1=<hex> over `<ts>.<body>`; SSRF guard
 * blocks RFC1918/loopback/link-local/CGNAT/reserved, v4 AND v6 (incl.
 * IPv4-mapped), HTTPS-only, DNS-rebinding-pinned, redirects refused.
 */

import { describe, expect, it } from "vitest";
import { signWebhookBody, verifyWebhookSignature } from "../src/dispatch/sign.js";
import { guardDestination, isBlockedIp } from "../src/dispatch/ssrf.js";

describe("webhook HMAC signature (§6)", () => {
  const secret = "endpoint-secret-1";
  const body = JSON.stringify({ specversion: "1.0", data: { hello: "world" } });

  it("produces the t=<ts>,v1=<hex> format over ts.body", () => {
    const sig = signWebhookBody(secret, body, 1785400000);
    expect(sig).toMatch(/^t=1785400000,v1=[0-9a-f]{64}$/);
    // Known-vector stability: same input → same signature.
    expect(signWebhookBody(secret, body, 1785400000)).toBe(sig);
    // Different body or ts or secret → different signature.
    expect(signWebhookBody(secret, body, 1785400001)).not.toBe(sig);
    expect(signWebhookBody(secret, body + " ", 1785400000)).not.toBe(sig);
    expect(signWebhookBody("other", body, 1785400000)).not.toBe(sig);
  });

  it("round-trips through verifyWebhookSignature", () => {
    const now = Math.floor(Date.now() / 1000);
    const sig = signWebhookBody(secret, body, now);
    expect(verifyWebhookSignature(secret, body, sig)).toBe(true);
  });

  it("rejects tampered bodies and wrong secrets", () => {
    const now = Math.floor(Date.now() / 1000);
    const sig = signWebhookBody(secret, body, now);
    expect(verifyWebhookSignature(secret, body.replace("world", "mars"), sig)).toBe(false);
    expect(verifyWebhookSignature("wrong", body, sig)).toBe(false);
    expect(verifyWebhookSignature(secret, body, "t=1,v1=nothex")).toBe(false);
    expect(verifyWebhookSignature(secret, body, "garbage")).toBe(false);
  });

  it("rejects stale timestamps (replay window)", () => {
    const stale = Math.floor(Date.now() / 1000) - 3600;
    const sig = signWebhookBody(secret, body, stale);
    expect(verifyWebhookSignature(secret, body, sig)).toBe(false);
    expect(verifyWebhookSignature(secret, body, sig, 7200)).toBe(true); // wider tolerance accepts
  });
});

describe("SSRF guard (§13.4)", () => {
  it("blocks private/reserved IPv4 ranges", () => {
    for (const ip of ["10.0.0.1", "10.255.255.255", "127.0.0.1", "127.1.2.3", "169.254.1.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "198.18.0.1", "240.0.0.1"]) {
      expect(isBlockedIp(ip), ip).toBe(true);
    }
  });

  it("blocks private/reserved IPv6 incl. IPv4-mapped", () => {
    for (const ip of ["::1", "fe80::1", "fc00::1", "fd00::1", "ff02::1", "::", "::ffff:10.0.0.1", "::ffff:127.0.0.1"]) {
      expect(isBlockedIp(ip), ip).toBe(true);
    }
  });

  it("allows public addresses", () => {
    for (const ip of ["8.8.8.8", "203.0.113.10", "1.1.1.1", "2606:4700:4700::1111"]) {
      expect(isBlockedIp(ip), ip).toBe(false);
    }
  });

  it("fails closed on unparseable addresses", () => {
    expect(isBlockedIp("not-an-ip")).toBe(true);
  });

  it("rejects non-HTTPS destinations", async () => {
    const verdict = await guardDestination("http://hooks.example.com/x");
    expect(verdict).toMatchObject({ allow: false });
    if (!verdict.allow) expect(verdict.reason).toContain("HTTPS");
  });

  it("blocks hostnames resolving to private addresses (DNS-injected)", async () => {
    const verdict = await guardDestination("https://internal.example.com/hook", {
      resolveAll: async () => [{ address: "10.1.2.3", family: 4 }],
    });
    expect(verdict.allow).toBe(false);
  });

  it("blocks when ANY resolved address is private", async () => {
    const verdict = await guardDestination("https://roundrobin.example.com/hook", {
      resolveAll: async () => [
        { address: "8.8.8.8", family: 4 },
        { address: "192.168.0.5", family: 4 },
      ],
    });
    expect(verdict.allow).toBe(false);
  });

  it("allows + pins public resolutions", async () => {
    const verdict = await guardDestination("https://hooks.example.com/hook", {
      resolveAll: async () => [{ address: "93.184.216.34", family: 4 }],
    });
    expect(verdict).toMatchObject({ allow: true });
    if (verdict.allow) expect(verdict.addresses[0]).toMatchObject({ address: "93.184.216.34" });
  });

  it("allows public IP-literal destinations", async () => {
    const verdict = await guardDestination("https://93.184.216.34/hook");
    expect(verdict.allow).toBe(true);
  });

  it("blocks private IP-literal destinations", async () => {
    expect((await guardDestination("https://192.168.1.10/hook")).allow).toBe(false);
    expect((await guardDestination("https://[::1]/hook")).allow).toBe(false);
  });

  it("internal:true egress entries bypass the private-range block (admin-flagged)", async () => {
    const verdict = await guardDestination("https://internal.example.com/hook", {
      allowInternal: true,
      resolveAll: async () => [{ address: "10.1.2.3", family: 4 }],
    });
    expect(verdict.allow).toBe(true);
  });

  it("fails closed on DNS errors and empty answers", async () => {
    expect(
      (
        await guardDestination("https://nxdomain.example.com/", {
          resolveAll: async () => {
            throw new Error("ENOTFOUND");
          },
        })
      ).allow,
    ).toBe(false);
    expect((await guardDestination("https://empty.example.com/", { resolveAll: async () => [] })).allow).toBe(false);
  });
});
