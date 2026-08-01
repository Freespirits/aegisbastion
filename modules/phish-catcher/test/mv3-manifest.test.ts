/**
 * MV3 manifest validation (doc 07 §6.3/§7.1): minimal permissions, strict
 * CSP, ISOLATED world, no <all_urls>, referenced files exist.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const EXT = fileURLToPath(new URL("../extension", import.meta.url));
const manifest = JSON.parse(readFileSync(join(EXT, "manifest.json"), "utf8")) as {
  manifest_version: number;
  permissions?: string[];
  host_permissions?: string[];
  background?: { service_worker?: string };
  content_scripts?: { matches: string[]; js: string[]; world?: string }[];
  action?: { default_popup?: string };
  options_page?: string;
  content_security_policy?: { extension_pages?: string };
};

describe("Chrome MV3 manifest (doc 07 §6.3)", () => {
  it("is manifest v3", () => {
    expect(manifest.manifest_version).toBe(3);
  });

  it("requests only the minimal permission set (activeTab, storage, alarms; webRequest is Later)", () => {
    expect([...(manifest.permissions ?? [])].sort()).toEqual(["activeTab", "alarms", "storage"]);
  });

  it("scopes host permissions to the allowlisted webmail origins — never <all_urls>", () => {
    const hosts = manifest.host_permissions ?? [];
    expect(hosts).not.toContain("<all_urls>");
    for (const h of hosts) {
      expect(h).toMatch(/^https:\/\/(mail\.google\.com|outlook\.live\.com|outlook\.office\.com)\/\*$/);
    }
  });

  it("content scripts run ISOLATED on the same allowlist", () => {
    const scripts = manifest.content_scripts ?? [];
    expect(scripts.length).toBe(1);
    expect(scripts[0]?.world).toBe("ISOLATED");
    expect(scripts[0]?.matches.sort()).toEqual([...(manifest.host_permissions ?? [])].sort());
  });

  it("keeps a strict CSP: no unsafe-eval, no remote code, self-only connect (§7.1)", () => {
    const csp = manifest.content_security_policy?.extension_pages ?? "";
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toContain("http://");
    expect(csp).not.toContain("https://");
    expect(csp).toContain("connect-src 'self'");
  });

  it("references only files that exist in the package", () => {
    for (const f of [
      manifest.background?.service_worker,
      manifest.action?.default_popup,
      manifest.options_page,
      ...(manifest.content_scripts?.flatMap((c) => c.js) ?? []),
    ]) {
      if (typeof f === "string") {
        // dist/* bundles are produced by `npm run build:ext`; HTML/manifest ship as-is.
        if (f.startsWith("dist/")) continue;
        expect(existsSync(join(EXT, f)), f).toBe(true);
      }
    }
  });
});
