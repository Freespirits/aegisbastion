/**
 * Zero-external-transmission attestation (doc 07 §7.1 items 1 + 4):
 *
 *  1. Static dependency-graph gate — the detection packages (core, url,
 *     content, dom, intel) must contain NO network APIs and no imports of
 *     the transport-owning packages (node/, hub/, ext/). This stands in for
 *     the ESLint `no-restricted-imports` rule (eslint is not in the dep
 *     tree; the CI gate here is equivalent and enforced on every `npm test`).
 *  2. Runtime attestation — the full pipeline runs under a network-mocked
 *     sandbox: any egress attempt during analyze* throws, failing the test.
 */

import { describe, expect, it, vi, afterEach } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPhishCatcher } from "../src/index.js";
import { evidenceFromEmail, evidenceFromPage } from "../src/core/normalize.js";
import { evidenceFromUrl } from "../src/url/checks.js";
import { fakeIntel } from "./helpers.js";

const SRC = fileURLToPath(new URL("../src", import.meta.url));

const CLEAN_PACKAGES = ["core", "url", "content", "dom", "intel"];

const FORBIDDEN_PATTERNS: [RegExp, string][] = [
  [/\bfetch\s*\(/, "fetch("],
  [/\bXMLHttpRequest\b/, "XMLHttpRequest"],
  [/\bWebSocket\b/, "WebSocket"],
  [/\bsendBeacon\b/, "sendBeacon"],
  [/\bEventSource\b/, "EventSource"],
  [/\bnavigator\s*\.\s*sendBeacon/, "navigator.sendBeacon"],
  [/from\s+["']node:(?:net|dns|http|https|http2|dgram)["']/, "node: network import"],
  [/from\s+["'](?:net|dns|http|https|axios|node-fetch|undici)["']/, "network library import"],
  [/from\s+["'][^"']*\/(?:node|hub|ext)\//, "import of a transport-owning package"],
  [/import\s*\(\s*["'][^"']*\/(?:node|hub|ext)\//, "dynamic import of a transport-owning package"],
];

function* walk(dir: string): Generator<string> {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) yield* walk(path);
    else if (entry.endsWith(".ts")) yield path;
  }
}

describe("zero-external-transmission: static dependency-graph gate (§7.1)", () => {
  for (const pkg of CLEAN_PACKAGES) {
    it(`src/${pkg}/ contains no network APIs and no transport imports`, () => {
      for (const file of walk(join(SRC, pkg))) {
        const text = readFileSync(file, "utf8");
        for (const [pattern, label] of FORBIDDEN_PATTERNS) {
          expect(pattern.test(text), `${file}: forbidden ${label}`).toBe(false);
        }
      }
    });
  }

  it("the neutral + browser entries do not import node/hub/ext code", () => {
    for (const entry of ["index.ts", join("browser", "index.ts")]) {
      const text = readFileSync(join(SRC, entry), "utf8");
      for (const [pattern, label] of FORBIDDEN_PATTERNS.slice(6)) {
        expect(pattern.test(text), `${entry}: forbidden ${label}`).toBe(false);
      }
    }
  });
});

describe("zero-external-transmission: runtime attestation (§7.1 item 4)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("analyze* performs no egress under a network-mocked sandbox", async () => {
    const boom = (name: string) => () => {
      throw new Error(`EGRESS ATTEMPT: ${name}`);
    };
    vi.stubGlobal("fetch", boom("fetch"));
    vi.stubGlobal("XMLHttpRequest", boom("XMLHttpRequest"));
    vi.stubGlobal("WebSocket", boom("WebSocket"));
    vi.stubGlobal("EventSource", boom("EventSource"));
    Object.defineProperty(globalThis, "navigator", {
      value: { sendBeacon: boom("sendBeacon") },
      configurable: true,
    });

    const catcher = createPhishCatcher({ intel: fakeIntel() });

    // URL-only path
    const vUrl = catcher.analyzeUrl("https://paypa1.com/");
    expect(vUrl.verdict).toBe("suspicious");

    // Email path
    const email = evidenceFromEmail({
      headers: { authenticationResults: "mx; dmarc=fail header.from=bad.tk" },
      bodyText: "Confirm your password",
      urls: ["http://evil.tk/x"],
    });
    const vEmail = catcher.analyze(email);
    expect(vEmail.verdict).toBe("malicious");

    // Page path
    const page = evidenceFromPage({
      origin: "https://example.com",
      url: "https://example.com/",
      title: "PayPal — Sign In",
      forms: [{ action: "http://evil.tk/x", method: "POST", hasPasswordField: true, actionOrigin: "http://evil.tk" }],
    });
    const vPage = catcher.analyze(page);
    expect(vPage.score).toBeGreaterThan(0);

    // Reaching here means no stub fired — zero egress during analysis.
  });
});
