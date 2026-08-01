/**
 * Pipeline engine + scorer (doc 07 §2.2/§3.3): composability, policy
 * handling, family caps, hard-fail rules, degraded mode, time-boxing,
 * exception containment, explanations.
 */

import { describe, expect, it } from "vitest";
import { CheckRegistry, type Check } from "../src/core/check.js";
import { Pipeline } from "../src/core/pipeline.js";
import { DEFAULT_POLICY, resolvePolicy, type PolicyConfig } from "../src/core/policy.js";
import { evaluateHardFails } from "../src/core/scorer.js";
import type { Finding } from "../src/core/verdict.js";
import { createDefaultRegistry, createPhishCatcher, MVP_CHECK_IDS } from "../src/index.js";
import { evidenceFromUrl } from "../src/url/checks.js";
import { evidenceFromEmail } from "../src/core/normalize.js";
import { fakeIntel } from "./helpers.js";

const policy = (overrides: Partial<PolicyConfig> = {}): PolicyConfig =>
  resolvePolicy({ ...DEFAULT_POLICY, ...overrides } as PolicyConfig);

const finding = (ruleId: string, weight: number, flags?: string[]): Finding => ({
  ruleId,
  severity: "high",
  weight,
  detail: `${ruleId} detail`,
  ...(flags ? { flags } : {}),
});

function customCheck(id: string, family: "url" | "content", out: Finding[]): Check {
  return {
    id,
    version: 1,
    family,
    requires: [],
    defaultWeight: 10,
    run: () => out.map((f) => ({ ...f })),
  };
}

describe("registry composability", () => {
  it("registers custom checks and runs them in a subset pipeline", () => {
    const registry = new CheckRegistry();
    registry.register(customCheck("url.custom_a", "url", [finding("url.custom_a", 15)]));
    registry.register(customCheck("content.custom_b", "content", [finding("content.custom_b", 12)]));
    const pipeline = new Pipeline(registry);
    const verdict = pipeline.analyze(evidenceFromUrl("https://example.com/"));
    expect(verdict.findings.map((f) => f.ruleId).sort()).toEqual(["content.custom_b", "url.custom_a"]);
    expect(verdict.familyScores.url).toBe(15);
    expect(verdict.familyScores.content).toBe(12);
  });

  it("the default registry carries every normative MVP rule id", () => {
    const registry = createDefaultRegistry();
    expect(registry.ids().sort()).toEqual([...MVP_CHECK_IDS].sort());
    expect(registry.ids().length).toBe(30);
  });

  it("rejects re-registering a check at the same or lower version (§3.1 audit trail)", () => {
    const registry = new CheckRegistry();
    registry.register(customCheck("url.x", "url", []));
    expect(() => registry.register(customCheck("url.x", "url", []))).toThrow(/already registered/);
    registry.register({ ...customCheck("url.x", "url", []), version: 2 });
    expect(registry.get("url.x")?.version).toBe(2);
  });
});

describe("policy handling", () => {
  it("honors disabledChecks", () => {
    const catcher = createPhishCatcher({
      intel: fakeIntel(),
      policy: policy({ disabledChecks: ["url.typosquat"] }),
    });
    const v = catcher.analyzeUrl("https://paypa1.com/");
    expect(v.findings.map((f) => f.ruleId)).not.toContain("url.typosquat");
  });

  it("honors weightOverrides", () => {
    const catcher = createPhishCatcher({
      intel: fakeIntel(),
      policy: policy({ weightOverrides: { "url.typosquat": 39 } }),
    });
    const v = catcher.analyzeUrl("https://paypa1.com/");
    const f = v.findings.find((x) => x.ruleId === "url.typosquat");
    expect(f?.weight).toBe(39);
  });

  it("skips checks whose required Evidence fields are absent (requires gate)", () => {
    const v = createPhishCatcher({ intel: fakeIntel() }).analyzeUrl("https://example.com/");
    // url-kind evidence has no message/page → auth/dom/content checks skip.
    const families = new Set(v.findings.map((f) => f.ruleId.split(".")[0]));
    expect(families.has("auth")).toBe(false);
    expect(families.has("dom")).toBe(false);
  });
});

describe("scoring model (§3.3)", () => {
  it("caps each family at its policy cap", () => {
    const registry = new CheckRegistry();
    registry.register(customCheck("url.a", "url", [finding("url.a", 30)]));
    registry.register(customCheck("url.b", "url", [finding("url.b", 30)]));
    const pipeline = new Pipeline(registry);
    const v = pipeline.analyze(evidenceFromUrl("https://example.com/"));
    expect(v.familyScores.url).toBe(40); // 60 capped at the url cap
    expect(v.score).toBe(40);
  });

  it("maps thresholds to verdict labels", () => {
    const registry = new CheckRegistry();
    registry.register(customCheck("url.a", "url", [finding("url.a", 36)]));
    const v = new Pipeline(registry).analyze(evidenceFromUrl("https://example.com/"));
    expect(v.verdict).toBe("suspicious"); // 35–69
  });

  it("hard-fails on rep.url_blocklisted exact match regardless of score", () => {
    expect(evaluateHardFails([finding("rep.url_blocklisted", 100, ["exact"])])).not.toEqual([]);
    expect(evaluateHardFails([finding("rep.url_blocklisted", 100)])).toEqual([]);
  });

  it("hard-fails on dom.password_form_offdomain on a brand host", () => {
    expect(evaluateHardFails([finding("dom.password_form_offdomain", 35, ["brand_host"])])).not.toEqual([]);
    expect(evaluateHardFails([finding("dom.password_form_offdomain", 35)])).toEqual([]);
  });

  it("hard-fails on dmarc_fail + credential_request co-occurrence", () => {
    expect(
      evaluateHardFails([finding("auth.dmarc_fail", 35), finding("content.credential_request", 30)]),
    ).not.toEqual([]);
    expect(evaluateHardFails([finding("auth.dmarc_fail", 35)])).toEqual([]);
  });

  it("a hard fail forces verdict=malicious even below the score threshold", () => {
    const registry = new CheckRegistry();
    registry.register(customCheck("url.a", "url", [finding("auth.dmarc_fail", 5), finding("content.credential_request", 5)]));
    const v = new Pipeline(registry).analyze(evidenceFromUrl("https://example.com/"));
    expect(v.hardFail).toBe(true);
    expect(v.verdict).toBe("malicious");
    expect(v.score).toBeLessThan(70);
  });
});

describe("degraded + failure semantics (§9)", () => {
  it("zeroes the reputation family weight in degraded mode", () => {
    const registry = new CheckRegistry();
    registry.register({
      id: "rep.fake",
      version: 1,
      family: "reputation",
      requires: [],
      defaultWeight: 100,
      run: () => [{ ruleId: "rep.fake", severity: "critical", detail: "x" }],
    });
    const pipeline = new Pipeline(registry);
    const v = pipeline.analyze(evidenceFromUrl("https://example.com/"), { degradedIntel: true });
    expect(v.familyScores.reputation).toBe(0);
    expect(v.meta?.degradedIntel).toBe(true);
  });

  it("contains check exceptions — the pipeline never throws", () => {
    const registry = new CheckRegistry();
    registry.register({
      id: "url.boom",
      version: 1,
      family: "url",
      requires: [],
      defaultWeight: 10,
      run: () => {
        throw new Error("kaboom");
      },
    });
    const v = new Pipeline(registry).analyze(evidenceFromUrl("https://example.com/"));
    expect(v.verdict).toBe("clean");
    expect(v.meta?.checkErrors?.["url.boom"]).toBe("kaboom");
  });

  it("records checks that exceed their time-box", () => {
    const registry = new CheckRegistry();
    registry.register({
      id: "url.slow",
      version: 1,
      family: "url",
      requires: [],
      defaultWeight: 10,
      run: () => {
        const until = Date.now() + 25;
        while (Date.now() < until) { /* busy */ }
        return [];
      },
    });
    const v = new Pipeline(registry).analyze(evidenceFromUrl("https://example.com/"), {
      policy: policy({ checkTimeboxMs: 5 }),
    });
    expect(v.checkTimeouts).toContain("url.slow");
  });

  it("emits the sandbox_recommended hint (data, not an action — §8.5)", () => {
    const catcher = createPhishCatcher({ intel: fakeIntel() });
    const suspicious = catcher.analyzeUrl("https://paypa1.com/");
    expect(suspicious.verdict).toBe("suspicious");
    expect(suspicious.hints).toContainEqual({ sandbox_recommended: true });
  });
});

describe("explanations (§3.3: no black-box scores)", () => {
  it("renders top-N explanations from i18n templates", () => {
    const v = createPhishCatcher({ intel: fakeIntel() }).analyzeUrl("https://paypa1.com/");
    expect(v.explanations.length).toBeGreaterThan(0);
    expect(v.explanations.length).toBeLessThanOrEqual(5);
    expect(v.explanations.join(" ")).toContain("typosquat");
  });
});

describe("end-to-end email pipeline", () => {
  it("dmarc_fail + credential request + urgency → malicious via hard fail", () => {
    const ev = evidenceFromEmail({
      headers: {
        authenticationResults: "mx; spf=fail smtp.mailfrom=bad.tk; dkim=fail header.d=bad.tk; dmarc=fail header.from=bad.tk",
      },
      subject: "URGENT: account suspended",
      bodyText: "Confirm your password now.",
    });
    const v = createPhishCatcher({ intel: fakeIntel() }).analyze(ev);
    expect(v.hardFail).toBe(true);
    expect(v.hardFailReasons.join(" ")).toContain("dmarc_fail + content.credential_request");
    expect(v.verdict).toBe("malicious");
  });

  it("a clean newsletter scores clean", () => {
    const ev = evidenceFromEmail({
      headers: {
        from: "newsletter@example.com",
        replyTo: "newsletter@example.com",
        returnPath: "<bounces@example.com>",
        authenticationResults: "mx; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
      },
      subject: "July product updates",
      bodyText: "Dark mode is now generally available. Read more on our blog.",
      urls: ["https://example.com/blog/july"],
      anchors: [{ href: "https://example.com/blog/july", displayText: "Read more on example.com" }],
    });
    const v = createPhishCatcher({ intel: fakeIntel() }).analyze(ev);
    expect(v.verdict).toBe("clean");
    expect(v.score).toBeLessThan(35);
  });
});
