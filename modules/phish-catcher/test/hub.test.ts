/**
 * Hub seam (doc 07 §5/§8; doc 00 §4): the scan.request authorization gate,
 * §5.4 redaction, the report queue, the inert-by-default transport, and the
 * SDK agent-module mapping (offline fakes — no bus, no gatekeeper).
 */

import { describe, expect, it } from "vitest";
import type { ScopeTokenClaims } from "@aegisbastion/agent-sdk";
import { ScanRequestGate, HARD_CEILING_PER_MIN, DEFAULT_RATE_CAP_PER_MIN, type TokenVerifier } from "../src/hub/scan-gate.js";
import type { ScanRequestPayload } from "../src/hub/messages.js";
import { redactFindingReport, ReportQueue } from "../src/hub/redact.js";
import { InertHubTransport, createHubTransport } from "../src/hub/transport.js";
import { PhishBatchAgentModule } from "../src/hub/agent-module.js";
import { createPhishCatcher } from "../src/index.js";
import { evidenceFromEmail, evidenceFromUrl } from "../src/index.js";
import { fakeIntel } from "./helpers.js";

function claims(overrides: Partial<ScopeTokenClaims> = {}): ScopeTokenClaims {
  return {
    iss: "gatekeeper.platform",
    aud: "aegisbastion.modules",
    jti: "tok-1",
    sub: "agent-1",
    task_id: "task-1",
    roe_id: "roe-1",
    roe_version: 1,
    risk_class: "R1",
    capabilities: ["phish.url"],
    targets: { hash_alg: "sha256", manifest_uri: "blob://token-manifests/m", manifest_sha256: "ab" },
    iat: 0,
    exp: 9_999_999_999,
    ...overrides,
  };
}

const okVerifier: TokenVerifier = async () => claims();
const failingVerifier: TokenVerifier = async () => {
  throw new Error("JWKS unreachable (cached keys expired)");
};

function req(overrides: Partial<ScanRequestPayload> = {}): ScanRequestPayload {
  return { scopeId: "tenant-a", inputRefs: ["s3://samples/1.eml"], scopeToken: "jwt", taskId: "task-1", ...overrides };
}

function gate(overrides: Partial<ConstructorParameters<typeof ScanRequestGate>[0]> = {}): ScanRequestGate {
  return new ScanRequestGate({
    mode: "node-batch",
    scopeAllowlist: ["tenant-a"],
    verifyToken: okVerifier,
    ...overrides,
  });
}

describe("scan.request gate (§5.2 handling order, §8)", () => {
  it("browser-mode agents reject unconditionally (UNSUPPORTED_IN_MODE)", async () => {
    const g = gate({ mode: "browser-extension" });
    const d = await g.evaluate(req());
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("UNSUPPORTED_IN_MODE");
  });

  it("no token → ROE_INVALID (fail-closed, §8.2)", async () => {
    const d = await gate().evaluate(req({ scopeToken: undefined }));
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("ROE_INVALID");
  });

  it("token verification failure → ROE_INVALID (JWKS unreachable, §9)", async () => {
    const d = await gate({ verifyToken: failingVerifier }).evaluate(req());
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("ROE_INVALID");
  });

  it("out-of-allowlist scopeId → SCOPE_DENIED (§8.1)", async () => {
    const d = await gate().evaluate(req({ scopeId: "tenant-b" }));
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("SCOPE_DENIED");
  });

  it("accepts a valid, in-scope, under-cap request", async () => {
    const d = await gate().evaluate(req());
    expect(d.ok).toBe(true);
    if (d.ok) expect(d.effectiveRateCapPerMin).toBe(DEFAULT_RATE_CAP_PER_MIN);
  });

  it("enforces the per-scope rate cap (§8.3)", async () => {
    const g = gate();
    const big = req({ inputRefs: Array.from({ length: 600 }, (_, i) => `s3://s/${i}.eml`) });
    expect((await g.evaluate(big)).ok).toBe(true); // 600/600 capacity
    const d = await g.evaluate(req());
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("RATE_CAPPED");
  });

  it("the token's tighter rate_caps claim wins", async () => {
    const g = gate({ verifyToken: async () => claims({ rate_caps: { max_rps: 1 } }) }); // 60/min
    const d = await g.evaluate(req({ inputRefs: Array.from({ length: 61 }, (_, i) => `s3://s/${i}.eml`) }));
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("RATE_CAPPED");
  });

  it("the compiled-in ceiling (5000/min) cannot be raised by config", async () => {
    const g = gate({ defaultRateCapPerMin: 100_000 });
    const d = await g.evaluate(req({ inputRefs: Array.from({ length: HARD_CEILING_PER_MIN + 1 }, (_, i) => `s3://s/${i}.eml`) }));
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.reason).toBe("RATE_CAPPED");
  });
});

describe("finding.report redaction (§5.4, non-negotiable)", () => {
  it("hashes URLs/sender/message-id and never carries content", () => {
    const ev = evidenceFromEmail({
      headers: { from: "Alice <alice@example.com>", messageId: "<m-1@example.com>" },
      subject: "top secret subject",
      bodyText: "TOP SECRET BODY",
      urls: ["http://evil.tk/x"],
      attachments: [{ filename: "a.exe", contentType: "application/octet-stream", size: 10, sha256: "ab".repeat(32) }],
    });
    const verdict = createPhishCatcher({ intel: fakeIntel() }).analyze(ev);
    const report = redactFindingReport(ev, verdict, { urlSalt: "s3-cr3t", consent: "user-item" }, "r-1");
    const json = JSON.stringify(report);
    expect(json).not.toContain("TOP SECRET BODY");
    expect(json).not.toContain("top secret subject");
    expect(json).not.toContain("http://evil.tk/x");
    expect(json).not.toContain("alice@example.com");
    expect(json).not.toContain("m-1@example.com");
    expect(report.urlHashes[0]).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(report.senderHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(report.messageIdHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(report.attachments?.[0]?.sha256).toBe("ab".repeat(32));
    expect(report.consent).toBe("user-item");
  });

  it("supports the org-policy cleartext-host-only mode (§5.4)", () => {
    const ev = evidenceFromUrl("http://evil.tk/steal?creds=1");
    const verdict = createPhishCatcher({ intel: fakeIntel() }).analyze(ev);
    const report = redactFindingReport(ev, verdict, { urlSalt: "x", allowCleartextHost: true, consent: "org-policy" }, "r-2");
    expect(report.urlHashes[0]).toBe("host:evil.tk");
    expect(JSON.stringify(report)).not.toContain("creds=1");
  });
});

describe("report queue (§5.4: ring buffer 500, drop oldest)", () => {
  it("caps at 500 and drops oldest first", () => {
    const q = new ReportQueue(500);
    const ev = evidenceFromUrl("https://example.com/");
    const verdict = createPhishCatcher({ intel: fakeIntel() }).analyze(ev);
    for (let i = 0; i < 505; i++) {
      q.enqueue(redactFindingReport(ev, verdict, { urlSalt: "x", consent: "org-policy" }, `r-${i}`));
    }
    expect(q.size).toBe(500);
    const drained = q.drain(2);
    expect(drained[0]?.reportId).toBe("r-5"); // r-0..r-4 dropped
    q.requeue(drained);
    expect(q.size).toBe(500);
  });
});

describe("hub transport seam (MVP-A inert by default, doc 00 §4)", () => {
  it("the default transport is inert and transmits nothing", async () => {
    const t = new InertHubTransport("node-batch");
    let pushes = 0;
    await t.start({ onScanRequest: () => { pushes++; }, onPolicyPush: () => { pushes++; }, onIntelPush: () => { pushes++; } });
    expect(t.live).toBe(false);
    await t.sendHeartbeat({ bundleVersion: "1", policyVersion: 1, counters: { analyzed: 1, clean: 1, suspicious: 0, malicious: 0, reportsQueued: 0 } });
    await t.sendScanRejected({ scopeId: "x", reason: "SCOPE_DENIED" });
    expect(t.droppedCounts()).toEqual({ heartbeat: 1, scanResult: 0, scanRejected: 1, findingReport: 0 });
    expect(pushes).toBe(0);
    await t.stop();
  });

  it("the factory returns inert unless the feature flag is on", async () => {
    const t = await createHubTransport({ mode: "node-batch" });
    expect(t).toBeInstanceOf(InertHubTransport);
    const t2 = await createHubTransport({ enabled: false, mode: "node-batch" });
    expect(t2.live).toBe(false);
  });
});

describe("SDK agent module (doc 01 §9.1 plan/run/abort — offline fake ctx)", () => {
  const assignment = (params: Record<string, unknown>, capability = "phish.url") => ({
    taskId: "task-1",
    missionId: "mission-1",
    capability,
    params,
    authorizationToken: "jwt",
    riskClass: 1,
    timeoutS: 60,
  });

  function fakeCtx(params: Record<string, unknown>, capability?: string) {
    const progress: unknown[] = [];
    return {
      progress,
      ctx: {
        agentId: "agent-1",
        assignment: assignment(params, capability) as never,
        auth: null,
        signal: new AbortController().signal,
        touch: async () => {},
        reportProgress: async (p: unknown) => {
          progress.push(p);
        },
        currentToken: () => "jwt",
      },
    };
  }

  const module = () =>
    new PhishBatchAgentModule({
      catcher: createPhishCatcher({ intel: fakeIntel() }),
      gate: gate(),
      redaction: { urlSalt: "test-salt" },
    });

  it("plan() rejects unsupported capabilities and missing scopeId", async () => {
    const m = module();
    await expect(m.plan(assignment({ scopeId: "tenant-a", urls: ["https://example.com"] }, "stress.ddos") as never)).rejects.toThrow(/unsupported capability/);
    await expect(m.plan(assignment({ urls: ["https://example.com"] }) as never)).rejects.toThrow(/scopeId/);
    await expect(m.plan(assignment({ scopeId: "tenant-a" }) as never)).rejects.toThrow(/urls|inputRefs/);
  });

  it("run() returns scan.rejected when the gate denies", async () => {
    const { ctx } = fakeCtx({ scopeId: "tenant-b", urls: ["https://example.com"] });
    const outcome = await module().run(ctx as never);
    expect(outcome.summary?.type).toBe("scan.rejected");
    expect(outcome.summary?.reason).toBe("SCOPE_DENIED");
  });

  it("run() scores URLs and returns an aggregate scan.result with redacted reports", async () => {
    const urls = ["https://example.com/", "https://paypa1.com/", "https://evil.tk/"];
    const { ctx, progress } = fakeCtx({ scopeId: "tenant-a", urls });
    const outcome = await module().run(ctx as never);
    expect(outcome.summary?.type).toBe("scan.result");
    const agg = outcome.summary?.aggregate as { items: number; clean: number; suspicious: number; malicious: number };
    expect(agg.items).toBe(3);
    expect(agg.clean + agg.suspicious + agg.malicious).toBe(3);
    expect(agg.suspicious).toBeGreaterThanOrEqual(1); // paypa1.com typosquat
    // Reports are redacted (no cleartext URLs).
    expect(JSON.stringify(outcome.summary?.reports)).not.toContain("https://paypa1.com/");
    expect(progress.length).toBe(1);
  });
});
