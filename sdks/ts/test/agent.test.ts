/**
 * High-level agent runner (doc 01 §9.1): ACK, guardrail enforcement
 * (REJECTED_UNAUTHORIZED on missing/invalid tokens), kill ≤ 5 s, and honest
 * TaskResult reporting with targets_touched + TARGET_TOUCHED audit records.
 */

import { describe, expect, it } from "vitest";
import { create } from "@bufbuild/protobuf";
import { createHash } from "node:crypto";
import type { JsonObject } from "@bufbuild/protobuf";
import { TaskAssignmentSchema, TaskResultStatus, type TaskResult } from "@aegisbastion/gen/aegisbastion/platform/v1/task_pb.js";
import { RiskClass } from "@aegisbastion/gen/aegisbastion/platform/v1/types_pb.js";
import { Agent, type AgentModule, type RunOutcome, type TaskContext } from "../src/agent.js";
import type { RegistryClient } from "../src/registry.js";
import { Pep } from "../src/pep.js";
import { JwksCache } from "../src/jwks.js";
import { RevocationCache } from "../src/revocation.js";
import { AuditEmitter } from "../src/audit.js";
import type { AuditEvent } from "@aegisbastion/gen/aegisbastion/platform/v1/audit_pb.js";
import { makeKey, signToken, NOW } from "./helpers.js";

const ASSIGNMENT = {
  taskId: "tsk_1",
  missionId: "msn_1",
  planId: "pln_1",
  capability: "monitor.watch",
  timeoutS: 300,
};

class FakeRegistry {
  results: TaskResult[] = [];
  acked: string[] = [];
  progress: JsonObject[] = [];
  private queued: ReturnType<typeof createAssignment>[] = [];

  async register(): Promise<string> {
    return "agent_test";
  }
  async heartbeat(): Promise<boolean> {
    return false;
  }
  async ackTask(_agentId: string, taskId: string): Promise<void> {
    this.acked.push(taskId);
  }
  async reportProgress(_a: string, _t: string, p: JsonObject): Promise<void> {
    this.progress.push(p);
  }
  async reportResult(result: TaskResult): Promise<void> {
    this.results.push(result);
  }
  push(a: ReturnType<typeof createAssignment>): void {
    this.queued.push(a);
  }
  async *streamTasks(_agentId: string, signal?: AbortSignal): AsyncGenerator<ReturnType<typeof createAssignment>> {
    for (;;) {
      while (this.queued.length > 0) {
        yield this.queued.shift()!;
      }
      if (signal?.aborted) return;
      await new Promise((r) => setTimeout(r, 10));
    }
  }
}

function createAssignment(over: Record<string, unknown> = {}) {
  return create(TaskAssignmentSchema, { ...ASSIGNMENT, ...over });
}

function asRegistry(fake: FakeRegistry): RegistryClient {
  return fake as unknown as RegistryClient;
}

async function waitFor(cond: () => boolean, ms = 5000): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (cond()) return;
    if (Date.now() - start > ms) throw new Error("waitFor timeout");
    await new Promise((r) => setTimeout(r, 20));
  }
}

const noopPep = () => new Pep({ jwks: new JwksCache({ fetchKeys: async () => [] }), manifestFetcher: { fetch: async () => new Uint8Array() } });

describe("Agent runner", () => {
  it("reports REJECTED_UNAUTHORIZED for an R1 assignment with no token (fail-closed)", async () => {
    const registry = new FakeRegistry();
    let ran = false;
    const module: AgentModule = {
      plan: async () => {},
      run: async (): Promise<RunOutcome> => {
        ran = true;
        return {};
      },
      abort: () => {},
    };
    const agent = new Agent({
      manifest: {} as never,
      module,
      registry: asRegistry(registry),
      pep: noopPep(),
      revocations: new RevocationCache(),
      transport: "stream",
    });
    await agent.start();
    registry.push(createAssignment({ riskClass: RiskClass.R1, authorizationToken: "" }));
    await waitFor(() => registry.results.length === 1);
    expect(registry.acked).toEqual(["tsk_1"]); // ACK within 10 s
    expect(registry.results[0]!.status).toBe(TaskResultStatus.REJECTED_UNAUTHORIZED);
    expect(ran).toBe(false); // no target contact without a valid token
    await agent.stop();
  });

  it("runs an R0 task and reports SUCCEEDED", async () => {
    const registry = new FakeRegistry();
    const module: AgentModule = {
      plan: async () => {},
      run: async (ctx: TaskContext): Promise<RunOutcome> => {
        await ctx.reportProgress({ percent: 50 });
        return { summary: { findings: 0 } };
      },
      abort: () => {},
    };
    const agent = new Agent({
      manifest: {} as never,
      module,
      registry: asRegistry(registry),
      pep: noopPep(),
      revocations: new RevocationCache(),
      transport: "stream",
    });
    await agent.start();
    registry.push(createAssignment({ riskClass: RiskClass.R0 }));
    await waitFor(() => registry.results.length === 1);
    expect(registry.results[0]!.status).toBe(TaskResultStatus.SUCCEEDED);
    expect(registry.progress).toEqual([{ percent: 50 }]);
    await agent.stop();
  });

  it("R1 happy path: token → manifest → touch gates + audits each target", async () => {
    const key = await makeKey("gk-a");
    const targets = ["https://api.acme.com/graphql"];
    const bytes = JSON.stringify(targets);
    const jwks = new JwksCache({ fetchKeys: async () => [key.publicJwk] });
    await jwks.start();
    const pep = new Pep({
      jwks,
      manifestFetcher: { fetch: async () => new TextEncoder().encode(bytes) },
      revocations: new RevocationCache(),
      nowSeconds: () => NOW,
    });
    const token = await signToken(key, {
      task_id: "tsk_1",
      risk_class: "R1",
      targets: {
        hash_alg: "sha256",
        manifest_uri: "blob://token-manifests/tok/targets.json",
        manifest_sha256: createHash("sha256").update(bytes).digest("hex"),
        count: 1,
      },
    });

    const registry = new FakeRegistry();
    const auditEvents: AuditEvent[] = [];
    const audit = new AuditEmitter(async (e) => {
      auditEvents.push(e);
    });
    const module: AgentModule = {
      plan: async () => {},
      run: async (ctx: TaskContext): Promise<RunOutcome> => {
        await ctx.touch("https://api.acme.com/graphql"); // in manifest → allowed
        await expect(ctx.touch("https://attacker.example.com")).rejects.toMatchObject({
          code: "TARGET_NOT_IN_MANIFEST",
        });
        return { summary: { ok: true } };
      },
      abort: () => {},
    };
    const agent = new Agent({
      manifest: {} as never,
      module,
      registry: asRegistry(registry),
      pep,
      revocations: new RevocationCache(),
      audit,
      transport: "stream",
    });
    await agent.start();
    registry.push(createAssignment({ riskClass: RiskClass.R1, authorizationToken: token }));
    await waitFor(() => registry.results.length === 1);
    expect(registry.results[0]!.status).toBe(TaskResultStatus.SUCCEEDED);
    expect(registry.results[0]!.metrics?.targetsTouched).toEqual(["https://api.acme.com/graphql"]);
    // Per-probe TARGET_TOUCHED record — the authoritative cross-check (Ruling A.4).
    expect(auditEvents).toHaveLength(1);
    expect(auditEvents[0]!.payload).toMatchObject({
      target: "https://api.acme.com/graphql",
    });
    expect(auditEvents[0]!.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    await agent.stop();
    jwks.stop();
  });

  it("halts within the kill SLA: abort() invoked, result KILLED", async () => {
    const registry = new FakeRegistry();
    let runStarted = false;
    let aborted = false;
    const module: AgentModule = {
      plan: async () => {},
      run: async (ctx: TaskContext): Promise<RunOutcome> => {
        runStarted = true;
        await new Promise<void>((resolve, reject) => {
          ctx.signal.addEventListener("abort", () => reject(new Error("halted")), { once: true });
        });
        return {};
      },
      abort: () => {
        aborted = true;
      },
    };
    const agent = new Agent({
      manifest: {} as never,
      module,
      registry: asRegistry(registry),
      pep: noopPep(),
      revocations: new RevocationCache(),
      transport: "stream",
    });
    await agent.start();
    registry.push(createAssignment({ riskClass: RiskClass.R0 }));
    await waitFor(() => runStarted);
    const killStart = Date.now();
    agent.abortTask("tsk_1", "control.kill");
    await waitFor(() => registry.results.length === 1);
    expect(Date.now() - killStart).toBeLessThan(5000); // 5 s halt SLA (doc 01 §10.5)
    expect(aborted).toBe(true);
    expect(registry.results[0]!.status).toBe(TaskResultStatus.KILLED);
    await agent.stop();
  });
});
