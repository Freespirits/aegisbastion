/**
 * High-level agent runner (doc 01 §9.1). Module teams implement ONE
 * interface — plan / run / abort — and the SDK implements contract items 3–8
 * of doc 01 §9 as library calls: assignment consumption + ACK, client-side
 * authorization enforcement (PEP guardrails), heartbeats, kill-switch
 * handling (≤ 5 s), honest TaskResult reporting with targets_touched,
 * idempotency on task_id, and trace-context propagation.
 */

import { create } from "@bufbuild/protobuf";
import type { JsonObject } from "@bufbuild/protobuf";
import { timestampFromDate, timestampNow } from "@bufbuild/protobuf/wkt";
import type { AgentManifest } from "@aegisbastion/gen/aegisbastion/platform/v1/registry_pb.js";
import {
  TaskResultSchema,
  TaskResultStatus,
  type TaskAssignment,
} from "@aegisbastion/gen/aegisbastion/platform/v1/task_pb.js";
import { RiskClass } from "@aegisbastion/gen/aegisbastion/platform/v1/types_pb.js";
import { AuditEmitter } from "./audit.js";
import type { BusClient } from "./bus.js";
import { PepError, isPepError } from "./errors.js";
import { scopeHashCheckpoint } from "./jcs.js";
import type { Pep, TaskAuthorization } from "./pep.js";
import type { RegistryClient } from "./registry.js";
import { TokenReauthorizer } from "./refresh.js";
import { refreshScopeToken } from "./gatekeeper.js";
import type { TokenServiceClient } from "./gatekeeper.js";
import { decodeControlKill, type RevocationCache } from "./revocation.js";

/** What the module's run() returns; the SDK wraps it in a TaskResult. */
export interface RunOutcome {
  summary?: JsonObject;
  artifactRefs?: string[];
  /** Extra metrics merged into TaskResultMetrics (targets_touched is SDK-owned). */
  requestsSent?: number | bigint;
}

export interface TaskContext {
  readonly agentId: string;
  readonly assignment: TaskAssignment;
  /**
   * The PEP authorization for this task (null for R0 — R0 requires no
   * per-target token, doc 11 §1, and R0 work makes no target contact).
   */
  readonly auth: TaskAuthorization | null;
  /** Fires on kill switch, revocation, re-authorization denial, or timeout. */
  readonly signal: AbortSignal;
  /**
   * Gate + record one target touch (doc 01 §9 item 4/6): PEP checkTarget
   * (manifest or scope-bound evaluation, exclusions-first, rate caps,
   * revocation) followed by the per-probe TARGET_TOUCHED audit record —
   * the authoritative cross-check (Ruling A.4). Throws PepError on denial.
   */
  touch: (target: string) => Promise<void>;
  /** Stream progress to the Orchestrator (module-defined payload). */
  reportProgress: (progress: JsonObject) => Promise<void>;
  /** The current Scope Token (the re-authorizer may swap it mid-run). */
  currentToken: () => string | null;
}

/**
 * The module contract (doc 01 §9.1). Throw from plan() when params are
 * unsupported; run() performs work within SDK-enforced guardrails; abort()
 * is invoked by the SDK on kill/timeout and must stop target contact ≤ 5 s.
 */
export interface AgentModule {
  plan(assignment: TaskAssignment): Promise<void>;
  run(ctx: TaskContext): Promise<RunOutcome>;
  abort(taskId: string): void;
}

export interface AgentOptions {
  manifest: AgentManifest;
  module: AgentModule;
  registry: RegistryClient;
  pep: Pep;
  revocations: RevocationCache;
  /** Required for the bus transport and for control.kill / revocations. */
  bus?: BusClient;
  /** Enables the mid-run re-authorization loop for R1+ tasks. */
  tokenClient?: TokenServiceClient;
  audit?: AuditEmitter;
  transport?: "bus" | "stream";
  /** Doc 01 §8.1: 10 s heartbeat cadence (30 s Registry TTL). */
  heartbeatIntervalMs?: number;
}

interface RunningTask {
  taskId: string;
  abortController: AbortController;
  claims: TaskAuthorization | null;
  token: string | null;
  reauthorizer: TokenReauthorizer | null;
  finished: boolean;
}

const HEARTBEAT_MS = 10_000;

export class Agent {
  private agentId = "";
  private readonly running = new Map<string, RunningTask>();
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private stops: Array<() => Promise<void>> = [];
  private started = false;

  constructor(private readonly opts: AgentOptions) {}

  get id(): string {
    return this.agentId;
  }

  /** Register (re-register on version change), then start all loops. */
  async start(): Promise<void> {
    if (this.started) throw new Error("agent already started");
    this.started = true;

    this.agentId = await this.opts.registry.register(this.opts.manifest);
    if (this.agentId === "") throw new Error("registry returned an empty agent_id");

    const transport = this.opts.transport ?? (this.opts.bus ? "bus" : "stream");

    if (this.opts.bus) {
      const revStop = await this.opts.bus.subscribeRevocations(this.agentId, (event) => {
        this.opts.revocations.applyEvent(event);
        this.sweepRevokedTasks();
      });
      this.stops.push(revStop.stop);

      const killStop = this.opts.bus.subscribeKill((data) => this.handleControlKill(data));
      this.stops.push(killStop.stop);

      if (transport === "bus") {
        const assignStop = await this.opts.bus.consumeAssignments(
          this.agentId,
          async (delivery) => {
            await this.acceptAssignment(delivery.assignment);
          },
        );
        this.stops.push(assignStop.stop);
      }
    }

    if (transport === "stream") {
      const streamStop = new AbortController();
      const loop = this.streamLoop(streamStop.signal).catch(() => {});
      this.stops.push(async () => {
        streamStop.abort();
        await loop;
      });
    }

    this.startHeartbeats();
  }

  async stop(): Promise<void> {
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    for (const task of this.running.values()) {
      this.abortTask(task.taskId, "agent shutdown");
    }
    for (const stop of this.stops.splice(0)) {
      await stop();
    }
    this.started = false;
  }

  // --- assignment intake ----------------------------------------------------

  /** ACK fast (≤ 10 s, doc 01 §9 item 3), then execute in the background. */
  private async acceptAssignment(assignment: TaskAssignment): Promise<void> {
    if (this.running.has(assignment.taskId)) return; // idempotent on task_id
    await this.opts.registry.ackTask(this.agentId, assignment.taskId);
    // Execution errors are funneled into the TaskResult — never rethrown.
    void this.execute(assignment).catch(() => {});
  }

  private async streamLoop(signal: AbortSignal): Promise<void> {
    for (;;) {
      if (signal.aborted) return;
      try {
        for await (const assignment of this.opts.registry.streamTasks(this.agentId, signal)) {
          if (signal.aborted) return;
          await this.acceptAssignment(assignment);
        }
      } catch {
        if (signal.aborted) return;
        await new Promise((r) => setTimeout(r, 2_000)); // reconnect backoff
      }
    }
  }

  // --- execution ------------------------------------------------------------

  private async execute(assignment: TaskAssignment): Promise<void> {
    const taskId = assignment.taskId;
    const abortController = new AbortController();
    const task: RunningTask = {
      taskId,
      abortController,
      claims: null,
      token: assignment.authorizationToken || null,
      reauthorizer: null,
      finished: false,
    };
    this.running.set(taskId, task);
    const startedAt = new Date();

    try {
      await this.opts.module.plan(assignment);

      // Client-side authorization (doc 01 §9 item 4): R1+ requires a valid
      // Scope Token; any mismatch → REJECTED_UNAUTHORIZED (fail-closed).
      if (assignment.riskClass !== RiskClass.R0) {
        if (task.token === null) {
          throw new PepError("TOKEN_MISSING", "R1+ assignment carries no Scope Token");
        }
        task.claims = await this.opts.pep.authorizeTask(task.token, taskId);
        this.opts.revocations.assertNotRevoked(task.claims.claims);
        this.startReauthorization(task);
      }

      const ctx = this.buildTaskContext(task, assignment);
      const outcome = await this.runWithDeadline(task, assignment, ctx);
      if (task.finished) return;
      task.finished = true;
      await this.report(task, assignment, TaskResultStatus.SUCCEEDED, startedAt, outcome);
    } catch (err) {
      if (task.finished) return;
      task.finished = true;
      const status = this.statusForError(err, abortController.signal.aborted);
      await this.report(task, assignment, status, startedAt, {
        summary: { error: (err as Error).message },
      }).catch(() => {});
    } finally {
      task.reauthorizer?.stop().catch(() => {});
      this.running.delete(taskId);
    }
  }

  private statusForError(err: unknown, aborted: boolean): TaskResultStatus {
    if (isPepError(err)) {
      if (err.code === "KILLED" || (aborted && err.code !== "RATE_LIMITED")) {
        return TaskResultStatus.KILLED;
      }
      return TaskResultStatus.REJECTED_UNAUTHORIZED;
    }
    if (aborted) return TaskResultStatus.KILLED;
    return TaskResultStatus.FAILED;
  }

  private buildTaskContext(task: RunningTask, assignment: TaskAssignment): TaskContext {
    const touched: string[] = [];
    (task as RunningTask & { touched?: string[] }).touched = touched;
    return {
      agentId: this.agentId,
      assignment,
      auth: task.claims,
      signal: task.abortController.signal,
      touch: async (target: string) => {
        if (task.claims === null) {
          throw new PepError("TOKEN_MISSING", "no authorization for target contact");
        }
        task.claims.checkTarget(target, assignment.capability);
        touched.push(target);
        if (this.opts.audit && task.claims) {
          await this.opts.audit.targetTouched({
            agentId: this.agentId,
            taskId: assignment.taskId,
            missionId: assignment.missionId,
            roeId: task.claims.claims.roe_id,
            target,
            tokenJti: task.claims.claims.jti,
            capability: assignment.capability,
          });
        }
      },
      reportProgress: async (progress: JsonObject) => {
        await this.opts.registry.reportProgress(this.agentId, assignment.taskId, progress);
      },
      currentToken: () => task.token,
    };
  }

  /** Enforce timeout_s / deadline (doc 01 §5.6); abort the module on expiry. */
  private runWithDeadline(
    task: RunningTask,
    assignment: TaskAssignment,
    ctx: TaskContext,
  ): Promise<RunOutcome> {
    return new Promise<RunOutcome>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const timeouts: number[] = [];
      if (assignment.timeoutS > 0) timeouts.push(assignment.timeoutS * 1000);
      if (assignment.deadline) {
        timeouts.push(Number(assignment.deadline.seconds) * 1000 - Date.now());
      }
      const ms = timeouts.length > 0 ? Math.min(...timeouts) : 0;
      if (ms > 0) {
        timer = setTimeout(() => {
          this.abortTask(task.taskId, "deadline exceeded");
          reject(new PepError("KILLED", "task exceeded timeout_s/deadline"));
        }, ms);
      }
      this.opts.module.run(ctx).then(
        (outcome) => {
          if (timer !== null) clearTimeout(timer);
          resolve(outcome);
        },
        (err: unknown) => {
          if (timer !== null) clearTimeout(timer);
          reject(err instanceof Error ? err : new Error(String(err)));
        },
      );
    });
  }

  private async report(
    task: RunningTask,
    assignment: TaskAssignment,
    status: TaskResultStatus,
    startedAt: Date,
    outcome: RunOutcome,
  ): Promise<void> {
    const touched = (task as RunningTask & { touched?: string[] }).touched ?? [];
    // Ruling A.4: a scope-hash checkpoint may accompany — never replace —
    // the per-probe TARGET_TOUCHED records.
    const targetsTouched = [...touched];
    if (task.claims?.scopeBound && task.claims.manifest.form === "scope") {
      targetsTouched.push(scopeHashCheckpoint(task.claims.manifest.sha256));
    }
    const result = create(TaskResultSchema, {
      taskId: assignment.taskId,
      agentId: this.agentId,
      status,
      startedAt: timestampFromDate(startedAt),
      finishedAt: timestampNow(),
      summary: outcome.summary ?? {},
      artifactRefs: outcome.artifactRefs ?? [],
      metrics: {
        requestsSent: BigInt(outcome.requestsSent ?? 0),
        targetsTouched,
      },
      error: status === TaskResultStatus.FAILED ? String(outcome.summary?.error ?? "") : "",
    });
    await this.opts.registry.reportResult(result);
  }

  // --- re-authorization -----------------------------------------------------

  private startReauthorization(task: RunningTask): void {
    if (!this.opts.tokenClient || task.token === null) return;
    const client = this.opts.tokenClient;
    task.reauthorizer = new TokenReauthorizer({
      refresh: async (current) => {
        const res = await refreshScopeToken(client, current);
        return res.token;
      },
    });
    task.reauthorizer.start(
      () => task.token ?? "",
      {
        onSuccessor: (token) => {
          task.token = token;
          // Re-verify the successor and swap the authorization context.
          void this.opts.pep
            .authorizeTask(token, task.taskId)
            .then((auth) => {
              task.claims = auth;
            })
            .catch(() => this.abortTask(task.taskId, "successor token failed verification"));
        },
        onDenied: () => {
          // Policy re-check failed (RoE revoked, approval lapsed): halt now.
          this.abortTask(task.taskId, "re-authorization denied");
        },
        onRefreshError: () => {
          // Transport failures are retried by the loop until token expiry.
        },
      },
    );
  }

  // --- kill / revocation ----------------------------------------------------

  /** Abort one task: stop target contact ≤ 5 s (doc 01 §10.5). */
  abortTask(taskId: string, reason: string): void {
    const task = this.running.get(taskId);
    if (!task || task.finished) return;
    task.abortController.abort();
    this.opts.module.abort(taskId);
    void reason;
  }

  private sweepRevokedTasks(): void {
    for (const task of this.running.values()) {
      if (task.claims === null) continue;
      const signal = this.opts.revocations.check(task.claims.claims);
      if (signal !== null) this.abortTask(task.taskId, signal.reason);
    }
  }

  private handleControlKill(data: Uint8Array): void {
    const decoded = decodeControlKill(data);
    if ("global" in decoded) {
      // Fail-safe: unparseable kill broadcast ⇒ halt everything.
      for (const task of this.running.values()) this.abortTask(task.taskId, "control.kill");
      return;
    }
    if (decoded.revocation) {
      this.opts.revocations.apply(decoded.revocation);
      this.sweepRevokedTasks();
    }
  }

  // --- heartbeats -----------------------------------------------------------

  private startHeartbeats(): void {
    const interval = this.opts.heartbeatIntervalMs ?? HEARTBEAT_MS;
    this.heartbeatTimer = setInterval(() => {
      const runningIds = [...this.running.keys()];
      this.opts.registry
        .heartbeat(this.agentId, runningIds)
        .then((killActive) => {
          if (killActive) {
            for (const id of runningIds) this.abortTask(id, "kill switch (heartbeat)");
          }
        })
        .catch(() => {
          // Heartbeat failures surface via Registry TTL (30 s) — the
          // Orchestrator drains this agent; no local action needed.
        });
    }, interval);
    this.heartbeatTimer.unref?.();
  }

  /** Introspection for tests/diagnostics. */
  runningTaskIds(): string[] {
    return [...this.running.keys()];
  }

  /** Auth summary for structured logs — never carries target lists. */
  describeAuth(auth: TaskAuthorization | null): JsonObject {
    if (auth === null) return { authorized: false };
    return {
      authorized: true,
      jti: auth.claims.jti,
      riskClass: auth.claims.risk_class,
      scopeBound: auth.scopeBound,
      manifestSha256: auth.manifest.sha256,
    };
  }
}
