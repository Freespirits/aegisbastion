/**
 * The Phish-Catcher batch module for the platform TS agent SDK
 * (doc 01 §9.1: plan / run / abort — everything else is SDK library calls;
 * Ruling C10). Loaded ONLY by the MVP-B hub transport
 * (agent-sdk-transport.ts) behind the feature flag; MVP-A ships standalone
 * (doc 00 §4). Type-only SDK imports keep this file side-effect-free.
 *
 * Task mapping: a `scan.request` (doc 07 §5.2) arrives as a TaskAssignment
 * whose params carry the ScanRequestPayload. The module re-runs the §5.2/§8
 * gate (Scope Token vs gatekeeper JWKS, scope allowlist, rate cap) — the
 * SDK's PEP is the platform layer, this gate is the module's own
 * defense-in-depth per doc 07 §8. Rejections are reported as
 * `scan.rejected`; accepted scans report aggregate stats + redacted
 * per-item FindingReports in the TaskResult summary (`scan.result`).
 */

import type { AgentModule, RunOutcome, TaskContext } from "@aegisbastion/agent-sdk";
import type { TaskAssignment } from "@aegisbastion/agent-sdk";
import type { JsonValue } from "@bufbuild/protobuf";
import type { PhishCatcher } from "../index.js";
import type { Evidence } from "../core/evidence.js";
import { evidenceFromUrl } from "../url/checks.js";
import type { ScanRejectReason, ScanRequestPayload, FindingReportPayload } from "./messages.js";
import { redactFindingReport, type RedactionContext } from "./redact.js";
import type { ScanRequestGate } from "./scan-gate.js";
import { LIB_VERSION } from "../core/version.js";

/** Capabilities a batch scan task may exercise (doc 07 §5.2 register set). */
export const BATCH_CAPABILITIES = ["phish.email", "phish.url"] as const;

export interface BatchAuditSink {
  write(record: {
    type: "SCAN_REQUEST_ACCEPTED" | "SCAN_REQUEST_REJECTED" | "TOKEN_VERIFICATION_FAILURE";
    detail: Record<string, unknown>;
  }): Promise<void>;
}

export interface PhishBatchModuleDeps {
  catcher: PhishCatcher;
  gate: ScanRequestGate;
  audit?: BatchAuditSink;
  /** Redaction context for reports (hub-issued salt; §5.4). */
  redaction?: Omit<RedactionContext, "consent">;
  /** Deterministic id/time injection for tests. */
  makeReportId?: () => string;
  now?: () => Date;
}

interface BatchParams extends ScanRequestPayload {
  /** Literal URLs to score (CLI-fed batches). */
  urls?: string[];
}

function readParams(assignment: TaskAssignment): BatchParams {
  const p = (assignment.params ?? {}) as Record<string, unknown>;
  const scopeId = typeof p.scopeId === "string" ? p.scopeId : "";
  const inputRefs = Array.isArray(p.inputRefs) ? p.inputRefs.filter((v): v is string => typeof v === "string") : [];
  const urls = Array.isArray(p.urls) ? p.urls.filter((v): v is string => typeof v === "string") : undefined;
  const rateCapPerMin = typeof p.rateCapPerMin === "number" ? p.rateCapPerMin : undefined;
  const scopeToken =
    typeof p.scopeToken === "string" && p.scopeToken !== ""
      ? p.scopeToken
      : assignment.authorizationToken !== ""
        ? assignment.authorizationToken
        : undefined;
  const roeRef = typeof p.roeRef === "string" ? p.roeRef : undefined;
  return {
    scopeId,
    inputRefs,
    ...(urls !== undefined ? { urls } : {}),
    ...(rateCapPerMin !== undefined ? { rateCapPerMin } : {}),
    ...(scopeToken !== undefined ? { scopeToken } : {}),
    taskId: assignment.taskId,
    ...(roeRef !== undefined ? { roeRef } : {}),
  };
}

export class PhishBatchAgentModule implements AgentModule {
  private readonly aborted = new Set<string>();
  private readonly now: () => Date;

  constructor(private readonly deps: PhishBatchModuleDeps) {
    this.now = deps.now ?? (() => new Date());
  }

  /** plan(task) → validate params, throw when unsupported (doc 01 §9.1). */
  async plan(assignment: TaskAssignment): Promise<void> {
    if (!(BATCH_CAPABILITIES as readonly string[]).includes(assignment.capability)) {
      throw new Error(`unsupported capability: ${assignment.capability}`);
    }
    const params = readParams(assignment);
    if (params.scopeId === "") throw new Error("scan.request params missing scopeId");
    if ((params.urls?.length ?? 0) === 0 && params.inputRefs.length === 0) {
      throw new Error("scan.request params carry neither urls nor inputRefs");
    }
  }

  async run(ctx: TaskContext): Promise<RunOutcome> {
    const params = readParams(ctx.assignment);
    const audit = this.deps.audit;

    const decision = await this.deps.gate.evaluate(params);
    if (!decision.ok) {
      const reason: ScanRejectReason = decision.reason;
      await audit?.write({
        type: reason === "ROE_INVALID" ? "TOKEN_VERIFICATION_FAILURE" : "SCAN_REQUEST_REJECTED",
        detail: { scopeId: params.scopeId, reason, taskId: ctx.assignment.taskId },
      });
      // scan.rejected (§5.2) — carried in the TaskResult summary.
      return {
        summary: {
          type: "scan.rejected",
          scopeId: params.scopeId,
          reason,
          detail: decision.detail,
        },
      };
    }
    await audit?.write({
      type: "SCAN_REQUEST_ACCEPTED",
      detail: { scopeId: params.scopeId, taskId: ctx.assignment.taskId, jti: decision.claims.jti },
    });

    // inputRefs (s3://…) resolve via the hub-side artifact service — that
    // contract is MVP-B (doc 00 §4); literal-url batches work today.
    const urls = params.urls ?? [];
    if (urls.length === 0) {
      throw new Error("inputRefs resolution requires the hub artifact service (MVP-B); pass literal urls");
    }

    const aggregate = { items: 0, clean: 0, suspicious: 0, malicious: 0 };
    const reports: FindingReportPayload[] = [];
    for (const url of urls) {
      if (ctx.signal.aborted || this.aborted.has(ctx.assignment.taskId)) break;
      const verdict = this.deps.catcher.analyzeUrl(url);
      aggregate.items++;
      aggregate[verdict.verdict]++;
      if (verdict.verdict !== "clean" && this.deps.redaction) {
        const ev: Evidence = evidenceFromUrl(url);
        reports.push(
          redactFindingReport(ev, verdict, { ...this.deps.redaction, consent: "org-policy" },
            this.deps.makeReportId?.() ?? `${ctx.assignment.taskId}-${reports.length}`, this.now()),
        );
      }
    }

    const aggregateJson = { ...aggregate };
    await ctx.reportProgress({ type: "scan.progress", scopeId: params.scopeId, aggregate: aggregateJson });

    // scan.result (§5.2): aggregate stats + redacted reports, roeRef echoed.
    return {
      summary: {
        type: "scan.result",
        scopeId: params.scopeId,
        ...(params.roeRef !== undefined ? { roeRef: params.roeRef } : {}),
        aggregate: aggregateJson,
        reports: reports as unknown as JsonValue,
        aborted: ctx.signal.aborted || this.aborted.has(ctx.assignment.taskId),
        libVersion: LIB_VERSION,
      },
      requestsSent: BigInt(aggregate.items),
    };
  }

  /** abort() — invoked by the SDK on kill/timeout (doc 01 §9.1). */
  abort(taskId: string): void {
    this.aborted.add(taskId);
  }
}
