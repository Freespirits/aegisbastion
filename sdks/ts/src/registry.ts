/**
 * Registry StreamTasks client — the agent-facing RPC surface (doc 01 §8.3
 * "AgentAPI", §9 item 3). Agents either subscribe to the bus (bus.ts) or
 * long-poll AgentService.StreamTasks; the TaskAssignment payload is identical
 * either way. Register / Heartbeat / AckTask / ReportProgress / ReportResult
 * complete the surface. Heartbeats run at 10 s cadence (doc 01 §8.1).
 */

import { createClient, type Client } from "@connectrpc/connect";
import { createGrpcTransport } from "@connectrpc/connect-node";
import { timestampNow } from "@bufbuild/protobuf/wkt";
import type { JsonObject } from "@bufbuild/protobuf";
import {
  AgentService,
  type AgentManifest,
} from "@aegisbastion/gen/aegisbastion/platform/v1/registry_pb.js";
import type {
  TaskAssignment,
  TaskResult,
} from "@aegisbastion/gen/aegisbastion/platform/v1/task_pb.js";
import { grpcNodeOptions, type GrpcClientOptions } from "./gatekeeper.js";

export type AgentServiceClient = Client<typeof AgentService>;

export function createAgentServiceClient(opts: GrpcClientOptions): AgentServiceClient {
  return createClient(
    AgentService,
    createGrpcTransport({
      baseUrl: opts.baseUrl,
      nodeOptions: opts.tls ? grpcNodeOptions(opts.tls) : undefined,
    }),
  );
}

/**
 * Thin convenience wrapper with the SDK's call semantics baked in
 * (heartbeat payload shape, Struct conversion, stream iteration).
 */
export class RegistryClient {
  constructor(private readonly client: AgentServiceClient) {}

  /** Register or re-register (re-register on version change, doc 01 §9.1). */
  async register(manifest: AgentManifest): Promise<string> {
    const res = await this.client.register({ manifest });
    return res.agentId;
  }

  /**
   * One heartbeat. Returns true when a kill switch is active for this agent —
   * the caller must halt target contact within 5 s (doc 01 §10.5).
   */
  async heartbeat(agentId: string, runningTaskIds: string[]): Promise<boolean> {
    const res = await this.client.heartbeat({
      agentId,
      ts: timestampNow(),
      runningTaskIds,
    });
    return res.killActive;
  }

  /** ACK an assignment (within 10 s or it redelivers, doc 01 §9 item 3). */
  async ackTask(agentId: string, taskId: string): Promise<void> {
    await this.client.ackTask({ agentId, taskId });
  }

  /** Stream execution progress (module-defined payload). */
  async reportProgress(agentId: string, taskId: string, progress: JsonObject): Promise<void> {
    await this.client.reportProgress({ agentId, taskId, progress });
  }

  /** Deliver the terminal TaskResult (idempotent on task_id). */
  async reportResult(result: TaskResult): Promise<void> {
    await this.client.reportResult({ result });
  }

  /** Long-poll assignment stream (alternative to the bus, doc 01 §8.3). */
  async *streamTasks(agentId: string, signal?: AbortSignal): AsyncGenerator<TaskAssignment> {
    const stream = this.client.streamTasks({ agentId }, { signal });
    for await (const res of stream) {
      if (res.assignment) yield res.assignment;
    }
  }
}
