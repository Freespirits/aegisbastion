/**
 * MVP-B hub transport adapter over the platform TS agent SDK
 * (`@aegisbastion/agent-sdk` — bus / `StreamTasks`, doc 01 §8.3/§9.1;
 * Ruling C10). Inert by default: this module loads ONLY via
 * `createHubTransport({ enabled: true })` or `phish-catcher agent` with
 * PHISH_HUB=on. MVP-A ships the standalone library (doc 00 §4).
 *
 * Ownership split on the live transport:
 *  - registration, heartbeats, kill-switch, TaskResult reporting (incl.
 *    scan.result / scan.rejected summaries on `task.result`) are owned by
 *    the SDK Agent (doc 01 §9 contract) — callers must NOT push them
 *    through this interface (TransportOwnershipError);
 *  - `finding.report` (§5.4) queues locally (ring buffer, drop-oldest) until
 *    the hub-side report-ingest contract lands with MVP-B.
 */

import { PhishCatcher, type PhishCatcherOptions } from "../index.js";
import { LIB_VERSION } from "../core/version.js";
import { PhishBatchAgentModule, type BatchAuditSink } from "./agent-module.js";
import type {
  AgentHeartbeatPayload,
  FindingReportPayload,
  ScanRejectedPayload,
  ScanRequestPayload,
  ScanResultPayload,
} from "./messages.js";
import { ReportQueue, type RedactionContext } from "./redact.js";
import { ScanRequestGate, type DeploymentMode } from "./scan-gate.js";
import type { HubPushHandlers, HubTransport } from "./transport.js";

export class TransportOwnershipError extends Error {
  constructor(surface: string) {
    super(
      `${surface} is owned by the SDK Agent on the live transport (doc 01 §9); ` +
        `results and heartbeats flow through the agent loop, not this interface`,
    );
    this.name = "TransportOwnershipError";
  }
}

export interface AgentSdkTransportOptions {
  mode: DeploymentMode;
  /** NATS servers, e.g. "nats://localhost:4222". */
  natsServers: string | string[];
  /** platform-core AgentService gRPC baseUrl, e.g. "http://localhost:50052". */
  registryUrl: string;
  /** gatekeeper gRPC baseUrl, e.g. "http://localhost:50051". */
  gatekeeperUrl: string;
  /** MinIO (token-manifests bucket) for PEP manifest verification. */
  minio: { endpoint: string; accessKeyId: string; secretAccessKey: string; region?: string };
  /** SPIFFE ID of this agent (platform-CA-issued identity, doc 01 §9.1). */
  spiffeId?: string;
  /** Enrolled scope allowlist (§8.1). */
  scopeAllowlist: readonly string[];
  /** gRPC mTLS material (compose dev host may run plaintext). */
  tls?: { caCert?: string; clientCert?: string; clientKey?: string };
  /** Detector wiring (bundle/policy via IntelStore, extra checks). */
  catcher?: PhishCatcherOptions;
  /** §5.4 redaction salt (hub-issued, rotated every 24 h). */
  reportSalt?: string;
  audit?: BatchAuditSink;
}

export class AgentSdkHubTransport implements HubTransport {
  readonly live = true;
  private readonly catcher: PhishCatcher;
  private readonly reports = new ReportQueue(500);
  private agent: { start(): Promise<void>; stop(): Promise<void> } | null = null;
  private bus: { close(): Promise<void> } | null = null;
  private jwks: { stop(): void } | null = null;

  constructor(private readonly opts: AgentSdkTransportOptions) {
    this.catcher = new PhishCatcher(opts.catcher ?? {});
  }

  get mode(): DeploymentMode {
    return this.opts.mode;
  }

  /** The redacted-report queue (§5.4; flushed when report-ingest lands). */
  reportQueue(): ReportQueue {
    return this.reports;
  }

  async start(_handlers: HubPushHandlers): Promise<void> {
    const sdk = await import("@aegisbastion/agent-sdk");

    const bus = await sdk.BusClient.connect({ servers: this.opts.natsServers });
    this.bus = bus;

    const grpc = {
      baseUrl: this.opts.registryUrl,
      ...(this.opts.tls ? { tls: this.opts.tls } : {}),
    };
    const registry = new sdk.RegistryClient(sdk.createAgentServiceClient(grpc));
    const tokenClient = sdk.createTokenServiceClient({
      baseUrl: this.opts.gatekeeperUrl,
      ...(this.opts.tls ? { tls: this.opts.tls } : {}),
    });

    const jwks = new sdk.JwksCache({ fetchKeys: sdk.jwksFetcher(tokenClient) });
    await jwks.start(); // fail-closed when gatekeeper JWKS is unreachable (§9)
    this.jwks = jwks;

    const revocations = new sdk.RevocationCache();
    const manifestFetcher = sdk.createS3ManifestFetcher({
      endpoint: this.opts.minio.endpoint,
      accessKeyId: this.opts.minio.accessKeyId,
      secretAccessKey: this.opts.minio.secretAccessKey,
      ...(this.opts.minio.region !== undefined ? { region: this.opts.minio.region } : {}),
    });
    const pep = new sdk.Pep({ jwks, manifestFetcher, revocations });

    const gate = new ScanRequestGate({
      mode: this.opts.mode,
      scopeAllowlist: this.opts.scopeAllowlist,
      verifyToken: (token, expectedTaskId) =>
        sdk.verifyScopeToken(token, {
          getKey: jwks.getKey,
          ...(expectedTaskId !== undefined ? { expectedTaskId } : {}),
        }),
    });

    const module = new PhishBatchAgentModule({
      catcher: this.catcher,
      gate,
      ...(this.opts.audit !== undefined ? { audit: this.opts.audit } : {}),
      ...(this.opts.reportSalt !== undefined
        ? { redaction: { urlSalt: this.opts.reportSalt } satisfies Omit<RedactionContext, "consent"> }
        : {}),
    });

    const { create } = await import("@bufbuild/protobuf");
    const agent = new sdk.Agent({
      manifest: create(sdk.AgentManifestSchema, {
        agentId: "",
        agentType: sdk.AgentType.PHISH_CATCHER,
        version: LIB_VERSION,
        buildHash: "",
        capabilities: [
          { name: "phish.email", riskClassMax: sdk.RiskClass.R0, schemaVersion: "1" },
          { name: "phish.page", riskClassMax: sdk.RiskClass.R0, schemaVersion: "1" },
          { name: "phish.url", riskClassMax: sdk.RiskClass.R0, schemaVersion: "1" },
          { name: "intel.phishing_indicators", riskClassMax: sdk.RiskClass.R0, schemaVersion: "1" },
        ],
        identity: { spiffeId: this.opts.spiffeId ?? "" },
        limits: { maxConcurrentTasks: 4 },
        region: "",
        sandboxed: false,
      }),
      module,
      registry,
      pep,
      revocations,
      bus,
      tokenClient,
      transport: "bus",
    });
    this.agent = agent;
    await agent.start();
  }

  async stop(): Promise<void> {
    await this.agent?.stop();
    this.jwks?.stop();
    await this.bus?.close();
    this.agent = null;
    this.bus = null;
    this.jwks = null;
  }

  // --- ownership split (see file header) -------------------------------------

  async sendHeartbeat(_p: AgentHeartbeatPayload): Promise<void> {
    throw new TransportOwnershipError("agent.heartbeat");
  }

  async sendScanResult(_p: ScanResultPayload): Promise<void> {
    throw new TransportOwnershipError("scan.result");
  }

  async sendScanRejected(_p: ScanRejectedPayload): Promise<void> {
    throw new TransportOwnershipError("scan.rejected");
  }

  /** §5.4: queue locally; flushed when the MVP-B report-ingest lands. */
  async sendFindingReport(report: FindingReportPayload): Promise<void> {
    this.reports.enqueue(report);
  }
}

/** CLI `agent` entry (feature-flagged): build from env, run until signal. */
export async function startHubAgent(io: {
  env: Record<string, string | undefined>;
  stdout: (line: string) => void;
  stderr: (line: string) => void;
}): Promise<void> {
  const env = io.env;
  const required = ["PHISH_HUB_NATS", "PHISH_HUB_REGISTRY_URL", "PHISH_HUB_GATEKEEPER_URL", "PHISH_HUB_MINIO_ENDPOINT"];
  const missing = required.filter((k) => !env[k]);
  if (missing.length > 0) {
    throw new Error(`hub wiring incomplete — missing: ${missing.join(", ")}`);
  }
  const transport = new AgentSdkHubTransport({
    mode: "node-batch",
    natsServers: env.PHISH_HUB_NATS ?? "",
    registryUrl: env.PHISH_HUB_REGISTRY_URL ?? "",
    gatekeeperUrl: env.PHISH_HUB_GATEKEEPER_URL ?? "",
    minio: {
      endpoint: env.PHISH_HUB_MINIO_ENDPOINT ?? "",
      accessKeyId: env.PHISH_HUB_MINIO_ACCESS_KEY ?? "",
      secretAccessKey: env.PHISH_HUB_MINIO_SECRET_KEY ?? "",
    },
    ...(env.PHISH_HUB_SPIFFE_ID ? { spiffeId: env.PHISH_HUB_SPIFFE_ID } : {}),
    scopeAllowlist: (env.PHISH_HUB_SCOPES ?? "").split(",").map((s) => s.trim()).filter((s) => s !== ""),
    ...(env.PHISH_HUB_REPORT_SALT ? { reportSalt: env.PHISH_HUB_REPORT_SALT } : {}),
  });
  await transport.start({});
  io.stdout("phish-catcher hub agent started (MVP-B transport, @aegisbastion/agent-sdk over bus)");
  await new Promise<void>((resolvePromise) => {
    const done = () => resolvePromise();
    process.once("SIGINT", done);
    process.once("SIGTERM", done);
  });
  await transport.stop();
  io.stdout("phish-catcher hub agent stopped");
}
