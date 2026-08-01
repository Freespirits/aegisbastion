# @aegisbastion/agent-sdk

The AegisBastion **platform TypeScript agent SDK**, merged with gatekeeper's
**pep-sdk** (Ruling B — one library, two names). This is the only supported
way for TypeScript modules (alert service, dashboard, phish-catcher per
Ruling C10) to talk to the hub: over the JetStream bus / `AgentService.StreamTasks`,
never bespoke transports.

Contracts implemented:

- **Bus client** (`BusClient`) — doc 01 §8 envelope (`event_id` ULID, `type`,
  `ts`, `mission_id`, `trace_context`, protobuf `Any` payload), `task.assign.{agent_id}`
  WorkQueue consumers with ack/nak semantics, publishers for module event
  subjects (`monitor.changes`, `*.alert`, `detect.findings`, …), the
  `tasks.revocations.v1` subscription, and `control.kill` (**CORE NATS
  broadcast only — no JetStream stream**, doc 01 §8.1). Consumers are
  idempotent on `event_id` / `task_id`.
- **Registry StreamTasks client** (`RegistryClient`) — `Register` /
  `Heartbeat` (10 s cadence) / `AckTask` (≤ 10 s) / `ReportProgress` /
  `ReportResult` / `StreamTasks` (doc 01 §8.3), via the generated
  `AgentService` stubs over gRPC (mTLS-ready).
- **PEP guardrails** (`Pep` / `TaskAuthorization`) — the PEP-2 execution gate:
  Scope Token verification (EdDSA via `jose` against a cached JWKS from
  gatekeeper `TokenService.GetJWKS`; `aud=aegisbastion.modules`,
  `iss=gatekeeper.platform`, task-bound `jti`/`task_id`, **15-min TTL** for
  R1–R3, 60 s leeway, 120 s skew rejection), target-in-manifest checks
  (exact-enumerated form), scope-bound scope evaluation for R1
  `monitor.watch` / `monitor.rescan` watch tokens (Ruling A: doc 01 §10.1
  canonicalized matching, longest-prefix/exact-host, **exclusions always
  win**, fail-closed), embedded rate caps (`max_rps` / `max_concurrent`),
  revocation cache, and kill-switch handling (≤ 5 s halt).
- **Re-authorization loop** (`TokenReauthorizer`) — mid-run re-authorization
  via `RefreshToken`: gatekeeper re-runs the policy check and mints a
  successor token bound to the same `task_id`; a denial halts the task.
- **Audit helpers** (`AuditEmitter`, `targetTouchedEvent`,
  `scopeHashCheckpoint`) — per-probe `TARGET_TOUCHED` records (the
  authoritative cross-check, Ruling A.4), the checkpoint
  `targets_touched: ["scope:sha256:<hash>"]` form, and hash-chained events
  (`sha256(prev_hash || JCS(event))` — JCS / RFC 8785 via `canonicalize`).
- **MinIO manifest fetch/verify** (`createS3ManifestFetcher`,
  `fetchAndVerifyManifest`) — fetches `blob://<bucket>/<key>` manifests from
  MinIO (S3 API, `forcePathStyle`), verifies `sha256(bytes) ==
  targets.manifest_sha256` **before** parsing, then parses the
  exact-enumerated target list or the canonical scope document (whose hash IS
  the `scope:sha256:<hash>` audit value).

## Usage

```ts
import {
  Agent, BusClient, JwksCache, Pep, RegistryClient, RevocationCache,
  createAgentServiceClient, createS3ManifestFetcher, createTokenServiceClient,
  jwksFetcher,
} from "@aegisbastion/agent-sdk";

const tokenClient = createTokenServiceClient({ baseUrl: "https://gatekeeper:8443", tls });
const registry = new RegistryClient(createAgentServiceClient({ baseUrl: "https://orchestrator:8443", tls }));
const bus = await BusClient.connect({ servers: "nats://nats:4222" });

const jwks = new JwksCache({ fetchKeys: jwksFetcher(tokenClient) });
await jwks.start();

const pep = new Pep({
  jwks,
  manifestFetcher: createS3ManifestFetcher({
    endpoint: "http://minio:9000",
    accessKeyId: process.env.MINIO_ACCESS_KEY!,
    secretAccessKey: process.env.MINIO_SECRET_KEY!,
  }),
  revocations: new RevocationCache(),
});

const agent = new Agent({
  manifest,             // aegisbastion.platform.v1.AgentManifest
  registry, bus, pep,
  tokenClient,          // enables the mid-run re-authorization loop
  revocations: new RevocationCache(),
  module: {
    async plan(assignment) { /* validate params or throw */ },
    async run(ctx) {
      await ctx.touch("https://api.acme.com/graphql"); // PEP-gated + audited
      return { summary: { findings: 0 } };
    },
    abort(taskId) { /* stop target contact ≤ 5 s */ },
  },
});
await agent.start();
```

Every guardrail failure throws `PepError` with a stable `code`
(`TOKEN_SIGNATURE_INVALID`, `TOKEN_EXPIRED`, `TOKEN_AUDIENCE_INVALID`,
`TOKEN_TASK_MISMATCH`, `TOKEN_TTL_EXCEEDED`, `TOKEN_SCOPE_BOUND_MISUSE`,
`MANIFEST_HASH_MISMATCH`, `TARGET_NOT_IN_MANIFEST`, `TARGET_NOT_IN_SCOPE`,
`TARGET_EXCLUDED`, `RATE_LIMITED`, `REVOKED`, `KILLED`, …). Everything is
**fail-closed**.

## Development

```bash
npm run typecheck   # tsc --noEmit (strict)
npm test            # vitest — the guarantee matrix (95 tests)
npm run build       # tsup → dist/ (ESM + d.ts; @aegisbastion/gen bundled in)
```

Generated stubs come from `@aegisbastion/gen` (`bin/buf.exe generate` at the repo
root); never edit `gen/` by hand.
