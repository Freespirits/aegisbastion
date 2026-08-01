/**
 * @aegisbastion/agent-sdk — the platform TypeScript agent SDK merged with
 * gatekeeper's pep-sdk (Ruling B; doc 01 §9.1; doc 11 §9 item 4).
 *
 * Consumed by every TypeScript module (alert service, dashboard,
 * phish-catcher per Ruling C10) — modules talk to the hub via THIS SDK over
 * the bus / StreamTasks, never bespoke transports.
 */

// Errors
export { PepError, isPepError, type PepErrorCode } from "./errors.js";

// Envelope + subjects (doc 01 §8)
export {
  newEnvelope,
  encodeEnvelope,
  decodeEnvelope,
  IdempotencySet,
  type EnvelopeOptions,
} from "./envelope.js";
export { SUBJECTS } from "./subjects.js";
export { ulid } from "./ulid.js";

// JCS / hashing / audit chain (doc 01 §10.2, §5.9)
export {
  jcs,
  sha256Hex,
  sha256JcsHex,
  scopeHashCheckpoint,
  auditChainHash,
} from "./jcs.js";

// Scope Token (Authorization Token v1.1 — doc 01 §5.5, doc 11 §3.2)
export {
  verifyScopeToken,
  parseScopeTokenClaims,
  TOKEN_ISSUER,
  TOKEN_AUDIENCE,
  MAX_TOKEN_TTL_SECONDS,
  CLOCK_LEEWAY_SECONDS,
  MAX_CLOCK_SKEW_SECONDS,
  SCOPE_BOUND_CAPABILITIES,
  type ScopeTokenClaims,
  type TargetManifestRef,
  type TokenRateCaps,
  type RiskClassName,
  type VerifyTokenOptions,
} from "./token.js";
export { JwksCache, type JwksCacheOptions } from "./jwks.js";

// Scope evaluation (doc 01 §10.1, Ruling A.5 — exclusions always win)
export {
  canonicalizeTarget,
  evaluateTargetInScope,
  isTargetInManifest,
  ruleMatchesTarget,
  parseIpv4,
  parseIpv6,
  parseCidr,
  ipv4InCidr,
  ipv6InCidr,
  type CanonicalScope,
  type CanonicalTarget,
  type ScopeVerdict,
  type Cidr,
} from "./scope.js";

// Manifests (doc 01 §5.5; MinIO bucket token-manifests)
export {
  parseManifestUri,
  createS3ManifestFetcher,
  fetchAndVerifyManifest,
  type ManifestFetcher,
  type ScopeManifest,
  type VerifiedManifest,
  type S3ManifestFetcherOptions,
} from "./manifest.js";

// Rate caps (doc 01 §10.3, doc 11 §3.2)
export {
  TokenBucketRateLimiter,
  ConcurrencyLimiter,
  RateCapsEnforcer,
  DEFAULT_MAX_RPS_R1,
} from "./ratecap.js";

// Revocation + kill switch (doc 11 §7, Ruling C11)
export {
  RevocationCache,
  decodeControlKill,
  type KillSignal,
} from "./revocation.js";

// PEP guardrails (PEP-2, Ruling B.2)
export { Pep, TaskAuthorization, type PepOptions } from "./pep.js";

// Gatekeeper clients (doc 11 §3.2)
export {
  createTokenServiceClient,
  jwksFetcher,
  refreshScopeToken,
  grpcNodeOptions,
  type TokenServiceClient,
  type GrpcClientOptions,
  type GrpcTlsOptions,
} from "./gatekeeper.js";

// Registry StreamTasks client (doc 01 §8.3)
export {
  createAgentServiceClient,
  RegistryClient,
  type AgentServiceClient,
} from "./registry.js";

// Re-authorization loop (doc 11 §3.2 — RefreshToken is re-authorization)
export {
  TokenReauthorizer,
  type ReauthorizationCallbacks,
  type TokenReauthorizerOptions,
} from "./refresh.js";

// Audit helpers (doc 01 §5.9, Ruling A.4)
export {
  buildAuditEvent,
  targetTouchedEvent,
  AuditEmitter,
  type AuditEventInput,
} from "./audit.js";

// Bus client (doc 01 §8, Ruling C3)
export {
  BusClient,
  STREAMS,
  type BusClientOptions,
  type AssignmentDelivery,
} from "./bus.js";

// High-level runner (doc 01 §9.1)
export {
  Agent,
  type AgentModule,
  type AgentOptions,
  type TaskContext,
  type RunOutcome,
} from "./agent.js";

// Contract schemas consumers routinely need (generated from proto/ — the
// source of truth is @aegisbastion/gen; these re-exports exist so SDK consumers
// do not have to depend on codegen layout details).
export { EnvelopeSchema, type Envelope } from "@aegisbastion/gen/aegisbastion/platform/v1/bus_pb.js";
export {
  TaskAssignmentSchema,
  TaskResultSchema,
  TaskResultStatus,
  type TaskAssignment,
  type TaskResult,
} from "@aegisbastion/gen/aegisbastion/platform/v1/task_pb.js";
export {
  RiskClass,
  TraceContextSchema,
  RateCapsSchema,
} from "@aegisbastion/gen/aegisbastion/platform/v1/types_pb.js";
export {
  AgentManifestSchema,
  CapabilitySchema,
  AgentType,
  type AgentManifest,
  type Capability,
} from "@aegisbastion/gen/aegisbastion/platform/v1/registry_pb.js";
export {
  AuditEventSchema,
  AuditEventType,
  type AuditEvent,
} from "@aegisbastion/gen/aegisbastion/platform/v1/audit_pb.js";
export {
  RevocationEventSchema,
  RevocationSchema,
  RevocationScope,
  type Revocation,
  type RevocationEvent,
} from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/revocation_pb.js";
export {
  ScopeTokenClaimsSchema,
  JsonWebKeySchema,
  type JsonWebKey,
} from "@aegisbastion/gen/aegisbastion/gatekeeper/v1/token_pb.js";
