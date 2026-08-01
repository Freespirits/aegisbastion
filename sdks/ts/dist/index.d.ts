import { DescMessage, MessageShape, JsonObject } from '@bufbuild/protobuf';
import { Envelope } from '@aegisbastion/gen/aegisbastion/platform/v1/bus_pb.js';
export { Envelope, EnvelopeSchema } from '@aegisbastion/gen/aegisbastion/platform/v1/bus_pb.js';
import { JWTVerifyGetKey } from 'jose';
import { JsonWebKey, TokenService, RefreshTokenResponse } from '@aegisbastion/gen/aegisbastion/gatekeeper/v1/token_pb.js';
export { JsonWebKey, JsonWebKeySchema, ScopeTokenClaimsSchema } from '@aegisbastion/gen/aegisbastion/gatekeeper/v1/token_pb.js';
import { Revocation, RevocationEvent } from '@aegisbastion/gen/aegisbastion/gatekeeper/v1/revocation_pb.js';
export { Revocation, RevocationEvent, RevocationEventSchema, RevocationSchema, RevocationScope } from '@aegisbastion/gen/aegisbastion/gatekeeper/v1/revocation_pb.js';
import { Client } from '@connectrpc/connect';
import { Buffer } from 'node:buffer';
import { AgentService, AgentManifest } from '@aegisbastion/gen/aegisbastion/platform/v1/registry_pb.js';
export { AgentManifest, AgentManifestSchema, AgentType, Capability, CapabilitySchema } from '@aegisbastion/gen/aegisbastion/platform/v1/registry_pb.js';
import { TaskResult, TaskAssignment } from '@aegisbastion/gen/aegisbastion/platform/v1/task_pb.js';
export { TaskAssignment, TaskAssignmentSchema, TaskResult, TaskResultSchema, TaskResultStatus } from '@aegisbastion/gen/aegisbastion/platform/v1/task_pb.js';
import { AuditEvent, AuditEventType } from '@aegisbastion/gen/aegisbastion/platform/v1/audit_pb.js';
export { AuditEvent, AuditEventSchema, AuditEventType } from '@aegisbastion/gen/aegisbastion/platform/v1/audit_pb.js';
import { NatsConnection, ConnectionOptions } from '@nats-io/transport-node';
import { JetStreamClient, PubAck } from '@nats-io/jetstream';
export { RateCapsSchema, RiskClass, TraceContextSchema } from '@aegisbastion/gen/aegisbastion/platform/v1/types_pb.js';

/**
 * Error taxonomy for the agent SDK / PEP guardrails.
 *
 * Every guardrail failure is fail-closed (doc 01 §10.1, doc 11 §7): a refusal
 * is expressed by throwing one of these errors, never by returning a boolean
 * that a caller could ignore. `code` values are stable strings so modules can
 * map them onto TaskResultStatus.REJECTED_UNAUTHORIZED and audit payloads.
 */
type PepErrorCode = "TOKEN_MALFORMED" | "TOKEN_SIGNATURE_INVALID" | "TOKEN_EXPIRED" | "TOKEN_NOT_YET_VALID" | "TOKEN_TTL_EXCEEDED" | "TOKEN_ISSUER_INVALID" | "TOKEN_AUDIENCE_INVALID" | "TOKEN_TASK_MISMATCH" | "TOKEN_RISK_CLASS_INVALID" | "TOKEN_SCOPE_BOUND_MISUSE" | "TOKEN_MISSING" | "JWKS_UNAVAILABLE" | "MANIFEST_FETCH_FAILED" | "MANIFEST_HASH_MISMATCH" | "MANIFEST_MALFORMED" | "TARGET_NOT_IN_MANIFEST" | "TARGET_NOT_IN_SCOPE" | "TARGET_EXCLUDED" | "RATE_LIMITED" | "CONCURRENCY_LIMITED" | "REVOKED" | "KILLED" | "REAUTHORIZATION_DENIED";
declare class PepError extends Error {
    readonly code: PepErrorCode;
    /** Structured detail for audit payloads — never contains raw target lists. */
    readonly detail: Record<string, unknown>;
    constructor(code: PepErrorCode, message: string, detail?: Record<string, unknown>);
}
declare function isPepError(err: unknown): err is PepError;

/**
 * Bus envelope helpers (doc 01 §8.2). Every JetStream message is an
 * `aegisbastion.platform.v1.Envelope`: event_id (ULID), type (fully-qualified
 * payload type), ts, mission_id, trace_context, protobuf Any payload.
 * Consumers MUST be idempotent on event_id / task_id.
 */

interface EnvelopeOptions {
    /** Owning mission (empty for platform-internal messages). */
    missionId?: string;
    /** W3C trace context propagated from the triggering assignment/event. */
    traceContext?: {
        traceparent: string;
        tracestate?: string;
    };
}
/** Build an Envelope wrapping a typed payload message. */
declare function newEnvelope<Desc extends DescMessage>(payloadSchema: Desc, payload: MessageShape<Desc>, opts?: EnvelopeOptions): Envelope;
/** Serialize an Envelope to protobuf wire bytes. */
declare function encodeEnvelope(envelope: Envelope): Uint8Array;
/** Parse an Envelope from protobuf wire bytes. Throws on malformed input. */
declare function decodeEnvelope(bytes: Uint8Array): Envelope;
/**
 * Bounded idempotency set for event_id / task_id dedup (doc 01 §8.2: duplicate
 * delivery is expected under at-least-once). In-memory, insertion-ordered,
 * evicts oldest beyond capacity — redelivery-safe consumers stay cheap.
 */
declare class IdempotencySet {
    private readonly capacity;
    private readonly seen;
    constructor(capacity?: number);
    /** Returns true the first time a key is observed, false on duplicates. */
    firstSeen(key: string): boolean;
    get size(): number;
}

/**
 * Canonical bus subjects (doc 01 §8.1; doc 11 §9 item 9). JetStream is the
 * canonical platform bus (Ruling C3). `control.kill` is a CORE NATS broadcast
 * with NO JetStream stream (doc 01 §8.1); everything else listed here is a
 * durable JetStream subject.
 */
declare const SUBJECTS: {
    /** Orchestrator → specific agent (WorkQueue, ack-required). */
    readonly taskAssign: (agentId: string) => string;
    /** agents → Orchestrator (durable, at-least-once, idempotent on task_id). */
    readonly taskResult: "task.result";
    /** agents → Registry (ephemeral, 10 s cadence). */
    readonly agentHeartbeat: "agent.heartbeat";
    /** Orchestrator → commanders, UI (durable). */
    readonly missionEvents: "mission.events";
    /** Monitor agent → commanders (durable). */
    readonly monitorChanges: "monitor.changes";
    /** Monitor new-asset candidates (doc 03 §5). */
    readonly monitorAssetsNew: "monitor.assets.new";
    /** Monitor alerts in AlertEvent v1 form (doc 03 §5.3 mapping). */
    readonly monitorAlert: "monitor.alert";
    /** Detect findings, full stream (doc 04 §4.3). */
    readonly detectFindings: "detect.findings";
    /** Detect alerts in AlertEvent v1 form (Ruling C8 mapping). */
    readonly detectAlert: "detect.alert";
    /** Orchestrator → all agents. CORE NATS broadcast only — no JetStream. */
    readonly controlKill: "control.kill";
    /** all services → Audit Service (durable, never sampled). */
    readonly auditEvents: "audit.events";
    /** Alert agent ↔ notifier integrations (durable). */
    readonly alertOutbound: "alert.outbound";
    readonly authzDecisions: "authz.decisions.v1";
    readonly authzDenials: "authz.denials.v1";
    readonly roeEvents: "roe.events.v1";
    /** Revocation broadcast consumed by every PEP (kill ≤ 5 s SLA). */
    readonly tasksRevocations: "tasks.revocations.v1";
    readonly authzApprovals: "authz.approvals.v1";
    readonly auditAnomalies: "audit.anomalies.v1";
    /** Phish-Catcher intel feed bundles (doc 01 §9.2). */
    readonly intelFeedsPhishing: "intel.feeds.phishing";
};

/**
 * ULID generation (doc 01 §8.2: every envelope event_id is a ULID).
 * Crockford base32, 48-bit time + 80-bit randomness, monotonic within a tick.
 */
declare function ulid(now?: number): string;

/**
 * JCS (JSON Canonicalization Scheme, RFC 8785) helpers — the platform's single
 * canonicalization (doc 01 §10.2; doc 07 §12: "Do not invent a second
 * canonicalization"). Uses the `canonicalize` package; SHA-256 via node:crypto.
 */
/** Serialize a JSON value in JCS (RFC 8785) canonical form. */
declare function jcs(value: unknown): string;
/** SHA-256 hex digest of a string or byte buffer. */
declare function sha256Hex(data: string | Uint8Array): string;
/** SHA-256 of the JCS-canonical form of a JSON value, hex-encoded. */
declare function sha256JcsHex(value: unknown): string;
/**
 * The audit value form for scope-bound watch tokens (Ruling A.3):
 * the manifest hash IS the "scope:sha256:<hash>" checkpoint value accepted in
 * TaskResult.targets_touched — only alongside per-probe TARGET_TOUCHED records.
 */
declare function scopeHashCheckpoint(manifestSha256: string): string;
/**
 * Hash-chain helper for audit events (doc 01 §5.9, §10.4):
 *   hash = "sha256:" + sha256(prev_hash || JCS(event minus hash))
 * `prevHash` is the previous event's hash string ("" for the genesis event).
 */
declare function auditChainHash(eventWithoutHash: unknown, prevHash: string): string;

/**
 * Gatekeeper Scope Token verification (Authorization Token v1.1 — doc 01 §5.5
 * as amended by Ruling A, converged with doc 11 §3.2; Ruling C5).
 *
 * The Scope Token is the ONLY execution credential: Ed25519/EdDSA JWT,
 * JWKS-verified, task-bound (jti), audience "aegisbastion.modules", 15-minute TTL
 * for ALL active classes R1–R3. Verification is fully local (cached JWKS).
 *
 * Clock policy (doc 11 §7): 60 s leeway on nbf/exp; iat more than 120 s in the
 * future is rejected as skew/tamper. Everything here is fail-closed.
 */

declare const TOKEN_ISSUER = "gatekeeper.platform";
declare const TOKEN_AUDIENCE = "aegisbastion.modules";
/** Ruling C5: uniform 15-minute TTL for all active classes R1–R3. */
declare const MAX_TOKEN_TTL_SECONDS = 900;
/** Doc 11 §7: 60 s leeway on nbf/exp. */
declare const CLOCK_LEEWAY_SECONDS = 60;
/** Doc 11 §7: PEPs reject tokens with skew > 120 s and alert. */
declare const MAX_CLOCK_SKEW_SECONDS = 120;
/** Ruling A: scope-bound watch tokens are valid ONLY for these R1 capabilities. */
declare const SCOPE_BOUND_CAPABILITIES: Set<string>;
type RiskClassName = "R1" | "R2" | "R3";
/** Reference to the hashed target manifest (doc 01 §5.5, doc 11 §3.2). */
interface TargetManifestRef {
    hash_alg: "sha256";
    manifest_uri: string;
    manifest_sha256: string;
    count?: number;
}
/** Rate caps embedded in the token (max_rps ≡ rps — one claim set). */
interface TokenRateCaps {
    max_rps?: number;
    max_concurrent?: number;
}
/**
 * The Scope Token claim set as it appears in the JWT payload (JSON wire form,
 * doc 01 §5.5 / doc 11 §3.2 — field names are the exact JWT claim names).
 */
interface ScopeTokenClaims {
    iss: typeof TOKEN_ISSUER;
    aud: typeof TOKEN_AUDIENCE;
    /** Token id; also the authorization_token_id carried by AlertEvent v1. */
    jti: string;
    /** Executing agent/workload. */
    sub: string;
    /** Task this token is bound to (single-purpose). */
    task_id: string;
    roe_id: string;
    roe_version: number;
    risk_class: RiskClassName;
    capabilities: string[];
    targets: TargetManifestRef;
    /** Ruling A scope-bound watch-token form (R1 monitor.watch/rescan only). */
    scope_bound?: boolean;
    rate_caps?: TokenRateCaps;
    /** Four-eyes approval ref — mandatory for R3 / R2 stress.* on production. */
    approval_id?: string;
    iat: number;
    nbf?: number;
    exp: number;
}
interface VerifyTokenOptions {
    /** JWKS key resolver (see JwksCache.getKey). */
    getKey: JWTVerifyGetKey;
    /** The task this token is being used for — must equal the task_id claim. */
    expectedTaskId?: string;
    /** Override "now" (Unix seconds) — for tests. */
    nowSeconds?: number;
}
/** Validate the decoded payload's shape and claim-level rules. Fail-closed. */
declare function parseScopeTokenClaims(payload: unknown, nowSeconds: number): ScopeTokenClaims;
/**
 * Verify a compact Scope Token JWT against the cached JWKS and return its
 * validated claims. Throws PepError on ANY failure — fail-closed.
 *
 * Checks (doc 01 §5.5/§10, doc 11 §3.2/§7): EdDSA signature via JWKS (kid),
 * alg allowlist, iss, aud, exp/nbf with 60 s leeway, iat skew ≤ 120 s,
 * TTL ≤ 15 min, task binding, claim shape, Ruling A scope-bound rules.
 */
declare function verifyScopeToken(token: string, opts: VerifyTokenOptions): Promise<ScopeTokenClaims>;

/**
 * JWKS cache for local Scope Token verification (doc 01 §10.2, doc 11 §3.2):
 * public keys come from gatekeeper's TokenService.GetJWKS (published at
 * /.well-known/gatekeeper-jwks.json, internal + mTLS) and are cached; rotation
 * via kid header with two active keys max. An unknown kid triggers ONE refresh
 * (key rotation), then fails closed.
 */

interface JwksCacheOptions {
    /**
     * Fetches the current JWKS keys from gatekeeper (TokenService.GetJWKS).
     * Injected so the cache stays transport-agnostic (and testable).
     */
    fetchKeys: () => Promise<JsonWebKey[]>;
    /** Background refresh interval (default 5 min, matching PEP cache TTL norms). */
    refreshIntervalMs?: number;
}
declare class JwksCache {
    private readonly opts;
    private keys;
    private localSet;
    private refreshTimer;
    private refreshing;
    constructor(opts: JwksCacheOptions);
    /** Initial load. Throws JWKS_UNAVAILABLE when gatekeeper cannot be reached. */
    start(): Promise<void>;
    stop(): void;
    refresh(): Promise<void>;
    private doRefresh;
    /** Currently cached key ids (diagnostics / audit). */
    cachedKids(): string[];
    /**
     * jose-compatible key resolver. On an unknown kid (key rotation in
     * progress), refreshes the JWKS once and retries; still no match → the
     * caller's jwtVerify fails closed with JWKS_UNAVAILABLE.
     */
    getKey: JWTVerifyGetKey;
}

/**
 * Canonicalized target scope evaluation (doc 01 §10.1, doc 11 §3.1, Ruling A).
 *
 * Rules:
 *  - Targets and scope entries are canonicalized before matching (lowercase
 *    scheme/host, default ports dropped, trailing root dot stripped, fragments
 *    dropped).
 *  - Wildcard domains use TLS convention: "*.acme.com" matches any host with
 *    one or more leading labels under acme.com, NOT the apex itself; the apex
 *    must be listed separately (as doc 11 §3.1's example RoE does).
 *  - URL/path entries match by longest-prefix on the canonical URL form;
 *    bare hosts match exact-host only; CIDRs match IP targets in range.
 *  - EXCLUSIONS ALWAYS WIN over every include form (doc 01 §5.4, doc 11 §3.1).
 *  - asset_group_ids / cloud_accounts cannot be resolved client-side, so they
 *    never grant inclusion — fail-closed (doc 01 §10.1).
 *  - DNS names are never resolved to IPs client-side (no DNS rebinding games,
 *    and fail-closed: a hostname cannot sneak into a CIDR include).
 */
/** The canonical RoE scope carried by a scope-bound watch-token manifest. */
interface CanonicalScope {
    domains: string[];
    cidrs: string[];
    explicit_excludes: string[];
    asset_group_ids?: string[];
    cloud_accounts?: string[];
}
type ScopeVerdict = {
    allow: true;
    matchedBy: string;
} | {
    allow: false;
    code: "TARGET_EXCLUDED" | "TARGET_NOT_IN_SCOPE";
    matchedRule?: string;
};
declare function parseIpv4(s: string): number | null;
/** Parse an IPv6 address (with :: compression and optional embedded IPv4) to 16 bytes. */
declare function parseIpv6(s: string): Uint8Array | null;
interface CidrV4 {
    family: 4;
    base: number;
    bits: number;
}
interface CidrV6 {
    family: 6;
    base: Uint8Array;
    bits: number;
}
type Cidr = CidrV4 | CidrV6;
declare function parseCidr(s: string): Cidr | null;
declare function ipv4InCidr(ip: number, cidr: CidrV4): boolean;
declare function ipv6InCidr(ip: Uint8Array, cidr: CidrV6): boolean;
type CanonicalTarget = {
    kind: "ipv4";
    ip: number;
    canonical: string;
} | {
    kind: "ipv6";
    ip: Uint8Array;
    canonical: string;
} | {
    kind: "host";
    host: string;
    canonical: string;
} | {
    kind: "url";
    host: string;
    canonical: string;
    urlPrefix: string;
    hostPath: string;
};
/**
 * Canonicalize a target string. Throws PepError(TARGET_NOT_IN_SCOPE) on
 * unparseable input — malformed targets are never in scope (fail-closed).
 */
declare function canonicalizeTarget(raw: string): CanonicalTarget;
/**
 * Does one scope rule (include or exclude form) match a canonical target?
 * Rule forms: CIDR, bare IP, bare host, wildcard domain, URL/host-path prefix
 * (longest-prefix), or URL with scheme (longest-prefix).
 */
declare function ruleMatchesTarget(ruleRaw: string, target: CanonicalTarget): boolean;
/**
 * Evaluate one probe target against a canonical scope (Ruling A.5).
 * Exclusions are evaluated FIRST and always win; then includes (domains,
 * CIDRs). Anything unmatched is denied — fail-closed.
 */
declare function evaluateTargetInScope(rawTarget: string, scope: CanonicalScope): ScopeVerdict;
/**
 * Exact-enumerated manifest membership (doc 01 §5.5): the target must equal a
 * manifest entry after canonicalization. No wildcards, no scope expansion.
 */
declare function isTargetInManifest(rawTarget: string, manifestTargets: readonly string[]): boolean;

/**
 * Target manifest fetch + verify (doc 01 §5.5, doc 11 §3.2, Ruling A.3).
 *
 * Concrete targets never live inside the token; the token carries
 * `targets.manifest_uri` / `targets.manifest_sha256` pointing at an object in
 * MinIO (bucket `token-manifests`; S3 API, forcePathStyle). Two forms exist:
 *
 *  - exact-enumerated: a JSON array of target strings (R2/R3, and R1
 *    non-watch capabilities);
 *  - scope-bound watch form (Ruling A): the canonical RoE scope document
 *    (schemas/gatekeeper/v1/scope-manifest.schema.json), whose sha256 IS the
 *    audit value "scope:sha256:<hash>".
 *
 * The manifest bytes are hashed and compared against the token claim BEFORE
 * parsing; any mismatch or fetch failure is a hard failure (fail-closed).
 */

/** Canonical scope manifest document (scope-bound watch tokens, Ruling A). */
interface ScopeManifest {
    roe_id: string;
    roe_version: number;
    resolved_at?: string;
    scope: CanonicalScope;
}
type VerifiedManifest = {
    form: "exact";
    sha256: string;
    targets: string[];
} | {
    form: "scope";
    sha256: string;
    manifest: ScopeManifest;
};
/** Transport abstraction for manifest bytes — injectable for tests. */
interface ManifestFetcher {
    /** Fetch the raw bytes for a manifest URI. Throws on transport failure. */
    fetch(manifestUri: string): Promise<Uint8Array>;
}
interface S3ManifestFetcherOptions {
    /** MinIO endpoint, e.g. "http://localhost:9000" (MVP-A compose host). */
    endpoint: string;
    region?: string;
    accessKeyId: string;
    secretAccessKey: string;
    /**
     * Manifest bucket override. Default: the bucket from the blob:// URI
     * (gatekeeper writes to the `token-manifests` bucket).
     */
    bucketOverride?: string;
}
/** Parse a "blob://<bucket>/<key>" manifest URI. */
declare function parseManifestUri(uri: string): {
    bucket: string;
    key: string;
};
/**
 * Default fetcher: MinIO via the S3 API (@aws-sdk/client-s3, forcePathStyle —
 * the same client family works against Azure Blob later, doc 01 §11).
 * The AWS SDK is loaded lazily so PEP-only consumers (e.g. browser-adjacent
 * phish-catcher checks) never pay for it.
 */
declare function createS3ManifestFetcher(opts: S3ManifestFetcherOptions): ManifestFetcher;
/**
 * Fetch and verify a manifest against the token's TargetManifestRef, then
 * parse it into its typed form. Fail-closed at every step:
 * hash_alg must be sha256, sha256(bytes) must equal manifest_sha256, the
 * document must match its declared form.
 */
declare function fetchAndVerifyManifest(ref: TargetManifestRef, scopeBound: boolean, fetcher: ManifestFetcher): Promise<VerifiedManifest>;

/**
 * Agent-side rate-cap enforcement (doc 01 §10.3, doc 11 §3.2): the token is
 * NOT a capability to bypass rate limits — the PEP enforces the token's
 * embedded `rate_caps` (max_rps / max_concurrent) locally per burst, with no
 * PDP call per request. Exceeding a cap is a hard refusal (fail-closed).
 */

/** Doc 01 §10.3 / types.proto: default platform cap is 100 rps for R1. */
declare const DEFAULT_MAX_RPS_R1 = 100;
/**
 * Token bucket for the max_rps cap. Tokens refill continuously at maxRps per
 * second; capacity is one second's worth (burst of maxRps).
 */
declare class TokenBucketRateLimiter {
    private readonly maxRps;
    private readonly nowMs;
    private tokens;
    private lastRefillMs;
    constructor(maxRps: number, nowMs?: () => number);
    private refill;
    /** Consume one permit if available; false (deny) when the cap is exceeded. */
    tryAcquire(n?: number): boolean;
    /**
     * Wait for a permit. Rejects immediately with PepError(KILLED) when the
     * abort signal fires (kill-switch handling, doc 01 §10.5: stop target
     * contact within 5 s — workers must not linger in rate-limit sleep).
     */
    acquire(signal?: AbortSignal): Promise<void>;
}
/**
 * Semaphore for the max_concurrent cap. Slots are held for the duration of a
 * network action and MUST be released (use `withSlot`).
 */
declare class ConcurrencyLimiter {
    private readonly maxConcurrent;
    private inFlight;
    private readonly waiters;
    constructor(maxConcurrent: number);
    get current(): number;
    tryAcquireSlot(): (() => void) | null;
    acquireSlot(signal?: AbortSignal): Promise<() => void>;
    private release;
    /** Run `fn` holding a slot; the slot is always released afterwards. */
    withSlot<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T>;
}
/**
 * Combined per-token rate caps from the Scope Token claims. A cap that is
 * unset (0/absent) means "no token-embedded cap" — the RoE/Scheduler-level
 * caps still apply upstream; the SDK never invents a looser local cap than
 * the platform default for R1 when nothing is embedded.
 */
declare class RateCapsEnforcer {
    readonly rps: TokenBucketRateLimiter | null;
    readonly concurrency: ConcurrencyLimiter | null;
    constructor(caps: TokenRateCaps | undefined, opts?: {
        riskClass?: "R1" | "R2" | "R3";
        nowMs?: () => number;
    });
    /** Fail-closed check used by the PEP guard before every network action. */
    check(): void;
}

/**
 * Revocation cache + kill-switch handling (doc 11 §7, Ruling C11).
 *
 * gatekeeper's revocation-service emits `tasks.revocations.v1` (durable
 * JetStream); the Orchestrator maps those to `control.kill` (CORE NATS
 * broadcast, no stream). PEPs must ACK and halt in-flight work ≤ 5 s
 * (graceful: stop new requests, drain ≤ 5 s, report execution.halted).
 *
 * This cache is the local revocation set the PEP consults before every
 * network action; entries honor `expires_at` (temporary revocations lift).
 * Fail-safe direction: an unparseable control.kill broadcast is treated as a
 * GLOBAL kill — kill signals fail toward halting, never toward continuing.
 */

type KillSignal = {
    kind: "global";
    reason: string;
} | {
    kind: "roe";
    roeId: string;
    reason: string;
} | {
    kind: "target";
    target: string;
    reason: string;
} | {
    kind: "capability";
    capability: string;
    reason: string;
};
declare class RevocationCache {
    private readonly nowMs;
    private global;
    private readonly roes;
    private readonly targets;
    private readonly capabilities;
    private readonly seenRevocationIds;
    constructor(nowMs?: () => number);
    /** Apply one Revocation (idempotent on revocation_id). */
    apply(rev: Revocation): void;
    /** Apply a bus RevocationEvent. */
    applyEvent(event: RevocationEvent): void;
    private live;
    /**
     * The kill signal applying to this token/target/capability right now, or
     * null when nothing is revoked. Checked before EVERY network action.
     */
    check(claims: ScopeTokenClaims, rawTarget?: string, capability?: string): KillSignal | null;
    /** Throw PepError(REVOKED) when any revocation applies. */
    assertNotRevoked(claims: ScopeTokenClaims, rawTarget?: string, capability?: string): void;
    get size(): number;
}
/**
 * Decode a `control.kill` broadcast payload (CORE NATS, no JetStream stream,
 * doc 01 §8.1). Contract form: an Envelope whose Any payload is a gatekeeper
 * RevocationEvent (Ruling C11: the Orchestrator maps revocations to
 * control.kill). Fail-SAFE: anything unparseable is treated as a GLOBAL kill.
 */
declare function decodeControlKill(data: Uint8Array): RevocationEvent | {
    global: true;
};

/**
 * PEP guardrails — the merged platform agent SDK / gatekeeper pep-sdk
 * execution gate (PEP-2, Ruling B.2; doc 01 §9.1/§10.1 "Agent SDK" layer;
 * doc 11 §9 item 4).
 *
 * One `TaskAuthorization` per (task, token): verifies the Scope Token locally
 * (cached JWKS), fetches + verifies the hashed manifest from MinIO, and then
 * enforces — before EVERY network action — target membership (exact manifest,
 * or canonicalized scope evaluation with exclusions-first for scope-bound
 * watch tokens), the token's embedded rate caps, and the live revocation set.
 *
 * Everything fails closed: any mismatch throws PepError and the agent must
 * report REJECTED_UNAUTHORIZED / halt (doc 01 §9 item 4, §10.5).
 */

interface PepOptions {
    jwks: JwksCache;
    manifestFetcher: ManifestFetcher;
    revocations?: RevocationCache;
    /** Test hook: override "now" (Unix seconds) for token verification. */
    nowSeconds?: () => number;
}
declare class Pep {
    private readonly opts;
    private readonly manifestCache;
    constructor(opts: PepOptions);
    /**
     * Verify a Scope Token and its manifest, returning the authorization
     * context used to gate every subsequent target touch. Throws (fail-closed)
     * on forged/expired/wrong-audience/wrong-task tokens, manifest hash
     * mismatches, and active revocations.
     */
    authorizeTask(token: string, expectedTaskId: string): Promise<TaskAuthorization>;
    private verifiedManifest;
}
/**
 * The per-task guard. Modules call `checkTarget` before every network action
 * (doc 01 §5.5: "re-check every target string against the manifest before
 * each network action"; Ruling A.5 for scope-bound watch tokens).
 */
declare class TaskAuthorization {
    readonly claims: ScopeTokenClaims;
    readonly manifest: VerifiedManifest;
    private readonly revocations;
    readonly rateCaps: RateCapsEnforcer;
    constructor(claims: ScopeTokenClaims, manifest: VerifiedManifest, revocations: RevocationCache | null);
    /** True when this is a Ruling A scope-bound watch authorization. */
    get scopeBound(): boolean;
    /** Assert the task may exercise this capability at all. */
    assertCapability(capability: string): void;
    /**
     * Gate one target touch. Throws PepError on:
     *  - active revocation (global / RoE / capability / target),
     *  - target ∉ exact manifest (exact form),
     *  - target ∉ canonical scope or ∈ exclusions (scope-bound form;
     *    exclusions ALWAYS win),
     *  - embedded rate cap exceeded.
     */
    checkTarget(rawTarget: string, capability?: string): void;
}

/**
 * Gatekeeper clients (doc 11): the TokenService surface the SDK needs —
 * GetJWKS (key material for local verification) and RefreshToken (mid-run
 * re-authorization, doc 11 §3.2). The SDK never mints; only gatekeeper's
 * token-service mints (Ruling B/C9).
 */

interface GrpcTlsOptions {
    /** Platform CA cert (PEM) — mTLS everywhere (doc 01 §11). */
    caCert?: Uint8Array | string;
    /** Agent's platform-CA-issued client cert (PEM; SPIFFE ID in SANs). */
    clientCert?: Uint8Array | string;
    clientKey?: Uint8Array | string;
}
interface GrpcClientOptions {
    /** e.g. "https://gatekeeper:8443" (or http:// for the compose dev host). */
    baseUrl: string;
    tls?: GrpcTlsOptions;
}
declare function grpcNodeOptions(tls: GrpcTlsOptions): {
    ca?: string | Buffer;
    cert?: string | Buffer;
    key?: string | Buffer;
};
type TokenServiceClient = Client<typeof TokenService>;
declare function createTokenServiceClient(opts: GrpcClientOptions): TokenServiceClient;
/** fetchKeys implementation for JwksCache, backed by TokenService.GetJWKS. */
declare function jwksFetcher(client: TokenServiceClient): () => Promise<JsonWebKey[]>;
/**
 * Mid-run re-authorization (docs 01 §5.5, 03 §9.2, 11 §3.2): RefreshToken is
 * NOT an unauthenticated refresh — token-service re-runs the policy check
 * (RoE still active, not revoked, approval still valid) before minting a
 * successor token for the same task_id. An empty successor token means the
 * re-authorization was DENIED: the agent must halt when its current token
 * expires.
 */
declare function refreshScopeToken(client: TokenServiceClient, currentToken: string): Promise<RefreshTokenResponse>;

/**
 * Registry StreamTasks client — the agent-facing RPC surface (doc 01 §8.3
 * "AgentAPI", §9 item 3). Agents either subscribe to the bus (bus.ts) or
 * long-poll AgentService.StreamTasks; the TaskAssignment payload is identical
 * either way. Register / Heartbeat / AckTask / ReportProgress / ReportResult
 * complete the surface. Heartbeats run at 10 s cadence (doc 01 §8.1).
 */

type AgentServiceClient = Client<typeof AgentService>;
declare function createAgentServiceClient(opts: GrpcClientOptions): AgentServiceClient;
/**
 * Thin convenience wrapper with the SDK's call semantics baked in
 * (heartbeat payload shape, Struct conversion, stream iteration).
 */
declare class RegistryClient {
    private readonly client;
    constructor(client: AgentServiceClient);
    /** Register or re-register (re-register on version change, doc 01 §9.1). */
    register(manifest: AgentManifest): Promise<string>;
    /**
     * One heartbeat. Returns true when a kill switch is active for this agent —
     * the caller must halt target contact within 5 s (doc 01 §10.5).
     */
    heartbeat(agentId: string, runningTaskIds: string[]): Promise<boolean>;
    /** ACK an assignment (within 10 s or it redelivers, doc 01 §9 item 3). */
    ackTask(agentId: string, taskId: string): Promise<void>;
    /** Stream execution progress (module-defined payload). */
    reportProgress(agentId: string, taskId: string, progress: JsonObject): Promise<void>;
    /** Deliver the terminal TaskResult (idempotent on task_id). */
    reportResult(result: TaskResult): Promise<void>;
    /** Long-poll assignment stream (alternative to the bus, doc 01 §8.3). */
    streamTasks(agentId: string, signal?: AbortSignal): AsyncGenerator<TaskAssignment>;
}

/**
 * Token re-authorization loop (docs 01 §5.5, 03 §9.2, 11 §3.2; Ruling C5).
 *
 * Long-running work (watches, campaigns, stress tests) re-authorizes mid-run:
 * RefreshToken makes gatekeeper re-run the policy check and mint a SUCCESSOR
 * token bound to the same task_id. There is no unauthenticated refresh —
 * a denial (empty successor) means halt when the current token expires, and a
 * transport failure means the current unexpired token keeps working until it
 * does (doc 11 §7), after which the module halts.
 *
 * The loop refreshes at min(TTL/2, exp - 60s) so a successor is always in
 * hand before the current token expires, and retries transport errors with
 * capped backoff. Re-authorization denial fires `onDenied` once and stops the
 * loop — the PEP guard refuses new target touches at token expiry regardless.
 */
interface ReauthorizationCallbacks {
    /** Called with each successor token; swap it into the running task. */
    onSuccessor: (token: string) => void;
    /** Re-authorization was denied — halt when the current token expires. */
    onDenied?: () => void;
    /** Transport-level refresh failure (kept retrying until expiry). */
    onRefreshError?: (err: unknown) => void;
}
interface TokenReauthorizerOptions {
    /**
     * Performs the RefreshToken RPC. Injected so the loop stays
     * transport-agnostic (and unit-testable). Returns the successor token, or
     * "" when re-authorization was denied.
     */
    refresh: (currentToken: string) => Promise<string>;
    /** Test hook: override "now" (ms). */
    nowMs?: () => number;
    /** Test hook: override sleep. */
    sleep?: (ms: number) => Promise<void>;
}
declare class TokenReauthorizer {
    private readonly opts;
    private stopped;
    private loop;
    constructor(opts: TokenReauthorizerOptions);
    private now;
    private sleep;
    /**
     * Run the loop until stop() or a re-authorization denial. `currentToken`
     * is a getter because the successor becomes the next iteration's input.
     */
    start(getCurrentToken: () => string, cb: ReauthorizationCallbacks): void;
    stop(): Promise<void>;
    private tokenExpMs;
    private run;
}

/**
 * Audit helpers (doc 01 §5.9/§10.4, Ruling A.4).
 *
 * - `targetTouchedEvent` builds the per-probe TARGET_TOUCHED audit record —
 *   the AUTHORITATIVE cross-check for scope-bound watch tokens (a checkpoint
 *   `targets_touched: ["scope:sha256:…"]` entry is accepted only alongside
 *   these records).
 * - `scopeHashCheckpoint` (from jcs.ts) produces that checkpoint form.
 * - Events are published on `audit.events` (durable, never sampled).
 *
 * The audit of record for authorization state lives in gatekeeper's
 * audit-service (Ruling B); these events feed the command layer's operational
 * chain (aegisbastion.platform.v1.AuditEvent).
 */

interface AuditEventInput {
    type: AuditEventType;
    actor: {
        kind: string;
        id: string;
    };
    subject: {
        missionId?: string;
        taskId?: string;
        roeId?: string;
    };
    payload: JsonObject;
    /** Chain ordering assigned by the caller's local emitter (0 = unset). */
    seq?: bigint | number;
    /** Previous chain hash ("sha256:…"); "" for the genesis event. */
    prevHash?: string;
}
/**
 * Build a hash-chained platform AuditEvent (doc 01 §5.9):
 * hash = "sha256:" + sha256(prev_hash || JCS(event minus hash)).
 */
declare function buildAuditEvent(input: AuditEventInput): AuditEvent;
/**
 * Build the per-probe TARGET_TOUCHED record (Ruling A.4 — the authoritative
 * cross-check). One record per probe, emitted at touch time.
 */
declare function targetTouchedEvent(input: {
    agentId: string;
    taskId: string;
    missionId: string;
    roeId: string;
    target: string;
    tokenJti: string;
    capability: string;
    seq?: bigint | number;
    prevHash?: string;
}): AuditEvent;
/**
 * Local audit emitter: keeps the agent-side hash chain (seq + prev_hash) and
 * hands each event to a sink (typically BusClient.publish on audit.events).
 * Sinks are durable and never sampled (doc 01 §8.1); when the sink throws,
 * the error propagates — doc 11 §7: PEPs spool execution events and halt
 * module activity when the spool is full. The sink decides spooling policy.
 */
declare class AuditEmitter {
    private readonly sink;
    private seq;
    private prevHash;
    constructor(sink: (event: AuditEvent) => Promise<void>);
    emit(input: AuditEventInput): Promise<AuditEvent>;
    /** Emit one per-probe TARGET_TOUCHED record. */
    targetTouched(input: {
        agentId: string;
        taskId: string;
        missionId: string;
        roeId: string;
        target: string;
        tokenJti: string;
        capability: string;
    }): Promise<AuditEvent>;
}

/**
 * JetStream bus client (doc 01 §8, Ruling C3 — JetStream is the canonical
 * platform bus). Wraps: envelope publishing, the agent's task.assign consumer,
 * module event publishers (*.alert / monitor.changes / detect.findings / …),
 * the tasks.revocations.v1 subscription, and control.kill (CORE NATS
 * broadcast — NO JetStream stream, doc 01 §8.1).
 *
 * Consumers are idempotent on event_id / task_id (doc 01 §8.2) via a bounded
 * dedup set; assignment handlers ack only after successful handling (nak with
 * delay otherwise, so redelivery on lease expiry works per doc 01 §8.1).
 */

/** JetStream stream names, as bootstrapped by deploy/jetstream-bootstrap. */
declare const STREAMS: {
    readonly taskAssign: "TASK_ASSIGN";
    readonly gatekeeper: "GATEKEEPER";
};
interface BusClientOptions {
    /** e.g. "nats://localhost:4222" or ["nats://nats:4222"]. */
    servers: string | string[];
    /** NATS connection extras (credentials, TLS, name). */
    connection?: Omit<ConnectionOptions, "servers">;
}
interface AssignmentDelivery {
    envelopeId: string;
    assignment: TaskAssignment;
    /** Trace context propagated from the Orchestrator's envelope. */
    traceContext?: {
        traceparent: string;
        tracestate?: string;
    };
}
declare class BusClient {
    readonly nc: NatsConnection;
    readonly js: JetStreamClient;
    private constructor();
    static connect(opts: BusClientOptions): Promise<BusClient>;
    close(): Promise<void>;
    /** Publish a typed payload on a subject inside the platform envelope. */
    publish<Desc extends DescMessage>(subject: string, payloadSchema: Desc, payload: MessageShape<Desc>, opts?: EnvelopeOptions): Promise<PubAck>;
    /** Publish a pre-built envelope (e.g. audit events). */
    publishEnvelope(subject: string, envelopeBytes: Uint8Array): Promise<PubAck>;
    /**
     * Consume task assignments from `task.assign.{agentId}` (WorkQueue stream,
     * ack-required, redelivery on lease expiry — doc 01 §8.1). The handler MUST
     * be redelivery-safe; duplicates on task_id are filtered here, and the
     * Orchestrator-side consumer is idempotent as well (doc 01 §8.2).
     *
     * Ack semantics: ack after the handler resolves; nak(5s) when it throws so
     * the Orchestrator redelivers per the task lease.
     */
    consumeAssignments(agentId: string, handler: (delivery: AssignmentDelivery) => Promise<void>, opts?: {
        durableName?: string;
        signal?: AbortSignal;
    }): Promise<{
        stop: () => Promise<void>;
    }>;
    /**
     * Subscribe to `tasks.revocations.v1` (durable GATEKEEPER stream). The
     * handler is invoked once per RevocationEvent, deduped on event_id.
     */
    subscribeRevocations(agentId: string, handler: (event: RevocationEvent) => void): Promise<{
        stop: () => Promise<void>;
    }>;
    /**
     * Subscribe to `control.kill` — a CORE NATS broadcast with NO JetStream
     * stream (doc 01 §8.1). Agents must halt target contact within 5 s
     * (doc 01 §10.5). Raw payload bytes are handed to the caller (see
     * decodeControlKill in revocation.ts).
     */
    subscribeKill(handler: (data: Uint8Array) => void): {
        stop: () => Promise<void>;
    };
}

/**
 * High-level agent runner (doc 01 §9.1). Module teams implement ONE
 * interface — plan / run / abort — and the SDK implements contract items 3–8
 * of doc 01 §9 as library calls: assignment consumption + ACK, client-side
 * authorization enforcement (PEP guardrails), heartbeats, kill-switch
 * handling (≤ 5 s), honest TaskResult reporting with targets_touched,
 * idempotency on task_id, and trace-context propagation.
 */

/** What the module's run() returns; the SDK wraps it in a TaskResult. */
interface RunOutcome {
    summary?: JsonObject;
    artifactRefs?: string[];
    /** Extra metrics merged into TaskResultMetrics (targets_touched is SDK-owned). */
    requestsSent?: number | bigint;
}
interface TaskContext {
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
interface AgentModule {
    plan(assignment: TaskAssignment): Promise<void>;
    run(ctx: TaskContext): Promise<RunOutcome>;
    abort(taskId: string): void;
}
interface AgentOptions {
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
declare class Agent {
    private readonly opts;
    private agentId;
    private readonly running;
    private heartbeatTimer;
    private stops;
    private started;
    constructor(opts: AgentOptions);
    get id(): string;
    /** Register (re-register on version change), then start all loops. */
    start(): Promise<void>;
    stop(): Promise<void>;
    /** ACK fast (≤ 10 s, doc 01 §9 item 3), then execute in the background. */
    private acceptAssignment;
    private streamLoop;
    private execute;
    private statusForError;
    private buildTaskContext;
    /** Enforce timeout_s / deadline (doc 01 §5.6); abort the module on expiry. */
    private runWithDeadline;
    private report;
    private startReauthorization;
    /** Abort one task: stop target contact ≤ 5 s (doc 01 §10.5). */
    abortTask(taskId: string, reason: string): void;
    private sweepRevokedTasks;
    private handleControlKill;
    private startHeartbeats;
    /** Introspection for tests/diagnostics. */
    runningTaskIds(): string[];
    /** Auth summary for structured logs — never carries target lists. */
    describeAuth(auth: TaskAuthorization | null): JsonObject;
}

export { Agent, type AgentModule, type AgentOptions, type AgentServiceClient, type AssignmentDelivery, AuditEmitter, type AuditEventInput, BusClient, type BusClientOptions, CLOCK_LEEWAY_SECONDS, type CanonicalScope, type CanonicalTarget, type Cidr, ConcurrencyLimiter, DEFAULT_MAX_RPS_R1, type EnvelopeOptions, type GrpcClientOptions, type GrpcTlsOptions, IdempotencySet, JwksCache, type JwksCacheOptions, type KillSignal, MAX_CLOCK_SKEW_SECONDS, MAX_TOKEN_TTL_SECONDS, type ManifestFetcher, Pep, PepError, type PepErrorCode, type PepOptions, RateCapsEnforcer, type ReauthorizationCallbacks, RegistryClient, RevocationCache, type RiskClassName, type RunOutcome, type S3ManifestFetcherOptions, SCOPE_BOUND_CAPABILITIES, STREAMS, SUBJECTS, type ScopeManifest, type ScopeTokenClaims, type ScopeVerdict, TOKEN_AUDIENCE, TOKEN_ISSUER, type TargetManifestRef, TaskAuthorization, type TaskContext, TokenBucketRateLimiter, type TokenRateCaps, TokenReauthorizer, type TokenReauthorizerOptions, type TokenServiceClient, type VerifiedManifest, type VerifyTokenOptions, auditChainHash, buildAuditEvent, canonicalizeTarget, createAgentServiceClient, createS3ManifestFetcher, createTokenServiceClient, decodeControlKill, decodeEnvelope, encodeEnvelope, evaluateTargetInScope, fetchAndVerifyManifest, grpcNodeOptions, ipv4InCidr, ipv6InCidr, isPepError, isTargetInManifest, jcs, jwksFetcher, newEnvelope, parseCidr, parseIpv4, parseIpv6, parseManifestUri, parseScopeTokenClaims, refreshScopeToken, ruleMatchesTarget, scopeHashCheckpoint, sha256Hex, sha256JcsHex, targetTouchedEvent, ulid, verifyScopeToken };
