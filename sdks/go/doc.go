// Package agentsdk is the AegisBastion platform Go agent SDK — doc 01 §9.1's
// "Platform Agent SDK" merged with gatekeeper's pep-sdk (Ruling B.2 PEP-2:
// one library, two names). Agents MUST use this SDK rather than hand-rolling
// contract items (doc 01 §9 item 4).
//
// # Quick start
//
//	mod := &myModule{}            // implements agentsdk.Module
//	agent, err := agentsdk.New(agentsdk.Config{
//	    Manifest:       &platformv1.AgentManifest{AgentType: ..., Capabilities: ...},
//	    NATSURL:        "nats://localhost:4222",
//	    RegistryAddr:   "localhost:50052",          // platform-core AgentService
//	    GatekeeperAddr: "localhost:50051",          // gatekeeper TokenService
//	    DialOptions:    []grpc.DialOption{registry.InsecureDialOption()}, // mTLS in prod
//	    S3:             manifest.S3Config{Endpoint: "localhost:9000", ...},
//	}, mod)
//	err = agent.Run(ctx)          // registers, heartbeats, consumes, blocks
//
// # What module teams implement (doc 01 §9.1)
//
//	Module.Plan(t *Task) error                       — validate params
//	Module.Run(ctx, t *Task, emit *Emitter) error    — work, inside guardrails
//	Module.Abort()                                   — halt ≤ 5 s on kill
//
// During Run, EVERY network target contact goes through
// Task.AuthorizeTarget(ctx, target) — the full PEP-2 chain (revocation →
// token validity → manifest/scope check with exclusions-first → rate caps),
// which records the touch and emits the per-probe TARGET_TOUCHED audit
// record. Progress and module events go through Emitter (Progress, Event,
// SetSummary, AddRequests, AddArtifactRef). The terminal TaskResult (status,
// metrics.targets_touched, artifacts, summary) is built and reported by the
// SDK; status is derived from Run's error (KILLED / TIMEOUT /
// REJECTED_UNAUTHORIZED / FAILED / SUCCEEDED).
//
// # Public surface by package
//
// agentsdk (this package):
//   - Config, Agent, New, Agent.Run, Agent.AgentID, Agent.Close
//   - Module, Task (Assignment, AuthorizeTarget, Guard,
//     RequiresAuthorization), Emitter
//
// bus — NATS JetStream client (doc 01 §8):
//   - Client, Connect, FromConn, Close, Conn, JetStream
//   - Publish / PublishMsg / PublishCore / BuildMessage (outbox-friendly:
//     Nats-Msg-Id = event_id dedup), NewEnvelope, MarshalEnvelope,
//     UnmarshalEnvelope, UnpackPayload, PublishOptions
//   - Consume (durable JetStream consumer, Ack/Nak/Term dispositions,
//     MessageControl.InProgress), SubscribeCore (control.kill path)
//   - Subject consts (SubjectTaskResult, SubjectControlKill,
//     SubjectRevocations, …), SubjectTaskAssign, stream consts
//
// registry — AgentService gRPC client (doc 01 §8.3):
//   - Client, Dial, InsecureDialOption, Register, Heartbeat, AckTask,
//     ReportProgress, ReportResult, StreamTasks, AgentID, Close
//
// token — Scope Token verification (doc 01 §5.5, doc 11 §3.2):
//   - Verifier.Verify (EdDSA vs cached JWKS; aud=aegisbastion.modules; exp/nbf
//     with 60 s leeway; iat skew ≤ 120 s; TTL ≤ 15 min; task-bound jti;
//     scope_bound applicability; R3 approval binding)
//   - KeyCache + KeySource (HTTPKeySource / GRPCKeysSource), JWK
//   - Claims, TargetManifestRef, RateCaps, typed errors (ErrSignature,
//     ErrAudience, ErrExpired, ErrScopeBound, …)
//
// scope — doc 01 §10.1 canonicalized matching:
//   - Scope{Domains, CIDRs, ExplicitExcludes}, Scope.Evaluate → Decision
//     (longest-prefix/exact-host; EXCLUSIONS ALWAYS WIN; fail-closed)
//   - Canonicalize → Target (KindHost/KindIP/KindURL/KindCIDR)
//
// manifest — MinIO token-manifests fetch/verify (doc 11 §3.2):
//   - Load (fetch → sha256 == claim → parse exact/scope-bound form),
//     Fetcher, S3Fetcher, S3Config, MapURI, ScopeManifest
//   - Manifest.Contains (exact form), Manifest.EvaluateScope (scope form),
//     ScopeAuditValue ("scope:sha256:<hash>", Ruling A.3)
//
// pep — PEP-2 guardrails (Ruling B.2):
//   - Guard (AuthorizeTarget, Acquire/Release, Touched,
//     TargetsTouchedMetric, Update for re-authorization), GuardConfig
//   - RevocationCache (ApplyEvent / Apply / Replace / Revoked / Halted),
//     KillDecision (control.kill interpretation), RateLimiter
//   - typed denials (ErrRevoked, ErrTargetNotInManifest, ErrTargetExcluded,
//     ErrTargetOutOfScope, ErrTaskBinding, ErrNoAuthorization,
//     ErrRateLimited)
//
// audit — emission helpers (doc 01 §5.9/§10.4, Ruling A.4):
//   - Emitter (EmitterFunc, NopEmitter), NewEvent, TargetTouchedEvent,
//     ScopeViolationEvent, Ident
//   - ScopeHashValue / CheckpointTargetsTouched (the "scope:sha256:<hash>"
//     form — valid ONLY alongside per-probe TARGET_TOUCHED records)
//   - Canonical / CanonicalizeJSON — JCS (RFC 8785, doc 01 §10.2)
package agentsdk
