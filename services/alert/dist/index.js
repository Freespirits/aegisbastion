/**
 * @aegisbastion/alert — herald, the AegisBastion alert module (doc 05). Sole
 * notification egress (Ruling C7). Public surface for embedders/tests; the
 * deployable entrypoint is main.ts (`node dist/main.js`).
 */
export * from "./types.js";
export { loadConfig, validateConfig } from "./config.js";
export { loadValidators, validationErrors } from "./schemas.js";
export { Pipeline, pipelineOptionsFromConfig, noopSinks } from "./pipeline.js";
export { AuthzEnforcer, requiresAuthorization, capabilitiesCoverModule } from "./authz/enforce.js";
export { httpJwksFetcher } from "./authz/jwks.js";
export { AssetCache, GraphQlAssetLookup, effectiveSeverity, enrichEvent } from "./enrich.js";
export { dedupCheck, fingerprintFor } from "./dedup.js";
export { correlate, correlationKeyFor } from "./correlate.js";
export { routeIncident, policyMatches, applyEgressPolicy, egressAllows, bootstrapPolicies, defaultEscalationPolicy, urgencyForSeverity, bumpUrgency, } from "./routing.js";
export { runDueEscalations, nextEscalationState, initialEscalationState, EscalationLoop } from "./escalate.js";
export { Dispatcher, DispatchLoop, backoffFor } from "./dispatch/dispatcher.js";
export { RecordedSink } from "./dispatch/sink.js";
export { LiveSink, sendSlack, sendTeams, sendWebhook, sendSplunkBatch, sendSyslog, renderSlackPayload, renderTeamsPayload, renderWebhookEnvelope, renderSplunkEvent, renderSyslogLine } from "./dispatch/adapters.js";
export { signWebhookBody, verifyWebhookSignature } from "./dispatch/sign.js";
export { guardDestination, isBlockedIp, pinnedLookup } from "./dispatch/ssrf.js";
export { redactEventForTarget } from "./dispatch/redact.js";
export { renderText } from "./dispatch/templates.js";
export { TokenBucket, BucketRegistry, bucketKey } from "./dispatch/ratelimit.js";
export { mintAckToken, verifyAckToken, ackCallbackUrl, ACK_TOKEN_TTL_SECONDS } from "./acktoken.js";
export { Metrics } from "./metrics.js";
export { MemoryStore } from "./db/memory.js";
export { PostgresStore } from "./db/pgstore.js";
export { createHttpServer } from "./httpapi.js";
export { busSinks, startIngestConsumer, INGRESS_STREAM, INGRESS_SUBJECTS, AUTHZ_TOKEN_HEADER } from "./buswire.js";
export { startHerald } from "./main.js";
