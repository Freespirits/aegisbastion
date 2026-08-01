/**
 * @aegisbastion/alert — herald, the AegisBastion alert module (doc 05). Sole
 * notification egress (Ruling C7). Public surface for embedders/tests; the
 * deployable entrypoint is main.ts (`node dist/main.js`).
 */

export * from "./types.js";
export { loadConfig, validateConfig, type HeraldConfig } from "./config.js";
export { loadValidators, validationErrors, type AlertValidators } from "./schemas.js";
export { Pipeline, pipelineOptionsFromConfig, noopSinks, type PipelineOptions, type PipelineSinks, type IngestResult } from "./pipeline.js";
export { AuthzEnforcer, requiresAuthorization, capabilitiesCoverModule, type AuthzVerdict } from "./authz/enforce.js";
export { httpJwksFetcher } from "./authz/jwks.js";
export { AssetCache, GraphQlAssetLookup, effectiveSeverity, enrichEvent, type AssetLookup, type AssetInfo, type DpQueryOptions } from "./enrich.js";
export { dedupCheck, fingerprintFor } from "./dedup.js";
export { correlate, correlationKeyFor } from "./correlate.js";
export {
  routeIncident,
  policyMatches,
  applyEgressPolicy,
  egressAllows,
  bootstrapPolicies,
  defaultEscalationPolicy,
  urgencyForSeverity,
  bumpUrgency,
  type RouteDecision,
} from "./routing.js";
export { runDueEscalations, nextEscalationState, initialEscalationState, EscalationLoop, type EscalationDriver } from "./escalate.js";
export { Dispatcher, DispatchLoop, backoffFor, type DispatcherOptions } from "./dispatch/dispatcher.js";
export { RecordedSink, type DeliverySink, type SendRequest, type SendResult } from "./dispatch/sink.js";
export { LiveSink, sendSlack, sendTeams, sendWebhook, sendSplunkBatch, sendSyslog, renderSlackPayload, renderTeamsPayload, renderWebhookEnvelope, renderSplunkEvent, renderSyslogLine, type AdapterContext } from "./dispatch/adapters.js";
export { signWebhookBody, verifyWebhookSignature } from "./dispatch/sign.js";
export { guardDestination, isBlockedIp, pinnedLookup, type SsrfVerdict } from "./dispatch/ssrf.js";
export { redactEventForTarget } from "./dispatch/redact.js";
export { renderText } from "./dispatch/templates.js";
export { TokenBucket, BucketRegistry, bucketKey } from "./dispatch/ratelimit.js";
export { mintAckToken, verifyAckToken, ackCallbackUrl, ACK_TOKEN_TTL_SECONDS, type AckToken } from "./acktoken.js";
export { Metrics } from "./metrics.js";
export { MemoryStore } from "./db/memory.js";
export { PostgresStore } from "./db/pgstore.js";
export type { Store, StoredAlert, DedupOutcome } from "./store.js";
export { createHttpServer, type HttpApiDeps } from "./httpapi.js";
export { busSinks, startIngestConsumer, INGRESS_STREAM, INGRESS_SUBJECTS, AUTHZ_TOKEN_HEADER } from "./buswire.js";
export { startHerald } from "./main.js";
