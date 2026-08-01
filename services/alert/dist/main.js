/**
 * herald — composition root (doc 05). Wires: config → schema validators →
 * Postgres store → JWKS cache + authz enforcer → asset cache → pipeline →
 * dispatcher/escalation/authz-retry loops → JetStream ingest consumer +
 * lifecycle/DLQ/audit publishers → REST surface. Graceful on SIGINT/SIGTERM.
 *
 * Fail-closed posture (§12/§13.1): boot NEVER requires gatekeeper — when the
 * JWKS is unreachable the enforcer reports `unavailable` and alerts requiring
 * an authorization context are HELD (not delivered), retried for 15 min, then
 * quarantined. Readiness reports the JWKS state honestly.
 */
import { BusClient, JwksCache, createS3ManifestFetcher } from "@aegisbastion/agent-sdk";
import { loadConfig, validateConfig } from "./config.js";
import { loadValidators } from "./schemas.js";
import { PostgresStore } from "./db/pgstore.js";
import { AuthzEnforcer } from "./authz/enforce.js";
import { httpJwksFetcher } from "./authz/jwks.js";
import { AssetCache, GraphQlAssetLookup } from "./enrich.js";
import { Pipeline, noopSinks, pipelineOptionsFromConfig } from "./pipeline.js";
import { Dispatcher, DispatchLoop } from "./dispatch/dispatcher.js";
import { RecordedSink } from "./dispatch/sink.js";
import { LiveSink } from "./dispatch/adapters.js";
import { BucketRegistry } from "./dispatch/ratelimit.js";
import { EscalationLoop, runDueEscalations } from "./escalate.js";
import { Metrics } from "./metrics.js";
import { createHttpServer } from "./httpapi.js";
import { busSinks, startIngestConsumer } from "./buswire.js";
export async function startHerald() {
    const cfg = loadConfig();
    validateConfig(cfg);
    const validators = loadValidators();
    const metrics = new Metrics();
    const store = new PostgresStore(cfg.databaseUrl);
    // --- authz spine (§13.1) ---------------------------------------------------
    const jwksCache = new JwksCache({
        fetchKeys: httpJwksFetcher(cfg.gatekeeperJwksUrl),
        refreshIntervalMs: cfg.jwksRefreshMs,
    });
    let jwksReady = false;
    try {
        await jwksCache.start();
        jwksReady = true;
        console.log(`herald: JWKS loaded from ${cfg.gatekeeperJwksUrl} (kids: ${jwksCache.cachedKids().join(", ")})`);
    }
    catch (err) {
        // §12: boot without gatekeeper — held alerts, honest readiness.
        console.error(`herald: JWKS unavailable at boot (${err.message}) — authz-required alerts will be HELD`);
    }
    const enforcer = new AuthzEnforcer({
        jwksCache,
        manifestFetcher: createS3ManifestFetcher({
            endpoint: `${cfg.s3.useTls ? "https" : "http"}://${cfg.s3.endpoint}`,
            accessKeyId: cfg.s3.accessKey,
            secretAccessKey: cfg.s3.secretKey,
        }),
    });
    // --- enrichment (§3.1 C2, fail-soft) ---------------------------------------
    const assetCache = new AssetCache(cfg.dpQueryUrl
        ? new GraphQlAssetLookup(cfg.dpQueryUrl, {
            principal: cfg.dpPrincipal,
            ...(cfg.dpTenant ? { tenant: cfg.dpTenant } : {}),
        })
        : null, cfg.assetCacheTtlMs);
    // --- bus (optional; tests/dev run in-process) -------------------------------
    let bus = null;
    let consumer = null;
    let sinks = noopSinks;
    if (cfg.busEnabled) {
        bus = await BusClient.connect({ servers: cfg.natsUrl, connection: { name: "herald" } });
        sinks = busSinks(bus, { onForwarded: (auditId) => store.markAuditForwarded(auditId, new Date()) });
    }
    const pipeline = new Pipeline(pipelineOptionsFromConfig(cfg, { store, enforcer, assetCache, sinks, metrics }));
    // --- dispatch (C6) -----------------------------------------------------------
    const resolveSecret = (ref) => process.env[`HERALD_SECRET_${ref.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`];
    const adapterCtx = {
        slackDefaultWebhookUrl: cfg.slackWebhookUrl,
        teamsDefaultWebhookUrl: cfg.teamsWebhookUrl,
        splunkHecToken: cfg.splunkHecToken,
        resolveSecret,
        defaultWebhookSecret: cfg.webhookSigningSecret,
        timeoutMs: cfg.webhookTimeoutMs,
    };
    const sink = cfg.deliveryMode === "live" ? new LiveSink(adapterCtx) : new RecordedSink();
    const dispatcher = new Dispatcher({
        store,
        sink,
        buckets: new BucketRegistry(cfg.rateCaps.perSecond, cfg.rateCaps.burst),
        metrics,
        sinks,
        egressFor: (orgId) => pipeline.egressFor(orgId),
        retryBackoffMinutes: cfg.retryBackoffMinutes,
        maxAttempts: cfg.maxDeliveryAttempts,
        publicBaseUrl: cfg.publicBaseUrl,
        ackSigningSecret: cfg.ackSigningSecret,
        splunkContext: cfg.deliveryMode === "live" ? adapterCtx : null,
    });
    if (bus) {
        consumer = await startIngestConsumer(bus, pipeline, validators, {
            onPoison: async (subject, errors) => {
                console.error(`herald: poison message on ${subject}: ${errors.join("; ")}`);
                await store.appendAudit({
                    orgId: "",
                    actor: { kind: "service", id: "herald" },
                    action: "ingest_reject",
                    entityIds: { subject },
                    decisionDetail: { errors },
                    requestHash: "",
                });
            },
        });
        console.log(`herald: consuming ALERT_INGRESS (durable herald-ingest) from ${cfg.natsUrl}`);
    }
    // --- loops (C7 escalation, C6 dispatch, §12 authz retry) ---------------------
    const dispatchLoop = new DispatchLoop(dispatcher, cfg.dispatchScanMs, (err) => console.error(`herald: dispatch loop error: ${err.message}`));
    const escalationLoop = new EscalationLoop(store, pipeline, cfg.escalationScanMs, (err) => console.error(`herald: escalation loop error: ${err.message}`));
    const authzRetryTimer = setInterval(() => {
        pipeline.runDueAuthzRetries(new Date()).catch((err) => console.error(`herald: authz retry loop error: ${err.message}`));
    }, cfg.authzRetryMs);
    authzRetryTimer.unref?.();
    dispatchLoop.start();
    escalationLoop.start();
    // --- REST surface (C8) -------------------------------------------------------
    const server = createHttpServer({
        config: cfg,
        pipeline,
        store,
        validators,
        metrics,
        readiness: async () => {
            let db = false;
            try {
                await store.ping();
                db = true;
            }
            catch {
                db = false;
            }
            const checks = { db, jwks: jwksReady || jwksCache.cachedKids().length > 0, bus: !cfg.busEnabled || bus !== null };
            jwksReady = checks.jwks;
            return { ready: checks.db && checks.bus, checks }; // JWKS reported, not gated (§12 hold semantics)
        },
    });
    const [host, portStr] = cfg.httpListen.startsWith(":")
        ? ["0.0.0.0", cfg.httpListen.slice(1)]
        : cfg.httpListen.split(":");
    await new Promise((resolveListen) => server.listen(Number(portStr), host, resolveListen));
    console.log(`herald: HTTP on ${host}:${portStr} (delivery mode: ${cfg.deliveryMode})`);
    // Prime one escalation scan so due timers fire promptly at boot.
    runDueEscalations(store, pipeline, new Date()).catch(() => { });
    const stop = async () => {
        dispatchLoop.stop();
        escalationLoop.stop();
        clearInterval(authzRetryTimer);
        await consumer?.stop();
        await new Promise((r) => server.close(() => r()));
        await bus?.close();
        enforcer.stop();
        await sink.close();
        await store.close();
    };
    process.on("SIGINT", () => void stop().then(() => process.exit(0)));
    process.on("SIGTERM", () => void stop().then(() => process.exit(0)));
    return { stop };
}
const isMain = process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, "/")}`).href;
if (isMain) {
    startHerald().catch((err) => {
        console.error(`herald: fatal: ${err.stack ?? err}`);
        process.exit(1);
    });
}
