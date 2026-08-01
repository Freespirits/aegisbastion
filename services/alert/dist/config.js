/**
 * Environment configuration (compose-compatible, doc 05 §16: helm values →
 * env here). Every secret comes from the environment; nothing is hard-coded.
 * Defaults target the MVP-A compose host (deploy/docker-compose.yml).
 */
function env(name, fallback = "") {
    const v = process.env[name];
    return v === undefined || v === "" ? fallback : v;
}
function envInt(name, fallback) {
    const v = process.env[name];
    if (v === undefined || v === "")
        return fallback;
    const n = Number.parseInt(v, 10);
    if (!Number.isFinite(n))
        throw new Error(`config: ${name} must be an integer, got ${v}`);
    return n;
}
export function loadConfig(overrides = {}) {
    const cfg = {
        httpListen: env("HERALD_HTTP_LISTEN", ":8086"),
        databaseUrl: env("DATABASE_URL"),
        natsUrl: env("NATS_URL", "nats://localhost:4222"),
        busEnabled: env("HERALD_BUS_ENABLED", "true") !== "false",
        gatekeeperJwksUrl: env("GATEKEEPER_JWKS_URL", "http://localhost:8080/.well-known/gatekeeper-jwks.json"),
        s3: {
            endpoint: env("S3_ENDPOINT", "localhost:9000"),
            accessKey: env("S3_ACCESS_KEY"),
            secretKey: env("S3_SECRET_KEY"),
            useTls: env("S3_USE_TLS", "false") === "true",
        },
        dpQueryUrl: env("DP_QUERY_URL"),
        dpPrincipal: env("HERALD_DP_PRINCIPAL", "herald"),
        dpTenant: env("HERALD_DP_TENANT"),
        assetCacheTtlMs: envInt("HERALD_ASSET_CACHE_TTL_MS", 5 * 60 * 1000),
        jwksRefreshMs: envInt("HERALD_JWKS_REFRESH_MS", 5 * 60 * 1000),
        defaultDedupWindowSeconds: envInt("HERALD_DEDUP_WINDOW_SECONDS", 86_400),
        maxDedupWindowSeconds: envInt("HERALD_DEDUP_MAX_WINDOW_SECONDS", 7 * 86_400),
        escalationScanMs: envInt("HERALD_ESCALATION_SCAN_MS", 5_000),
        dispatchScanMs: envInt("HERALD_DISPATCH_SCAN_MS", 2_000),
        authzHoldQuarantineMs: envInt("HERALD_AUTHZ_HOLD_QUARANTINE_MS", 15 * 60 * 1000),
        deliveryMode: env("HERALD_DELIVERY_MODE", "record") === "live" ? "live" : "record",
        slackWebhookUrl: env("ALERT_SLACK_WEBHOOK_URL"),
        webhookSigningSecret: env("ALERT_WEBHOOK_SIGNING_SECRET"),
        adminActors: new Set(env("HERALD_ADMIN_ACTORS", "cai,hexstrike-ai").split(",").map((s) => s.trim()).filter(Boolean)),
        egressSeedJson: env("HERALD_EGRESS_SEED_JSON"),
        rateCaps: {
            perSecond: envInt("HERALD_RATE_PER_SECOND", 1),
            burst: envInt("HERALD_RATE_BURST", 20),
        },
        webhookTimeoutMs: envInt("HERALD_WEBHOOK_TIMEOUT_MS", 5_000),
        splunkHecToken: env("ALERT_SPLUNK_HEC_TOKEN"),
        teamsWebhookUrl: env("ALERT_TEAMS_WEBHOOK_URL"),
        orgSiemWebhookUrl: env("HERALD_ORG_SIEM_WEBHOOK_URL"),
        publicBaseUrl: env("HERALD_PUBLIC_BASE_URL", "http://localhost:8086"),
        ackSigningSecret: env("HERALD_ACK_SIGNING_SECRET", env("ALERT_WEBHOOK_SIGNING_SECRET")),
        authzRetryMs: envInt("HERALD_AUTHZ_RETRY_MS", 60_000),
        retryBackoffMinutes: [1, 2, 4, 8, 16],
        maxDeliveryAttempts: envInt("HERALD_MAX_DELIVERY_ATTEMPTS", 6),
        ...overrides,
    };
    return cfg;
}
/** Startup validation: required settings must exist for the chosen mode. */
export function validateConfig(cfg) {
    if (!cfg.databaseUrl)
        throw new Error("config: DATABASE_URL is required");
    if (cfg.busEnabled && !cfg.natsUrl)
        throw new Error("config: NATS_URL is required when the bus is enabled");
    if (!cfg.gatekeeperJwksUrl)
        throw new Error("config: GATEKEEPER_JWKS_URL is required (fail-closed authz, doc 05 §13.1)");
    if (cfg.deliveryMode === "live" && !cfg.webhookSigningSecret) {
        // Per-endpoint secrets may still resolve via egress policy secret_refs; the
        // env default is only the bootstrap fallback, so this is a warning-level
        // concern at boot — keep it non-fatal but loud.
        console.warn("herald: ALERT_WEBHOOK_SIGNING_SECRET unset — webhook endpoints without a secret_ref cannot be signed");
    }
}
