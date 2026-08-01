/**
 * Channel adapters (doc 05 §6). Each adapter renders its provider payload
 * and executes the delivery; per-channel rate caps and retries live in the
 * dispatcher, SSRF guarding + DNS pinning in dispatch/ssrf.ts (all HTTPS
 * sends go through it), HMAC signing for generic webhooks in dispatch/sign.ts.
 *
 * MVP adapter set (doc 05 §15): Slack (incoming webhook), Teams (incoming
 * webhook / Adaptive Card), Splunk HEC (sourcetype=aegisbastion:alert, batch
 * ≤100), generic syslog (RFC 5424 + CEF), generic signed webhook.
 */
import net from "node:net";
import tls from "node:tls";
import { ulid } from "@aegisbastion/agent-sdk";
import { guardDestination, pinnedLookup } from "./ssrf.js";
import { classifyStatus, postJson } from "./httpjson.js";
import { signWebhookBody } from "./sign.js";
const SEVERITY_COLORS = {
    critical: "#d32f2f",
    high: "#f57c00",
    medium: "#fbc02d",
    low: "#9e9e9e",
    info: "#9e9e9e",
};
function destinationUrl(destination, fallback) {
    if (destination.startsWith("https://"))
        return destination;
    return fallback;
}
async function guardedPost(rawUrl, body, headers, ctx, allowInternal) {
    const verdict = await guardDestination(rawUrl, {
        allowInternal,
        ...(ctx.resolveAll ? { resolveAll: ctx.resolveAll } : {}),
    });
    if (!verdict.allow) {
        return { ok: false, error: `SSRF guard blocked destination: ${verdict.reason}` };
    }
    const started = Date.now();
    try {
        const res = await postJson(new URL(rawUrl), body, {
            headers,
            timeoutMs: ctx.timeoutMs,
            lookup: pinnedLookup(verdict.addresses),
        });
        const latencyMs = Date.now() - started;
        const cls = classifyStatus(res.status);
        if (cls === "ok") {
            return { ok: true, providerResponseCode: res.status, latencyMs, payloadSnapshot: safeJson(body) };
        }
        if (cls === "redirect-refused") {
            // §13.4: no redirects are followed — fail the delivery.
            return { ok: false, providerResponseCode: res.status, latencyMs, error: `redirect refused (${res.status})` };
        }
        return {
            ok: false,
            providerResponseCode: res.status,
            latencyMs,
            error: `provider HTTP ${res.status}: ${res.body.slice(0, 200)}`,
            ...(res.retryAfterMs !== undefined ? { retryAfterMs: res.retryAfterMs } : {}),
        };
    }
    catch (err) {
        return { ok: false, latencyMs: Date.now() - started, error: err.message };
    }
}
function safeJson(body) {
    try {
        return JSON.parse(body);
    }
    catch {
        return { raw: body.slice(0, 1024) };
    }
}
// ---------------------------------------------------------------------------
// Slack (§6): incoming webhook, severity-colored attachment + blocks.
// ---------------------------------------------------------------------------
export function renderSlackPayload(req) {
    const { incident, text } = req;
    const blocks = [
        { type: "header", text: { type: "plain_text", text: incident.title.slice(0, 150) } },
        { type: "section", text: { type: "mrkdwn", text: text.slice(0, 2900) } },
        {
            type: "context",
            elements: [
                {
                    type: "mrkdwn",
                    text: `incident \`${incident.incidentId}\` • org ${incident.orgId} • ${incident.category} • alerts ×${incident.alertCount}`,
                },
            ],
        },
    ];
    // §6/§9: "Acknowledge / View incident" button → signed callback token (§12).
    // Incoming webhooks cannot receive Slack interactivity posts, so the MVP-A
    // button is a link to herald's signed ack endpoint (see README deviation 4).
    if (req.ackUrl) {
        blocks.push({
            type: "actions",
            elements: [
                { type: "button", text: { type: "plain_text", text: "Acknowledge" }, url: req.ackUrl, style: "primary" },
            ],
        });
    }
    return {
        text: `${incident.severity.toUpperCase()}: ${incident.title}`.slice(0, 200),
        attachments: [{ color: SEVERITY_COLORS[incident.severity], blocks }],
    };
}
export async function sendSlack(req, ctx) {
    const url = destinationUrl(req.delivery.destination, ctx.slackDefaultWebhookUrl);
    if (!url)
        return { ok: false, error: "no Slack webhook URL configured for destination" };
    const payload = renderSlackPayload(req);
    const mention = req.delivery.mention;
    if (mention)
        payload.text = `${mention} ${payload.text}`;
    return guardedPost(url, JSON.stringify(payload), {}, ctx, req.egressEntry?.internal === true);
}
// ---------------------------------------------------------------------------
// Microsoft Teams (§6): Adaptive Card via incoming webhook; 429 backoff is
// surfaced via retryAfterMs for the dispatcher.
// ---------------------------------------------------------------------------
export function renderTeamsPayload(req) {
    const { incident, text } = req;
    return {
        type: "message",
        attachments: [
            {
                contentType: "application/vnd.microsoft.card.adaptive",
                contentUrl: null,
                content: {
                    $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
                    type: "AdaptiveCard",
                    version: "1.4",
                    body: [
                        {
                            type: "TextBlock",
                            size: "Large",
                            weight: "Bolder",
                            color: incident.severity === "critical" ? "Attention" : incident.severity === "high" ? "Warning" : "Default",
                            text: incident.title.slice(0, 250),
                        },
                        { type: "TextBlock", text: text.slice(0, 4000), wrap: true },
                        {
                            type: "FactSet",
                            facts: [
                                { title: "Incident", value: incident.incidentId },
                                { title: "Severity", value: incident.severity },
                                { title: "Category", value: incident.category },
                                { title: "Alerts", value: String(incident.alertCount) },
                            ],
                        },
                    ],
                    // §9 ack action (link-style; Graph actionable messages are Later).
                    ...(req.ackUrl ? { actions: [{ type: "Action.OpenUrl", title: "Acknowledge", url: req.ackUrl }] } : {}),
                },
            },
        ],
    };
}
export async function sendTeams(req, ctx) {
    const url = destinationUrl(req.delivery.destination, ctx.teamsDefaultWebhookUrl);
    if (!url)
        return { ok: false, error: "no Teams webhook URL configured for destination" };
    return guardedPost(url, JSON.stringify(renderTeamsPayload(req)), {}, ctx, req.egressEntry?.internal === true);
}
export function renderWebhookEnvelope(req, now) {
    return {
        specversion: "1.0",
        id: `dlvmsg_${ulid()}`,
        source: "//aegisbastion/alert",
        type: "com.aegisbastion.alert.delivery.v1",
        subject: `incident/${req.incident.incidentId}`,
        time: now.toISOString(),
        datacontenttype: "application/json",
        data: { incident: req.incident, alerts: req.alerts, text: req.text },
    };
}
export async function sendWebhook(req, ctx, now = new Date()) {
    const body = JSON.stringify(renderWebhookEnvelope(req, now));
    const secretRef = req.egressEntry?.secret_ref;
    const secret = (secretRef ? ctx.resolveSecret(secretRef) : undefined) ?? ctx.defaultWebhookSecret;
    if (!secret) {
        return { ok: false, error: "no signing secret available for webhook endpoint (§13.5)" };
    }
    const signature = signWebhookBody(secret, body, Math.floor(now.getTime() / 1000));
    const result = await guardedPost(req.delivery.destination, body, { "x-aegisbastion-signature": signature, "x-aegisbastion-delivery": req.delivery.deliveryId }, ctx, req.egressEntry?.internal === true);
    if (result.ok)
        result.payloadSnapshot = { signature, envelope: safeJson(body) };
    return result;
}
// ---------------------------------------------------------------------------
// Splunk HEC (§6): JSON event per alert, sourcetype=aegisbastion:alert, batched
// up to 100 events/POST by the dispatcher (sendSplunkBatch).
// ---------------------------------------------------------------------------
export function renderSplunkEvent(req, alert) {
    return {
        time: Date.parse(alert.occurred_at) / 1000,
        sourcetype: "aegisbastion:alert",
        source: `herald:${alert.source_module}`,
        event: {
            incident_id: req.incident.incidentId,
            severity: req.incident.severity,
            category: alert.category,
            title: alert.title,
            alert,
        },
    };
}
export async function sendSplunkBatch(reqs, ctx) {
    const first = reqs[0];
    const destination = first.delivery.destination;
    const url = destination.startsWith("https://")
        ? destination
        : first.egressEntry && first.egressEntry.pattern.startsWith("https://")
            ? first.egressEntry.pattern
            : "";
    if (!url) {
        return { ok: false, error: `no Splunk HEC URL resolvable for destination ${destination}` };
    }
    const index = destination.startsWith("https://") ? undefined : destination;
    const token = (first.egressEntry?.secret_ref ? ctx.resolveSecret(first.egressEntry.secret_ref) : undefined) ?? ctx.splunkHecToken;
    const events = reqs.flatMap((req) => req.alerts.map((a) => renderSplunkEvent(req, a)));
    const body = events
        .map((e) => JSON.stringify(index ? { ...e, index } : e))
        .join("\n");
    const result = await guardedPost(`${url.replace(/\/$/, "")}/services/collector`, body, token ? { authorization: `Splunk ${token}` } : {}, ctx, first.egressEntry?.internal === true);
    if (result.ok)
        result.payloadSnapshot = { events: events.length };
    return result;
}
// ---------------------------------------------------------------------------
// Generic syslog (§6): RFC 5424 over TCP/TLS, CEF (default) or LEEF framing.
// Persistent socket per destination with reconnect; failed sends surface as
// retryable SendResults so the dispatcher's backoff/DLQ handles the spool.
// ---------------------------------------------------------------------------
const SYSLOG_SEVERITY = { critical: 2, high: 3, medium: 4, low: 5, info: 6 };
const CEF_SEVERITY = { critical: 10, high: 8, medium: 5, low: 2, info: 1 };
function cefEscape(s) {
    return s.replace(/\\/g, "\\\\").replace(/([|=])/g, "\\$1").replace(/[\r\n]+/g, " ");
}
export function renderSyslogLine(req, alert, now = new Date()) {
    const pri = 13 * 8 + SYSLOG_SEVERITY[req.incident.severity]; // facility=security/authorization(13)
    const ts = now.toISOString();
    const host = "herald";
    if (req.delivery.template === "leef_v1") {
        const leef = `LEEF:2.0|AegisBastion|herald|1.0|${alert.category}|${cefEscape(alert.title)}\tsev=${CEF_SEVERITY[req.incident.severity]}\tincident=${req.incident.incidentId}\tasset=${cefEscape(alert.asset.identifier)}`;
        return `<${pri}>1 ${ts} ${host} herald - - - ${leef}`;
    }
    const cef = `CEF:0|AegisBastion|herald|1.0|${alert.category}|${cefEscape(alert.title)}|${CEF_SEVERITY[req.incident.severity]}|incident=${req.incident.incidentId} asset=${cefEscape(alert.asset.identifier)} sev=${req.incident.severity} cnt=${req.incident.alertCount}`;
    return `<${pri}>1 ${ts} ${host} herald - - - ${cef}`;
}
function parseSyslogDestination(destination) {
    const m = /^(?:(tcp|tls):\/\/)?([^:/]+):(\d+)$/.exec(destination);
    if (!m)
        throw new Error(`invalid syslog destination ${destination} (want [tcp|tls://]host:port)`);
    return { host: m[2], port: Number(m[3]), useTls: m[1] === "tls" };
}
async function defaultDial(destination) {
    const { host, port, useTls } = parseSyslogDestination(destination);
    return new Promise((resolveSocket, rejectSocket) => {
        const onError = (err) => rejectSocket(err);
        if (useTls) {
            const sock = tls.connect({ host, port, servername: host }, () => resolveSocket(sock));
            sock.once("error", onError);
        }
        else {
            const sock = net.createConnection({ host, port }, () => resolveSocket(sock));
            sock.once("error", onError);
        }
    });
}
export async function sendSyslog(req, ctx) {
    const started = Date.now();
    const dial = ctx.syslogDial ?? defaultDial;
    let sock;
    try {
        sock = await dial(req.delivery.destination);
    }
    catch (err) {
        return { ok: false, latencyMs: Date.now() - started, error: `syslog connect failed: ${err.message}` };
    }
    try {
        const lines = req.alerts.map((a) => renderSyslogLine(req, a));
        await new Promise((resolveWrite, rejectWrite) => {
            sock.write(lines.join("\n") + "\n", (err) => (err ? rejectWrite(err) : resolveWrite()));
        });
        return { ok: true, latencyMs: Date.now() - started, payloadSnapshot: { lines: lines.length } };
    }
    catch (err) {
        return { ok: false, latencyMs: Date.now() - started, error: `syslog write failed: ${err.message}` };
    }
    finally {
        sock.destroy();
    }
}
// ---------------------------------------------------------------------------
// LiveSink — production fan-out (§6 registry: adapters are plugins).
// ---------------------------------------------------------------------------
export class LiveSink {
    ctx;
    mode = "live";
    constructor(ctx) {
        this.ctx = ctx;
    }
    async send(req) {
        try {
            switch (req.delivery.channel) {
                case "slack":
                    return await sendSlack(req, this.ctx);
                case "teams":
                    return await sendTeams(req, this.ctx);
                case "webhook":
                    return await sendWebhook(req, this.ctx);
                case "splunk-hec":
                    return await sendSplunkBatch([req], this.ctx);
                case "syslog":
                    return await sendSyslog(req, this.ctx);
            }
        }
        catch (err) {
            return { ok: false, error: `adapter error: ${err.message}` };
        }
    }
    async close() { }
}
export const ADAPTER_CHANNELS = ["slack", "teams", "splunk-hec", "syslog", "webhook"];
