/**
 * REST control + ingest surface (doc 05 §4.1/§5.10) on node:http (zero extra
 * dependencies — the SSRF/audit guarantees stay auditable). Endpoints:
 *
 *   GET  /healthz | /readyz
 *   POST /v1/alerts                     ingest (CloudEvents envelope or bare AlertEvent)
 *   POST /v1/notify                     commander NotifyOrder (§4.2)
 *   GET  /v1/alerts | /v1/alerts/{id}
 *   GET  /v1/incidents | /v1/incidents/{id}
 *   POST /v1/incidents/{id}/resolve
 *   POST /v1/acks  (+ GET /v1/acks?token=… channel callback, §9/§12)
 *   GET/POST /v1/policies/routing       PUT/DELETE /v1/policies/routing/{id}
 *   GET/POST /v1/policies/escalation    PUT /v1/policies/escalation/{id}
 *   GET/PUT  /v1/egress/{org}           org-level egress policy (§13.2)
 *   POST /v1/routes/test                herald_test_route dry-run (§4.1)
 *   GET  /v1/deliveries                 delivery tracking (§5.6)
 *   GET  /v1/status | /v1/metrics       (§4.3/§14)
 *
 * Actor identity (§13.7): the `X-AegisBastion-Actor` header carries the commander/
 * user id; mutations + channel_override require an admin actor
 * (HERALD_ADMIN_ACTORS). mTLS/SPIFFE + OIDC service tokens land with MVP-B
 * (doc 05 §10; the MVP-A compose host has no identity provider) — README
 * deviation 5.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { sha256JcsHex, ulid } from "@aegisbastion/agent-sdk";
import type { HeraldConfig } from "./config.js";
import type { Pipeline } from "./pipeline.js";
import { MAX_ALERT_PAYLOAD_BYTES } from "./pipeline.js";
import type { AlertValidators } from "./schemas.js";
import { validationErrors } from "./schemas.js";
import type { Store } from "./store.js";
import type { Metrics } from "./metrics.js";
import { verifyAckToken } from "./acktoken.js";
import { newEscalationPolicyId, newRoutingPolicyId } from "./ids.js";
import { CHANNELS, SEVERITIES, type AlertEvent, type Channel, type EgressEntry, type EscalationPolicy, type RoutingPolicy, type Severity } from "./types.js";

export interface HttpApiDeps {
  config: HeraldConfig;
  pipeline: Pipeline;
  store: Store;
  validators: AlertValidators;
  metrics: Metrics;
  readiness: () => Promise<{ ready: boolean; checks: Record<string, boolean> }>;
}

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  actor: string;
  body?: unknown;
  params: Record<string, string>;
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(payload);
}

function isAdmin(deps: HttpApiDeps, actor: string): boolean {
  return deps.config.adminActors.has(actor);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_ALERT_PAYLOAD_BYTES * 2) {
      throw new BodyTooLargeError();
    }
    chunks.push(chunk as Buffer);
  }
  if (chunks.length === 0) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

class BodyTooLargeError extends Error {
  constructor() {
    super("payload too large");
  }
}

function badRequest(res: ServerResponse, message: string, details: unknown = undefined): void {
  send(res, 400, { error: message, ...(details !== undefined ? { details } : {}) });
}

function actorOf(req: IncomingMessage): string {
  const h = req.headers["x-aegisbastion-actor"];
  return (Array.isArray(h) ? h[0] : h)?.trim() || "anonymous";
}

function severityParam(v: string | null): Severity | undefined {
  return (SEVERITIES as readonly string[]).includes(v ?? "") ? (v as Severity) : undefined;
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async function handleIngestAlert(deps: HttpApiDeps, ctx: Ctx): Promise<void> {
  const body = ctx.body as Record<string, unknown> | undefined;
  if (!body || typeof body !== "object") return badRequest(ctx.res, "JSON body required");

  // Accept a CloudEvents envelope (bus form) or a bare AlertEvent.
  let event: AlertEvent;
  if (typeof body.specversion === "string") {
    if (!deps.validators.envelope(body)) {
      return badRequest(ctx.res, "invalid CloudEvents envelope", validationErrors(deps.validators.envelope));
    }
    event = body.data;
  } else {
    if (!deps.validators.alertEvent(body)) {
      return badRequest(ctx.res, "invalid AlertEvent v1", validationErrors(deps.validators.alertEvent));
    }
    event = body;
  }
  if (!deps.validators.alertEvent(event)) {
    return badRequest(ctx.res, "invalid AlertEvent v1", validationErrors(deps.validators.alertEvent));
  }

  const tokenHeader = ctx.req.headers["authorization-token"];
  const token =
    (Array.isArray(tokenHeader) ? tokenHeader[0] : tokenHeader) ??
    (typeof body.authorization_token === "string" ? body.authorization_token : undefined);

  const result = await deps.pipeline.ingest(event, {
    receivedAt: new Date(),
    ...(token ? { authorizationToken: token } : {}),
    ...(ctx.req.headers["idempotency-key"] ? { idempotencyKey: String(ctx.req.headers["idempotency-key"]) } : {}),
  });
  switch (result.status) {
    case "processed":
    case "renotified":
      return send(ctx.res, 202, result);
    case "duplicate":
      return send(ctx.res, 200, result);
    case "suppressed":
      return send(ctx.res, 202, result);
    case "held":
      return send(ctx.res, 202, result);
    case "rejected":
      return send(ctx.res, result.code === "OCCURRED_AT_OUT_OF_RANGE" ? 400 : 403, result);
  }
}

async function handleNotify(deps: HttpApiDeps, ctx: Ctx): Promise<void> {
  const body = ctx.body as Record<string, unknown> | undefined;
  if (!body || typeof body !== "object") return badRequest(ctx.res, "JSON body required");
  const payload = body.payload as { title?: unknown; body?: unknown; context_url?: unknown } | undefined;
  if (typeof body.org_id !== "string" || body.org_id === "") return badRequest(ctx.res, "org_id is required");
  if (!payload || typeof payload.title !== "string" || payload.title === "") {
    return badRequest(ctx.res, "payload.title is required");
  }
  const channelOverride = Array.isArray(body.channel_override) ? (body.channel_override as string[]) : undefined;
  if (channelOverride && !isAdmin(deps, ctx.actor)) {
    return send(ctx.res, 403, { error: "channel_override requires herald:admin (§13.7)" });
  }
  const result = await deps.pipeline.notify({
    org_id: body.org_id,
    ...(typeof body.order_id === "string" ? { order_id: body.order_id } : {}),
    issued_by: ctx.actor,
    ...(typeof body.authorization_token_id === "string" ? { authorization_token_id: body.authorization_token_id } : {}),
    ...(typeof body.authorization_token === "string" ? { authorization_token: body.authorization_token } : {}),
    ...(channelOverride ? { channel_override: channelOverride } : {}),
    ...(severityParam(typeof body.severity_floor === "string" ? body.severity_floor : null)
      ? { severity_floor: severityParam(body.severity_floor as string)! }
      : {}),
    ...(severityParam(typeof body.severity === "string" ? body.severity : null)
      ? { severity: severityParam(body.severity as string)! }
      : {}),
    ...(typeof body.category === "string" ? { category: body.category as AlertEvent["category"] } : {}),
    payload: {
      title: payload.title,
      ...(typeof payload.body === "string" ? { body: payload.body } : {}),
      ...(typeof payload.context_url === "string" ? { context_url: payload.context_url } : {}),
    },
    ...(typeof body.requires_ack === "boolean" ? { requires_ack: body.requires_ack } : {}),
    ...(body.asset && typeof body.asset === "object" ? { asset: body.asset as AlertEvent["asset"] } : {}),
  });
  return send(ctx.res, result.status === "rejected" ? 403 : 202, result);
}

async function handleAckPost(deps: HttpApiDeps, ctx: Ctx): Promise<void> {
  const body = ctx.body as Record<string, unknown> | undefined;
  if (!body || typeof body !== "object") return badRequest(ctx.res, "JSON body required");
  let incidentId = typeof body.incident_id === "string" ? body.incident_id : undefined;
  let nonce = ulid();
  let by = typeof body.actor === "string" && body.actor !== "" ? body.actor : ctx.actor;
  const note = typeof body.note === "string" ? body.note : "";

  if (typeof body.token === "string") {
    const decoded = verifyAckToken(deps.config.ackSigningSecret, body.token);
    if (!decoded) return send(ctx.res, 403, { error: "invalid or expired ack callback token" });
    incidentId = decoded.incidentId;
    nonce = decoded.nonce;
    if (typeof body.actor !== "string") by = "channel-callback";
  }
  if (!incidentId && typeof body.alert_id === "string") {
    const alert = await deps.store.getAlert(body.alert_id);
    incidentId = alert?.incidentId;
    if (!incidentId) return send(ctx.res, 404, { error: "alert has no incident (or unknown alert_id)" });
  }
  if (!incidentId) return badRequest(ctx.res, "incident_id (or alert_id, or token) is required");

  const result = await deps.pipeline.ack({ incidentId, by, note, nonce });
  return send(ctx.res, result === "notfound" ? 404 : result === "nonce_used" ? 409 : 200, { status: result });
}

async function handleAckCallback(deps: HttpApiDeps, ctx: Ctx): Promise<void> {
  const token = ctx.url.searchParams.get("token") ?? "";
  const decoded = verifyAckToken(deps.config.ackSigningSecret, token);
  if (!decoded) return send(ctx.res, 403, { status: "invalid_or_expired_token" });
  const result = await deps.pipeline.ack({
    incidentId: decoded.incidentId,
    by: "channel-callback",
    note: "ack via channel callback link",
    nonce: decoded.nonce,
  });
  return send(ctx.res, result === "notfound" ? 404 : result === "nonce_used" ? 409 : 200, { status: result });
}

function parseRoutingPolicy(body: Record<string, unknown>, actor: string, existing?: RoutingPolicy): RoutingPolicy | string {
  const orgId = typeof body.org_id === "string" ? body.org_id : existing?.orgId;
  if (!orgId) return "org_id is required";
  const priority = typeof body.priority === "number" ? body.priority : existing?.priority;
  if (priority === undefined) return "priority is required";
  const targets = Array.isArray(body.targets) ? body.targets : existing?.targets;
  if (!targets || targets.length === 0) return "targets is required";
  for (const t of targets as { channel?: unknown; destination?: unknown }[]) {
    if (!(CHANNELS as readonly unknown[]).includes(t.channel)) return `invalid channel: ${String(t.channel)}`;
    if (typeof t.destination !== "string" || t.destination === "") return "every target needs a destination";
  }
  const match = (body.match ?? existing?.match ?? {}) as RoutingPolicy["match"];
  return {
    policyId: existing?.policyId ?? (typeof body.policy_id === "string" ? body.policy_id : newRoutingPolicyId()),
    orgId,
    priority,
    enabled: typeof body.enabled === "boolean" ? body.enabled : (existing?.enabled ?? true),
    match,
    targets: targets as RoutingPolicy["targets"],
    ...(typeof body.escalation_policy_id === "string"
      ? { escalationPolicyId: body.escalation_policy_id }
      : existing?.escalationPolicyId
        ? { escalationPolicyId: existing.escalationPolicyId }
        : {}),
    ...(typeof body.suppress_if_acknowledged_within === "number"
      ? { suppressIfAcknowledgedWithin: body.suppress_if_acknowledged_within }
      : {}),
    createdBy: existing?.createdBy ?? actor,
    createdAt: existing?.createdAt ?? new Date(),
  };
}

function parseEscalationPolicy(body: Record<string, unknown>, existing?: EscalationPolicy): EscalationPolicy | string {
  const orgId = typeof body.org_id === "string" ? body.org_id : existing?.orgId;
  if (!orgId) return "org_id is required";
  const steps = Array.isArray(body.steps) ? body.steps : existing?.steps;
  if (!steps || steps.length === 0) return "steps is required";
  for (const s of steps as { step?: unknown; wait_seconds?: unknown; targets?: unknown }[]) {
    if (typeof s.step !== "number" || typeof s.wait_seconds !== "number" || !Array.isArray(s.targets)) {
      return "every step needs {step, wait_seconds, targets[]}";
    }
  }
  return {
    policyId: existing?.policyId ?? (typeof body.policy_id === "string" ? body.policy_id : newEscalationPolicyId()),
    orgId,
    steps: steps as EscalationPolicy["steps"],
    repeatLastStepEverySeconds:
      typeof body.repeat_last_step_every_seconds === "number"
        ? body.repeat_last_step_every_seconds
        : (existing?.repeatLastStepEverySeconds ?? 0),
    maxRepeats: typeof body.max_repeats === "number" ? body.max_repeats : (existing?.maxRepeats ?? 0),
    stopOn: Array.isArray(body.stop_on) ? (body.stop_on as string[]) : (existing?.stopOn ?? ["ack", "resolved"]),
  };
}

function parseEgressEntries(body: unknown): EgressEntry[] | string {
  const entries = (body as { entries?: unknown })?.entries ?? body;
  if (!Array.isArray(entries)) return "entries array required";
  for (const e of entries as EgressEntry[]) {
    if (!(CHANNELS as readonly unknown[]).includes(e.channel)) return `invalid channel: ${String(e.channel)}`;
    if (typeof e.pattern !== "string" || e.pattern === "") return "every entry needs a pattern";
  }
  return entries as EgressEntry[];
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

export function createHttpServer(deps: HttpApiDeps): Server {
  const { store, pipeline, config, metrics } = deps;

  const routes: Array<{
    method: string;
    pattern: RegExp;
    keys: string[];
    admin?: boolean;
    handler: (ctx: Ctx) => Promise<void>;
  }> = [
    {
      method: "GET",
      pattern: /^\/healthz$/,
      keys: [],
      handler: async ({ res }) => send(res, 200, { status: "ok" }),
    },
    {
      method: "GET",
      pattern: /^\/readyz$/,
      keys: [],
      handler: async ({ res }) => {
        const { ready, checks } = await deps.readiness();
        send(res, ready ? 200 : 503, { ready, checks });
      },
    },
    { method: "POST", pattern: /^\/v1\/alerts$/, keys: [], handler: (ctx) => handleIngestAlert(deps, ctx) },
    { method: "POST", pattern: /^\/v1\/notify$/, keys: [], handler: (ctx) => handleNotify(deps, ctx) },
    {
      method: "GET",
      pattern: /^\/v1\/alerts$/,
      keys: [],
      handler: async ({ res, url }) => {
        const rows = await store.listAlerts({
          ...(url.searchParams.get("org_id") ? { orgId: url.searchParams.get("org_id")! } : {}),
          ...(url.searchParams.get("state") ? { state: url.searchParams.get("state") as never } : {}),
          ...(url.searchParams.get("severity_gte") ? { severityGte: url.searchParams.get("severity_gte")! } : {}),
          ...(url.searchParams.get("incident_id") ? { incidentId: url.searchParams.get("incident_id")! } : {}),
          ...(url.searchParams.get("cursor") ? { cursor: url.searchParams.get("cursor")! } : {}),
          ...(url.searchParams.get("limit") ? { limit: Number(url.searchParams.get("limit")) } : {}),
        });
        send(res, 200, { alerts: rows, next_cursor: rows.length > 0 ? rows[rows.length - 1]!.eventId : null });
      },
    },
    {
      method: "GET",
      pattern: /^\/v1\/alerts\/([^/]+)$/,
      keys: ["id"],
      handler: async ({ res, params }) => {
        const row = await store.getAlert(params.id!);
        return row ? send(res, 200, row) : send(res, 404, { error: "alert not found" });
      },
    },
    {
      method: "GET",
      pattern: /^\/v1\/incidents$/,
      keys: [],
      handler: async ({ res, url }) => {
        const rows = await store.listIncidents({
          ...(url.searchParams.get("org_id") ? { orgId: url.searchParams.get("org_id")! } : {}),
          ...(url.searchParams.get("state") ? { state: url.searchParams.get("state")! } : {}),
          ...(url.searchParams.get("severity_gte") ? { severityGte: url.searchParams.get("severity_gte")! } : {}),
          ...(url.searchParams.get("limit") ? { limit: Number(url.searchParams.get("limit")) } : {}),
        });
        send(res, 200, { incidents: rows });
      },
    },
    {
      method: "GET",
      pattern: /^\/v1\/incidents\/([^/]+)$/,
      keys: ["id"],
      handler: async ({ res, params }) => {
        const inc = await store.getIncident(params.id!);
        if (!inc) return send(res, 404, { error: "incident not found" });
        const alertIds = await store.incidentAlerts(inc.incidentId);
        send(res, 200, { ...inc, alert_ids: alertIds });
      },
    },
    {
      method: "POST",
      pattern: /^\/v1\/incidents\/([^/]+)\/resolve$/,
      keys: ["id"],
      handler: async ({ res, params, actor }) => {
        const inc = await store.getIncident(params.id!);
        if (!inc) return send(res, 404, { error: "incident not found" });
        await pipeline.resolve(inc.incidentId, actor);
        send(res, 200, { status: "resolved" });
      },
    },
    { method: "POST", pattern: /^\/v1\/acks$/, keys: [], handler: (ctx) => handleAckPost(deps, ctx) },
    { method: "GET", pattern: /^\/v1\/acks$/, keys: [], handler: (ctx) => handleAckCallback(deps, ctx) },
    {
      method: "GET",
      pattern: /^\/v1\/policies\/routing$/,
      keys: [],
      handler: async ({ res, url }) => {
        const orgId = url.searchParams.get("org_id") ?? "";
        send(res, 200, { policies: await store.routingPolicies(orgId) });
      },
    },
    {
      method: "POST",
      pattern: /^\/v1\/policies\/routing$/,
      keys: [],
      admin: true,
      handler: async ({ res, body, actor }) => {
        const parsed = parseRoutingPolicy(body as Record<string, unknown>, actor);
        if (typeof parsed === "string") return badRequest(res, parsed);
        await store.putRoutingPolicy(parsed);
        await store.appendAudit({
          orgId: parsed.orgId,
          actor: { kind: "commander", id: actor },
          action: "policy_create",
          entityIds: { policy_id: parsed.policyId },
          decisionDetail: { kind: "routing", priority: parsed.priority },
          requestHash: sha256JcsHex(body),
        });
        send(res, 201, parsed);
      },
    },
    {
      method: "PUT",
      pattern: /^\/v1\/policies\/routing\/([^/]+)$/,
      keys: ["id"],
      admin: true,
      handler: async ({ res, body, actor, params }) => {
        const existing = await store.getRoutingPolicy(params.id!);
        const parsed = parseRoutingPolicy(
          { ...(body as Record<string, unknown>), policy_id: params.id },
          actor,
          existing ?? undefined,
        );
        if (typeof parsed === "string") return badRequest(res, parsed);
        await store.putRoutingPolicy(parsed);
        await store.appendAudit({
          orgId: parsed.orgId,
          actor: { kind: "commander", id: actor },
          action: "policy_update",
          entityIds: { policy_id: parsed.policyId },
          decisionDetail: { kind: "routing", before: existing ?? null },
          requestHash: sha256JcsHex(body),
        });
        send(res, 200, parsed);
      },
    },
    {
      method: "DELETE",
      pattern: /^\/v1\/policies\/routing\/([^/]+)$/,
      keys: ["id"],
      admin: true,
      handler: async ({ res, actor, params }) => {
        const existing = await store.getRoutingPolicy(params.id!);
        if (!existing) return send(res, 404, { error: "policy not found" });
        await store.putRoutingPolicy({ ...existing, enabled: false });
        await store.appendAudit({
          orgId: existing.orgId,
          actor: { kind: "commander", id: actor },
          action: "policy_update",
          entityIds: { policy_id: existing.policyId },
          decisionDetail: { kind: "routing", disabled: true },
          requestHash: sha256JcsHex({ disabled: params.id }),
        });
        send(res, 200, { status: "disabled", policy_id: existing.policyId });
      },
    },
    {
      method: "GET",
      pattern: /^\/v1\/policies\/escalation$/,
      keys: [],
      handler: async ({ res, url }) => {
        const orgId = url.searchParams.get("org_id") ?? "";
        const id = url.searchParams.get("policy_id");
        if (id) {
          const p = await pipeline.escalationPolicyFor(orgId, id);
          return p ? send(res, 200, p) : send(res, 404, { error: "policy not found" });
        }
        badRequest(res, "policy_id query param required (list-all is not part of §5.10)");
      },
    },
    {
      method: "POST",
      pattern: /^\/v1\/policies\/escalation$/,
      keys: [],
      admin: true,
      handler: async ({ res, body, actor }) => {
        const parsed = parseEscalationPolicy(body as Record<string, unknown>);
        if (typeof parsed === "string") return badRequest(res, parsed);
        await store.putEscalationPolicy(parsed);
        await store.appendAudit({
          orgId: parsed.orgId,
          actor: { kind: "commander", id: actor },
          action: "policy_create",
          entityIds: { policy_id: parsed.policyId },
          decisionDetail: { kind: "escalation", steps: parsed.steps.length },
          requestHash: sha256JcsHex(body),
        });
        send(res, 201, parsed);
      },
    },
    {
      method: "PUT",
      pattern: /^\/v1\/policies\/escalation\/([^/]+)$/,
      keys: ["id"],
      admin: true,
      handler: async ({ res, body, actor, params }) => {
        const orgId = (body as Record<string, unknown>).org_id;
        const existing =
          typeof orgId === "string" ? await store.escalationPolicy(orgId, params.id!) : null;
        const parsed = parseEscalationPolicy(
          { ...(body as Record<string, unknown>), policy_id: params.id },
          existing ?? undefined,
        );
        if (typeof parsed === "string") return badRequest(res, parsed);
        await store.putEscalationPolicy(parsed);
        await store.appendAudit({
          orgId: parsed.orgId,
          actor: { kind: "commander", id: actor },
          action: "policy_update",
          entityIds: { policy_id: parsed.policyId },
          decisionDetail: { kind: "escalation", before: existing ?? null },
          requestHash: sha256JcsHex(body),
        });
        send(res, 200, parsed);
      },
    },
    {
      method: "GET",
      pattern: /^\/v1\/egress\/([^/]+)$/,
      keys: ["org"],
      handler: async ({ res, params }) => {
        const entries = await pipeline.egressFor(params.org!);
        send(res, 200, { org_id: params.org, entries: entries ?? [] });
      },
    },
    {
      method: "PUT",
      pattern: /^\/v1\/egress\/([^/]+)$/,
      keys: ["org"],
      admin: true,
      handler: async ({ res, body, actor, params }) => {
        const entries = parseEgressEntries(body);
        if (typeof entries === "string") return badRequest(res, entries);
        const before = await store.egressPolicy(params.org!);
        await store.putEgressPolicy(params.org!, entries, actor);
        await store.appendAudit({
          orgId: params.org!,
          actor: { kind: "commander", id: actor },
          action: "egress_update",
          entityIds: { org_id: params.org! },
          decisionDetail: { before: before ?? null, after_count: entries.length },
          requestHash: sha256JcsHex(body),
        });
        send(res, 200, { org_id: params.org, entries });
      },
    },
    {
      method: "POST",
      pattern: /^\/v1\/routes\/test$/,
      keys: [],
      handler: async ({ res, body }) => {
        if (!deps.validators.alertEvent(body)) {
          return badRequest(res, "invalid AlertEvent v1", validationErrors(deps.validators.alertEvent));
        }
        send(res, 200, await pipeline.testRoute(body));
      },
    },
    {
      method: "GET",
      pattern: /^\/v1\/deliveries$/,
      keys: [],
      handler: async ({ res, url }) => {
        const rows = await store.listDeliveries({
          ...(url.searchParams.get("org_id") ? { orgId: url.searchParams.get("org_id")! } : {}),
          ...(url.searchParams.get("incident_id") ? { incidentId: url.searchParams.get("incident_id")! } : {}),
          ...(url.searchParams.get("alert_id") ? { alertId: url.searchParams.get("alert_id")! } : {}),
          ...(url.searchParams.get("channel") ? { channel: url.searchParams.get("channel") as Channel } : {}),
          ...(url.searchParams.get("status") ? { status: url.searchParams.get("status") as never } : {}),
          ...(url.searchParams.get("limit") ? { limit: Number(url.searchParams.get("limit")) } : {}),
        });
        send(res, 200, { deliveries: rows });
      },
    },
    {
      method: "GET",
      pattern: /^\/v1\/status$/,
      keys: [],
      handler: async ({ res }) => {
        const counts = await store.deliveryStatusCounts();
        send(res, 200, {
          queue_depth: (counts.pending ?? 0) + (counts.failed ?? 0),
          dlq_size: counts.dlq ?? 0,
          deliveries: counts,
          delivery_mode: config.deliveryMode,
          time: new Date().toISOString(),
        });
      },
    },
    {
      method: "GET",
      pattern: /^\/v1\/metrics$/,
      keys: [],
      handler: async ({ res }) => {
        const counts = await store.deliveryStatusCounts();
        send(res, 200, metrics.render({
          "herald_queue_depth": (counts.pending ?? 0) + (counts.failed ?? 0),
          "herald_dlq_size": counts.dlq ?? 0,
        }), { "content-type": "text/plain; version=0.0.4" });
      },
    },
  ];

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://herald");
      const actor = actorOf(req);
      for (const route of routes) {
        if (route.method !== req.method) continue;
        const m = route.pattern.exec(url.pathname);
        if (!m) continue;
        if (route.admin && !isAdmin(deps, actor)) {
          return send(res, 403, { error: "herald:admin required (§13.7)", actor });
        }
        let body: unknown;
        if (req.method === "POST" || req.method === "PUT") {
          try {
            body = await readBody(req);
          } catch (err) {
            if (err instanceof BodyTooLargeError) return send(res, 413, { error: "payload too large" });
            return badRequest(res, "body is not valid JSON");
          }
        }
        const params: Record<string, string> = {};
        route.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1]!)));
        return await route.handler({ req, res, url, actor, body, params });
      }
      send(res, 404, { error: "not found" });
    } catch (err) {
      console.error(`herald: http error: ${(err as Error).stack ?? err}`);
      if (!res.headersSent) send(res, 500, { error: "internal error" });
    }
  });
}
