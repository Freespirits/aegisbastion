// src/errors.ts
var PepError = class extends Error {
  code;
  /** Structured detail for audit payloads — never contains raw target lists. */
  detail;
  constructor(code, message, detail = {}) {
    super(message);
    this.name = "PepError";
    this.code = code;
    this.detail = detail;
  }
};
function isPepError(err) {
  return err instanceof PepError;
}

// src/envelope.ts
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { anyPack, timestampNow } from "@bufbuild/protobuf/wkt";

// ../../gen/ts/aegisbastion/platform/v1/bus_pb.ts
import { fileDesc as fileDesc2, messageDesc as messageDesc2 } from "@bufbuild/protobuf/codegenv2";
import { file_google_protobuf_any, file_google_protobuf_timestamp } from "@bufbuild/protobuf/wkt";

// ../../gen/ts/aegisbastion/platform/v1/types_pb.ts
import { enumDesc, fileDesc, messageDesc } from "@bufbuild/protobuf/codegenv2";
var file_aegisbastion_platform_v1_types = /* @__PURE__ */ fileDesc("CiRhZWdpc2Jhc3Rpb24vcGxhdGZvcm0vdjEvdHlwZXMucHJvdG8SGGFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MSJICghSYXRlQ2FwcxIaChJtYXhfcnBzX3Blcl90YXJnZXQYASABKA0SIAoYbWF4X2NvbmN1cnJlbnRfaW50cnVzaXZlGAIgASgNIjcKDFRyYWNlQ29udGV4dBITCgt0cmFjZXBhcmVudBgBIAEoCRISCgp0cmFjZXN0YXRlGAIgASgJKnMKCVJpc2tDbGFzcxIaChZSSVNLX0NMQVNTX1VOU1BFQ0lGSUVEEAASEQoNUklTS19DTEFTU19SMBABEhEKDVJJU0tfQ0xBU1NfUjEQAhIRCg1SSVNLX0NMQVNTX1IyEAMSEQoNUklTS19DTEFTU19SMxAEKqEBCghQcmlvcml0eRIYChRQUklPUklUWV9VTlNQRUNJRklFRBAAEhQKEFBSSU9SSVRZX1AwX0tJTEwQARIYChRQUklPUklUWV9QMV9PUEVSQVRPUhACEhYKElBSSU9SSVRZX1AyX0NIQU5HRRADEhcKE1BSSU9SSVRZX1AzX1BMQU5ORUQQBBIaChZQUklPUklUWV9QNF9CQUNLR1JPVU5EEAUqUgoJQ29tbWFuZGVyEhkKFUNPTU1BTkRFUl9VTlNQRUNJRklFRBAAEhEKDUNPTU1BTkRFUl9DQUkQARIXChNDT01NQU5ERVJfSEVYU1RSSUtFEAJCUVpPZ2l0aHViLmNvbS9hZWdpc2Jhc3Rpb24vYWVnaXNiYXN0aW9uL2dlbi9nby9hZWdpc2Jhc3Rpb24vcGxhdGZvcm0vdjE7cGxhdGZvcm12MWIGcHJvdG8z");
var RateCapsSchema = /* @__PURE__ */ messageDesc(file_aegisbastion_platform_v1_types, 0);
var TraceContextSchema = /* @__PURE__ */ messageDesc(file_aegisbastion_platform_v1_types, 1);
var RiskClass = /* @__PURE__ */ ((RiskClass2) => {
  RiskClass2[RiskClass2["UNSPECIFIED"] = 0] = "UNSPECIFIED";
  RiskClass2[RiskClass2["R0"] = 1] = "R0";
  RiskClass2[RiskClass2["R1"] = 2] = "R1";
  RiskClass2[RiskClass2["R2"] = 3] = "R2";
  RiskClass2[RiskClass2["R3"] = 4] = "R3";
  return RiskClass2;
})(RiskClass || {});

// ../../gen/ts/aegisbastion/platform/v1/bus_pb.ts
var file_aegisbastion_platform_v1_bus = /* @__PURE__ */ fileDesc2("CiJhZWdpc2Jhc3Rpb24vcGxhdGZvcm0vdjEvYnVzLnByb3RvEhhhZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEizAEKCEVudmVsb3BlEhAKCGV2ZW50X2lkGAEgASgJEgwKBHR5cGUYAiABKAkSJgoCdHMYAyABKAsyGi5nb29nbGUucHJvdG9idWYuVGltZXN0YW1wEhIKCm1pc3Npb25faWQYBCABKAkSPQoNdHJhY2VfY29udGV4dBgFIAEoCzImLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5UcmFjZUNvbnRleHQSJQoHcGF5bG9hZBgGIAEoCzIULmdvb2dsZS5wcm90b2J1Zi5BbnlCUVpPZ2l0aHViLmNvbS9hZWdpc2Jhc3Rpb24vYWVnaXNiYXN0aW9uL2dlbi9nby9hZWdpc2Jhc3Rpb24vcGxhdGZvcm0vdjE7cGxhdGZvcm12MWIGcHJvdG8z", [file_google_protobuf_any, file_google_protobuf_timestamp, file_aegisbastion_platform_v1_types]);
var EnvelopeSchema = /* @__PURE__ */ messageDesc2(file_aegisbastion_platform_v1_bus, 0);

// src/ulid.ts
var ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
var lastTime = -1;
var lastRandom = new Uint8Array(10);
function randomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}
function encodeTime(now, length) {
  let str = "";
  for (let i = length - 1; i >= 0; i--) {
    str = ENCODING[now % 32] + str;
    now = Math.floor(now / 32);
  }
  return str;
}
function encodeRandom(bytes) {
  let str = "";
  let bitBuffer = 0;
  let bitCount = 0;
  for (const byte of bytes) {
    bitBuffer = bitBuffer << 8 | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      str += ENCODING[bitBuffer >> bitCount & 31];
    }
  }
  if (bitCount > 0) {
    str += ENCODING[bitBuffer << 5 - bitCount & 31];
  }
  return str;
}
function incrementRandom(bytes) {
  const next = new Uint8Array(bytes);
  for (let i = next.length - 1; i >= 0; i--) {
    if (next[i] === 255) {
      next[i] = 0;
    } else {
      next[i]++;
      return next;
    }
  }
  return randomBytes(bytes.length);
}
function ulid(now = Date.now()) {
  if (now === lastTime) {
    lastRandom = incrementRandom(lastRandom);
  } else {
    lastTime = now;
    lastRandom = randomBytes(10);
  }
  return encodeTime(now, 10) + encodeRandom(lastRandom);
}

// src/envelope.ts
function newEnvelope(payloadSchema, payload, opts = {}) {
  const trace = opts.traceContext ? create(TraceContextSchema, {
    traceparent: opts.traceContext.traceparent,
    tracestate: opts.traceContext.tracestate ?? ""
  }) : void 0;
  return create(EnvelopeSchema, {
    eventId: ulid(),
    type: payloadSchema.typeName,
    ts: timestampNow(),
    missionId: opts.missionId ?? "",
    ...trace ? { traceContext: trace } : {},
    payload: anyPack(payloadSchema, payload)
  });
}
function encodeEnvelope(envelope) {
  return toBinary(EnvelopeSchema, envelope);
}
function decodeEnvelope(bytes) {
  return fromBinary(EnvelopeSchema, bytes);
}
var IdempotencySet = class {
  constructor(capacity = 1e4) {
    this.capacity = capacity;
  }
  capacity;
  seen = /* @__PURE__ */ new Set();
  /** Returns true the first time a key is observed, false on duplicates. */
  firstSeen(key) {
    if (!key) return true;
    if (this.seen.has(key)) return false;
    if (this.seen.size >= this.capacity) {
      const oldest = this.seen.values().next().value;
      if (oldest !== void 0) this.seen.delete(oldest);
    }
    this.seen.add(key);
    return true;
  }
  get size() {
    return this.seen.size;
  }
};

// src/subjects.ts
var SUBJECTS = {
  /** Orchestrator → specific agent (WorkQueue, ack-required). */
  taskAssign: (agentId) => `task.assign.${agentId}`,
  /** agents → Orchestrator (durable, at-least-once, idempotent on task_id). */
  taskResult: "task.result",
  /** agents → Registry (ephemeral, 10 s cadence). */
  agentHeartbeat: "agent.heartbeat",
  /** Orchestrator → commanders, UI (durable). */
  missionEvents: "mission.events",
  /** Monitor agent → commanders (durable). */
  monitorChanges: "monitor.changes",
  /** Monitor new-asset candidates (doc 03 §5). */
  monitorAssetsNew: "monitor.assets.new",
  /** Monitor alerts in AlertEvent v1 form (doc 03 §5.3 mapping). */
  monitorAlert: "monitor.alert",
  /** Detect findings, full stream (doc 04 §4.3). */
  detectFindings: "detect.findings",
  /** Detect alerts in AlertEvent v1 form (Ruling C8 mapping). */
  detectAlert: "detect.alert",
  /** Orchestrator → all agents. CORE NATS broadcast only — no JetStream. */
  controlKill: "control.kill",
  /** all services → Audit Service (durable, never sampled). */
  auditEvents: "audit.events",
  /** Alert agent ↔ notifier integrations (durable). */
  alertOutbound: "alert.outbound",
  // Gatekeeper bus contracts (doc 11 §9 item 9).
  authzDecisions: "authz.decisions.v1",
  authzDenials: "authz.denials.v1",
  roeEvents: "roe.events.v1",
  /** Revocation broadcast consumed by every PEP (kill ≤ 5 s SLA). */
  tasksRevocations: "tasks.revocations.v1",
  authzApprovals: "authz.approvals.v1",
  auditAnomalies: "audit.anomalies.v1",
  /** Phish-Catcher intel feed bundles (doc 01 §9.2). */
  intelFeedsPhishing: "intel.feeds.phishing"
};

// src/jcs.ts
import { createHash } from "crypto";
import canonicalize from "canonicalize";
function jcs(value) {
  const out = canonicalize(value);
  if (out === void 0) {
    throw new Error("value is not JCS-serializable");
  }
  return out;
}
function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}
function sha256JcsHex(value) {
  return sha256Hex(jcs(value));
}
function scopeHashCheckpoint(manifestSha256) {
  return `scope:sha256:${manifestSha256.toLowerCase()}`;
}
function auditChainHash(eventWithoutHash, prevHash) {
  return `sha256:${sha256Hex(prevHash + jcs(eventWithoutHash))}`;
}

// src/token.ts
import { errors as joseErrors, jwtVerify } from "jose";
var TOKEN_ISSUER = "gatekeeper.platform";
var TOKEN_AUDIENCE = "aegisbastion.modules";
var MAX_TOKEN_TTL_SECONDS = 900;
var CLOCK_LEEWAY_SECONDS = 60;
var MAX_CLOCK_SKEW_SECONDS = 120;
var SCOPE_BOUND_CAPABILITIES = /* @__PURE__ */ new Set(["monitor.watch", "monitor.rescan"]);
function isRecord(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function failClaims(message, detail = {}) {
  throw new PepError("TOKEN_MALFORMED", message, detail);
}
function parseScopeTokenClaims(payload, nowSeconds) {
  if (!isRecord(payload)) failClaims("payload is not an object");
  if (payload.iss !== TOKEN_ISSUER) {
    throw new PepError("TOKEN_ISSUER_INVALID", `unexpected iss: ${String(payload.iss)}`);
  }
  if (payload.aud !== TOKEN_AUDIENCE) {
    throw new PepError("TOKEN_AUDIENCE_INVALID", `unexpected aud: ${String(payload.aud)}`);
  }
  for (const field of ["jti", "sub", "task_id", "roe_id"]) {
    if (typeof payload[field] !== "string" || payload[field] === "") {
      failClaims(`missing or invalid claim: ${field}`);
    }
  }
  if (typeof payload.roe_version !== "number" || !Number.isInteger(payload.roe_version) || payload.roe_version < 1) {
    failClaims("missing or invalid claim: roe_version");
  }
  if (payload.risk_class !== "R1" && payload.risk_class !== "R2" && payload.risk_class !== "R3") {
    throw new PepError("TOKEN_RISK_CLASS_INVALID", `unexpected risk_class: ${String(payload.risk_class)}`);
  }
  if (!Array.isArray(payload.capabilities) || payload.capabilities.length === 0 || !payload.capabilities.every((c) => typeof c === "string" && c !== "")) {
    failClaims("missing or invalid claim: capabilities");
  }
  if (!isRecord(payload.targets)) failClaims("missing or invalid claim: targets");
  const targets = payload.targets;
  if (targets.hash_alg !== "sha256") failClaims("targets.hash_alg must be sha256");
  if (typeof targets.manifest_uri !== "string" || targets.manifest_uri === "") {
    failClaims("missing or invalid claim: targets.manifest_uri");
  }
  if (typeof targets.manifest_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(targets.manifest_sha256)) {
    failClaims("missing or invalid claim: targets.manifest_sha256 (expected 64 lowercase hex chars)");
  }
  if (targets.count !== void 0 && (typeof targets.count !== "number" || targets.count < 0)) {
    failClaims("invalid claim: targets.count");
  }
  if (typeof payload.iat !== "number" || typeof payload.exp !== "number") {
    failClaims("missing or invalid claims: iat/exp");
  }
  if (payload.exp - payload.iat > MAX_TOKEN_TTL_SECONDS) {
    throw new PepError("TOKEN_TTL_EXCEEDED", `token TTL ${payload.exp - payload.iat}s exceeds ${MAX_TOKEN_TTL_SECONDS}s`, {
      ttl: payload.exp - payload.iat
    });
  }
  if (payload.iat > nowSeconds + MAX_CLOCK_SKEW_SECONDS) {
    throw new PepError("TOKEN_NOT_YET_VALID", "iat is more than 120s in the future (clock skew or tamper)", {
      iat: payload.iat
    });
  }
  if (payload.scope_bound !== void 0 && typeof payload.scope_bound !== "boolean") {
    failClaims("invalid claim: scope_bound");
  }
  if (payload.scope_bound === true) {
    const capabilities = payload.capabilities;
    if (payload.risk_class !== "R1" || !capabilities.every((c) => SCOPE_BOUND_CAPABILITIES.has(c))) {
      throw new PepError(
        "TOKEN_SCOPE_BOUND_MISUSE",
        "scope_bound tokens are valid only for R1 monitor.watch / monitor.rescan",
        { risk_class: payload.risk_class, capabilities }
      );
    }
  }
  if (payload.rate_caps !== void 0) {
    if (!isRecord(payload.rate_caps)) failClaims("invalid claim: rate_caps");
    for (const k of ["max_rps", "max_concurrent"]) {
      const v = payload.rate_caps[k];
      if (v !== void 0 && (typeof v !== "number" || v < 0)) failClaims(`invalid claim: rate_caps.${k}`);
    }
  }
  if (payload.approval_id !== void 0 && typeof payload.approval_id !== "string") {
    failClaims("invalid claim: approval_id");
  }
  return payload;
}
async function verifyScopeToken(token, opts) {
  if (!token) {
    throw new PepError("TOKEN_MISSING", "no Scope Token presented");
  }
  const nowSeconds = opts.nowSeconds ?? Math.floor(Date.now() / 1e3);
  let payload;
  try {
    const result = await jwtVerify(token, opts.getKey, {
      algorithms: ["EdDSA"],
      issuer: TOKEN_ISSUER,
      audience: TOKEN_AUDIENCE,
      clockTolerance: CLOCK_LEEWAY_SECONDS,
      ...opts.nowSeconds !== void 0 ? { currentDate: new Date(opts.nowSeconds * 1e3) } : {}
    });
    payload = result.payload;
  } catch (err) {
    if (err instanceof joseErrors.JWTExpired) {
      throw new PepError("TOKEN_EXPIRED", "Scope Token expired", { jti: void 0 });
    }
    if (err instanceof joseErrors.JWTClaimValidationFailed) {
      const claim = err.claim;
      if (claim === "aud") throw new PepError("TOKEN_AUDIENCE_INVALID", "audience mismatch");
      if (claim === "iss") throw new PepError("TOKEN_ISSUER_INVALID", "issuer mismatch");
      if (claim === "nbf") throw new PepError("TOKEN_NOT_YET_VALID", "token not yet valid (nbf)");
      throw new PepError("TOKEN_MALFORMED", `claim validation failed: ${String(claim)}`);
    }
    if (err instanceof joseErrors.JWSSignatureVerificationFailed || err instanceof joseErrors.JOSEAlgNotAllowed) {
      throw new PepError("TOKEN_SIGNATURE_INVALID", "Scope Token signature verification failed");
    }
    if (err instanceof joseErrors.JWKSNoMatchingKey) {
      throw new PepError("JWKS_UNAVAILABLE", "no JWKS key matches the token kid");
    }
    throw new PepError("TOKEN_MALFORMED", `token verification failed: ${err.message}`);
  }
  const claims = parseScopeTokenClaims(payload, nowSeconds);
  if (opts.expectedTaskId !== void 0 && claims.task_id !== opts.expectedTaskId) {
    throw new PepError("TOKEN_TASK_MISMATCH", "token is bound to a different task_id", {
      expected: opts.expectedTaskId
    });
  }
  return claims;
}

// src/jwks.ts
import { createLocalJWKSet } from "jose";
var JwksCache = class {
  constructor(opts) {
    this.opts = opts;
  }
  opts;
  keys = [];
  localSet = null;
  refreshTimer = null;
  refreshing = null;
  /** Initial load. Throws JWKS_UNAVAILABLE when gatekeeper cannot be reached. */
  async start() {
    await this.refresh();
    const interval = this.opts.refreshIntervalMs ?? 5 * 60 * 1e3;
    this.refreshTimer = setInterval(() => {
      this.refresh().catch(() => {
      });
    }, interval);
    this.refreshTimer.unref?.();
  }
  stop() {
    if (this.refreshTimer !== null) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }
  async refresh() {
    this.refreshing ??= this.doRefresh().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }
  async doRefresh() {
    let keys;
    try {
      keys = await this.opts.fetchKeys();
    } catch (err) {
      throw new PepError("JWKS_UNAVAILABLE", `failed to fetch JWKS: ${err.message}`);
    }
    const active = keys.filter((k) => k.kty === "OKP" && k.crv === "Ed25519" && k.kid !== "");
    if (active.length === 0) {
      throw new PepError("JWKS_UNAVAILABLE", "JWKS contains no active Ed25519 keys");
    }
    const jwks = {
      keys: active.map((k) => ({
        kty: k.kty,
        crv: k.crv,
        kid: k.kid,
        alg: k.alg || "EdDSA",
        use: k.use || "sig",
        x: k.x
      }))
    };
    this.keys = active;
    this.localSet = createLocalJWKSet(jwks);
  }
  /** Currently cached key ids (diagnostics / audit). */
  cachedKids() {
    return this.keys.map((k) => k.kid);
  }
  /**
   * jose-compatible key resolver. On an unknown kid (key rotation in
   * progress), refreshes the JWKS once and retries; still no match → the
   * caller's jwtVerify fails closed with JWKS_UNAVAILABLE.
   */
  getKey = async (protectedHeader, token) => {
    if (this.localSet !== null) {
      try {
        return await this.localSet(protectedHeader, token);
      } catch {
      }
    }
    await this.refresh();
    if (this.localSet === null) {
      throw new PepError("JWKS_UNAVAILABLE", "JWKS cache is empty");
    }
    return this.localSet(protectedHeader, token);
  };
};

// src/scope.ts
function parseIpv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  let v = 0;
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i]);
    if (octet > 255 || m[i].length > 1 && m[i].startsWith("0")) return null;
    v = v * 256 + octet;
  }
  return v >>> 0;
}
function parseIpv6(s) {
  let input = s.toLowerCase();
  if (input.startsWith("[") && input.endsWith("]")) input = input.slice(1, -1);
  if (!/^[0-9a-f:.]+$/.test(input)) return null;
  let ipv4Tail = null;
  const lastColon = input.lastIndexOf(":");
  if (lastColon >= 0) {
    const tail = input.slice(lastColon + 1);
    if (tail.includes(".")) {
      const v4 = parseIpv4(tail);
      if (v4 === null) return null;
      ipv4Tail = [v4 >>> 24 & 255, v4 >>> 16 & 255, v4 >>> 8 & 255, v4 & 255];
      input = lastColon > 0 && input[lastColon - 1] === ":" ? input.slice(0, lastColon + 1) : input.slice(0, lastColon);
    }
  }
  const halves = input.split("::");
  if (halves.length > 2) return null;
  const groups = [];
  const parseHalf = (half) => {
    if (half === "") return [];
    const parts = half.split(":");
    const out = [];
    for (const p of parts) {
      if (!/^[0-9a-f]{1,4}$/.test(p)) return null;
      out.push(parseInt(p, 16));
    }
    return out;
  };
  const left = parseHalf(halves[0] ?? "");
  const right = halves.length === 2 ? parseHalf(halves[1] ?? "") : [];
  if (left === null || right === null) return null;
  const tailGroups = ipv4Tail ? 2 : 0;
  if (halves.length === 2) {
    const missing = 8 - left.length - right.length - tailGroups;
    if (missing < 0) return null;
    groups.push(...left, ...new Array(missing).fill(0), ...right);
  } else {
    if (left.length + tailGroups !== 8) return null;
    groups.push(...left);
  }
  if (ipv4Tail) {
    groups.push(ipv4Tail[0] << 8 | ipv4Tail[1], ipv4Tail[2] << 8 | ipv4Tail[3]);
  }
  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = groups[i] >>> 8 & 255;
    bytes[i * 2 + 1] = groups[i] & 255;
  }
  return bytes;
}
function parseCidr(s) {
  const slash = s.indexOf("/");
  if (slash < 0) return null;
  const addr = s.slice(0, slash);
  const bitsStr = s.slice(slash + 1);
  if (!/^\d{1,3}$/.test(bitsStr)) return null;
  const bits = Number(bitsStr);
  const v4 = parseIpv4(addr);
  if (v4 !== null) {
    if (bits > 32) return null;
    return { family: 4, base: v4, bits };
  }
  const v6 = parseIpv6(addr);
  if (v6 !== null) {
    if (bits > 128) return null;
    return { family: 6, base: v6, bits };
  }
  return null;
}
function ipv4InCidr(ip, cidr) {
  if (cidr.bits === 0) return true;
  const mask = ~0 << 32 - cidr.bits >>> 0;
  return (ip & mask) === (cidr.base & mask);
}
function ipv6InCidr(ip, cidr) {
  for (let i = 0; i < 16; i++) {
    const remaining = cidr.bits - i * 8;
    if (remaining <= 0) return true;
    if (remaining >= 8) {
      if (ip[i] !== cidr.base[i]) return false;
    } else {
      const mask = 255 << 8 - remaining & 255;
      if ((ip[i] & mask) !== (cidr.base[i] & mask)) return false;
      return true;
    }
  }
  return true;
}
var DEFAULT_PORTS = { "http:": "80", "https:": "443" };
function canonicalizeTarget(raw) {
  const input = raw.trim().toLowerCase();
  if (input === "") {
    throw new PepError("TARGET_NOT_IN_SCOPE", "empty target string");
  }
  const v4 = parseIpv4(input);
  if (v4 !== null) return { kind: "ipv4", ip: v4, canonical: input };
  if (input.startsWith("[") || /^[0-9a-f:]*:[0-9a-f:.]*$/.test(input)) {
    const v6 = parseIpv6(input);
    if (v6 !== null) return { kind: "ipv6", ip: v6, canonical: input };
  }
  if (input.includes("://")) {
    let url;
    try {
      url = new URL(input);
    } catch {
      throw new PepError("TARGET_NOT_IN_SCOPE", `unparseable URL target: ${raw}`);
    }
    const host = url.hostname.replace(/\.$/, "");
    const port = url.port === DEFAULT_PORTS[url.protocol] ? "" : url.port;
    const portSuffix = port ? `:${port}` : "";
    const path = url.pathname === "/" ? "" : url.pathname;
    const canonical = `${url.protocol}//${host}${portSuffix}${path}${url.search}`;
    return {
      kind: "url",
      host,
      canonical,
      urlPrefix: `${url.protocol}//${host}${portSuffix}${path}`,
      hostPath: `${host}${portSuffix}${path}`
    };
  }
  const slash = input.indexOf("/");
  const hostPart = (slash >= 0 ? input.slice(0, slash) : input).replace(/\.$/, "");
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(hostPart)) {
    throw new PepError("TARGET_NOT_IN_SCOPE", `unparseable target: ${raw}`);
  }
  if (slash >= 0) {
    return { kind: "url", host: hostPart, canonical: input, urlPrefix: input, hostPath: input };
  }
  return { kind: "host", host: hostPart, canonical: hostPart };
}
function hostMatchesDomain(host, domainEntry) {
  const entry = domainEntry.trim().toLowerCase().replace(/\.$/, "");
  if (entry.startsWith("*.")) {
    const suffix = entry.slice(1);
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return host === entry;
}
function ruleMatchesTarget(ruleRaw, target) {
  const rule = ruleRaw.trim().toLowerCase();
  if (rule === "") return false;
  const cidr = parseCidr(rule);
  if (cidr !== null) {
    if (target.kind === "ipv4" && cidr.family === 4) return ipv4InCidr(target.ip, cidr);
    if (target.kind === "ipv6" && cidr.family === 6) return ipv6InCidr(target.ip, cidr);
    return false;
  }
  const v4 = parseIpv4(rule);
  if (v4 !== null) return target.kind === "ipv4" && target.ip === v4;
  if (rule.startsWith("[") || /^[0-9a-f:]*:[0-9a-f:.]*$/.test(rule)) {
    const v6 = parseIpv6(rule);
    if (v6 !== null && target.kind === "ipv6") {
      if (target.ip.length !== v6.length) return false;
      return target.ip.every((b, i) => b === v6[i]);
    }
  }
  if (rule.includes("/")) {
    if (target.kind !== "url") return false;
    const targetForm = rule.includes("://") ? target.urlPrefix : target.hostPath;
    let prefix;
    try {
      const ct = canonicalizeTarget(rule);
      prefix = ct.kind === "url" ? rule.includes("://") ? ct.urlPrefix : ct.hostPath : ct.canonical;
    } catch {
      return false;
    }
    return targetForm === prefix || targetForm.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`);
  }
  const host = rule.replace(/\.$/, "");
  if (host.startsWith("*.")) {
    if (target.kind === "host" || target.kind === "url") return hostMatchesDomain(target.host, host);
    return false;
  }
  if (target.kind === "host" || target.kind === "url") return target.host === host;
  return false;
}
function evaluateTargetInScope(rawTarget, scope) {
  const target = canonicalizeTarget(rawTarget);
  for (const exclusion of scope.explicit_excludes) {
    if (ruleMatchesTarget(exclusion, target)) {
      return { allow: false, code: "TARGET_EXCLUDED", matchedRule: exclusion };
    }
  }
  for (const domain of scope.domains) {
    if ((target.kind === "host" || target.kind === "url") && hostMatchesDomain(target.host, domain)) {
      return { allow: true, matchedBy: domain };
    }
    if (domain.includes("/") && ruleMatchesTarget(domain, target)) {
      return { allow: true, matchedBy: domain };
    }
  }
  for (const cidrRaw of scope.cidrs) {
    const cidr = parseCidr(cidrRaw.trim().toLowerCase());
    if (cidr === null) continue;
    if (target.kind === "ipv4" && cidr.family === 4 && ipv4InCidr(target.ip, cidr)) {
      return { allow: true, matchedBy: cidrRaw };
    }
    if (target.kind === "ipv6" && cidr.family === 6 && ipv6InCidr(target.ip, cidr)) {
      return { allow: true, matchedBy: cidrRaw };
    }
  }
  return { allow: false, code: "TARGET_NOT_IN_SCOPE" };
}
function isTargetInManifest(rawTarget, manifestTargets) {
  let target;
  try {
    target = canonicalizeTarget(rawTarget);
  } catch {
    return false;
  }
  for (const entry of manifestTargets) {
    try {
      if (canonicalizeTarget(entry).canonical === target.canonical) return true;
    } catch {
    }
  }
  return false;
}

// src/manifest.ts
import { createHash as createHash2 } from "crypto";
function parseManifestUri(uri) {
  const m = /^blob:\/\/([^/]+)\/(.+)$/.exec(uri);
  if (!m) {
    throw new PepError("MANIFEST_MALFORMED", `unparseable manifest_uri: ${uri}`);
  }
  return { bucket: m[1], key: m[2] };
}
function createS3ManifestFetcher(opts) {
  let clientPromise = null;
  const getClient = async () => {
    clientPromise ??= import("@aws-sdk/client-s3").then(
      ({ S3Client }) => new S3Client({
        endpoint: opts.endpoint,
        region: opts.region ?? "us-east-1",
        forcePathStyle: true,
        credentials: { accessKeyId: opts.accessKeyId, secretAccessKey: opts.secretAccessKey }
      })
    );
    return clientPromise;
  };
  return {
    async fetch(manifestUri) {
      const { bucket, key } = parseManifestUri(manifestUri);
      const client = await getClient();
      const { GetObjectCommand } = await import("@aws-sdk/client-s3");
      let res;
      try {
        res = await client.send(
          new GetObjectCommand({ Bucket: opts.bucketOverride ?? bucket, Key: key })
        );
      } catch (err) {
        throw new PepError(
          "MANIFEST_FETCH_FAILED",
          `manifest fetch failed for ${manifestUri}: ${err.message}`
        );
      }
      if (!res.Body?.transformToByteArray) {
        throw new PepError("MANIFEST_FETCH_FAILED", `empty manifest body for ${manifestUri}`);
      }
      return res.Body.transformToByteArray();
    }
  };
}
async function fetchAndVerifyManifest(ref, scopeBound, fetcher) {
  if (ref.hash_alg !== "sha256") {
    throw new PepError("MANIFEST_MALFORMED", `unsupported manifest hash_alg: ${ref.hash_alg}`);
  }
  let bytes;
  try {
    bytes = await fetcher.fetch(ref.manifest_uri);
  } catch (err) {
    if (err instanceof PepError) throw err;
    throw new PepError("MANIFEST_FETCH_FAILED", `manifest fetch failed: ${err.message}`);
  }
  const actual = createHash2("sha256").update(bytes).digest("hex");
  if (actual !== ref.manifest_sha256.toLowerCase()) {
    throw new PepError("MANIFEST_HASH_MISMATCH", "manifest sha256 does not match the token claim", {
      expected: ref.manifest_sha256,
      actual
    });
  }
  let doc;
  try {
    doc = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new PepError("MANIFEST_MALFORMED", "manifest is not valid JSON");
  }
  if (scopeBound) {
    return { form: "scope", sha256: actual, manifest: parseScopeManifest(doc) };
  }
  return { form: "exact", sha256: actual, targets: parseExactManifest(doc, ref.count) };
}
function parseExactManifest(doc, expectedCount) {
  const targets = Array.isArray(doc) ? doc : doc !== null && typeof doc === "object" && Array.isArray(doc.targets) ? doc.targets : null;
  if (targets === null || !targets.every((t) => typeof t === "string" && t !== "")) {
    throw new PepError("MANIFEST_MALFORMED", "exact manifest must be a string array of targets");
  }
  if (expectedCount !== void 0 && expectedCount !== 0 && targets.length !== expectedCount) {
    throw new PepError("MANIFEST_MALFORMED", "manifest target count does not match the token claim", {
      expected: expectedCount,
      actual: targets.length
    });
  }
  return targets;
}
function parseScopeManifest(doc) {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw new PepError("MANIFEST_MALFORMED", "scope manifest must be an object");
  }
  const m = doc;
  if (typeof m.roe_id !== "string" || !m.roe_id.startsWith("roe_")) {
    throw new PepError("MANIFEST_MALFORMED", "scope manifest missing valid roe_id");
  }
  if (typeof m.roe_version !== "number" || !Number.isInteger(m.roe_version) || m.roe_version < 1) {
    throw new PepError("MANIFEST_MALFORMED", "scope manifest missing valid roe_version");
  }
  if (m.resolved_at !== void 0 && typeof m.resolved_at !== "string") {
    throw new PepError("MANIFEST_MALFORMED", "scope manifest resolved_at must be a string");
  }
  if (m.scope === null || typeof m.scope !== "object" || Array.isArray(m.scope)) {
    throw new PepError("MANIFEST_MALFORMED", "scope manifest missing scope object");
  }
  const scope = m.scope;
  const stringArray = (v, name, required) => {
    if (v === void 0) {
      if (required) throw new PepError("MANIFEST_MALFORMED", `scope manifest missing scope.${name}`);
      return [];
    }
    if (!Array.isArray(v) || !v.every((x) => typeof x === "string" && x !== "")) {
      throw new PepError("MANIFEST_MALFORMED", `scope.${name} must be a non-empty-string array`);
    }
    return v;
  };
  return {
    roe_id: m.roe_id,
    roe_version: m.roe_version,
    ...m.resolved_at !== void 0 ? { resolved_at: m.resolved_at } : {},
    scope: {
      domains: stringArray(scope.domains, "domains", true),
      cidrs: stringArray(scope.cidrs, "cidrs", true),
      explicit_excludes: stringArray(scope.explicit_excludes, "explicit_excludes", true),
      asset_group_ids: stringArray(scope.asset_group_ids, "asset_group_ids", false),
      cloud_accounts: stringArray(scope.cloud_accounts, "cloud_accounts", false)
    }
  };
}

// src/ratecap.ts
var DEFAULT_MAX_RPS_R1 = 100;
var TokenBucketRateLimiter = class {
  constructor(maxRps, nowMs = () => Date.now()) {
    this.maxRps = maxRps;
    this.nowMs = nowMs;
    if (maxRps <= 0) {
      throw new PepError("RATE_LIMITED", "max_rps must be positive when set");
    }
    this.tokens = maxRps;
    this.lastRefillMs = nowMs();
  }
  maxRps;
  nowMs;
  tokens;
  lastRefillMs;
  refill() {
    const now = this.nowMs();
    const elapsed = (now - this.lastRefillMs) / 1e3;
    if (elapsed > 0) {
      this.tokens = Math.min(this.maxRps, this.tokens + elapsed * this.maxRps);
      this.lastRefillMs = now;
    }
  }
  /** Consume one permit if available; false (deny) when the cap is exceeded. */
  tryAcquire(n = 1) {
    this.refill();
    if (this.tokens >= n) {
      this.tokens -= n;
      return true;
    }
    return false;
  }
  /**
   * Wait for a permit. Rejects immediately with PepError(KILLED) when the
   * abort signal fires (kill-switch handling, doc 01 §10.5: stop target
   * contact within 5 s — workers must not linger in rate-limit sleep).
   */
  async acquire(signal) {
    for (; ; ) {
      if (signal?.aborted) {
        throw new PepError("KILLED", "aborted while waiting on rate limiter");
      }
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const deficitMs = (1 - this.tokens) / this.maxRps * 1e3;
      await sleep(Math.min(Math.max(deficitMs, 1), 1e3), signal);
    }
  }
};
var ConcurrencyLimiter = class {
  constructor(maxConcurrent) {
    this.maxConcurrent = maxConcurrent;
    if (maxConcurrent <= 0) {
      throw new PepError("CONCURRENCY_LIMITED", "max_concurrent must be positive when set");
    }
  }
  maxConcurrent;
  inFlight = 0;
  waiters = [];
  get current() {
    return this.inFlight;
  }
  tryAcquireSlot() {
    if (this.inFlight >= this.maxConcurrent) return null;
    this.inFlight += 1;
    return () => this.release();
  }
  async acquireSlot(signal) {
    const immediate = this.tryAcquireSlot();
    if (immediate !== null) return immediate;
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        const i = this.waiters.indexOf(grant);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(new PepError("KILLED", "aborted while waiting on concurrency slot"));
      };
      const grant = () => {
        signal?.removeEventListener("abort", onAbort);
        this.inFlight += 1;
        resolve(() => this.release());
      };
      this.waiters.push(grant);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }
  release() {
    const next = this.waiters.shift();
    if (next) {
      next();
    } else {
      this.inFlight = Math.max(0, this.inFlight - 1);
    }
  }
  /** Run `fn` holding a slot; the slot is always released afterwards. */
  async withSlot(fn, signal) {
    const release = await this.acquireSlot(signal);
    try {
      return await fn();
    } finally {
      release();
    }
  }
};
var RateCapsEnforcer = class {
  rps;
  concurrency;
  constructor(caps, opts = {}) {
    const maxRps = caps?.max_rps && caps.max_rps > 0 ? caps.max_rps : null;
    const maxConcurrent = caps?.max_concurrent && caps.max_concurrent > 0 ? caps.max_concurrent : null;
    const effectiveRps = maxRps ?? (opts.riskClass === "R1" ? DEFAULT_MAX_RPS_R1 : null);
    this.rps = effectiveRps !== null ? new TokenBucketRateLimiter(effectiveRps, opts.nowMs) : null;
    this.concurrency = maxConcurrent !== null ? new ConcurrencyLimiter(maxConcurrent) : null;
  }
  /** Fail-closed check used by the PEP guard before every network action. */
  check() {
    if (this.rps !== null && !this.rps.tryAcquire()) {
      throw new PepError("RATE_LIMITED", "token max_rps exceeded");
    }
  }
};
function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new PepError("KILLED", "aborted during rate-limit wait"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

// src/revocation.ts
import { fromBinary as fromBinary2 } from "@bufbuild/protobuf";
import { anyUnpack, timestampDate } from "@bufbuild/protobuf/wkt";

// ../../gen/ts/aegisbastion/gatekeeper/v1/revocation_pb.ts
import { enumDesc as enumDesc2, fileDesc as fileDesc3, messageDesc as messageDesc3, serviceDesc } from "@bufbuild/protobuf/codegenv2";
import { file_google_protobuf_timestamp as file_google_protobuf_timestamp2 } from "@bufbuild/protobuf/wkt";
var file_aegisbastion_gatekeeper_v1_revocation = /* @__PURE__ */ fileDesc3("CithZWdpc2Jhc3Rpb24vZ2F0ZWtlZXBlci92MS9yZXZvY2F0aW9uLnByb3RvEhphZWdpc2Jhc3Rpb24uZ2F0ZWtlZXBlci52MSLuAQoKUmV2b2NhdGlvbhIVCg1yZXZvY2F0aW9uX2lkGAEgASgJEjoKBXNjb3BlGAIgASgOMisuYWVnaXNiYXN0aW9uLmdhdGVrZWVwZXIudjEuUmV2b2NhdGlvblNjb3BlEgsKA2tleRgDIAEoCRIRCglpc3N1ZWRfYnkYBCABKAkSLQoJaXNzdWVkX2F0GAUgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcBIOCgZyZWFzb24YBiABKAkSLgoKZXhwaXJlc19hdBgHIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXAidQoPUmV2b2NhdGlvbkV2ZW50EjoKCnJldm9jYXRpb24YASABKAsyJi5hZWdpc2Jhc3Rpb24uZ2F0ZWtlZXBlci52MS5SZXZvY2F0aW9uEiYKAnRzGAIgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcCKrAQoNUmV2b2tlUmVxdWVzdBI6CgVzY29wZRgBIAEoDjIrLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLlJldm9jYXRpb25TY29wZRILCgNrZXkYAiABKAkSEQoJaXNzdWVkX2J5GAMgASgJEg4KBnJlYXNvbhgEIAEoCRIuCgpleHBpcmVzX2F0GAUgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcCJMCg5SZXZva2VSZXNwb25zZRI6CgpyZXZvY2F0aW9uGAEgASgLMiYuYWVnaXNiYXN0aW9uLmdhdGVrZWVwZXIudjEuUmV2b2NhdGlvbiJhChZMaXN0UmV2b2NhdGlvbnNSZXF1ZXN0EjoKBXNjb3BlGAEgASgOMisuYWVnaXNiYXN0aW9uLmdhdGVrZWVwZXIudjEuUmV2b2NhdGlvblNjb3BlEgsKA2tleRgCIAEoCSJWChdMaXN0UmV2b2NhdGlvbnNSZXNwb25zZRI7CgtyZXZvY2F0aW9ucxgBIAMoCzImLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLlJldm9jYXRpb24qqAEKD1Jldm9jYXRpb25TY29wZRIgChxSRVZPQ0FUSU9OX1NDT1BFX1VOU1BFQ0lGSUVEEAASGwoXUkVWT0NBVElPTl9TQ09QRV9HTE9CQUwQARIYChRSRVZPQ0FUSU9OX1NDT1BFX1JPRRACEhsKF1JFVk9DQVRJT05fU0NPUEVfVEFSR0VUEAMSHwobUkVWT0NBVElPTl9TQ09QRV9DQVBBQklMSVRZEAQy8AEKEVJldm9jYXRpb25TZXJ2aWNlEl8KBlJldm9rZRIpLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLlJldm9rZVJlcXVlc3QaKi5hZWdpc2Jhc3Rpb24uZ2F0ZWtlZXBlci52MS5SZXZva2VSZXNwb25zZRJ6Cg9MaXN0UmV2b2NhdGlvbnMSMi5hZWdpc2Jhc3Rpb24uZ2F0ZWtlZXBlci52MS5MaXN0UmV2b2NhdGlvbnNSZXF1ZXN0GjMuYWVnaXNiYXN0aW9uLmdhdGVrZWVwZXIudjEuTGlzdFJldm9jYXRpb25zUmVzcG9uc2VCVVpTZ2l0aHViLmNvbS9hZWdpc2Jhc3Rpb24vYWVnaXNiYXN0aW9uL2dlbi9nby9hZWdpc2Jhc3Rpb24vZ2F0ZWtlZXBlci92MTtnYXRla2VlcGVydjFiBnByb3RvMw", [file_google_protobuf_timestamp2]);
var RevocationSchema = /* @__PURE__ */ messageDesc3(file_aegisbastion_gatekeeper_v1_revocation, 0);
var RevocationEventSchema = /* @__PURE__ */ messageDesc3(file_aegisbastion_gatekeeper_v1_revocation, 1);
var RevocationScope = /* @__PURE__ */ ((RevocationScope2) => {
  RevocationScope2[RevocationScope2["UNSPECIFIED"] = 0] = "UNSPECIFIED";
  RevocationScope2[RevocationScope2["GLOBAL"] = 1] = "GLOBAL";
  RevocationScope2[RevocationScope2["ROE"] = 2] = "ROE";
  RevocationScope2[RevocationScope2["TARGET"] = 3] = "TARGET";
  RevocationScope2[RevocationScope2["CAPABILITY"] = 4] = "CAPABILITY";
  return RevocationScope2;
})(RevocationScope || {});

// src/revocation.ts
var RevocationCache = class {
  constructor(nowMs = () => Date.now()) {
    this.nowMs = nowMs;
  }
  nowMs;
  global = null;
  roes = /* @__PURE__ */ new Map();
  targets = /* @__PURE__ */ new Map();
  capabilities = /* @__PURE__ */ new Map();
  seenRevocationIds = /* @__PURE__ */ new Set();
  /** Apply one Revocation (idempotent on revocation_id). */
  apply(rev) {
    if (rev.revocationId && this.seenRevocationIds.has(rev.revocationId)) return;
    if (rev.revocationId) this.seenRevocationIds.add(rev.revocationId);
    const entry = {
      revocationId: rev.revocationId,
      expiresAtMs: rev.expiresAt ? timestampDate(rev.expiresAt).getTime() : null
    };
    switch (rev.scope) {
      case 1 /* GLOBAL */:
        this.global = entry;
        break;
      case 2 /* ROE */:
        if (rev.key) this.roes.set(rev.key, entry);
        break;
      case 3 /* TARGET */: {
        if (rev.key) {
          let canonical = rev.key;
          try {
            canonical = canonicalizeTarget(rev.key).canonical;
          } catch {
          }
          this.targets.set(canonical, entry);
        }
        break;
      }
      case 4 /* CAPABILITY */:
        if (rev.key) this.capabilities.set(rev.key, entry);
        break;
      default:
        this.global = entry;
        break;
    }
  }
  /** Apply a bus RevocationEvent. */
  applyEvent(event) {
    if (event.revocation) this.apply(event.revocation);
  }
  live(entry) {
    return entry != null && (entry.expiresAtMs === null || entry.expiresAtMs > this.nowMs());
  }
  /**
   * The kill signal applying to this token/target/capability right now, or
   * null when nothing is revoked. Checked before EVERY network action.
   */
  check(claims, rawTarget, capability) {
    if (this.live(this.global)) {
      return { kind: "global", reason: "platform-wide revocation active" };
    }
    if (this.live(this.roes.get(claims.roe_id))) {
      return { kind: "roe", roeId: claims.roe_id, reason: `RoE ${claims.roe_id} revoked` };
    }
    if (capability !== void 0 && this.live(this.capabilities.get(capability))) {
      return { kind: "capability", capability, reason: `capability ${capability} revoked` };
    }
    for (const cap of claims.capabilities) {
      if (this.live(this.capabilities.get(cap))) {
        return { kind: "capability", capability: cap, reason: `capability ${cap} revoked` };
      }
    }
    if (rawTarget !== void 0) {
      let canonical = null;
      try {
        canonical = canonicalizeTarget(rawTarget).canonical;
      } catch {
        canonical = null;
      }
      const entry = (canonical !== null ? this.targets.get(canonical) : void 0) ?? this.targets.get(rawTarget);
      if (this.live(entry)) {
        return { kind: "target", target: rawTarget, reason: `target revoked` };
      }
    }
    return null;
  }
  /** Throw PepError(REVOKED) when any revocation applies. */
  assertNotRevoked(claims, rawTarget, capability) {
    const signal = this.check(claims, rawTarget, capability);
    if (signal !== null) {
      throw new PepError("REVOKED", signal.reason, { kind: signal.kind });
    }
  }
  get size() {
    return (this.global ? 1 : 0) + this.roes.size + this.targets.size + this.capabilities.size;
  }
};
function decodeControlKill(data) {
  try {
    const envelope = fromBinary2(EnvelopeSchema, data);
    if (envelope.payload) {
      const event = anyUnpack(envelope.payload, RevocationEventSchema);
      if (event) return event;
    }
  } catch {
  }
  return { global: true };
}

// src/pep.ts
var Pep = class {
  constructor(opts) {
    this.opts = opts;
  }
  opts;
  manifestCache = /* @__PURE__ */ new Map();
  /**
   * Verify a Scope Token and its manifest, returning the authorization
   * context used to gate every subsequent target touch. Throws (fail-closed)
   * on forged/expired/wrong-audience/wrong-task tokens, manifest hash
   * mismatches, and active revocations.
   */
  async authorizeTask(token, expectedTaskId) {
    const claims = await verifyScopeToken(token, {
      getKey: this.opts.jwks.getKey,
      expectedTaskId,
      ...this.opts.nowSeconds ? { nowSeconds: this.opts.nowSeconds() } : {}
    });
    const manifest = await this.verifiedManifest(claims);
    this.opts.revocations?.assertNotRevoked(claims);
    return new TaskAuthorization(claims, manifest, this.opts.revocations ?? null);
  }
  verifiedManifest(claims) {
    const key = claims.targets.manifest_sha256;
    let cached = this.manifestCache.get(key);
    if (!cached) {
      cached = fetchAndVerifyManifest(claims.targets, claims.scope_bound === true, this.opts.manifestFetcher).catch(
        (err) => {
          this.manifestCache.delete(key);
          throw err;
        }
      );
      this.manifestCache.set(key, cached);
    }
    return cached;
  }
};
var TaskAuthorization = class {
  constructor(claims, manifest, revocations) {
    this.claims = claims;
    this.manifest = manifest;
    this.revocations = revocations;
    this.rateCaps = new RateCapsEnforcer(claims.rate_caps, { riskClass: claims.risk_class });
  }
  claims;
  manifest;
  revocations;
  rateCaps;
  /** True when this is a Ruling A scope-bound watch authorization. */
  get scopeBound() {
    return this.claims.scope_bound === true;
  }
  /** Assert the task may exercise this capability at all. */
  assertCapability(capability) {
    if (!this.claims.capabilities.includes(capability)) {
      throw new PepError("TARGET_NOT_IN_SCOPE", `capability not granted by token: ${capability}`, {
        capability
      });
    }
    this.revocations?.assertNotRevoked(this.claims, void 0, capability);
  }
  /**
   * Gate one target touch. Throws PepError on:
   *  - active revocation (global / RoE / capability / target),
   *  - target ∉ exact manifest (exact form),
   *  - target ∉ canonical scope or ∈ exclusions (scope-bound form;
   *    exclusions ALWAYS win),
   *  - embedded rate cap exceeded.
   */
  checkTarget(rawTarget, capability) {
    if (capability !== void 0) this.assertCapability(capability);
    this.revocations?.assertNotRevoked(this.claims, rawTarget, capability);
    if (this.manifest.form === "exact") {
      if (!isTargetInManifest(rawTarget, this.manifest.targets)) {
        throw new PepError("TARGET_NOT_IN_MANIFEST", `target not in token manifest: ${rawTarget}`);
      }
    } else {
      const verdict = evaluateTargetInScope(rawTarget, this.manifest.manifest.scope);
      if (!verdict.allow) {
        throw new PepError(verdict.code, `target denied by scope (${verdict.code}): ${rawTarget}`, {
          matchedRule: verdict.matchedRule
        });
      }
    }
    this.rateCaps.check();
  }
};

// src/gatekeeper.ts
import { createClient } from "@connectrpc/connect";
import { createGrpcTransport } from "@connectrpc/connect-node";
import { Buffer } from "buffer";

// ../../gen/ts/aegisbastion/gatekeeper/v1/token_pb.ts
import { fileDesc as fileDesc4, messageDesc as messageDesc4, serviceDesc as serviceDesc2 } from "@bufbuild/protobuf/codegenv2";
var file_aegisbastion_gatekeeper_v1_token = /* @__PURE__ */ fileDesc4("CiZhZWdpc2Jhc3Rpb24vZ2F0ZWtlZXBlci92MS90b2tlbi5wcm90bxIaYWVnaXNiYXN0aW9uLmdhdGVrZWVwZXIudjEimgMKEFNjb3BlVG9rZW5DbGFpbXMSCwoDaXNzGAEgASgJEgsKA2F1ZBgCIAEoCRILCgNqdGkYAyABKAkSCwoDc3ViGAQgASgJEg8KB3Rhc2tfaWQYBSABKAkSDgoGcm9lX2lkGAYgASgJEhMKC3JvZV92ZXJzaW9uGAcgASgEEjcKCnJpc2tfY2xhc3MYCCABKA4yIy5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuUmlza0NsYXNzEhQKDGNhcGFiaWxpdGllcxgJIAMoCRI+Cgd0YXJnZXRzGAogASgLMi0uYWVnaXNiYXN0aW9uLmdhdGVrZWVwZXIudjEuVGFyZ2V0TWFuaWZlc3RSZWYSEwoLc2NvcGVfYm91bmQYCyABKAgSPAoJcmF0ZV9jYXBzGAwgASgLMikuYWVnaXNiYXN0aW9uLmdhdGVrZWVwZXIudjEuVG9rZW5SYXRlQ2FwcxITCgthcHByb3ZhbF9pZBgNIAEoCRILCgNpYXQYDiABKAMSCwoDbmJmGA8gASgDEgsKA2V4cBgQIAEoAyJjChFUYXJnZXRNYW5pZmVzdFJlZhIQCghoYXNoX2FsZxgBIAEoCRIUCgxtYW5pZmVzdF91cmkYAiABKAkSFwoPbWFuaWZlc3Rfc2hhMjU2GAMgASgJEg0KBWNvdW50GAQgASgNIjgKDVRva2VuUmF0ZUNhcHMSDwoHbWF4X3JwcxgBIAEoDRIWCg5tYXhfY29uY3VycmVudBgCIAEoDSJvChBNaW50VG9rZW5SZXF1ZXN0EhMKC2RlY2lzaW9uX2lkGAEgASgJEg8KB3Rhc2tfaWQYAiABKAkSDwoHc3ViamVjdBgDIAEoCRIPCgd0YXJnZXRzGAQgAygJEhMKC3Njb3BlX2JvdW5kGAUgASgIImAKEU1pbnRUb2tlblJlc3BvbnNlEg0KBXRva2VuGAEgASgJEjwKBmNsYWltcxgCIAEoCzIsLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLlNjb3BlVG9rZW5DbGFpbXMidgoURXhjaGFuZ2VUb2tlblJlcXVlc3QSFAoMcGFyZW50X3Rva2VuGAEgASgJEhgKEG5hcnJvd2VkX3RhcmdldHMYAiADKAkSFgoOd29ya2VyX3Rhc2tfaWQYAyABKAkSFgoOd29ya2VyX3N1YmplY3QYBCABKAkiZAoVRXhjaGFuZ2VUb2tlblJlc3BvbnNlEg0KBXRva2VuGAEgASgJEjwKBmNsYWltcxgCIAEoCzIsLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLlNjb3BlVG9rZW5DbGFpbXMiLAoTUmVmcmVzaFRva2VuUmVxdWVzdBIVCg1jdXJyZW50X3Rva2VuGAEgASgJImMKFFJlZnJlc2hUb2tlblJlc3BvbnNlEg0KBXRva2VuGAEgASgJEjwKBmNsYWltcxgCIAEoCzIsLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLlNjb3BlVG9rZW5DbGFpbXMiMQoSUmV2b2tlVG9rZW5SZXF1ZXN0EgsKA2p0aRgBIAEoCRIOCgZyZWFzb24YAiABKAkiJgoTUmV2b2tlVG9rZW5SZXNwb25zZRIPCgdyZXZva2VkGAEgASgIIh0KDkdldEpXS1NSZXF1ZXN0EgsKA2tpZBgBIAEoCSJHCg9HZXRKV0tTUmVzcG9uc2USNAoEa2V5cxgBIAMoCzImLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLkpzb25XZWJLZXkiWAoKSnNvbldlYktleRILCgNrdHkYASABKAkSCwoDY3J2GAIgASgJEgsKA2tpZBgDIAEoCRILCgNhbGcYBCABKAkSCwoDdXNlGAUgASgJEgkKAXgYBiABKAkytQQKDFRva2VuU2VydmljZRJoCglNaW50VG9rZW4SLC5hZWdpc2Jhc3Rpb24uZ2F0ZWtlZXBlci52MS5NaW50VG9rZW5SZXF1ZXN0Gi0uYWVnaXNiYXN0aW9uLmdhdGVrZWVwZXIudjEuTWludFRva2VuUmVzcG9uc2USdAoNRXhjaGFuZ2VUb2tlbhIwLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLkV4Y2hhbmdlVG9rZW5SZXF1ZXN0GjEuYWVnaXNiYXN0aW9uLmdhdGVrZWVwZXIudjEuRXhjaGFuZ2VUb2tlblJlc3BvbnNlEnEKDFJlZnJlc2hUb2tlbhIvLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLlJlZnJlc2hUb2tlblJlcXVlc3QaMC5hZWdpc2Jhc3Rpb24uZ2F0ZWtlZXBlci52MS5SZWZyZXNoVG9rZW5SZXNwb25zZRJuCgtSZXZva2VUb2tlbhIuLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLlJldm9rZVRva2VuUmVxdWVzdBovLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLlJldm9rZVRva2VuUmVzcG9uc2USYgoHR2V0SldLUxIqLmFlZ2lzYmFzdGlvbi5nYXRla2VlcGVyLnYxLkdldEpXS1NSZXF1ZXN0GisuYWVnaXNiYXN0aW9uLmdhdGVrZWVwZXIudjEuR2V0SldLU1Jlc3BvbnNlQlVaU2dpdGh1Yi5jb20vYWVnaXNiYXN0aW9uL2FlZ2lzYmFzdGlvbi9nZW4vZ28vYWVnaXNiYXN0aW9uL2dhdGVrZWVwZXIvdjE7Z2F0ZWtlZXBlcnYxYgZwcm90bzM", [file_aegisbastion_platform_v1_types]);
var ScopeTokenClaimsSchema = /* @__PURE__ */ messageDesc4(file_aegisbastion_gatekeeper_v1_token, 0);
var JsonWebKeySchema = /* @__PURE__ */ messageDesc4(file_aegisbastion_gatekeeper_v1_token, 13);
var TokenService = /* @__PURE__ */ serviceDesc2(file_aegisbastion_gatekeeper_v1_token, 0);

// src/gatekeeper.ts
function pem(v) {
  return typeof v === "string" ? v : Buffer.from(v);
}
function grpcNodeOptions(tls) {
  return {
    ...tls.caCert ? { ca: pem(tls.caCert) } : {},
    ...tls.clientCert ? { cert: pem(tls.clientCert) } : {},
    ...tls.clientKey ? { key: pem(tls.clientKey) } : {}
  };
}
function transportFor(opts) {
  return createGrpcTransport({
    baseUrl: opts.baseUrl,
    nodeOptions: opts.tls ? grpcNodeOptions(opts.tls) : void 0
  });
}
function createTokenServiceClient(opts) {
  return createClient(TokenService, transportFor(opts));
}
function jwksFetcher(client) {
  return async () => {
    const res = await client.getJWKS({ kid: "" });
    return res.keys;
  };
}
async function refreshScopeToken(client, currentToken) {
  return client.refreshToken({ currentToken });
}

// src/registry.ts
import { createClient as createClient2 } from "@connectrpc/connect";
import { createGrpcTransport as createGrpcTransport2 } from "@connectrpc/connect-node";
import { timestampNow as timestampNow2 } from "@bufbuild/protobuf/wkt";

// ../../gen/ts/aegisbastion/platform/v1/registry_pb.ts
import { enumDesc as enumDesc4, fileDesc as fileDesc6, messageDesc as messageDesc6, serviceDesc as serviceDesc3 } from "@bufbuild/protobuf/codegenv2";
import { file_google_protobuf_struct as file_google_protobuf_struct2, file_google_protobuf_timestamp as file_google_protobuf_timestamp4 } from "@bufbuild/protobuf/wkt";

// ../../gen/ts/aegisbastion/platform/v1/task_pb.ts
import { enumDesc as enumDesc3, fileDesc as fileDesc5, messageDesc as messageDesc5 } from "@bufbuild/protobuf/codegenv2";
import { file_google_protobuf_struct, file_google_protobuf_timestamp as file_google_protobuf_timestamp3 } from "@bufbuild/protobuf/wkt";
var file_aegisbastion_platform_v1_task = /* @__PURE__ */ fileDesc5("CiNhZWdpc2Jhc3Rpb24vcGxhdGZvcm0vdjEvdGFzay5wcm90bxIYYWVnaXNiYXN0aW9uLnBsYXRmb3JtLnYxIjAKDkFydGlmYWN0VXBsb2FkEg4KBmJ1Y2tldBgBIAEoCRIOCgZwcmVmaXgYAiABKAkirQMKDlRhc2tBc3NpZ25tZW50Eg8KB3Rhc2tfaWQYASABKAkSEgoKbWlzc2lvbl9pZBgCIAEoCRIPCgdwbGFuX2lkGAMgASgJEhIKCmNhcGFiaWxpdHkYBCABKAkSNwoKcmlza19jbGFzcxgFIAEoDjIjLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5SaXNrQ2xhc3MSDwoHdGFyZ2V0cxgGIAMoCRInCgZwYXJhbXMYByABKAsyFy5nb29nbGUucHJvdG9idWYuU3RydWN0EhEKCXRpbWVvdXRfcxgIIAEoDRIsCghkZWFkbGluZRgJIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXASGwoTYXV0aG9yaXphdGlvbl90b2tlbhgKIAEoCRJBCg9hcnRpZmFjdF91cGxvYWQYCyABKAsyKC5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuQXJ0aWZhY3RVcGxvYWQSPQoNdHJhY2VfY29udGV4dBgMIAEoCzImLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5UcmFjZUNvbnRleHQi2gIKClRhc2tSZXN1bHQSDwoHdGFza19pZBgBIAEoCRIQCghhZ2VudF9pZBgCIAEoCRI6CgZzdGF0dXMYAyABKA4yKi5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuVGFza1Jlc3VsdFN0YXR1cxIuCgpzdGFydGVkX2F0GAQgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcBIvCgtmaW5pc2hlZF9hdBgFIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXASKAoHc3VtbWFyeRgGIAEoCzIXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3QSFQoNYXJ0aWZhY3RfcmVmcxgHIAMoCRI8CgdtZXRyaWNzGAggASgLMisuYWVnaXNiYXN0aW9uLnBsYXRmb3JtLnYxLlRhc2tSZXN1bHRNZXRyaWNzEg0KBWVycm9yGAkgASgJIkMKEVRhc2tSZXN1bHRNZXRyaWNzEhUKDXJlcXVlc3RzX3NlbnQYASABKAQSFwoPdGFyZ2V0c190b3VjaGVkGAIgAygJKowDCglUYXNrU3RhdGUSGgoWVEFTS19TVEFURV9VTlNQRUNJRklFRBAAEhYKElRBU0tfU1RBVEVfUEVORElORxABEhkKFVRBU0tfU1RBVEVfVkFMSURBVElORxACEhUKEVRBU0tfU1RBVEVfUVVFVUVEEAMSGQoVVEFTS19TVEFURV9ESVNQQVRDSEVEEAQSFgoSVEFTS19TVEFURV9SVU5OSU5HEAUSFwoTVEFTS19TVEFURV9SRVBPUlRFRBAGEhgKFFRBU0tfU1RBVEVfVkFMSURBVEVEEAcSGAoUVEFTS19TVEFURV9DT01QTEVURUQQCBIkCiBUQVNLX1NUQVRFX1JFSkVDVEVEX1VOQVVUSE9SSVpFRBAJEhYKElRBU0tfU1RBVEVfRVhQSVJFRBAKEhUKEVRBU0tfU1RBVEVfRkFJTEVEEAsSEwoPVEFTS19TVEFURV9ERUFEEAwSFQoRVEFTS19TVEFURV9LSUxMRUQQDRIYChRUQVNLX1NUQVRFX0NBTkNFTExFRBAOKuQBChBUYXNrUmVzdWx0U3RhdHVzEiIKHlRBU0tfUkVTVUxUX1NUQVRVU19VTlNQRUNJRklFRBAAEiAKHFRBU0tfUkVTVUxUX1NUQVRVU19TVUNDRUVERUQQARIdChlUQVNLX1JFU1VMVF9TVEFUVVNfRkFJTEVEEAISLAooVEFTS19SRVNVTFRfU1RBVFVTX1JFSkVDVEVEX1VOQVVUSE9SSVpFRBADEh0KGVRBU0tfUkVTVUxUX1NUQVRVU19LSUxMRUQQBBIeChpUQVNLX1JFU1VMVF9TVEFUVVNfVElNRU9VVBAFQlFaT2dpdGh1Yi5jb20vYWVnaXNiYXN0aW9uL2FlZ2lzYmFzdGlvbi9nZW4vZ28vYWVnaXNiYXN0aW9uL3BsYXRmb3JtL3YxO3BsYXRmb3JtdjFiBnByb3RvMw", [file_google_protobuf_struct, file_google_protobuf_timestamp3, file_aegisbastion_platform_v1_types]);
var TaskAssignmentSchema = /* @__PURE__ */ messageDesc5(file_aegisbastion_platform_v1_task, 1);
var TaskResultSchema = /* @__PURE__ */ messageDesc5(file_aegisbastion_platform_v1_task, 2);
var TaskResultStatus = /* @__PURE__ */ ((TaskResultStatus2) => {
  TaskResultStatus2[TaskResultStatus2["UNSPECIFIED"] = 0] = "UNSPECIFIED";
  TaskResultStatus2[TaskResultStatus2["SUCCEEDED"] = 1] = "SUCCEEDED";
  TaskResultStatus2[TaskResultStatus2["FAILED"] = 2] = "FAILED";
  TaskResultStatus2[TaskResultStatus2["REJECTED_UNAUTHORIZED"] = 3] = "REJECTED_UNAUTHORIZED";
  TaskResultStatus2[TaskResultStatus2["KILLED"] = 4] = "KILLED";
  TaskResultStatus2[TaskResultStatus2["TIMEOUT"] = 5] = "TIMEOUT";
  return TaskResultStatus2;
})(TaskResultStatus || {});

// ../../gen/ts/aegisbastion/platform/v1/registry_pb.ts
var file_aegisbastion_platform_v1_registry = /* @__PURE__ */ fileDesc6("CidhZWdpc2Jhc3Rpb24vcGxhdGZvcm0vdjEvcmVnaXN0cnkucHJvdG8SGGFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MSJvCgpDYXBhYmlsaXR5EgwKBG5hbWUYASABKAkSOwoOcmlza19jbGFzc19tYXgYAiABKA4yIy5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuUmlza0NsYXNzEhYKDnNjaGVtYV92ZXJzaW9uGAMgASgJIiIKDUFnZW50SWRlbnRpdHkSEQoJc3BpZmZlX2lkGAEgASgJIisKC0FnZW50TGltaXRzEhwKFG1heF9jb25jdXJyZW50X3Rhc2tzGAEgASgNItACCg1BZ2VudE1hbmlmZXN0EhAKCGFnZW50X2lkGAEgASgJEjcKCmFnZW50X3R5cGUYAiABKA4yIy5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuQWdlbnRUeXBlEg8KB3ZlcnNpb24YAyABKAkSEgoKYnVpbGRfaGFzaBgEIAEoCRI6CgxjYXBhYmlsaXRpZXMYBSADKAsyJC5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuQ2FwYWJpbGl0eRI5CghpZGVudGl0eRgGIAEoCzInLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5BZ2VudElkZW50aXR5EjUKBmxpbWl0cxgHIAEoCzIlLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5BZ2VudExpbWl0cxIOCgZyZWdpb24YCCABKAkSEQoJc2FuZGJveGVkGAkgASgIIkwKD1JlZ2lzdGVyUmVxdWVzdBI5CghtYW5pZmVzdBgBIAEoCzInLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5BZ2VudE1hbmlmZXN0IiQKEFJlZ2lzdGVyUmVzcG9uc2USEAoIYWdlbnRfaWQYASABKAkiZgoQSGVhcnRiZWF0UmVxdWVzdBIQCghhZ2VudF9pZBgBIAEoCRImCgJ0cxgCIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXASGAoQcnVubmluZ190YXNrX2lkcxgDIAMoCSIoChFIZWFydGJlYXRSZXNwb25zZRITCgtraWxsX2FjdGl2ZRgBIAEoCCIzCg5BY2tUYXNrUmVxdWVzdBIQCghhZ2VudF9pZBgBIAEoCRIPCgd0YXNrX2lkGAIgASgJIiAKD0Fja1Rhc2tSZXNwb25zZRINCgVhY2tlZBgBIAEoCCJlChVSZXBvcnRQcm9ncmVzc1JlcXVlc3QSEAoIYWdlbnRfaWQYASABKAkSDwoHdGFza19pZBgCIAEoCRIpCghwcm9ncmVzcxgDIAEoCzIXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3QiKgoWUmVwb3J0UHJvZ3Jlc3NSZXNwb25zZRIQCghyZWNvcmRlZBgBIAEoCCJLChNSZXBvcnRSZXN1bHRSZXF1ZXN0EjQKBnJlc3VsdBgBIAEoCzIkLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5UYXNrUmVzdWx0IigKFFJlcG9ydFJlc3VsdFJlc3BvbnNlEhAKCHJlY29yZGVkGAEgASgIIiYKElN0cmVhbVRhc2tzUmVxdWVzdBIQCghhZ2VudF9pZBgBIAEoCSJTChNTdHJlYW1UYXNrc1Jlc3BvbnNlEjwKCmFzc2lnbm1lbnQYASABKAsyKC5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuVGFza0Fzc2lnbm1lbnQq2wEKCUFnZW50VHlwZRIaChZBR0VOVF9UWVBFX1VOU1BFQ0lGSUVEEAASFwoTQUdFTlRfVFlQRV9ESVNDT1ZFUhABEhYKEkFHRU5UX1RZUEVfTU9OSVRPUhACEhUKEUFHRU5UX1RZUEVfREVURUNUEAMSFAoQQUdFTlRfVFlQRV9BTEVSVBAEEhoKFkFHRU5UX1RZUEVfRERPU19FTkdJTkUQBRIcChhBR0VOVF9UWVBFX1BISVNIX0NBVENIRVIQBhIaChZBR0VOVF9UWVBFX0FJX1JFRF9URUFNEAcyiQUKDEFnZW50U2VydmljZRJhCghSZWdpc3RlchIpLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5SZWdpc3RlclJlcXVlc3QaKi5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuUmVnaXN0ZXJSZXNwb25zZRJkCglIZWFydGJlYXQSKi5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuSGVhcnRiZWF0UmVxdWVzdBorLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5IZWFydGJlYXRSZXNwb25zZRJeCgdBY2tUYXNrEiguYWVnaXNiYXN0aW9uLnBsYXRmb3JtLnYxLkFja1Rhc2tSZXF1ZXN0GikuYWVnaXNiYXN0aW9uLnBsYXRmb3JtLnYxLkFja1Rhc2tSZXNwb25zZRJzCg5SZXBvcnRQcm9ncmVzcxIvLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5SZXBvcnRQcm9ncmVzc1JlcXVlc3QaMC5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuUmVwb3J0UHJvZ3Jlc3NSZXNwb25zZRJtCgxSZXBvcnRSZXN1bHQSLS5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuUmVwb3J0UmVzdWx0UmVxdWVzdBouLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5SZXBvcnRSZXN1bHRSZXNwb25zZRJsCgtTdHJlYW1UYXNrcxIsLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5TdHJlYW1UYXNrc1JlcXVlc3QaLS5hZWdpc2Jhc3Rpb24ucGxhdGZvcm0udjEuU3RyZWFtVGFza3NSZXNwb25zZTABQlFaT2dpdGh1Yi5jb20vYWVnaXNiYXN0aW9uL2FlZ2lzYmFzdGlvbi9nZW4vZ28vYWVnaXNiYXN0aW9uL3BsYXRmb3JtL3YxO3BsYXRmb3JtdjFiBnByb3RvMw", [file_google_protobuf_struct2, file_google_protobuf_timestamp4, file_aegisbastion_platform_v1_task, file_aegisbastion_platform_v1_types]);
var CapabilitySchema = /* @__PURE__ */ messageDesc6(file_aegisbastion_platform_v1_registry, 0);
var AgentManifestSchema = /* @__PURE__ */ messageDesc6(file_aegisbastion_platform_v1_registry, 3);
var AgentType = /* @__PURE__ */ ((AgentType2) => {
  AgentType2[AgentType2["UNSPECIFIED"] = 0] = "UNSPECIFIED";
  AgentType2[AgentType2["DISCOVER"] = 1] = "DISCOVER";
  AgentType2[AgentType2["MONITOR"] = 2] = "MONITOR";
  AgentType2[AgentType2["DETECT"] = 3] = "DETECT";
  AgentType2[AgentType2["ALERT"] = 4] = "ALERT";
  AgentType2[AgentType2["DDOS_ENGINE"] = 5] = "DDOS_ENGINE";
  AgentType2[AgentType2["PHISH_CATCHER"] = 6] = "PHISH_CATCHER";
  AgentType2[AgentType2["AI_RED_TEAM"] = 7] = "AI_RED_TEAM";
  return AgentType2;
})(AgentType || {});
var AgentService = /* @__PURE__ */ serviceDesc3(file_aegisbastion_platform_v1_registry, 0);

// src/registry.ts
function createAgentServiceClient(opts) {
  return createClient2(
    AgentService,
    createGrpcTransport2({
      baseUrl: opts.baseUrl,
      nodeOptions: opts.tls ? grpcNodeOptions(opts.tls) : void 0
    })
  );
}
var RegistryClient = class {
  constructor(client) {
    this.client = client;
  }
  client;
  /** Register or re-register (re-register on version change, doc 01 §9.1). */
  async register(manifest) {
    const res = await this.client.register({ manifest });
    return res.agentId;
  }
  /**
   * One heartbeat. Returns true when a kill switch is active for this agent —
   * the caller must halt target contact within 5 s (doc 01 §10.5).
   */
  async heartbeat(agentId, runningTaskIds) {
    const res = await this.client.heartbeat({
      agentId,
      ts: timestampNow2(),
      runningTaskIds
    });
    return res.killActive;
  }
  /** ACK an assignment (within 10 s or it redelivers, doc 01 §9 item 3). */
  async ackTask(agentId, taskId) {
    await this.client.ackTask({ agentId, taskId });
  }
  /** Stream execution progress (module-defined payload). */
  async reportProgress(agentId, taskId, progress) {
    await this.client.reportProgress({ agentId, taskId, progress });
  }
  /** Deliver the terminal TaskResult (idempotent on task_id). */
  async reportResult(result) {
    await this.client.reportResult({ result });
  }
  /** Long-poll assignment stream (alternative to the bus, doc 01 §8.3). */
  async *streamTasks(agentId, signal) {
    const stream = this.client.streamTasks({ agentId }, { signal });
    for await (const res of stream) {
      if (res.assignment) yield res.assignment;
    }
  }
};

// src/refresh.ts
import { decodeJwt } from "jose";
var REFRESH_MARGIN_MS = 6e4;
var MIN_DELAY_MS = 5e3;
var MAX_BACKOFF_MS = 6e4;
var TokenReauthorizer = class {
  constructor(opts) {
    this.opts = opts;
  }
  opts;
  stopped = false;
  loop = null;
  now() {
    return this.opts.nowMs?.() ?? Date.now();
  }
  sleep(ms) {
    return this.opts.sleep?.(ms) ?? new Promise((r) => setTimeout(r, ms));
  }
  /**
   * Run the loop until stop() or a re-authorization denial. `currentToken`
   * is a getter because the successor becomes the next iteration's input.
   */
  start(getCurrentToken, cb) {
    if (this.loop !== null) throw new Error("TokenReauthorizer already started");
    this.stopped = false;
    this.loop = this.run(getCurrentToken, cb).catch((err) => {
      cb.onRefreshError?.(err);
    });
  }
  async stop() {
    this.stopped = true;
    await this.loop;
  }
  tokenExpMs(token) {
    try {
      const { exp } = decodeJwt(token);
      if (typeof exp === "number") return exp * 1e3;
    } catch {
    }
    throw new PepError("TOKEN_MALFORMED", "cannot decode exp from current token");
  }
  async run(getCurrentToken, cb) {
    let backoff = MIN_DELAY_MS;
    for (; ; ) {
      if (this.stopped) return;
      const current = getCurrentToken();
      const expMs = this.tokenExpMs(current);
      const now = this.now();
      const ttlRemaining = expMs - now;
      if (ttlRemaining <= 0) return;
      const waitMs = Math.max(
        MIN_DELAY_MS,
        Math.min(ttlRemaining / 2, ttlRemaining - REFRESH_MARGIN_MS)
      );
      await this.sleep(waitMs);
      if (this.stopped) return;
      let successor;
      try {
        successor = await this.opts.refresh(getCurrentToken());
      } catch (err) {
        cb.onRefreshError?.(err);
        const remaining = this.tokenExpMs(getCurrentToken()) - this.now();
        if (remaining <= MIN_DELAY_MS) return;
        await this.sleep(Math.min(backoff, remaining / 2));
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
        continue;
      }
      backoff = MIN_DELAY_MS;
      if (successor === "") {
        cb.onDenied?.();
        return;
      }
      cb.onSuccessor(successor);
    }
  }
};

// src/audit.ts
import { create as create2, toJson } from "@bufbuild/protobuf";
import { timestampNow as timestampNow3 } from "@bufbuild/protobuf/wkt";

// ../../gen/ts/aegisbastion/platform/v1/audit_pb.ts
import { enumDesc as enumDesc5, fileDesc as fileDesc7, messageDesc as messageDesc7 } from "@bufbuild/protobuf/codegenv2";
import { file_google_protobuf_struct as file_google_protobuf_struct3, file_google_protobuf_timestamp as file_google_protobuf_timestamp5 } from "@bufbuild/protobuf/wkt";
var file_aegisbastion_platform_v1_audit = /* @__PURE__ */ fileDesc7("CiRhZWdpc2Jhc3Rpb24vcGxhdGZvcm0vdjEvYXVkaXQucHJvdG8SGGFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MSImCgpBdWRpdEFjdG9yEgwKBGtpbmQYASABKAkSCgoCaWQYAiABKAkiQwoMQXVkaXRTdWJqZWN0EhIKCm1pc3Npb25faWQYASABKAkSDwoHdGFza19pZBgCIAEoCRIOCgZyb2VfaWQYAyABKAkixAIKCkF1ZGl0RXZlbnQSEAoIZXZlbnRfaWQYASABKAkSCwoDc2VxGAIgASgEEiYKAnRzGAMgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcBI2CgR0eXBlGAQgASgOMiguYWVnaXNiYXN0aW9uLnBsYXRmb3JtLnYxLkF1ZGl0RXZlbnRUeXBlEjMKBWFjdG9yGAUgASgLMiQuYWVnaXNiYXN0aW9uLnBsYXRmb3JtLnYxLkF1ZGl0QWN0b3ISNwoHc3ViamVjdBgGIAEoCzImLmFlZ2lzYmFzdGlvbi5wbGF0Zm9ybS52MS5BdWRpdFN1YmplY3QSKAoHcGF5bG9hZBgHIAEoCzIXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3QSEQoJcHJldl9oYXNoGAggASgJEgwKBGhhc2gYCSABKAkq+QIKDkF1ZGl0RXZlbnRUeXBlEiAKHEFVRElUX0VWRU5UX1RZUEVfVU5TUEVDSUZJRUQQABIkCiBBVURJVF9FVkVOVF9UWVBFX01JU1NJT05fQ1JFQVRFRBABEiMKH0FVRElUX0VWRU5UX1RZUEVfUExBTl9TVUJNSVRURUQQAhIjCh9BVURJVF9FVkVOVF9UWVBFX0FVVEhaX0RFQ0lTSU9OEAMSJAogQVVESVRfRVZFTlRfVFlQRV9UQVNLX0RJU1BBVENIRUQQBBIjCh9BVURJVF9FVkVOVF9UWVBFX1RBUkdFVF9UT1VDSEVEEAUSIAocQVVESVRfRVZFTlRfVFlQRV9UQVNLX1JFU1VMVBAGEiAKHEFVRElUX0VWRU5UX1RZUEVfUk9FX1JFVk9LRUQQBxIgChxBVURJVF9FVkVOVF9UWVBFX0tJTExfU1dJVENIEAgSJAogQVVESVRfRVZFTlRfVFlQRV9TQ09QRV9WSU9MQVRJT04QCUJRWk9naXRodWIuY29tL2FlZ2lzYmFzdGlvbi9hZWdpc2Jhc3Rpb24vZ2VuL2dvL2FlZ2lzYmFzdGlvbi9wbGF0Zm9ybS92MTtwbGF0Zm9ybXYxYgZwcm90bzM", [file_google_protobuf_struct3, file_google_protobuf_timestamp5]);
var AuditActorSchema = /* @__PURE__ */ messageDesc7(file_aegisbastion_platform_v1_audit, 0);
var AuditSubjectSchema = /* @__PURE__ */ messageDesc7(file_aegisbastion_platform_v1_audit, 1);
var AuditEventSchema = /* @__PURE__ */ messageDesc7(file_aegisbastion_platform_v1_audit, 2);
var AuditEventType = /* @__PURE__ */ ((AuditEventType2) => {
  AuditEventType2[AuditEventType2["UNSPECIFIED"] = 0] = "UNSPECIFIED";
  AuditEventType2[AuditEventType2["MISSION_CREATED"] = 1] = "MISSION_CREATED";
  AuditEventType2[AuditEventType2["PLAN_SUBMITTED"] = 2] = "PLAN_SUBMITTED";
  AuditEventType2[AuditEventType2["AUTHZ_DECISION"] = 3] = "AUTHZ_DECISION";
  AuditEventType2[AuditEventType2["TASK_DISPATCHED"] = 4] = "TASK_DISPATCHED";
  AuditEventType2[AuditEventType2["TARGET_TOUCHED"] = 5] = "TARGET_TOUCHED";
  AuditEventType2[AuditEventType2["TASK_RESULT"] = 6] = "TASK_RESULT";
  AuditEventType2[AuditEventType2["ROE_REVOKED"] = 7] = "ROE_REVOKED";
  AuditEventType2[AuditEventType2["KILL_SWITCH"] = 8] = "KILL_SWITCH";
  AuditEventType2[AuditEventType2["SCOPE_VIOLATION"] = 9] = "SCOPE_VIOLATION";
  return AuditEventType2;
})(AuditEventType || {});

// src/audit.ts
function buildAuditEvent(input) {
  const event = create2(AuditEventSchema, {
    eventId: `aud_${ulid()}`,
    seq: BigInt(input.seq ?? 0),
    ts: timestampNow3(),
    type: input.type,
    actor: create2(AuditActorSchema, input.actor),
    subject: create2(AuditSubjectSchema, {
      missionId: input.subject.missionId ?? "",
      taskId: input.subject.taskId ?? "",
      roeId: input.subject.roeId ?? ""
    }),
    payload: input.payload,
    prevHash: input.prevHash ?? "",
    hash: ""
  });
  const canonical = toJson(AuditEventSchema, event);
  event.hash = auditChainHash(canonical, event.prevHash);
  return event;
}
function targetTouchedEvent(input) {
  return buildAuditEvent({
    type: 5 /* TARGET_TOUCHED */,
    actor: { kind: "agent", id: input.agentId },
    subject: { missionId: input.missionId, taskId: input.taskId, roeId: input.roeId },
    payload: {
      target: input.target,
      token_jti: input.tokenJti,
      capability: input.capability
    },
    ...input.seq !== void 0 ? { seq: input.seq } : {},
    ...input.prevHash !== void 0 ? { prevHash: input.prevHash } : {}
  });
}
var AuditEmitter = class {
  constructor(sink) {
    this.sink = sink;
  }
  sink;
  seq = 0n;
  prevHash = "";
  async emit(input) {
    const event = buildAuditEvent({ ...input, seq: ++this.seq, prevHash: this.prevHash });
    await this.sink(event);
    this.prevHash = event.hash;
    return event;
  }
  /** Emit one per-probe TARGET_TOUCHED record. */
  async targetTouched(input) {
    return this.emit({
      type: 5 /* TARGET_TOUCHED */,
      actor: { kind: "agent", id: input.agentId },
      subject: { missionId: input.missionId, taskId: input.taskId, roeId: input.roeId },
      payload: {
        target: input.target,
        token_jti: input.tokenJti,
        capability: input.capability
      }
    });
  }
};

// src/bus.ts
import { connect } from "@nats-io/transport-node";
import {
  AckPolicy,
  DeliverPolicy,
  jetstream,
  jetstreamManager
} from "@nats-io/jetstream";
import { anyUnpack as anyUnpack2 } from "@bufbuild/protobuf/wkt";
var STREAMS = {
  taskAssign: "TASK_ASSIGN",
  gatekeeper: "GATEKEEPER"
};
var BusClient = class _BusClient {
  constructor(nc, js) {
    this.nc = nc;
    this.js = js;
  }
  nc;
  js;
  static async connect(opts) {
    const nc = await connect({ servers: opts.servers, ...opts.connection });
    return new _BusClient(nc, jetstream(nc));
  }
  async close() {
    await this.nc.drain();
  }
  /** Publish a typed payload on a subject inside the platform envelope. */
  async publish(subject, payloadSchema, payload, opts = {}) {
    const envelope = newEnvelope(payloadSchema, payload, opts);
    return this.js.publish(subject, encodeEnvelope(envelope));
  }
  /** Publish a pre-built envelope (e.g. audit events). */
  async publishEnvelope(subject, envelopeBytes) {
    return this.js.publish(subject, envelopeBytes);
  }
  /**
   * Consume task assignments from `task.assign.{agentId}` (WorkQueue stream,
   * ack-required, redelivery on lease expiry — doc 01 §8.1). The handler MUST
   * be redelivery-safe; duplicates on task_id are filtered here, and the
   * Orchestrator-side consumer is idempotent as well (doc 01 §8.2).
   *
   * Ack semantics: ack after the handler resolves; nak(5s) when it throws so
   * the Orchestrator redelivers per the task lease.
   */
  async consumeAssignments(agentId, handler, opts = {}) {
    const jsm = await jetstreamManager(this.nc);
    const durable = opts.durableName ?? `agent-${agentId}`;
    await jsm.consumers.add(STREAMS.taskAssign, {
      durable_name: durable,
      filter_subject: SUBJECTS.taskAssign(agentId),
      ack_policy: AckPolicy.Explicit,
      deliver_policy: DeliverPolicy.All,
      // Orchestrator lease-expiry redelivery relies on the ack wait (doc 01
      // §6.3); 30 s matches the Registry heartbeat TTL window.
      ack_wait: 3e10,
      // nanoseconds
      max_deliver: 5
    });
    const consumer = await this.js.consumers.get(STREAMS.taskAssign, durable);
    const messages = await consumer.consume();
    const dedup = new IdempotencySet();
    const loop = (async () => {
      for await (const msg of messages) {
        if (opts.signal?.aborted) break;
        try {
          const envelope = decodeEnvelope(msg.data);
          if (!dedup.firstSeen(envelope.eventId)) {
            msg.ack();
            continue;
          }
          const assignment = envelope.payload ? anyUnpack2(envelope.payload, TaskAssignmentSchema) : void 0;
          if (!assignment) {
            msg.term("unrecognized assignment payload");
            continue;
          }
          await handler({
            envelopeId: envelope.eventId,
            assignment,
            ...envelope.traceContext ? {
              traceContext: {
                traceparent: envelope.traceContext.traceparent,
                tracestate: envelope.traceContext.tracestate
              }
            } : {}
          });
          msg.ack();
        } catch {
          msg.nak(5e3);
        }
      }
    })();
    return {
      stop: async () => {
        messages.stop();
        await loop.catch(() => {
        });
      }
    };
  }
  /**
   * Subscribe to `tasks.revocations.v1` (durable GATEKEEPER stream). The
   * handler is invoked once per RevocationEvent, deduped on event_id.
   */
  async subscribeRevocations(agentId, handler) {
    const jsm = await jetstreamManager(this.nc);
    const durable = `revocations-${agentId}`;
    await jsm.consumers.add(STREAMS.gatekeeper, {
      durable_name: durable,
      filter_subject: SUBJECTS.tasksRevocations,
      ack_policy: AckPolicy.Explicit,
      deliver_policy: DeliverPolicy.All,
      ack_wait: 3e10,
      max_deliver: 10
    });
    const consumer = await this.js.consumers.get(STREAMS.gatekeeper, durable);
    const messages = await consumer.consume();
    const dedup = new IdempotencySet();
    const loop = (async () => {
      for await (const msg of messages) {
        try {
          const envelope = decodeEnvelope(msg.data);
          if (dedup.firstSeen(envelope.eventId) && envelope.payload) {
            const event = anyUnpack2(envelope.payload, RevocationEventSchema);
            if (event) handler(event);
          }
          msg.ack();
        } catch {
          msg.nak(1e3);
        }
      }
    })();
    return {
      stop: async () => {
        messages.stop();
        await loop.catch(() => {
        });
      }
    };
  }
  /**
   * Subscribe to `control.kill` — a CORE NATS broadcast with NO JetStream
   * stream (doc 01 §8.1). Agents must halt target contact within 5 s
   * (doc 01 §10.5). Raw payload bytes are handed to the caller (see
   * decodeControlKill in revocation.ts).
   */
  subscribeKill(handler) {
    const sub = this.nc.subscribe(SUBJECTS.controlKill);
    const loop = (async () => {
      for await (const msg of sub) {
        handler(msg.data);
      }
    })();
    return {
      stop: async () => {
        sub.unsubscribe();
        await loop.catch(() => {
        });
      }
    };
  }
};

// src/agent.ts
import { create as create3 } from "@bufbuild/protobuf";
import { timestampFromDate, timestampNow as timestampNow4 } from "@bufbuild/protobuf/wkt";
var HEARTBEAT_MS = 1e4;
var Agent = class {
  constructor(opts) {
    this.opts = opts;
  }
  opts;
  agentId = "";
  running = /* @__PURE__ */ new Map();
  heartbeatTimer = null;
  stops = [];
  started = false;
  get id() {
    return this.agentId;
  }
  /** Register (re-register on version change), then start all loops. */
  async start() {
    if (this.started) throw new Error("agent already started");
    this.started = true;
    this.agentId = await this.opts.registry.register(this.opts.manifest);
    if (this.agentId === "") throw new Error("registry returned an empty agent_id");
    const transport = this.opts.transport ?? (this.opts.bus ? "bus" : "stream");
    if (this.opts.bus) {
      const revStop = await this.opts.bus.subscribeRevocations(this.agentId, (event) => {
        this.opts.revocations.applyEvent(event);
        this.sweepRevokedTasks();
      });
      this.stops.push(revStop.stop);
      const killStop = this.opts.bus.subscribeKill((data) => this.handleControlKill(data));
      this.stops.push(killStop.stop);
      if (transport === "bus") {
        const assignStop = await this.opts.bus.consumeAssignments(
          this.agentId,
          async (delivery) => {
            await this.acceptAssignment(delivery.assignment);
          }
        );
        this.stops.push(assignStop.stop);
      }
    }
    if (transport === "stream") {
      const streamStop = new AbortController();
      const loop = this.streamLoop(streamStop.signal).catch(() => {
      });
      this.stops.push(async () => {
        streamStop.abort();
        await loop;
      });
    }
    this.startHeartbeats();
  }
  async stop() {
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    for (const task of this.running.values()) {
      this.abortTask(task.taskId, "agent shutdown");
    }
    for (const stop of this.stops.splice(0)) {
      await stop();
    }
    this.started = false;
  }
  // --- assignment intake ----------------------------------------------------
  /** ACK fast (≤ 10 s, doc 01 §9 item 3), then execute in the background. */
  async acceptAssignment(assignment) {
    if (this.running.has(assignment.taskId)) return;
    await this.opts.registry.ackTask(this.agentId, assignment.taskId);
    void this.execute(assignment).catch(() => {
    });
  }
  async streamLoop(signal) {
    for (; ; ) {
      if (signal.aborted) return;
      try {
        for await (const assignment of this.opts.registry.streamTasks(this.agentId, signal)) {
          if (signal.aborted) return;
          await this.acceptAssignment(assignment);
        }
      } catch {
        if (signal.aborted) return;
        await new Promise((r) => setTimeout(r, 2e3));
      }
    }
  }
  // --- execution ------------------------------------------------------------
  async execute(assignment) {
    const taskId = assignment.taskId;
    const abortController = new AbortController();
    const task = {
      taskId,
      abortController,
      claims: null,
      token: assignment.authorizationToken || null,
      reauthorizer: null,
      finished: false
    };
    this.running.set(taskId, task);
    const startedAt = /* @__PURE__ */ new Date();
    try {
      await this.opts.module.plan(assignment);
      if (assignment.riskClass !== 1 /* R0 */) {
        if (task.token === null) {
          throw new PepError("TOKEN_MISSING", "R1+ assignment carries no Scope Token");
        }
        task.claims = await this.opts.pep.authorizeTask(task.token, taskId);
        this.opts.revocations.assertNotRevoked(task.claims.claims);
        this.startReauthorization(task);
      }
      const ctx = this.buildTaskContext(task, assignment);
      const outcome = await this.runWithDeadline(task, assignment, ctx);
      if (task.finished) return;
      task.finished = true;
      await this.report(task, assignment, 1 /* SUCCEEDED */, startedAt, outcome);
    } catch (err) {
      if (task.finished) return;
      task.finished = true;
      const status = this.statusForError(err, abortController.signal.aborted);
      await this.report(task, assignment, status, startedAt, {
        summary: { error: err.message }
      }).catch(() => {
      });
    } finally {
      task.reauthorizer?.stop().catch(() => {
      });
      this.running.delete(taskId);
    }
  }
  statusForError(err, aborted) {
    if (isPepError(err)) {
      if (err.code === "KILLED" || aborted && err.code !== "RATE_LIMITED") {
        return 4 /* KILLED */;
      }
      return 3 /* REJECTED_UNAUTHORIZED */;
    }
    if (aborted) return 4 /* KILLED */;
    return 2 /* FAILED */;
  }
  buildTaskContext(task, assignment) {
    const touched = [];
    task.touched = touched;
    return {
      agentId: this.agentId,
      assignment,
      auth: task.claims,
      signal: task.abortController.signal,
      touch: async (target) => {
        if (task.claims === null) {
          throw new PepError("TOKEN_MISSING", "no authorization for target contact");
        }
        task.claims.checkTarget(target, assignment.capability);
        touched.push(target);
        if (this.opts.audit && task.claims) {
          await this.opts.audit.targetTouched({
            agentId: this.agentId,
            taskId: assignment.taskId,
            missionId: assignment.missionId,
            roeId: task.claims.claims.roe_id,
            target,
            tokenJti: task.claims.claims.jti,
            capability: assignment.capability
          });
        }
      },
      reportProgress: async (progress) => {
        await this.opts.registry.reportProgress(this.agentId, assignment.taskId, progress);
      },
      currentToken: () => task.token
    };
  }
  /** Enforce timeout_s / deadline (doc 01 §5.6); abort the module on expiry. */
  runWithDeadline(task, assignment, ctx) {
    return new Promise((resolve, reject) => {
      let timer = null;
      const timeouts = [];
      if (assignment.timeoutS > 0) timeouts.push(assignment.timeoutS * 1e3);
      if (assignment.deadline) {
        timeouts.push(Number(assignment.deadline.seconds) * 1e3 - Date.now());
      }
      const ms = timeouts.length > 0 ? Math.min(...timeouts) : 0;
      if (ms > 0) {
        timer = setTimeout(() => {
          this.abortTask(task.taskId, "deadline exceeded");
          reject(new PepError("KILLED", "task exceeded timeout_s/deadline"));
        }, ms);
      }
      this.opts.module.run(ctx).then(
        (outcome) => {
          if (timer !== null) clearTimeout(timer);
          resolve(outcome);
        },
        (err) => {
          if (timer !== null) clearTimeout(timer);
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      );
    });
  }
  async report(task, assignment, status, startedAt, outcome) {
    const touched = task.touched ?? [];
    const targetsTouched = [...touched];
    if (task.claims?.scopeBound && task.claims.manifest.form === "scope") {
      targetsTouched.push(scopeHashCheckpoint(task.claims.manifest.sha256));
    }
    const result = create3(TaskResultSchema, {
      taskId: assignment.taskId,
      agentId: this.agentId,
      status,
      startedAt: timestampFromDate(startedAt),
      finishedAt: timestampNow4(),
      summary: outcome.summary ?? {},
      artifactRefs: outcome.artifactRefs ?? [],
      metrics: {
        requestsSent: BigInt(outcome.requestsSent ?? 0),
        targetsTouched
      },
      error: status === 2 /* FAILED */ ? String(outcome.summary?.error ?? "") : ""
    });
    await this.opts.registry.reportResult(result);
  }
  // --- re-authorization -----------------------------------------------------
  startReauthorization(task) {
    if (!this.opts.tokenClient || task.token === null) return;
    const client = this.opts.tokenClient;
    task.reauthorizer = new TokenReauthorizer({
      refresh: async (current) => {
        const res = await refreshScopeToken(client, current);
        return res.token;
      }
    });
    task.reauthorizer.start(
      () => task.token ?? "",
      {
        onSuccessor: (token) => {
          task.token = token;
          void this.opts.pep.authorizeTask(token, task.taskId).then((auth) => {
            task.claims = auth;
          }).catch(() => this.abortTask(task.taskId, "successor token failed verification"));
        },
        onDenied: () => {
          this.abortTask(task.taskId, "re-authorization denied");
        },
        onRefreshError: () => {
        }
      }
    );
  }
  // --- kill / revocation ----------------------------------------------------
  /** Abort one task: stop target contact ≤ 5 s (doc 01 §10.5). */
  abortTask(taskId, reason) {
    const task = this.running.get(taskId);
    if (!task || task.finished) return;
    task.abortController.abort();
    this.opts.module.abort(taskId);
    void reason;
  }
  sweepRevokedTasks() {
    for (const task of this.running.values()) {
      if (task.claims === null) continue;
      const signal = this.opts.revocations.check(task.claims.claims);
      if (signal !== null) this.abortTask(task.taskId, signal.reason);
    }
  }
  handleControlKill(data) {
    const decoded = decodeControlKill(data);
    if ("global" in decoded) {
      for (const task of this.running.values()) this.abortTask(task.taskId, "control.kill");
      return;
    }
    if (decoded.revocation) {
      this.opts.revocations.apply(decoded.revocation);
      this.sweepRevokedTasks();
    }
  }
  // --- heartbeats -----------------------------------------------------------
  startHeartbeats() {
    const interval = this.opts.heartbeatIntervalMs ?? HEARTBEAT_MS;
    this.heartbeatTimer = setInterval(() => {
      const runningIds = [...this.running.keys()];
      this.opts.registry.heartbeat(this.agentId, runningIds).then((killActive) => {
        if (killActive) {
          for (const id of runningIds) this.abortTask(id, "kill switch (heartbeat)");
        }
      }).catch(() => {
      });
    }, interval);
    this.heartbeatTimer.unref?.();
  }
  /** Introspection for tests/diagnostics. */
  runningTaskIds() {
    return [...this.running.keys()];
  }
  /** Auth summary for structured logs — never carries target lists. */
  describeAuth(auth) {
    if (auth === null) return { authorized: false };
    return {
      authorized: true,
      jti: auth.claims.jti,
      riskClass: auth.claims.risk_class,
      scopeBound: auth.scopeBound,
      manifestSha256: auth.manifest.sha256
    };
  }
};
export {
  Agent,
  AgentManifestSchema,
  AgentType,
  AuditEmitter,
  AuditEventSchema,
  AuditEventType,
  BusClient,
  CLOCK_LEEWAY_SECONDS,
  CapabilitySchema,
  ConcurrencyLimiter,
  DEFAULT_MAX_RPS_R1,
  EnvelopeSchema,
  IdempotencySet,
  JsonWebKeySchema,
  JwksCache,
  MAX_CLOCK_SKEW_SECONDS,
  MAX_TOKEN_TTL_SECONDS,
  Pep,
  PepError,
  RateCapsEnforcer,
  RateCapsSchema,
  RegistryClient,
  RevocationCache,
  RevocationEventSchema,
  RevocationSchema,
  RevocationScope,
  RiskClass,
  SCOPE_BOUND_CAPABILITIES,
  STREAMS,
  SUBJECTS,
  ScopeTokenClaimsSchema,
  TOKEN_AUDIENCE,
  TOKEN_ISSUER,
  TaskAssignmentSchema,
  TaskAuthorization,
  TaskResultSchema,
  TaskResultStatus,
  TokenBucketRateLimiter,
  TokenReauthorizer,
  TraceContextSchema,
  auditChainHash,
  buildAuditEvent,
  canonicalizeTarget,
  createAgentServiceClient,
  createS3ManifestFetcher,
  createTokenServiceClient,
  decodeControlKill,
  decodeEnvelope,
  encodeEnvelope,
  evaluateTargetInScope,
  fetchAndVerifyManifest,
  grpcNodeOptions,
  ipv4InCidr,
  ipv6InCidr,
  isPepError,
  isTargetInManifest,
  jcs,
  jwksFetcher,
  newEnvelope,
  parseCidr,
  parseIpv4,
  parseIpv6,
  parseManifestUri,
  parseScopeTokenClaims,
  refreshScopeToken,
  ruleMatchesTarget,
  scopeHashCheckpoint,
  sha256Hex,
  sha256JcsHex,
  targetTouchedEvent,
  ulid,
  verifyScopeToken
};
