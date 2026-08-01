// Server-side environment configuration (12-factor, doc 01 §14 single Compose
// host). Everything here is server-only: it is imported exclusively from
// route handlers and server components, never from client components — no
// backend URL or secret reaches the browser (doc 10 §2.1).

export interface DashboardEnv {
  gatekeeperUrl: string;
  platformCoreUrl: string;
  dataPlatformUrl: string;
  heraldUrl: string;
  sessionSecret: string;
  sessionCookie: string;
  orgId: string;
  tenantId: string;
  oidc: {
    issuer: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    scopes: string;
  } | null;
  devAuthEnabled: boolean;
  devAuthToken: string;
  devAuthFallbackRoles: string[];
  stepUpTtlSeconds: number;
}

function get(key: string, fallback = ""): string {
  const v = process.env[key];
  return v === undefined || v === "" ? fallback : v;
}

let cached: DashboardEnv | null = null;

/** Resolved environment. Throws when SESSION_SECRET is missing outside dev/build. */
export function env(): DashboardEnv {
  if (cached) return cached;
  const devAuthEnabled = get("DEV_AUTH_ENABLED", "false") === "true";
  const sessionSecret = get("SESSION_SECRET");
  // During `next build` prerendering there is no runtime env — defer the
  // hard requirement to actual request handling.
  const isBuild = process.env.NEXT_PHASE === "phase-production-build";
  if (!sessionSecret && !devAuthEnabled && !isBuild) {
    throw new Error("SESSION_SECRET is required (or enable DEV_AUTH_ENABLED for local dev)");
  }
  const issuer = get("OIDC_ISSUER");
  cached = {
    gatekeeperUrl: get("GATEKEEPER_URL", "http://localhost:8080").replace(/\/$/, ""),
    platformCoreUrl: get("PLATFORM_CORE_URL", "http://localhost:8081").replace(/\/$/, ""),
    dataPlatformUrl: get("DATA_PLATFORM_URL", "http://localhost:8082").replace(/\/$/, ""),
    heraldUrl: get("HERALD_URL", "http://localhost:8086").replace(/\/$/, ""),
    sessionSecret: sessionSecret || "dev-only-insecure-session-secret-change-me",
    sessionCookie: get("SESSION_COOKIE", "aegisbastion_session"),
    orgId: get("DASHBOARD_ORG_ID", "org_acme"),
    tenantId: get("DASHBOARD_TENANT_ID"),
    oidc: issuer
      ? {
          issuer: issuer.replace(/\/$/, ""),
          clientId: get("OIDC_CLIENT_ID"),
          clientSecret: get("OIDC_CLIENT_SECRET"),
          redirectUri: get(
            "OIDC_REDIRECT_URI",
            "http://localhost:3000/api/auth/oidc/callback",
          ),
          scopes: get("OIDC_SCOPES", "openid profile email"),
        }
      : null,
    devAuthEnabled,
    devAuthToken: get("DEV_AUTH_TOKEN"),
    devAuthFallbackRoles: get("DEV_AUTH_FALLBACK_ROLES", "operator")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    stepUpTtlSeconds: Number(get("STEPUP_TTL_SECONDS", "300")) || 300,
  };
  return cached;
}

/** Test hook: reset the cached env. */
export function __resetEnvForTests(): void {
  cached = null;
}
