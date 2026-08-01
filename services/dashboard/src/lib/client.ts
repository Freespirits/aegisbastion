// Browser-side fetch helpers. The ONLY backend the browser ever talks to is
// this app's own /api/* BFF surface (doc 10 §2.1 — no downstream URLs or
// tokens in the client).

export interface ClientSession {
  sub: string;
  name: string;
  orgId: string;
  roles: string[];
  dev: boolean;
}

export interface SessionInfo {
  authenticated: boolean;
  oidcEnabled: boolean;
  devAuthEnabled: boolean;
  session?: ClientSession;
  capabilities?: string[];
  stepUp?: { active: boolean; until: number | null };
}

export async function fetchSession(): Promise<SessionInfo> {
  const res = await fetch("/api/auth/session", { cache: "no-store" });
  return (await res.json()) as SessionInfo;
}

/** Error shape thrown for non-2xx BFF responses; carries the upstream body. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
  ) {
    super(
      typeof body === "object" && body !== null && "detail" in body
        ? String((body as { detail: unknown }).detail)
        : typeof body === "object" && body !== null && "error" in body
          ? JSON.stringify((body as { error: unknown }).error)
          : `HTTP ${status}`,
    );
    this.name = "ApiError";
  }
}

async function parse(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export async function api<T = unknown>(
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<T> {
  const res = await fetch(path, {
    method: init.method ?? "GET",
    headers: init.body !== undefined ? { "content-type": "application/json" } : undefined,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    cache: "no-store",
  });
  const data = await parse(res);
  if (!res.ok) throw new ApiError(res.status, data);
  return data as T;
}

/** GraphQL read via the BFF proxy (doc 09 §5 query contract). */
export async function gql<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
  const res = await api<{ data?: T; errors?: { message: string }[] }>("/api/graphql", {
    method: "POST",
    body: { query, variables: variables ?? {} },
  });
  if (res.errors?.length) throw new Error(res.errors.map((e) => e.message).join("; "));
  if (res.data === undefined) throw new Error("empty GraphQL response");
  return res.data;
}
