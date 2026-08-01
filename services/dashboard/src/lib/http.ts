// BFF proxy plumbing (doc 10 §2.1 REST API svc: "proxying to the owning
// platform service"). Conventions per doc 10 §4.4: upstream problem+json and
// gatekeeper/platform error bodies are passed through with their
// machine-readable reason codes intact; every response carries X-Request-Id;
// an unreachable backend is a 503 + Retry-After (doc 10 §8), never a silent
// 500, and offensive paths fail closed.

import { NextResponse } from "next/server";

export class BackendUnavailable extends Error {
  constructor(
    public readonly backend: string,
    cause: unknown,
  ) {
    super(`${backend} unavailable: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "BackendUnavailable";
  }
}

/** RFC 9457 problem+json response (doc 10 §4.4). */
export function problem(
  status: number,
  title: string,
  detail?: string,
  extra?: Record<string, unknown>,
): NextResponse {
  return NextResponse.json(
    { type: "about:blank", title, status, ...(detail ? { detail } : {}), ...extra },
    {
      status,
      headers: {
        "content-type": "application/problem+json",
        ...(status === 503 ? { "retry-after": "5" } : {}),
      },
    },
  );
}

/** Fetch an upstream service with a request id and a hard timeout. */
export async function backendFetch(
  backend: string,
  url: string,
  init: RequestInit = {},
  timeoutMs = 10_000,
): Promise<{ res: Response; requestId: string }> {
  const requestId = crypto.randomUUID();
  const headers = new Headers(init.headers);
  headers.set("x-request-id", requestId);
  try {
    const res = await fetch(url, {
      ...init,
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(timeoutMs),
    });
    return { res, requestId };
  } catch (err) {
    throw new BackendUnavailable(backend, err);
  }
}

/** Pass an upstream response through verbatim (status + body + content type). */
export async function passthrough(res: Response, requestId: string): Promise<NextResponse> {
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") ?? "application/json",
      "x-request-id": requestId,
    },
  });
}

/** Proxy one call; converts transport failure into the doc 10 §8 503 shape. */
export async function proxy(
  backend: string,
  url: string,
  init: RequestInit = {},
  timeoutMs?: number,
): Promise<NextResponse> {
  try {
    const { res, requestId } = await backendFetch(backend, url, init, timeoutMs);
    return passthrough(res, requestId);
  } catch (err) {
    if (err instanceof BackendUnavailable) {
      return problem(503, "Backend Unavailable", err.message, { backend });
    }
    throw err;
  }
}

/** Forward a typed-client call ({res, requestId}) with §8 failure mapping. */
export async function forward(
  call: Promise<{ res: Response; requestId: string }>,
): Promise<NextResponse> {
  try {
    const { res, requestId } = await call;
    return passthrough(res, requestId);
  } catch (err) {
    if (err instanceof BackendUnavailable) {
      return problem(503, "Backend Unavailable", err.message, { backend: err.backend });
    }
    throw err;
  }
}

/** Parse a JSON body; returns null when absent/invalid. */
export async function readJson<T = unknown>(req: Request): Promise<T | null> {
  try {
    const text = await req.text();
    if (!text) return null;
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}
