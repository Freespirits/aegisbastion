// Login guard: the edge middleware bounces cookie-less requests to /login
// (pages) or 401s them (API), and lets authenticated/public requests through.

import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { middleware } from "@/middleware";

function req(path: string, withCookie = false): NextRequest {
  const r = new NextRequest(new URL(`http://localhost:3000${path}`));
  if (withCookie) {
    r.cookies.set("aegisbastion_session", "sealed-value");
  }
  return r;
}

describe("middleware login guard", () => {
  it("redirects unauthenticated page requests to /login, preserving the target", () => {
    const res = middleware(req("/findings"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("http://localhost:3000/login?next=%2Ffindings");
  });

  it("returns 401 JSON for unauthenticated API requests (no redirect)", () => {
    const res = middleware(req("/api/graphql"));
    expect(res.status).toBe(401);
  });

  it("lets authenticated requests through", () => {
    const res = middleware(req("/findings", true));
    // NextResponse.next() has no redirect location.
    expect(res.headers.get("location")).toBeNull();
  });

  it("never guards the login page or auth endpoints", () => {
    for (const path of ["/login", "/api/auth/session", "/api/auth/dev-login"]) {
      const res = middleware(req(path));
      expect(res.headers.get("location")).toBeNull();
      expect(res.status).not.toBe(401);
    }
  });
});
