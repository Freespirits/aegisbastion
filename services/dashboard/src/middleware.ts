// Edge middleware: fast cookie-presence guard so unauthenticated browser
// requests bounce to /login before any page render. The sealed session is
// fully verified server-side in the (app) layout — this is UX, not the
// security boundary (every /api route re-verifies).

import { NextRequest, NextResponse } from "next/server";

const PUBLIC_PREFIXES = ["/login", "/api/auth/", "/_next/", "/favicon.ico"];

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (PUBLIC_PREFIXES.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
  }
  const cookie = req.cookies.get(process.env.SESSION_COOKIE ?? "aegisbastion_session");
  if (!cookie?.value) {
    if (pathname.startsWith("/api/")) {
      return NextResponse.json(
        { type: "about:blank", title: "Unauthorized", status: 401, detail: "login required" },
        { status: 401 },
      );
    }
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image).*)"],
};
