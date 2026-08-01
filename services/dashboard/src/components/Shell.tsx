"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import type { ClientSession } from "@/lib/client";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/assets", label: "Attack Surface" },
  { href: "/findings", label: "Findings" },
  { href: "/missions", label: "Missions" },
  { href: "/authorizations", label: "Authorizations (RoE)" },
  { href: "/approvals", label: "Approval Queue" },
  { href: "/alert-rules", label: "Alert Rules" },
];

export function Shell({
  session,
  stepUpActive,
  children,
}: {
  session: ClientSession;
  stepUpActive: boolean;
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/login");
    router.refresh();
  }

  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">
          STRIKE<span>48</span>
        </div>
        {NAV.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={`navlink${pathname === item.href ? " active" : ""}`}
          >
            {item.label}
          </Link>
        ))}
        <div className="userbox">
          <div className="mono" style={{ color: "var(--fg)" }}>
            {session.name}
          </div>
          <div>{session.orgId}</div>
          <div className="mt">
            {session.roles.length ? session.roles.join(", ") : "read-only"}
            {session.dev ? " · dev" : ""}
          </div>
          <div className="mt">
            <span className={`pill ${stepUpActive ? "ok" : ""}`}>
              {stepUpActive ? "step-up active" : "no step-up"}
            </span>
          </div>
          <div className="mt">
            <button type="button" onClick={logout}>
              Sign out
            </button>
          </div>
        </div>
      </nav>
      <main className="main">{children}</main>
    </div>
  );
}
