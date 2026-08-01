// Authenticated app shell: the real server-side login guard. Middleware only
// checks cookie presence; HERE the sealed session is verified, and
// unauthenticated requests are redirected (the "login guard").

import { redirect } from "next/navigation";
import { getSession, hasStepUp } from "@/lib/session";
import { Shell } from "@/components/Shell";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  if (!session) redirect("/login");
  return (
    <Shell
      session={{
        sub: session.sub,
        name: session.name,
        orgId: session.orgId,
        roles: session.roles,
        dev: session.dev,
      }}
      stepUpActive={hasStepUp(session)}
    >
      {children}
    </Shell>
  );
}
