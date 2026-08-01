import { Suspense } from "react";
import { env } from "@/env";
import { LoginForm } from "@/components/LoginForm";

// Reads server env — never prerender.
export const dynamic = "force-dynamic";

export default function LoginPage() {
  const e = env();
  return (
    <div className="login-wrap">
      <Suspense>
        <LoginForm oidcEnabled={!!e.oidc} devAuthEnabled={e.devAuthEnabled} />
      </Suspense>
    </div>
  );
}
