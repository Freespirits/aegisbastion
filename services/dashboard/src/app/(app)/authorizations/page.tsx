import { getSession } from "@/lib/session";
import { capabilitiesOf } from "@/lib/roles";
import { RoeManager } from "@/components/RoeManager";

export default async function AuthorizationsPage() {
  const session = await getSession();
  const caps = session ? [...capabilitiesOf(session.roles)] : ["read"];
  return (
    <>
      <h1 className="page-title">Authorizations — Rules of Engagement</h1>
      <p className="page-sub">
        RoE records live exclusively in gatekeeper (Ruling B). Create drafts, activate, suspend,
        revoke — all via the gatekeeper admin-api, all step-up gated.
      </p>
      <RoeManager capabilities={caps} />
    </>
  );
}
