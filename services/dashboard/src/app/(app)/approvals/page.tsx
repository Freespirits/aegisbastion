import { getSession } from "@/lib/session";
import { capabilitiesOf } from "@/lib/roles";
import { ApprovalsQueue } from "@/components/ApprovalsQueue";

export default async function ApprovalsPage() {
  const session = await getSession();
  const caps = session ? [...capabilitiesOf(session.roles)] : ["read"];
  return (
    <>
      <h1 className="page-title">Approval Queue</h1>
      <p className="page-sub">
        Pending four-eyes approvals for offensive work (R3 always; R2 stress.* on production —
        Ruling B.4). Recorded by gatekeeper&apos;s approval-service with segregation of duties.
      </p>
      <ApprovalsQueue capabilities={caps} principal={session?.sub ?? ""} />
    </>
  );
}
