import { getSession } from "@/lib/session";
import { capabilitiesOf } from "@/lib/roles";
import { MissionsConsole } from "@/components/MissionsConsole";

export default async function MissionsPage() {
  const session = await getSession();
  const caps = session ? [...capabilitiesOf(session.roles)] : ["read"];
  return (
    <>
      <h1 className="page-title">Missions</h1>
      <p className="page-sub">
        Gated launch via the platform-core Mission API and mission pause/resume/kill. The
        Orchestrator&apos;s dispatch PEP calls gatekeeper before any R1+ task — no mission here
        bypasses the gate (doc 10 §7.1, Ruling B).
      </p>
      <MissionsConsole capabilities={caps} />
    </>
  );
}
