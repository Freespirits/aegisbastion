import { getSession } from "@/lib/session";
import { capabilitiesOf } from "@/lib/roles";
import { FindingsBoard } from "@/components/FindingsBoard";

export default async function FindingsPage() {
  const session = await getSession();
  const caps = session ? [...capabilitiesOf(session.roles)] : ["read"];
  return (
    <>
      <h1 className="page-title">Findings</h1>
      <p className="page-sub">
        Triage queue over the data platform&apos;s findings store (doc 09, Ruling C4). Lifecycle
        edges (doc 04 §7.3) are enforced by 09 — invalid transitions come back as problem+json.
      </p>
      <FindingsBoard capabilities={caps} />
    </>
  );
}
