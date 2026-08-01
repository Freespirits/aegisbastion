import { getSession } from "@/lib/session";
import { capabilitiesOf } from "@/lib/roles";
import { AlertRules } from "@/components/AlertRules";

export default async function AlertRulesPage() {
  const session = await getSession();
  const caps = session ? [...capabilitiesOf(session.roles)] : ["read"];
  return (
    <>
      <h1 className="page-title">Alert Rules</h1>
      <p className="page-sub">
        Notification routing policies, managed through herald&apos;s control API (doc 05 §4.1).
        Herald owns delivery end-to-end — this console is a client only (Ruling C7).
      </p>
      <AlertRules capabilities={caps} orgId={session?.orgId ?? ""} />
    </>
  );
}
