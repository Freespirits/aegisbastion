import { AssetsExplorer } from "@/components/AssetsExplorer";

export default function AssetsPage() {
  return (
    <>
      <h1 className="page-title">Attack Surface</h1>
      <p className="page-sub">
        Assets and relationships, read from the data platform (doc 09 Query API — the system of
        record, Ruling C4), tenant-scoped by TPEL.
      </p>
      <AssetsExplorer />
    </>
  );
}
