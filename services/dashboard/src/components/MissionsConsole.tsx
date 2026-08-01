"use client";

import { useState } from "react";
import { MissionControl } from "@/components/MissionControl";
import { MissionLaunch } from "@/components/MissionLaunch";
import type { Mission } from "@/lib/types";

export function MissionsConsole({ capabilities }: { capabilities: string[] }) {
  const [created, setCreated] = useState<Mission | null>(null);
  return (
    <>
      <MissionLaunch capabilities={capabilities} onCreated={setCreated} />
      <MissionControl capabilities={capabilities} created={created} />
    </>
  );
}
