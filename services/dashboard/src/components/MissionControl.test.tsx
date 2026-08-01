// Mission control RBAC gating: without the missions.control affordance the
// pause/resume/kill controls are disabled with an explanation.

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MissionControl } from "@/components/MissionControl";
import type { Mission } from "@/lib/types";

const MISSION: Mission = {
  mission_id: "msn_01J8ZK",
  name: "acme watch",
  owning_commander: "COMMANDER_HEXSTRIKE",
  objective: "map and monitor acme.com",
  roe_id: "roe_01J7AA",
  roe_version: "3",
  created_by: "op_jane@example.com",
  created_at: "2026-07-30T06:00:00Z",
  state: "MISSION_STATE_ACTIVE",
};

afterEach(cleanup);

describe("MissionControl — RBAC-gated buttons", () => {
  it("disables pause/resume/kill without missions.control", () => {
    render(<MissionControl capabilities={["read"]} created={MISSION} />);
    expect(screen.getByTestId("control-denied")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "pause" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "resume" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "kill" })).toBeDisabled();
  });

  it("enables pause for controllers on an ACTIVE mission, resume only when PAUSED", () => {
    render(<MissionControl capabilities={["read", "missions.control"]} created={MISSION} />);
    expect(screen.queryByTestId("control-denied")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "pause" })).toBeEnabled();
    // ACTIVE → resume does not apply.
    expect(screen.getByRole("button", { name: "resume" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "kill" })).toBeEnabled();
  });

  it("enables resume on a PAUSED mission and disables pause", () => {
    render(
      <MissionControl
        capabilities={["read", "missions.control"]}
        created={{ ...MISSION, state: "MISSION_STATE_PAUSED" }}
      />,
    );
    expect(screen.getByRole("button", { name: "resume" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "pause" })).toBeDisabled();
  });

  it("disables kill on a KILLED mission (terminal)", () => {
    render(
      <MissionControl
        capabilities={["read", "missions.control"]}
        created={{ ...MISSION, state: "MISSION_STATE_KILLED" }}
      />,
    );
    expect(screen.getByRole("button", { name: "kill" })).toBeDisabled();
  });

  it("hides the audit-trail button without audit.view", () => {
    render(<MissionControl capabilities={["read", "missions.control"]} created={MISSION} />);
    expect(screen.queryByRole("button", { name: "audit trail" })).not.toBeInTheDocument();
  });

  it("shows the audit-trail button with audit.view", () => {
    render(
      <MissionControl capabilities={["read", "missions.control", "audit.view"]} created={MISSION} />,
    );
    expect(screen.getByRole("button", { name: "audit trail" })).toBeInTheDocument();
  });
});
