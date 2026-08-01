// Findings board: list rendering with a mocked GraphQL backend, plus the
// RBAC gate on lifecycle-transition buttons.

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FindingsBoard } from "@/components/FindingsBoard";
import type { GqlFinding } from "@/lib/types";

const FINDING: GqlFinding = {
  findingId: "11111111-1111-4111-8111-111111111111",
  assetUid: "asset-uid-1",
  module: "detect",
  checkId: "nuclei:cve-2024-0001",
  title: "Exposed admin panel",
  severity: "high",
  state: "triaged",
  validation: { verdict: "CONFIRMED" },
  risk: { score: 8.4 },
  evidenceRef: "s3://evidence/abc",
  occurrence: 3,
  firstSeen: "2026-07-30T06:00:00Z",
  lastSeen: "2026-07-31T04:00:00Z",
  taskId: "task-1",
  sensitive: false,
  createdAt: "2026-07-30T06:00:00Z",
  updatedAt: "2026-07-31T04:00:00Z",
  transitions: [
    { fromState: null, toState: "new", actor: { Type: "service", ID: "detect" }, note: null, ts: "2026-07-30T06:00:00Z" },
    { fromState: "new", toState: "triaged", actor: { Type: "human", ID: "op_jane" }, note: null, ts: "2026-07-30T07:00:00Z" },
  ],
};

function graphqlResponse(findings: GqlFinding[]): Response {
  return new Response(
    JSON.stringify({
      data: {
        findings: {
          nodes: findings,
          pageInfo: { hasNextPage: false, endCursor: null, totalCount: findings.length },
        },
      },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === "/api/graphql") return graphqlResponse([FINDING]);
    if (url.startsWith("/api/findings/") && init?.method === "POST") {
      return new Response(JSON.stringify({ changed: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("not found", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("FindingsBoard — findings list rendering (mocked GraphQL)", () => {
  it("renders findings from the data platform with severity, state and counts", async () => {
    render(<FindingsBoard capabilities={["read", "findings.triage"]} />);
    expect(await screen.findByText("Exposed admin panel")).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "high" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "triaged" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "3" })).toBeInTheDocument();
    expect(screen.getByText("1 findings in this tenant")).toBeInTheDocument();
    // Went through the BFF proxy, never to a backend URL directly.
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/graphql",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("shows the empty state when nothing matches", async () => {
    fetchMock.mockImplementation(async () => graphqlResponse([]));
    render(<FindingsBoard capabilities={["read"]} />);
    expect(await screen.findByText("no findings match the filter")).toBeInTheDocument();
  });

  it("opens the detail panel with lifecycle history on row click", async () => {
    render(<FindingsBoard capabilities={["read", "findings.triage"]} />);
    const user = userEvent.setup();
    await user.click(await screen.findByText("Exposed admin panel"));
    expect(await screen.findByTestId("finding-detail")).toBeInTheDocument();
    expect(screen.getByText(/nuclei:cve-2024-0001/)).toBeInTheDocument();
    // doc 04 §7.3 edges from "triaged": validating + false_positive.
    expect(screen.getByRole("button", { name: "→ validating" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "→ false_positive" })).toBeEnabled();
  });

  it("posts a transition through the BFF and reloads", async () => {
    render(<FindingsBoard capabilities={["read", "findings.triage"]} />);
    const user = userEvent.setup();
    await user.click(await screen.findByText("Exposed admin panel"));
    await user.click(await screen.findByRole("button", { name: "→ validating" }));
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        `/api/findings/${FINDING.findingId}/transitions`,
        expect.objectContaining({ method: "POST" }),
      );
    });
  });
});

describe("FindingsBoard — RBAC-gated transition buttons", () => {
  it("disables transitions and explains why without the findings.triage affordance", async () => {
    render(<FindingsBoard capabilities={["read"]} />);
    const user = userEvent.setup();
    await user.click(await screen.findByText("Exposed admin panel"));
    expect(await screen.findByTestId("triage-denied")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "→ validating" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "→ false_positive" })).toBeDisabled();
  });
});
