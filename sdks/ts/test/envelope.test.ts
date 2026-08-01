/**
 * Bus envelope + idempotency (doc 01 §8.2).
 */

import { describe, expect, it } from "vitest";
import { create } from "@bufbuild/protobuf";
import { anyUnpack } from "@bufbuild/protobuf/wkt";
import { TaskAssignmentSchema } from "@aegisbastion/gen/aegisbastion/platform/v1/task_pb.js";
import { RiskClass } from "@aegisbastion/gen/aegisbastion/platform/v1/types_pb.js";
import { decodeEnvelope, encodeEnvelope, IdempotencySet, newEnvelope } from "../src/envelope.js";
import { ulid } from "../src/ulid.js";

describe("envelope", () => {
  it("round-trips a typed payload with ULID event_id and fq type", () => {
    const assignment = create(TaskAssignmentSchema, {
      taskId: "tsk_1",
      missionId: "msn_1",
      capability: "monitor.watch",
      riskClass: RiskClass.R1,
      targets: ["api.acme.com"],
    });
    const env = newEnvelope(TaskAssignmentSchema, assignment, {
      missionId: "msn_1",
      traceContext: { traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" },
    });
    expect(env.eventId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(env.type).toBe("aegisbastion.platform.v1.TaskAssignment");
    expect(env.missionId).toBe("msn_1");
    expect(env.traceContext?.traceparent).toContain("4bf92f");

    const decoded = decodeEnvelope(encodeEnvelope(env));
    expect(decoded.eventId).toBe(env.eventId);
    const payload = decoded.payload ? anyUnpack(decoded.payload, TaskAssignmentSchema) : undefined;
    expect(payload?.taskId).toBe("tsk_1");
    expect(payload?.targets).toEqual(["api.acme.com"]);
  });

  it("decode rejects garbage (callers fail closed)", () => {
    expect(() => decodeEnvelope(new TextEncoder().encode("not-protobuf"))).toThrow();
  });
});

describe("IdempotencySet", () => {
  it("reports first sighting once", () => {
    const s = new IdempotencySet(3);
    expect(s.firstSeen("a")).toBe(true);
    expect(s.firstSeen("a")).toBe(false);
    expect(s.firstSeen("b")).toBe(true);
  });

  it("evicts the oldest keys beyond capacity", () => {
    const s = new IdempotencySet(2);
    s.firstSeen("a");
    s.firstSeen("b");
    s.firstSeen("c"); // evicts "a"
    expect(s.firstSeen("b")).toBe(false); // still remembered
    expect(s.firstSeen("a")).toBe(true); // forgotten
  });

  it("ignores empty keys", () => {
    const s = new IdempotencySet(2);
    expect(s.firstSeen("")).toBe(true);
    expect(s.firstSeen("")).toBe(true);
  });
});

describe("ulid", () => {
  it("generates 26-char Crockford-base32 ids, monotonic within a tick", () => {
    const a = ulid(1_800_000_000_000);
    const b = ulid(1_800_000_000_000);
    expect(a).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(b).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(a < b).toBe(true);
    expect(a.slice(0, 10)).toBe(b.slice(0, 10)); // same time component
  });
});
