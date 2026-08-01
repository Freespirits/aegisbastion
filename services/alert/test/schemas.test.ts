/**
 * Ingress schema validation (doc 05 §5.2, C1): AlertEvent v1 + CloudEvents
 * envelope validated against schemas/alert/v1 (the Phase-0 ratified contract).
 * Invalid payloads are REJECTED before any other processing.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { loadValidators, validationErrors } from "../src/schemas.js";
import { sampleEvent } from "./helpers.js";

const EXAMPLES = resolve(__dirname, "../../../schemas/examples");
const example = (name: string): unknown => JSON.parse(readFileSync(resolve(EXAMPLES, name), "utf8"));

const validators = loadValidators();

describe("AlertEvent v1 schema (schemas/alert/v1)", () => {
  it("accepts the repo's valid detect example", () => {
    expect(validators.alertEvent(example("alert-event.detect.valid.json"))).toBe(true);
  });

  it("accepts the repo's valid monitor-passive example (no token — passive)", () => {
    expect(validators.alertEvent(example("alert-event.monitor-passive.valid.json"))).toBe(true);
  });

  it("accepts the repo's valid CloudEvents envelope", () => {
    expect(validators.envelope(example("cloudevents-envelope.valid.json"))).toBe(true);
  });

  it("rejects the repo's missing-token invalid example (confirmed vuln without authorization_token_id)", () => {
    expect(validators.alertEvent(example("alert-event.missing-token.invalid.json"))).toBe(false);
  });

  it("rejects the repo's bad-source invalid envelope", () => {
    expect(validators.envelope(example("cloudevents-envelope.bad-source.invalid.json"))).toBe(false);
  });

  it("rejects a missing required field (title)", () => {
    const bad = sampleEvent() as unknown as Record<string, unknown>;
    delete bad.title;
    expect(validators.alertEvent(bad)).toBe(false);
    expect(validationErrors(validators.alertEvent).join(" ")).toContain("title");
  });

  it("rejects an invalid severity enum", () => {
    expect(validators.alertEvent(sampleEvent({ severity: "catastrophic" as never }))).toBe(false);
  });

  it("rejects an invalid source_module enum", () => {
    expect(validators.alertEvent(sampleEvent({ source_module: "nuclei" as never }))).toBe(false);
  });

  it("rejects additional properties (additionalProperties: false)", () => {
    const bad = { ...sampleEvent(), authorization_token: "jwt-in-event-is-not-in-the-schema" };
    expect(validators.alertEvent(bad)).toBe(false);
  });

  it("requires authorization_token_id for ddos-engine sources", () => {
    const bad = sampleEvent({ source_module: "ddos-engine", category: "stress-test" });
    expect(validators.alertEvent(bad)).toBe(false);
  });

  it("requires authorization_token_id for confirmed vuln/exposure alerts", () => {
    const bad = sampleEvent({ category: "vuln", confidence: "confirmed" });
    expect(validators.alertEvent(bad)).toBe(false);
  });

  it("accepts confirmed vuln with authorization_token_id", () => {
    const good = sampleEvent({ category: "vuln", confidence: "confirmed", authorization_token_id: "tok_abc" });
    expect(validators.alertEvent(good)).toBe(true);
  });
});
