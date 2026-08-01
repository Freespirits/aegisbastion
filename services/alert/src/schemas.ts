/**
 * AlertEvent v1 + CloudEvents envelope validation (doc 05 §5.1/§5.2).
 * The JSON Schemas in schemas/alert/v1 are the single source of truth — this
 * module only compiles them with ajv (draft 2020-12) exactly like
 * scripts/validate-schemas.mjs does. Invalid payloads are rejected at ingress
 * (C1) before any other processing.
 */

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type { ValidateFunction } from "ajv";
import type { AlertEnvelope, AlertEvent } from "./types.js";

export const ALERT_EVENT_SCHEMA_ID = "https://aegisbastion.io/schemas/alert/v1/alert-event.schema.json";
export const ALERT_ENVELOPE_SCHEMA_ID = "https://aegisbastion.io/schemas/alert/v1/cloudevents-alert-envelope.schema.json";

function defaultSchemaDir(): string {
  // src/schemas.ts (or dist/schemas.js) → repo root → schemas/alert/v1.
  const here = fileURLToPath(new URL(".", import.meta.url));
  return resolve(here, "../../../schemas/alert/v1");
}

export interface AlertValidators {
  alertEvent: ValidateFunction<AlertEvent>;
  envelope: ValidateFunction<AlertEnvelope>;
}

export function loadValidators(schemaDir: string = process.env.SCHEMA_DIR ?? defaultSchemaDir()): AlertValidators {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);
  const eventRaw = JSON.parse(readFileSync(join(schemaDir, "alert-event.schema.json"), "utf8"));
  const envelopeRaw = JSON.parse(readFileSync(join(schemaDir, "cloudevents-alert-envelope.schema.json"), "utf8"));
  ajv.addSchema(eventRaw);
  ajv.addSchema(envelopeRaw);
  return {
    alertEvent: ajv.getSchema<AlertEvent>(ALERT_EVENT_SCHEMA_ID)!,
    envelope: ajv.getSchema<AlertEnvelope>(ALERT_ENVELOPE_SCHEMA_ID)!,
  };
}

/** ajv errors → compact, log-safe strings (no payload echo beyond paths). */
export function validationErrors(validate: ValidateFunction<unknown>): string[] {
  return (validate.errors ?? []).map((e) => `${e.instancePath || "/"} ${e.message ?? "invalid"}`);
}
