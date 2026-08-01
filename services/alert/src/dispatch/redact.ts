/**
 * Data minimization / redaction (doc 05 §13.3): for pii|pci|hipaa payloads,
 * evidence bodies are redacted to type + location hash for chat channels
 * (Slack/Teams); full evidence goes only to destinations explicitly flagged
 * `evidence_grade: full` in the org egress policy. Raw payloads never leave
 * the platform in default templates.
 */

import { createHash } from "node:crypto";
import type { AlertEvent } from "../types.js";

export function redactEventForTarget(event: AlertEvent, evidenceGrade: "full" | "redacted" | undefined): AlertEvent {
  const pii = event.pii_classification ?? "none";
  if (pii === "none" || evidenceGrade === "full" || !event.evidence) {
    return event;
  }
  const proofStr = safeStringify(event.evidence.proof);
  const locationHash = createHash("sha256").update(proofStr).digest("hex").slice(0, 16);
  return {
    ...event,
    evidence: {
      ...(event.evidence.scanner ? { scanner: event.evidence.scanner } : {}),
      proof: {
        redacted: true,
        type: pii,
        detail: `${pii.toUpperCase()}-classified evidence withheld (location hash sha256:${locationHash})`,
      },
      ...(event.evidence.references ? { references: event.evidence.references } : {}),
    },
  };
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? "";
  } catch {
    return String(v);
  }
}
