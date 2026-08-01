/**
 * Normalizers (doc 07 §2.2 step 1): raw input → one immutable `Evidence`.
 * The URL normalizer lives in phish-url (`evidenceFromUrl`) because it needs
 * host/registered-domain/punycode parsing; these are pure data assembly.
 */

import { freezeEvidence, EVIDENCE_SCHEMA_VERSION, type ClientMeta, type Evidence, type MessageEvidence, type PageEvidence } from "./evidence.js";
import { DEFAULT_POLICY } from "./policy.js";
import { LIB_VERSION } from "./version.js";

export function defaultClientMeta(overrides: Partial<ClientMeta> = {}): ClientMeta {
  return {
    libVersion: LIB_VERSION,
    bundleVersion: "none",
    policyVersion: DEFAULT_POLICY.policyVersion,
    ...overrides,
  };
}

export interface EmailParts extends MessageEvidence {
  clientMeta?: Partial<ClientMeta>;
}

export function evidenceFromEmail(parts: EmailParts): Evidence {
  const { clientMeta, ...message } = parts;
  return freezeEvidence({
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    kind: "email",
    message,
    clientMeta: defaultClientMeta(clientMeta),
  });
}

export interface PageParts extends PageEvidence {
  clientMeta?: Partial<ClientMeta>;
}

export function evidenceFromPage(parts: PageParts): Evidence {
  const { clientMeta, ...page } = parts;
  return freezeEvidence({
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    kind: "page",
    page,
    clientMeta: defaultClientMeta(clientMeta),
  });
}

/** Re-stamp clientMeta (bundle/policy versions) without unfreezing callers. */
export function withClientMeta(ev: Evidence, meta: Partial<ClientMeta>): Evidence {
  const clone: Evidence = {
    ...ev,
    clientMeta: { ...ev.clientMeta, ...meta },
  };
  return freezeEvidence(clone);
}
