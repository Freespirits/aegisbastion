/**
 * Node entry (phish-node, doc 07 §2.1/§6.1): .eml intake, batch analysis,
 * the audit log, and the CLI. The hub agent transport lives behind the
 * feature flag in ../hub/ (MVP-B, doc 00 §4).
 */

import PostalMime from "postal-mime";
import type { ClientMeta, Evidence } from "../core/evidence.js";
import type { AnalyzeOptions } from "../core/pipeline.js";
import type { Verdict } from "../core/verdict.js";
import { PhishCatcher, createPhishCatcher, type PhishCatcherOptions } from "../index.js";
import { evidenceFromRawEml } from "./eml.js";

export { evidenceFromRawEml } from "./eml.js";
export { AuditLog, AUDIT_RETENTION_DAYS, type AuditEventType, type AuditRecord } from "./audit-log.js";
export { runCli, EXIT_CLEAN, EXIT_SUSPICIOUS, EXIT_MALICIOUS, EXIT_ERROR, type CliIo } from "./cli.js";
export * from "../index.js";

export type RawEmlInput = string | Uint8Array | ArrayBuffer;

export interface AnalyzeEmlOptions extends AnalyzeOptions {
  clientMeta?: Partial<ClientMeta>;
}

/** `analyze(rawEml | Buffer, opts?) → Promise<Verdict>` (doc 07 §6.1). */
export async function analyze(rawEml: RawEmlInput, opts: AnalyzeEmlOptions & PhishCatcherOptions = {}): Promise<Verdict> {
  const { clientMeta, extraChecks, intel, policy, ...analyzeOpts } = opts;
  const catcher = createPhishCatcher({
    ...(extraChecks !== undefined ? { extraChecks } : {}),
    ...(intel !== undefined ? { intel } : {}),
    ...(policy !== undefined ? { policy } : {}),
  });
  return analyzeWith(catcher, rawEml, { ...analyzeOpts, ...(clientMeta !== undefined ? { clientMeta } : {}) });
}

/** Analyze a raw message with a caller-provided catcher (bundle/policy applied). */
export async function analyzeWith(catcher: PhishCatcher, rawEml: RawEmlInput, opts: AnalyzeEmlOptions = {}): Promise<Verdict> {
  const { clientMeta, ...analyzeOpts } = opts;
  const ev: Evidence = await evidenceFromRawEml(rawEml as never, clientMeta);
  return catcher.analyze(ev, analyzeOpts);
}

/** Batch-score a list of URLs (bulk scoring path used by the CLI). */
export function analyzeUrls(catcher: PhishCatcher, urls: readonly string[], opts: AnalyzeOptions = {}): Verdict[] {
  return urls.map((u) => catcher.analyzeUrl(u, opts));
}

export { PostalMime };
