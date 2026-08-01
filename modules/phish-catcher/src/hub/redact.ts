/**
 * §5.4 redaction for `finding.report` (non-negotiable):
 *  - URLs → salted SHA-256 (salt from hub, rotated every 24 h) unless org
 *    policy explicitly allows cleartext host only;
 *  - email body/subject → NEVER sent; attachment content → never sent
 *    (hash + type only);
 *  - sender → hashed; Message-ID → hashed; no screenshots.
 *
 * The redactor is pure: the salt is injected (hub-issued), hashing is the
 * local SHA-256 (intel/sha256.ts). What is NOT in the output type cannot
 * leak — the report schema has no body/subject fields at all.
 */

import type { Evidence } from "../core/evidence.js";
import type { Verdict } from "../core/verdict.js";
import { parseMailbox } from "../content/headers.js";
import { sha256Hex } from "../intel/sha256.js";
import type { FindingReportPayload } from "./messages.js";

export interface RedactionContext {
  /** Hub-issued salt (rotated every 24 h, §5.4). */
  urlSalt: string;
  /** Org policy: cleartext host only (never full URL) instead of hashes. */
  allowCleartextHost?: boolean;
  consent: FindingReportPayload["consent"];
}

function hashUrl(raw: string, ctx: RedactionContext): string {
  if (ctx.allowCleartextHost === true) {
    try {
      return `host:${new URL(raw).hostname.toLowerCase()}`;
    } catch {
      return `host:`;
    }
  }
  return `sha256:${sha256Hex(`${ctx.urlSalt}${raw}`)}`;
}

/** Build a redacted FindingReport from Evidence + Verdict. */
export function redactFindingReport(
  ev: Evidence,
  verdict: Verdict,
  ctx: RedactionContext,
  reportId: string,
  now: Date = new Date(),
): FindingReportPayload {
  const urls: string[] = [];
  if (ev.url) urls.push(ev.url.raw);
  if (ev.message?.urls) urls.push(...ev.message.urls);
  if (ev.page) urls.push(ev.page.url);

  const report: FindingReportPayload = {
    schemaVersion: 1,
    reportId,
    ts: now.toISOString(),
    kind: ev.kind,
    verdict: verdict.verdict,
    score: verdict.score,
    ruleIds: [...new Set(verdict.findings.map((f) => f.ruleId))],
    urlHashes: urls.map((u) => hashUrl(u, ctx)),
    clientMeta: { ...verdict.clientMeta },
    consent: ctx.consent,
  };

  if (ev.message) {
    const from = parseMailbox(ev.message.headers.from);
    if (from) report.senderHash = `sha256:${sha256Hex(`${ctx.urlSalt}${from.address}`)}`;
    if (ev.message.headers.messageId !== undefined) {
      report.messageIdHash = `sha256:${sha256Hex(`${ctx.urlSalt}${ev.message.headers.messageId}`)}`;
    }
    if (ev.message.attachments && ev.message.attachments.length > 0) {
      report.attachments = ev.message.attachments.map((a) => ({
        sha256: a.sha256 ?? "",
        contentType: a.contentType,
      }));
    }
  }
  return report;
}

/** Local report queue: ring buffer, max 500, drop oldest first (§5.4). */
export class ReportQueue {
  private items: FindingReportPayload[] = [];
  constructor(private readonly max = 500) {}

  enqueue(report: FindingReportPayload): void {
    this.items.push(report);
    if (this.items.length > this.max) {
      this.items.splice(0, this.items.length - this.max);
    }
  }

  /** Drain up to `n` reports (opportunistic flush, §5.4). */
  drain(n = this.items.length): FindingReportPayload[] {
    return this.items.splice(0, Math.min(n, this.items.length));
  }

  /** Requeue reports that failed to flush (newest wins on overflow). */
  requeue(reports: FindingReportPayload[]): void {
    this.items = [...reports, ...this.items];
    if (this.items.length > this.max) {
      this.items.length = this.max;
    }
  }

  get size(): number {
    return this.items.length;
  }
}
