/**
 * Append-only local audit log (doc 07 §8.4): JSONL, daily rotation, 30-day
 * retention. Every scan.request (accepted or rejected), policy/bundle
 * application, finding.report flush, and token verification failure is
 * written here; when the hub transport is live (MVP-B) records are mirrored
 * with the agent signature to gatekeeper's audit of record (doc 11 §3.4).
 *
 * Node-only (fs) — never imported by neutral/browser entries.
 */

import { appendFile, mkdir, readdir, rm } from "node:fs/promises";
import { join } from "node:path";

export const AUDIT_RETENTION_DAYS = 30;

export type AuditEventType =
  | "SCAN_REQUEST_ACCEPTED"
  | "SCAN_REQUEST_REJECTED"
  | "POLICY_APPLIED"
  | "POLICY_REJECTED"
  | "BUNDLE_APPLIED"
  | "BUNDLE_REJECTED"
  | "INTEGRITY_FAILURE"
  | "TOKEN_VERIFICATION_FAILURE"
  | "REPORT_FLUSH"
  | "CONSENT_GRANTED";

export interface AuditRecord {
  /** ISO timestamp (set by the sink). */
  ts?: string;
  type: AuditEventType;
  /** Structured detail — MUST be redacted (no content, §5.4). */
  detail: Record<string, unknown>;
}

function dayStamp(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export class AuditLog {
  constructor(
    private readonly dir: string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  private fileFor(day: string): string {
    return join(this.dir, `audit-${day}.jsonl`);
  }

  /** Append one record. Creates the directory lazily. Never throws. */
  async write(record: AuditRecord): Promise<void> {
    try {
      await mkdir(this.dir, { recursive: true });
      const line = JSON.stringify({ ts: this.now().toISOString(), ...record }) + "\n";
      await appendFile(this.fileFor(dayStamp(this.now())), line, "utf8");
    } catch {
      // Local audit failure must never break detection; the hub mirror is
      // the audit of record when online (§8.4).
    }
  }

  /** Retention sweep: delete rotated files older than 30 days (§8.4). */
  async sweep(): Promise<number> {
    let removed = 0;
    try {
      const cutoff = this.now().getTime() - AUDIT_RETENTION_DAYS * 24 * 60 * 60 * 1000;
      for (const name of await readdir(this.dir)) {
        const m = /^audit-(\d{4}-\d{2}-\d{2})\.jsonl$/.exec(name);
        if (!m) continue;
        if (Date.parse(`${m[1]}T00:00:00Z`) < cutoff) {
          await rm(join(this.dir, name), { force: true });
          removed++;
        }
      }
    } catch {
      // best-effort retention
    }
    return removed;
  }
}
