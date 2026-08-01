/**
 * The reputation-family checks (doc 07 §3.2): offline reputation via the
 * signed intel bundle — Bloom-filter membership with exact-hash confirmation
 * (fp rate ≤ 0.1%; the exact table removes residual false positives before
 * any verdict, §3.2/§9). All lookups are local (§7.2: "the privacy property
 * and the availability property are the same property"). When the bundle is
 * stale (`ctx.degradedIntel`), checks skip — the engine zeroes the family
 * weight anyway (§9 degraded_mode).
 *
 * `rep.url_blocklisted` positives are exact-confirmed by construction (the
 * IntelReaders contract), so they carry the "exact" flag that drives the
 * normative hard-fail rule (§3.3).
 */

import type { Check, EmittedFinding } from "../core/check.js";
import { collectUrls } from "../url/parse.js";
import { domainOfAddress, parseMailbox } from "../content/headers.js";

export const domainBlocklisted: Check = {
  id: "rep.domain_blocklisted",
  version: 1,
  family: "reputation",
  requires: [],
  defaultWeight: 70,
  run(ev, ctx) {
    if (ctx.degradedIntel) return [];
    const findings: EmittedFinding[] = [];
    const seen = new Set<string>();
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      const dom = inst.registeredDomain;
      if (dom === "" || seen.has(dom)) continue;
      if (ctx.intel.isDomainBlocklisted(dom)) {
        seen.add(dom);
        findings.push({
          ruleId: "rep.domain_blocklisted",
          severity: "high",
          detail: `domain "${dom}" is on the current blocklist (bundle ${ctx.intel.bundleVersion()})`,
        });
      }
    }
    return findings;
  },
};

export const urlBlocklisted: Check = {
  id: "rep.url_blocklisted",
  version: 1,
  family: "reputation",
  requires: [],
  defaultWeight: 100,
  run(ev, ctx) {
    if (ctx.degradedIntel) return [];
    const findings: EmittedFinding[] = [];
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      if (ctx.intel.isUrlBlocklisted(inst.raw)) {
        findings.push({
          ruleId: "rep.url_blocklisted",
          severity: "critical",
          // Bloom positive + exact-hash confirm = "exact" (§3.3 hard fail).
          flags: ["exact"],
          detail: `URL "${inst.raw.slice(0, 120)}" is an exact blocklist match (bundle ${ctx.intel.bundleVersion()})`,
        });
      }
    }
    return findings;
  },
};

export const senderBlocklisted: Check = {
  id: "rep.sender_blocklisted",
  version: 1,
  family: "reputation",
  requires: ["message"],
  defaultWeight: 60,
  run(ev, ctx) {
    if (ctx.degradedIntel) return [];
    const m = ev.message;
    if (!m) return [];
    const findings: EmittedFinding[] = [];
    const seen = new Set<string>();
    const candidates = [m.headers.from, m.headers.returnPath];
    for (const header of candidates) {
      if (ctx.deadline.expired()) break;
      const mailbox = parseMailbox(header);
      if (!mailbox) continue;
      const addr = mailbox.address;
      if (addr === "" || seen.has(addr)) continue;
      seen.add(addr);
      if (ctx.intel.isSenderBlocklisted(addr)) {
        findings.push({
          ruleId: "rep.sender_blocklisted",
          severity: "high",
          detail: `sender "${addr}" is on the current blocklist (bundle ${ctx.intel.bundleVersion()})`,
        });
        continue;
      }
      // Domain-level sender blocklist entry (blocklistEntry.domain form).
      const dom = domainOfAddress(addr);
      if (dom !== "" && ctx.intel.isDomainBlocklisted(dom)) {
        findings.push({
          ruleId: "rep.sender_blocklisted",
          severity: "high",
          weight: 50,
          detail: `sender domain "${dom}" is on the current blocklist (bundle ${ctx.intel.bundleVersion()})`,
        });
      }
    }
    return findings;
  },
};

/** The 3 reputation-family MVP checks (doc 07 §3.2; cert-age = Later). */
export const REP_CHECKS: readonly Check[] = [
  domainBlocklisted,
  urlBlocklisted,
  senderBlocklisted,
];
