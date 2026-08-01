/**
 * The auth + content families (doc 07 §3.2). Auth checks trust headers
 * ALREADY PRESENT in the message — no live DNS (§3.2). Content checks run
 * over subject + body text (+ stripped HTML). All pure, all local.
 */

import type { Check, EmittedFinding } from "../core/check.js";
import type { Evidence, MessageEvidence } from "../core/evidence.js";
import { registeredDomainOf } from "../url/parse.js";
import { authResultFor, domainOfAddress, parseMailbox } from "./headers.js";
import { credentialRequestMatches, DEFAULT_URGENCY_LEXICON, messageText, urgencyScore } from "./lexicon.js";
import { classifyAttachment } from "./attachments.js";

export { parseAuthenticationResults, parseReceivedSpf, authResultFor, parseMailbox, domainOfAddress } from "./headers.js";
export { htmlToText, messageText, urgencyScore, credentialRequestMatches, DEFAULT_URGENCY_LEXICON, CREDENTIAL_PATTERNS } from "./lexicon.js";
export { classifyAttachment } from "./attachments.js";

function msg(ev: Evidence): MessageEvidence | null {
  return ev.message ?? null;
}

/** SPF fail/softfail from Authentication-Results or Received-SPF (no DNS). */
export const spfFail: Check = {
  id: "auth.spf_fail",
  version: 1,
  family: "auth",
  requires: ["message"],
  defaultWeight: 25,
  run(ev) {
    const m = msg(ev);
    if (!m) return [];
    const r = authResultFor("spf", m.headers.authenticationResults, m.headers.receivedSpf);
    if (!r) return [];
    if (r.result === "fail") {
      return [{ ruleId: "auth.spf_fail", severity: "high", detail: "SPF result 'fail' for sender domain" }];
    }
    if (r.result === "softfail") {
      return [{ ruleId: "auth.spf_fail", severity: "medium", weight: 15, detail: "SPF result 'softfail' for sender domain" }];
    }
    return [];
  },
};

/** DKIM fail from Authentication-Results (local verify via key cache = Later, §11). */
export const dkimFail: Check = {
  id: "auth.dkim_fail",
  version: 1,
  family: "auth",
  requires: ["message"],
  defaultWeight: 20,
  run(ev) {
    const m = msg(ev);
    if (!m) return [];
    const r = authResultFor("dkim", m.headers.authenticationResults, undefined);
    if (r?.result === "fail") {
      return [{
        ruleId: "auth.dkim_fail",
        severity: "medium",
        detail: "DKIM result 'fail' (header-trust mode — no cached key consulted)",
      }];
    }
    return [];
  },
};

/** DMARC fail from Authentication-Results. Hard-fail combo member (§3.3). */
export const dmarcFail: Check = {
  id: "auth.dmarc_fail",
  version: 1,
  family: "auth",
  requires: ["message"],
  defaultWeight: 35,
  run(ev) {
    const m = msg(ev);
    if (!m) return [];
    const r = authResultFor("dmarc", m.headers.authenticationResults, undefined);
    if (r?.result === "fail") {
      return [{ ruleId: "auth.dmarc_fail", severity: "high", detail: "DMARC result 'fail' for sender domain" }];
    }
    return [];
  },
};

export const fromReplyToMismatch: Check = {
  id: "auth.from_replyto_mismatch",
  version: 1,
  family: "auth",
  requires: ["message"],
  defaultWeight: 8,
  run(ev) {
    const m = msg(ev);
    if (!m) return [];
    const from = parseMailbox(m.headers.from);
    const replyTo = parseMailbox(m.headers.replyTo);
    if (!from || !replyTo) return [];
    const fromDom = registeredDomainOf(domainOfAddress(from.address));
    const replyDom = registeredDomainOf(domainOfAddress(replyTo.address));
    if (fromDom !== "" && replyDom !== "" && fromDom !== replyDom) {
      return [{
        ruleId: "auth.from_replyto_mismatch",
        severity: "low",
        detail: `From domain "${fromDom}" but Reply-To domain "${replyDom}"`,
      }];
    }
    return [];
  },
};

/** Display name claims a brand the address domain doesn't (§3.2). */
export const fromDisplaySpoof: Check = {
  id: "auth.from_display_spoof",
  version: 1,
  family: "auth",
  requires: ["message"],
  defaultWeight: 25,
  run(ev, ctx) {
    const m = msg(ev);
    if (!m) return [];
    const from = parseMailbox(m.headers.from);
    if (!from || from.displayName === "") return [];
    const fromDom = registeredDomainOf(domainOfAddress(from.address));
    const display = from.displayName.toLowerCase();
    const findings: EmittedFinding[] = [];
    for (const brand of ctx.intel.brandDomains()) {
      if (ctx.deadline.expired()) break;
      const sld = brand.split(".")[0] ?? brand;
      if (sld.length < 4) continue;
      const claimsBrand = display.includes(brand) || display.includes(sld);
      const addressIsBrand = fromDom === brand || from.address.endsWith(`@${brand}`) || domainOfAddress(from.address).endsWith(`.${brand}`);
      if (claimsBrand && !addressIsBrand) {
        findings.push({
          ruleId: "auth.from_display_spoof",
          severity: "high",
          detail: `display name "${from.displayName}" claims "${brand}" but the address is "${from.address}"`,
        });
        break;
      }
    }
    return findings;
  },
};

export const returnPathMismatch: Check = {
  id: "auth.return_path_mismatch",
  version: 1,
  family: "auth",
  requires: ["message"],
  defaultWeight: 10,
  run(ev) {
    const m = msg(ev);
    if (!m) return [];
    const from = parseMailbox(m.headers.from);
    const returnPath = parseMailbox(m.headers.returnPath);
    if (!from || !returnPath) return [];
    const fromDom = registeredDomainOf(domainOfAddress(from.address));
    const rpDom = registeredDomainOf(domainOfAddress(returnPath.address));
    if (fromDom !== "" && rpDom !== "" && fromDom !== rpDom) {
      return [{
        ruleId: "auth.return_path_mismatch",
        severity: "low",
        detail: `From domain "${fromDom}" but Return-Path domain "${rpDom}"`,
      }];
    }
    return [];
  },
};

/** Weighted urgency phrase scorer (EN default; bundle lexicon for i18n). */
export const urgencyLexicon: Check = {
  id: "content.urgency_lexicon",
  version: 1,
  family: "content",
  requires: ["message"],
  defaultWeight: 15,
  run(ev, ctx) {
    const m = msg(ev);
    if (!m) return [];
    const text = messageText(m.subject, m.bodyText, m.bodyHtml);
    if (text === "") return [];
    const lexicon = ctx.intel.urgencyLexicon() ?? DEFAULT_URGENCY_LEXICON;
    const { score, matches } = urgencyScore(text, lexicon);
    if (score < 4) return [];
    return [{
      ruleId: "content.urgency_lexicon",
      severity: score >= 12 ? "high" : "medium",
      weight: Math.min(20, score * 2),
      detail: `urgency score ${score}: ${matches.slice(0, 5).map((p) => `"${p}"`).join(", ")}`,
    }];
  },
};

/** Asks for password/OTP/seed phrase patterns (§3.2). Hard-fail combo member. */
export const credentialRequest: Check = {
  id: "content.credential_request",
  version: 1,
  family: "content",
  requires: ["message"],
  defaultWeight: 30,
  run(ev) {
    const m = msg(ev);
    if (!m) return [];
    const text = messageText(m.subject, m.bodyText, m.bodyHtml);
    if (text === "") return [];
    const labels = credentialRequestMatches(text);
    if (labels.length === 0) return [];
    return [{
      ruleId: "content.credential_request",
      severity: "high",
      detail: `message requests credentials: ${labels.join(", ")}`,
    }];
  },
};

export const attachmentRisk: Check = {
  id: "content.attachment_risk",
  version: 1,
  family: "content",
  requires: ["message"],
  defaultWeight: 20,
  run(ev, ctx) {
    const m = msg(ev);
    if (!m?.attachments || m.attachments.length === 0) return [];
    const findings: EmittedFinding[] = [];
    for (const att of m.attachments) {
      if (ctx.deadline.expired()) break;
      const risk = classifyAttachment(att);
      if (risk) {
        findings.push({ ruleId: "content.attachment_risk", severity: risk.severity, weight: risk.weight, detail: risk.detail });
      }
    }
    return findings;
  },
};

/** The 6 auth-family + 3 content-family MVP checks (doc 07 §3.2/§11). */
export const CONTENT_CHECKS: readonly Check[] = [
  spfFail,
  dkimFail,
  dmarcFail,
  fromReplyToMismatch,
  fromDisplaySpoof,
  returnPathMismatch,
  urgencyLexicon,
  credentialRequest,
  attachmentRisk,
];
