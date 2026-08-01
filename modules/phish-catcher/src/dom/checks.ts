/**
 * The DOM-family checks (doc 07 §3.2, page-scan mode only — all declare
 * `requires: ["page"]`). Checks consume `PageEvidence` only; DOM walking
 * lives in `dom-adapter.ts`/`page-context.ts` (100% shared check code, §12).
 */

import type { Check, EmittedFinding } from "../core/check.js";
import type { Evidence } from "../core/evidence.js";
import { damerauLevenshtein } from "../url/distance.js";
import { isIpLiteral, parseUrl, registeredDomainOf } from "../url/parse.js";

export { extractPageEvidence, isOffOrigin, type ExtractionResult, type PageDom } from "./page-context.js";
export { extractFromDocument } from "./dom-adapter.js";

/** Brand-host test for the §3.3 hard-fail: listed exactly or typosquat ≤ 2. */
function brandHost(regDomain: string, brands: readonly string[]): string | null {
  for (const brand of brands) {
    if (regDomain === brand) return brand;
    if (regDomain.length >= 5 && damerauLevenshtein(regDomain, brand, 2) <= 2) return brand;
  }
  return null;
}

export const passwordFormOffdomain: Check = {
  id: "dom.password_form_offdomain",
  version: 1,
  family: "dom",
  requires: ["page"],
  defaultWeight: 35,
  run(ev, ctx) {
    const page = ev.page;
    if (!page) return [];
    const findings: EmittedFinding[] = [];
    const pageReg = registeredDomainOf(parseUrl(page.url)?.host ?? "");
    const brand = brandHost(pageReg, ctx.intel.brandDomains());
    for (const form of page.forms ?? []) {
      if (ctx.deadline.expired()) break;
      if (!form.hasPasswordField) continue;
      const actionHost = parseUrl(form.actionOrigin)?.host ?? "";
      const offOrigin = form.actionOrigin !== "" && form.actionOrigin !== page.origin;
      const ipAction = actionHost !== "" && isIpLiteral(actionHost);
      if (offOrigin || ipAction) {
        findings.push({
          ruleId: "dom.password_form_offdomain",
          severity: "critical",
          detail: `password form on "${page.origin}" posts to "${form.actionOrigin || form.action}"${ipAction ? " (IP literal)" : ""}`,
          // §3.3 hard-fail: on a brand-listed (or brand-lookalike) domain.
          ...(brand !== null ? { flags: ["brand_host"] } : {}),
        });
      }
    }
    return findings;
  },
};

export const formPostsHttp: Check = {
  id: "dom.form_posts_http",
  version: 1,
  family: "dom",
  requires: ["page"],
  defaultWeight: 20,
  run(ev) {
    const page = ev.page;
    if (!page) return [];
    const findings: EmittedFinding[] = [];
    for (const form of page.forms ?? []) {
      if (form.action.toLowerCase().startsWith("http://")) {
        findings.push({
          ruleId: "dom.form_posts_http",
          severity: "high",
          detail: `form on "${page.origin}" posts cleartext to "${form.action}"`,
        });
      }
    }
    return findings;
  },
};

export const hiddenIframe: Check = {
  id: "dom.hidden_iframe",
  version: 1,
  family: "dom",
  requires: ["page"],
  defaultWeight: 12,
  run(ev) {
    const page = ev.page;
    if (!page) return [];
    const findings: EmittedFinding[] = [];
    for (const frame of page.iframes ?? []) {
      if (frame.hidden && findings.length < 3) {
        findings.push({
          ruleId: "dom.hidden_iframe",
          severity: "medium",
          detail: `hidden iframe src "${frame.src || "(inline)"}"`,
        });
      }
    }
    return findings;
  },
};

export const overlayClickjack: Check = {
  id: "dom.overlay_clickjack",
  version: 1,
  family: "dom",
  requires: ["page"],
  defaultWeight: 20,
  run(ev) {
    const page = ev.page;
    if (!page || page.hasFullscreenOverlay !== true) return [];
    return [{
      ruleId: "dom.overlay_clickjack",
      severity: "high",
      detail: `full-viewport transparent overlay detected over "${page.origin}"`,
    }];
  },
};

export const titleBrandMismatch: Check = {
  id: "dom.title_brand_mismatch",
  version: 1,
  family: "dom",
  requires: ["page"],
  defaultWeight: 18,
  run(ev, ctx) {
    const page = ev.page;
    if (!page || page.title.trim() === "") return [];
    const pageHost = parseUrl(page.url)?.host ?? "";
    const pageReg = registeredDomainOf(pageHost);
    const title = page.title.toLowerCase();
    for (const brand of ctx.intel.brandDomains()) {
      if (ctx.deadline.expired()) break;
      const sld = brand.split(".")[0] ?? brand;
      if (sld.length < 4) continue;
      const claims = title.includes(brand) || title.includes(sld);
      const isBrand = pageReg === brand || pageHost.endsWith(`.${brand}`);
      if (claims && !isBrand) {
        return [{
          ruleId: "dom.title_brand_mismatch",
          severity: "medium",
          detail: `title "${page.title}" claims "${brand}" but the domain is "${pageHost}"`,
        }];
      }
    }
    return [];
  },
};

/** Signal-weight only (§3.2): external target=_blank without noopener. */
export const blankTargetNoopenerAbsent: Check = {
  id: "dom.blank_target_noopener_absent",
  version: 1,
  family: "dom",
  requires: ["page"],
  defaultWeight: 3,
  run(ev, ctx) {
    const page = ev.page;
    if (!page) return [];
    let count = 0;
    for (const link of page.links ?? []) {
      if (ctx.deadline.expired()) break;
      if (link.target?.toLowerCase() !== "_blank") continue;
      const rel = (link.rel ?? "").toLowerCase();
      if (rel.includes("noopener") || rel.includes("noreferrer")) continue;
      const parsed = parseUrl(link.href);
      if (!parsed) continue;
      const origin = `${parsed.scheme}://${parsed.host}${parsed.port === "" ? "" : `:${parsed.port}`}`;
      if (origin !== page.origin) count++;
    }
    if (count < 2) return [];
    return [{
      ruleId: "dom.blank_target_noopener_absent",
      severity: "info",
      detail: `${count} external target=_blank links without rel=noopener`,
    }];
  },
};

/** The 6 DOM-family MVP checks (doc 07 §3.2; favicon pHash compare = Later). */
export const DOM_CHECKS: readonly Check[] = [
  passwordFormOffdomain,
  formPostsHttp,
  hiddenIframe,
  overlayClickjack,
  titleBrandMismatch,
  blankTargetNoopenerAbsent,
];
