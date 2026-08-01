/**
 * The URL-family checks (doc 07 §3.2 — 12 normative rule ids). Pure,
 * synchronous, local-only: no DNS, no unshortening, no fetching (§1). Every
 * check polls the deadline token in its instance loop (§2.3).
 */

import type { Check, CheckContext, EmittedFinding } from "../core/check.js";
import type { Evidence, UrlEvidence, ClientMeta } from "../core/evidence.js";
import { freezeEvidence, EVIDENCE_SCHEMA_VERSION } from "../core/evidence.js";
import { defaultClientMeta } from "../core/normalize.js";
import { skeleton } from "./confusables.js";
import { damerauLevenshtein } from "./distance.js";
import { shannonEntropy } from "./entropy.js";
import { collectUrls, domainLikeInText, isIpLiteral, parseUrl, registeredDomainOf, type UrlInstance } from "./parse.js";
import { DEFAULT_TLD_RISK, KNOWN_SHORTENERS } from "./tables.js";

export { parseUrl, collectUrls, registeredDomainOf, isIpLiteral } from "./parse.js";
export { skeleton } from "./confusables.js";
export { damerauLevenshtein } from "./distance.js";
export { shannonEntropy } from "./entropy.js";
export { decodeHostLabels, decodePunycodeLabel } from "./punycode.js";
export { KNOWN_SHORTENERS, DEFAULT_TLD_RISK } from "./tables.js";

/** URL normalizer (doc 07 §2.2): URL string → minimal frozen Evidence. */
export function evidenceFromUrl(raw: string, clientMeta: Partial<ClientMeta> = {}): Evidence {
  const parsed = parseUrl(raw);
  const url: UrlEvidence = parsed
    ? {
        raw: parsed.raw,
        host: parsed.host,
        registeredDomain: parsed.registeredDomain,
        punyDecoded: parsed.punyDecoded,
        scheme: parsed.scheme,
      }
    : { raw: raw.trim(), host: "", registeredDomain: "", punyDecoded: "", scheme: "" };
  return freezeEvidence({
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    kind: "url",
    url,
    clientMeta: defaultClientMeta(clientMeta),
  });
}

/** Brand list guard: skip absurdly short brands (distance noise). */
function usableBrands(ctx: CheckContext): string[] {
  return ctx.intel.brandDomains().filter((b) => b.includes(".") && b.length >= 5);
}

export const idnHomograph: Check = {
  id: "url.idn_homograph",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 30,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    const brands = usableBrands(ctx);
    if (brands.length === 0) return findings;
    const extra = ctx.intel.confusables();
    const seen = new Set<string>();
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      const candidates = new Set<string>([
        skeleton(inst.registeredDomain, extra),
        skeleton(inst.sld, extra),
        skeleton(registeredDomainOf(inst.punyDecoded), extra),
      ]);
      for (const brand of brands) {
        const brandSk = skeleton(brand, extra);
        const brandSldSk = skeleton(brand.split(".")[0] ?? brand, extra);
        const hit =
          (candidates.has(brandSk) || candidates.has(brandSldSk)) &&
          inst.registeredDomain !== brand;
        if (hit && !seen.has(inst.registeredDomain)) {
          seen.add(inst.registeredDomain);
          findings.push({
            ruleId: "url.idn_homograph",
            severity: "high",
            detail: `host "${inst.host}" (decoded "${inst.punyDecoded}") visually imitates brand "${brand}"`,
          });
          break;
        }
      }
    }
    return findings;
  },
};

export const typosquat: Check = {
  id: "url.typosquat",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 30,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    const brands = usableBrands(ctx);
    if (brands.length === 0) return findings;
    const seen = new Set<string>();
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      if (isIpLiteral(inst.registeredDomain)) continue;
      for (const brand of brands) {
        if (inst.registeredDomain === brand) continue;
        const d = damerauLevenshtein(inst.registeredDomain, brand, 2);
        if (d <= 2 && !seen.has(inst.registeredDomain)) {
          seen.add(inst.registeredDomain);
          findings.push({
            ruleId: "url.typosquat",
            severity: "high",
            detail: `"${inst.registeredDomain}" is edit-distance ${d} from brand "${brand}"`,
          });
          break;
        }
      }
    }
    return findings;
  },
};

export const ipLiteralHost: Check = {
  id: "url.ip_literal_host",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 15,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      if (isIpLiteral(inst.host)) {
        findings.push({
          ruleId: "url.ip_literal_host",
          severity: "medium",
          detail: `host "${inst.host}" is an IP literal`,
        });
      }
    }
    return findings;
  },
};

export const atSignInUrl: Check = {
  id: "url.at_sign_in_url",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 12,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      if (inst.username !== "" || inst.password !== "") {
        findings.push({
          ruleId: "url.at_sign_in_url",
          severity: "medium",
          detail: `userinfo "${inst.username}@…" obscures the real host "${inst.host}"`,
        });
      }
    }
    return findings;
  },
};

export const excessSubdomains: Check = {
  id: "url.excess_subdomains",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 8,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      const labels = inst.host.split(".").filter((l) => l !== "");
      if (labels.length > 4) {
        findings.push({
          ruleId: "url.excess_subdomains",
          severity: "low",
          detail: `"${inst.host}" has ${labels.length} labels (>4)`,
        });
      }
    }
    return findings;
  },
};

export const suspiciousTld: Check = {
  id: "url.suspicious_tld",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 10,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    const bundleTable = ctx.intel.tldRiskTable();
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      const labels = inst.host.split(".");
      const tld = labels[labels.length - 1] ?? "";
      const risk = bundleTable[tld] ?? DEFAULT_TLD_RISK[tld] ?? 0;
      if (risk > 0) {
        findings.push({
          ruleId: "url.suspicious_tld",
          severity: risk >= 25 ? "high" : risk >= 15 ? "medium" : "low",
          weight: Math.min(30, risk),
          detail: `"${inst.host}" uses TLD ".${tld}" (risk ${risk})`,
        });
      }
    }
    return findings;
  },
};

export const urlEntropy: Check = {
  id: "url.url_entropy",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 8,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      if (!isIpLiteral(inst.sld) && inst.sld.length >= 10 && shannonEntropy(inst.sld) >= 4.0) {
        findings.push({
          ruleId: "url.url_entropy",
          severity: "low",
          detail: `domain label "${inst.sld}" looks random (entropy ${shannonEntropy(inst.sld).toFixed(2)})`,
        });
        continue;
      }
      for (const seg of inst.path.split("/").filter((s) => s.length >= 16)) {
        if (shannonEntropy(seg) >= 4.5) {
          findings.push({
            ruleId: "url.url_entropy",
            severity: "low",
            detail: `path segment of "${inst.host}" looks random (entropy ${shannonEntropy(seg).toFixed(2)})`,
          });
          break;
        }
      }
    }
    return findings;
  },
};

export const urlLength: Check = {
  id: "url.url_length",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 6,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      if (inst.raw.length > 75) {
        findings.push({
          ruleId: "url.url_length",
          severity: "low",
          detail: `URL is ${inst.raw.length} chars (>75)`,
        });
      }
    }
    return findings;
  },
};

export const shortenerKnown: Check = {
  id: "url.shortener_known",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 5,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      if (KNOWN_SHORTENERS.has(inst.registeredDomain)) {
        findings.push({
          ruleId: "url.shortener_known",
          severity: "info",
          detail: `"${inst.registeredDomain}" is a known URL shortener (destination hidden; no live expansion per doc 07 §1)`,
        });
      }
    }
    return findings;
  },
};

export const displayHrefMismatch: Check = {
  id: "url.display_href_mismatch",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 25,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    for (const anchor of collectUrls(ev).anchors) {
      if (ctx.deadline.expired()) break;
      if (!anchor.parsed) continue;
      const textDomain = domainLikeInText(anchor.displayText);
      if (!textDomain) continue;
      const textReg = registeredDomainOf(textDomain);
      if (textReg !== anchor.parsed.registeredDomain) {
        findings.push({
          ruleId: "url.display_href_mismatch",
          severity: "high",
          detail: `link text suggests "${textReg}" but the href goes to "${anchor.parsed.registeredDomain}"`,
        });
      }
    }
    return findings;
  },
};

export const portNonstandard: Check = {
  id: "url.port_nonstandard",
  version: 1,
  family: "url",
  requires: [],
  defaultWeight: 6,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      if (inst.port !== "") {
        findings.push({
          ruleId: "url.port_nonstandard",
          severity: "low",
          detail: `"${inst.host}" uses non-standard port ${inst.port}`,
        });
      }
    }
    return findings;
  },
};

export const schemeDowngrade: Check = {
  id: "url.scheme_downgrade",
  version: 1,
  family: "url",
  requires: ["page"],
  defaultWeight: 12,
  run(ev, ctx) {
    const findings: EmittedFinding[] = [];
    if (!ev.page || !ev.page.origin.toLowerCase().startsWith("https:")) return findings;
    for (const inst of collectUrls(ev).instances) {
      if (ctx.deadline.expired()) break;
      if (inst.role === "embedded" && inst.scheme === "http") {
        findings.push({
          ruleId: "url.scheme_downgrade",
          severity: "medium",
          detail: `https page "${ev.page.origin}" links to insecure http://${inst.host}`,
        });
      }
    }
    return findings;
  },
};

/** The 12 URL-family checks (doc 07 §3.2). */
export const URL_CHECKS: readonly Check[] = [
  idnHomograph,
  typosquat,
  ipLiteralHost,
  atSignInUrl,
  excessSubdomains,
  suspiciousTld,
  urlEntropy,
  urlLength,
  shortenerKnown,
  displayHrefMismatch,
  portNonstandard,
  schemeDowngrade,
];
