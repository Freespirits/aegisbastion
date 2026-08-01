/**
 * URL/domain parsing (phish-url, doc 07 §2.1): WHATWG URL parsing,
 * PSL-lite registrable-domain computation, punycode decoding, and the
 * unified `UrlInstance` view the URL-family checks consume.
 *
 * PSL-lite: a curated multi-part public-suffix table (~60 entries) + the
 * single-label fallback. Not the full Public Suffix List — the intel bundle
 * may extend it (`publicSuffixes`), and the limitation is documented.
 * All parsing is local; nothing is ever resolved or fetched (§1).
 */

import type { Evidence } from "../core/evidence.js";
import { decodeHostLabels } from "./punycode.js";

/** Curated multi-part public suffixes (PSL-lite). */
export const MULTIPART_SUFFIXES: ReadonlySet<string> = new Set([
  "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "nhs.uk", "org.uk", "plc.uk", "sch.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  "com.mx", "net.mx", "org.mx", "gob.mx",
  "com.tr", "net.tr", "org.tr", "gov.tr",
  "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in",
  "co.za", "net.za", "org.za", "gov.za",
  "com.sg", "net.sg", "org.sg", "gov.sg",
  "com.hk", "net.hk", "org.hk", "gov.hk",
  "com.tw", "net.tw", "org.tw", "gov.tw",
  "co.kr", "or.kr", "ne.kr", "go.kr",
  "com.ar", "net.ar", "org.ar", "gob.ar",
  "com.co", "net.co", "org.co", "gov.co",
  "com.pe", "net.pe", "org.pe", "gob.pe",
  "com.ve", "net.ve", "org.ve", "gob.ve",
  "com.ph", "net.ph", "org.ph", "gov.ph",
  "com.my", "net.my", "org.my", "gov.my",
  "co.th", "in.th", "ac.th", "go.th",
  "co.id", "or.id", "ac.id", "go.id",
  "com.vn", "net.vn", "org.vn", "gov.vn",
  "com.pk", "net.pk", "org.pk", "gov.pk",
  "co.il", "org.il", "ac.il", "gov.il",
  "com.ng", "net.ng", "org.ng", "gov.ng",
  "com.eg", "net.eg", "org.eg", "gov.eg",
  "com.sa", "net.sa", "org.sa", "gov.sa",
  "com.ae", "net.ae", "org.ae", "gov.ae",
  "co.ke", "or.ke", "ac.ke", "go.ke",
  "com.pl", "net.pl", "org.pl", "gov.pl",
  "com.ru", "net.ru", "org.ru",
  "pp.ru", "com.ua", "net.ua", "org.ua", "gov.ua",
]);

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export function isIpv4Literal(host: string): boolean {
  if (!IPV4_RE.test(host)) return false;
  return host.split(".").every((o) => Number(o) <= 255);
}

export function isIpLiteral(host: string): boolean {
  return isIpv4Literal(host) || host.startsWith("[") || host.includes(":");
}

export interface ParsedUrl {
  raw: string;
  scheme: string;
  host: string;
  /** Registrable domain (PSL-lite), or the host itself for IP literals. */
  registeredDomain: string;
  /** Host with `xn--` labels decoded to Unicode. */
  punyDecoded: string;
  port: string;
  path: string;
  username: string;
  password: string;
  /** Second-level domain label (registeredDomain minus public suffix). */
  sld: string;
  /** Public suffix used for the registered-domain split. */
  publicSuffix: string;
}

/** Compute the public suffix of a hostname against PSL-lite. */
export function publicSuffixOf(host: string, extraSuffixes: ReadonlySet<string> = new Set()): string {
  const labels = host.toLowerCase().split(".").filter((l) => l.length > 0);
  if (labels.length <= 1) return labels[0] ?? "";
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join(".");
    if (MULTIPART_SUFFIXES.has(candidate) || extraSuffixes.has(candidate)) return candidate;
  }
  return labels[labels.length - 1] ?? "";
}

/** Registrable domain = one label left of the public suffix (PSL-lite). */
export function registeredDomainOf(host: string, extraSuffixes: ReadonlySet<string> = new Set()): string {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (h === "" || isIpLiteral(h)) return h;
  const suffix = publicSuffixOf(h, extraSuffixes);
  const labels = h.split(".");
  const suffixLabels = suffix === "" ? 0 : suffix.split(".").length;
  if (labels.length <= suffixLabels) return h;
  return labels.slice(labels.length - suffixLabels - 1).join(".");
}

/**
 * Parse a URL string. Accepts bare hosts (`paypal.com/x`) by assuming http.
 * Returns null on unparseable input (callers skip — never throw).
 */
export function parseUrl(raw: string): ParsedUrl | null {
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    try {
      url = new URL(`http://${trimmed}`);
    } catch {
      return null;
    }
  }
  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  if (scheme !== "http" && scheme !== "https") return null;
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (host === "") return null;
  const registeredDomain = registeredDomainOf(host);
  const suffix = publicSuffixOf(host);
  const sld = isIpLiteral(registeredDomain)
    ? registeredDomain
    : (registeredDomain.split(".").slice(0, registeredDomain.split(".").length - suffix.split(".").length)[0] ?? registeredDomain);
  return {
    raw: trimmed,
    scheme,
    host,
    registeredDomain,
    punyDecoded: decodeHostLabels(host),
    port: url.port,
    path: url.pathname + url.search,
    username: url.username,
    password: url.password,
    sld,
    publicSuffix: suffix,
  };
}

/** Normalization for intel hashing (never for network use). */
export function normalizeUrlForHash(raw: string): string {
  const p = parseUrl(raw);
  if (!p) return raw.trim().toLowerCase();
  const port = p.port === "" ? "" : `:${p.port}`;
  return `${p.scheme}://${p.host}${port}${p.path}`.toLowerCase();
}

export type UrlSource = "primary" | "message" | "page";

/** "self" = the analyzed URL/page itself; "embedded" = a link found inside. */
export type UrlRole = "self" | "embedded";

export interface UrlInstance extends ParsedUrl {
  source: UrlSource;
  role: UrlRole;
}

export interface AnchorInstance {
  href: string;
  displayText: string;
  source: UrlSource;
  parsed: ParsedUrl | null;
}

/**
 * Collect the unified URL view over any Evidence kind (§2.2: URL-only path
 * synthesizes a minimal Evidence; email/page contribute their URLs/links).
 * Scanning instances are deduped by normalized form; anchors keep display
 * text for `url.display_href_mismatch`.
 */
export function collectUrls(ev: Evidence): { instances: UrlInstance[]; anchors: AnchorInstance[] } {
  const raws: Array<{ raw: string; source: UrlSource; role: UrlRole }> = [];
  if (ev.url) raws.push({ raw: ev.url.raw, source: "primary", role: "self" });
  if (ev.message?.urls) for (const u of ev.message.urls) raws.push({ raw: u, source: "message", role: "embedded" });
  if (ev.page) {
    raws.push({ raw: ev.page.url, source: "page", role: "self" });
    for (const l of ev.page.links ?? []) raws.push({ raw: l.href, source: "page", role: "embedded" });
  }
  const seen = new Set<string>();
  const instances: UrlInstance[] = [];
  for (const { raw, source, role } of raws) {
    const parsed = parseUrl(raw);
    if (!parsed) continue;
    const key = normalizeUrlForHash(raw);
    if (seen.has(key)) continue;
    seen.add(key);
    instances.push({ ...parsed, source, role });
  }

  const anchors: AnchorInstance[] = [];
  if (ev.message?.anchors) {
    for (const a of ev.message.anchors) {
      anchors.push({ href: a.href, displayText: a.displayText, source: "message", parsed: parseUrl(a.href) });
    }
  }
  if (ev.page?.links) {
    for (const l of ev.page.links) {
      anchors.push({ href: l.href, displayText: l.displayText, source: "page", parsed: parseUrl(l.href) });
    }
  }
  return { instances, anchors };
}

/** Extract a host-looking token from anchor display text, if present. */
export function domainLikeInText(text: string): string | null {
  const m = /(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/?#\s]|$)/i.exec(text.trim());
  const host = m?.[1]?.toLowerCase();
  return host && host.includes(".") ? host : null;
}
