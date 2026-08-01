/**
 * DOM extraction → `PageEvidence` (doc 07 §2.2: the browser path walks the
 * DOM; §6.3 content script reads the rendered message DOM). Split in two:
 *
 *  - `PageDom`: a structural snapshot the caller produces (content script
 *    from the live DOM, tests from fixtures) — keeps checks 100% shared
 *    between extension and Node (§12: gate via `requires`, never fork).
 *  - `extractPageEvidence`: PageDom → PageEvidence + the selector self-test
 *    (§9: 0 URLs + 0 forms on a message view → `extraction_degraded`,
 *    raw-HTML string-heuristic fallback is the caller's concern).
 */

import type { FormEvidence, IframeEvidence, LinkEvidence, PageEvidence } from "../core/evidence.js";
import { parseUrl } from "../url/parse.js";

export interface PageDomInput {
  type: string;
  name?: string;
}

export interface PageDomForm {
  /** Raw action attribute (may be relative or empty). */
  action: string;
  method: string;
  inputs: PageDomInput[];
}

export interface PageDomLink {
  href: string;
  text: string;
  target?: string;
  rel?: string;
}

export interface PageDomIframe {
  src: string;
  hidden: boolean;
}

export interface PageDom {
  url: string;
  origin: string;
  title: string;
  forms: PageDomForm[];
  links: PageDomLink[];
  iframes: PageDomIframe[];
  faviconHref?: string;
  hasFullscreenOverlay: boolean;
}

export interface ExtractionResult {
  page: PageEvidence;
  /** §9 self-test failed: 0 URLs + 0 forms where content was expected. */
  extractionDegraded: boolean;
}

function resolveActionOrigin(rawAction: string, pageOrigin: string): string {
  if (rawAction.trim() === "") return pageOrigin;
  try {
    return new URL(rawAction, pageOrigin).origin;
  } catch {
    return "";
  }
}

function toFormEvidence(form: PageDomForm, pageOrigin: string): FormEvidence {
  const action = form.action.trim() === "" ? pageOrigin : form.action.trim();
  return {
    action,
    method: (form.method || "GET").toUpperCase(),
    hasPasswordField: form.inputs.some((i) => i.type.toLowerCase() === "password"),
    actionOrigin: resolveActionOrigin(form.action, pageOrigin),
  };
}

export function extractPageEvidence(dom: PageDom, opts: { expectContent?: boolean } = {}): ExtractionResult {
  const forms = dom.forms.map((f) => toFormEvidence(f, dom.origin));
  const links: LinkEvidence[] = dom.links.map((l) => ({
    href: l.href,
    displayText: l.text,
    ...(l.target !== undefined ? { target: l.target } : {}),
    ...(l.rel !== undefined ? { rel: l.rel } : {}),
  }));
  const iframes: IframeEvidence[] = dom.iframes.map((i) => ({ src: i.src, hidden: i.hidden }));
  const page: PageEvidence = {
    origin: dom.origin,
    url: dom.url,
    title: dom.title,
    forms,
    links,
    iframes,
    hasFullscreenOverlay: dom.hasFullscreenOverlay,
  };
  const extractedUrls = links.length + iframes.length;
  const extractionDegraded = opts.expectContent === true && extractedUrls === 0 && forms.length === 0;
  return { page, extractionDegraded };
}

/** True when a URL string is an absolute http(s) URL pointing off-origin. */
export function isOffOrigin(url: string, pageOrigin: string): boolean {
  const parsed = parseUrl(url);
  if (!parsed) return false;
  try {
    return new URL(`${parsed.scheme}://${parsed.host}${parsed.port === "" ? "" : `:${parsed.port}`}`).origin !== pageOrigin;
  } catch {
    return false;
  }
}
