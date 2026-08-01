/**
 * Live-DOM adapter (browser runtime only, doc 07 §2.1 phish-dom): walks the
 * rendered DOM into a `PageDom` snapshot. Never imported by Node/test code
 * paths that lack a `document` — callers pass `document` explicitly. The
 * checks never touch the DOM; they consume `PageEvidence` (§12: 100% shared
 * check code).
 */

import type { PageDom, PageDomForm, PageDomIframe, PageDomLink } from "./page-context.js";

function elementHidden(el: Element): boolean {
  const style = (el.ownerDocument.defaultView ?? globalThis).getComputedStyle?.(el);
  if (!style) return false;
  if (style.display === "none" || style.visibility === "hidden") return true;
  if (Number(style.opacity) === 0) return true;
  const rect = el.getBoundingClientRect();
  return rect.width <= 1 || rect.height <= 1;
}

/** §3.2 `dom.overlay_clickjack` support: full-viewport transparent element. */
function detectFullscreenOverlay(doc: Document): boolean {
  const view = doc.defaultView;
  if (!view) return false;
  const vw = view.innerWidth;
  const vh = view.innerHeight;
  for (const el of doc.querySelectorAll("body *")) {
    const style = view.getComputedStyle(el);
    if (style.position !== "fixed" && style.position !== "absolute") continue;
    const rect = el.getBoundingClientRect();
    const covers = rect.width >= vw * 0.9 && rect.height >= vh * 0.9;
    if (!covers) continue;
    const transparent = Number(style.opacity) < 0.2 || style.backgroundColor === "rgba(0, 0, 0, 0)" || style.backgroundColor === "transparent";
    const zIndex = Number(style.zIndex);
    if (transparent && Number.isFinite(zIndex) && zIndex >= 1000 && style.pointerEvents !== "none") {
      return true;
    }
  }
  return false;
}

/** Read the rendered page (or a webmail message container) into a PageDom. */
export function extractFromDocument(doc: Document, root: ParentNode = doc): PageDom {
  const forms: PageDomForm[] = [];
  for (const form of root.querySelectorAll("form")) {
    const inputs = [...form.querySelectorAll("input")].map((i) => ({
      type: (i.getAttribute("type") ?? "text").toLowerCase(),
      ...(i.getAttribute("name") ? { name: i.getAttribute("name") ?? undefined } : {}),
    }));
    forms.push({
      action: form.getAttribute("action") ?? "",
      method: (form.getAttribute("method") ?? "GET").toUpperCase(),
      inputs,
    });
  }
  const links: PageDomLink[] = [];
  for (const a of root.querySelectorAll("a[href]")) {
    links.push({
      href: a.getAttribute("href") ?? "",
      text: (a.textContent ?? "").trim().slice(0, 200),
      ...(a.getAttribute("target") ? { target: a.getAttribute("target") ?? undefined } : {}),
      ...(a.getAttribute("rel") ? { rel: a.getAttribute("rel") ?? undefined } : {}),
    });
  }
  const iframes: PageDomIframe[] = [];
  for (const f of root.querySelectorAll("iframe")) {
    iframes.push({ src: f.getAttribute("src") ?? "", hidden: elementHidden(f) });
  }
  const favicon = doc.querySelector<HTMLLinkElement>('link[rel~="icon"]');
  return {
    url: doc.URL,
    origin: doc.location?.origin ?? "",
    title: doc.title ?? "",
    forms,
    links,
    iframes,
    ...(favicon?.href ? { faviconHref: favicon.href } : {}),
    hasFullscreenOverlay: detectFullscreenOverlay(doc),
  };
}
