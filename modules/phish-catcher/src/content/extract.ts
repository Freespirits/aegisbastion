/**
 * URL/anchor extraction from message text and HTML (intake-side, doc 07
 * §2.2 step 1). Shared by the Node .eml intake (phish-node) and the browser
 * content script — pure string processing, no DOM, no network (§7.1).
 */

import type { AnchorMeta } from "../core/evidence.js";

const URL_RE = /\bhttps?:\/\/[^\s<>"'()]+/gi;
/** Trailing punctuation that is almost never part of the URL. */
const TRAILING_RE = /[.,;:!?\])}'">]+$/;

/** Extract http(s) URLs from plain text (or pre-stripped HTML). */
export function extractUrlsFromText(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(URL_RE)) {
    const url = (m[0] ?? "").replace(TRAILING_RE, "");
    if (url !== "" && !seen.has(url)) {
      seen.add(url);
      out.push(url);
    }
  }
  return out;
}

const ANCHOR_RE = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
const TAG_RE = /<[^>]+>/g;

/** Extract anchors (href + visible text) from HTML — caps per-field length. */
export function extractAnchorsFromHtml(html: string, maxAnchors = 500): AnchorMeta[] {
  const out: AnchorMeta[] = [];
  for (const m of html.matchAll(ANCHOR_RE)) {
    if (out.length >= maxAnchors) break;
    const href = (m[1] ?? m[2] ?? m[3] ?? "").trim();
    if (href === "" || href.startsWith("#") || href.toLowerCase().startsWith("javascript:")) continue;
    const displayText = (m[4] ?? "")
      .replace(TAG_RE, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/&amp;/gi, "&")
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&quot;/gi, '"')
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 200);
    out.push({ href, displayText });
  }
  return out;
}

/** Combined URL set for a message: explicit text scan + anchor hrefs. */
export function collectMessageUrls(bodyText: string | undefined, bodyHtml: string | undefined, anchors: AnchorMeta[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const push = (u: string) => {
    if (u !== "" && !seen.has(u)) {
      seen.add(u);
      out.push(u);
    }
  };
  if (bodyText) for (const u of extractUrlsFromText(bodyText)) push(u);
  if (bodyHtml) for (const u of extractUrlsFromText(bodyHtml)) push(u);
  for (const a of anchors) push(a.href);
  return out;
}
