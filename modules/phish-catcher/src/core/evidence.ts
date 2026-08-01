/**
 * `Evidence` — the pipeline input (doc 07 §4.1, JSON Schema Draft 2020-12 in
 * schemas/evidence/v1/schema.json). Evidence NEVER leaves the client (§7):
 * it is normalized once, frozen, and consumed by pure checks only.
 */

export const EVIDENCE_SCHEMA_VERSION = 1 as const;

export interface MessageHeaders {
  from?: string;
  replyTo?: string;
  returnPath?: string;
  authenticationResults?: string;
  receivedSpf?: string;
  messageId?: string;
  /** Any additional raw headers the intake layer preserved (lowercased keys). */
  [extra: string]: string | undefined;
}

export interface AttachmentMeta {
  filename: string;
  contentType: string;
  size: number;
  /** Lowercase hex SHA-256 of the attachment bytes (computed at intake). */
  sha256?: string;
  macroDetected?: boolean;
}

export interface ImageMeta {
  /** cid: URI or https: URI — never fetched. */
  src: string;
  sha256?: string;
}

export interface AnchorMeta {
  href: string;
  displayText: string;
}

export interface MessageEvidence {
  headers: MessageHeaders;
  subject?: string;
  bodyText?: string;
  bodyHtml?: string;
  attachments?: AttachmentMeta[];
  urls?: string[];
  /** Anchors extracted from bodyHtml (href + visible text) at intake. */
  anchors?: AnchorMeta[];
  images?: ImageMeta[];
}

export interface FormEvidence {
  action: string;
  method: string;
  hasPasswordField: boolean;
  /** Resolved origin of the form action ("" when unresolvable/relative-root). */
  actionOrigin: string;
}

export interface LinkEvidence {
  href: string;
  displayText: string;
  target?: string;
  rel?: string;
}

export interface IframeEvidence {
  src: string;
  hidden: boolean;
}

export interface PageEvidence {
  origin: string;
  url: string;
  title: string;
  forms?: FormEvidence[];
  links?: LinkEvidence[];
  iframes?: IframeEvidence[];
  /** Later (doc 07 §3.2 dom.favicon_brand_mismatch): supplied, never fetched. */
  faviconPHash?: string;
  hasFullscreenOverlay?: boolean;
}

export interface UrlEvidence {
  raw: string;
  host: string;
  registeredDomain: string;
  punyDecoded: string;
  scheme: string;
}

export interface ClientMeta {
  libVersion: string;
  bundleVersion: string;
  policyVersion: number;
}

export type EvidenceKind = "email" | "page" | "url";

export interface Evidence {
  schemaVersion: typeof EVIDENCE_SCHEMA_VERSION;
  kind: EvidenceKind;
  message?: MessageEvidence;
  page?: PageEvidence;
  url?: UrlEvidence;
  clientMeta: ClientMeta;
}

/** Shallow-freeze the evidence graph — checks must treat it as immutable. */
export function freezeEvidence<T extends Evidence>(ev: T): T {
  if (ev.message) {
    Object.freeze(ev.message.headers);
    if (ev.message.attachments) for (const a of ev.message.attachments) Object.freeze(a);
    if (ev.message.urls) Object.freeze(ev.message.urls);
    if (ev.message.anchors) for (const a of ev.message.anchors) Object.freeze(a);
    if (ev.message.images) for (const i of ev.message.images) Object.freeze(i);
    Object.freeze(ev.message);
  }
  if (ev.page) {
    if (ev.page.forms) for (const f of ev.page.forms) Object.freeze(f);
    if (ev.page.links) for (const l of ev.page.links) Object.freeze(l);
    if (ev.page.iframes) for (const i of ev.page.iframes) Object.freeze(i);
    Object.freeze(ev.page);
  }
  if (ev.url) Object.freeze(ev.url);
  Object.freeze(ev.clientMeta);
  return Object.freeze(ev);
}
