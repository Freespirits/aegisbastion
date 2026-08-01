/**
 * .eml / raw MIME intake (phish-node, doc 07 §2.1/§2.2): postal-mime →
 * normalized `Evidence`. Parsing is local-only (§1); attachments are hashed
 * and classified by metadata — their bytes never leave the client (§5.4).
 */

import PostalMime from "postal-mime";
import type { Address, Email } from "postal-mime";
import type { AttachmentMeta, ClientMeta, MessageHeaders } from "../core/evidence.js";
import { evidenceFromEmail, type EmailParts } from "../core/normalize.js";
import type { Evidence } from "../core/evidence.js";
import { collectMessageUrls, extractAnchorsFromHtml } from "../content/extract.js";
import { sha256Hex, toHex, sha256 } from "../intel/sha256.js";
import { utf8ToBytes } from "../intel/base64.js";

function mailboxToHeader(addr: Address | undefined): string | undefined {
  if (!addr || addr.group !== undefined) return undefined;
  if (addr.address === undefined || addr.address === "") return undefined;
  return addr.name !== "" ? `${addr.name} <${addr.address}>` : addr.address;
}

function firstHeader(email: Email, key: string): string | undefined {
  return email.headers.find((h) => h.key === key)?.value;
}

function attachmentMeta(content: ArrayBuffer | Uint8Array | string): { bytes: Uint8Array; size: number; sha256: string } {
  const bytes =
    typeof content === "string"
      ? utf8ToBytes(content)
      : content instanceof Uint8Array
        ? content
        : new Uint8Array(content);
  return { bytes, size: bytes.byteLength, sha256: toHex(sha256(bytes)) };
}

/** OOXML macro detection: a zip member named vbaProject.bin (§3.2 metadata). */
function detectMacro(bytes: Uint8Array, filename: string): boolean | undefined {
  // PK zip magic + OOXML office extension → scan for the VBA project member.
  const isZip = bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b;
  if (!isZip || !/\.(?:docm|xlsm|pptm|docx|xlsx|pptx)$/i.test(filename)) return undefined;
  const needle = utf8ToBytes("vbaProject.bin");
  outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (bytes[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

/**
 * Parse a raw RFC 822 message into frozen `Evidence` (kind "email").
 * Never throws on malformed mail — degrades to whatever parts parsed.
 */
export async function evidenceFromRawEml(
  raw: string | Uint8Array | ArrayBuffer,
  clientMeta: Partial<ClientMeta> = {},
): Promise<Evidence> {
  const email = await PostalMime.parse(raw as never);

  const headers: MessageHeaders = {};
  const from = mailboxToHeader(email.from);
  if (from !== undefined) headers.from = from;
  const replyTo = (email.replyTo ?? []).map(mailboxToHeader).find((v) => v !== undefined);
  if (replyTo !== undefined) headers.replyTo = replyTo;
  if (email.returnPath !== undefined && email.returnPath !== "") headers.returnPath = email.returnPath;
  const authResults = firstHeader(email, "authentication-results");
  if (authResults !== undefined) headers.authenticationResults = authResults;
  const receivedSpf = firstHeader(email, "received-spf");
  if (receivedSpf !== undefined) headers.receivedSpf = receivedSpf;
  if (email.messageId !== undefined) headers.messageId = email.messageId;

  const anchors = email.html ? extractAnchorsFromHtml(email.html) : [];
  const attachments: AttachmentMeta[] = email.attachments.map((att) => {
    const { bytes, size, sha256: digest } = attachmentMeta(att.content);
    const filename = att.filename ?? "(unnamed)";
    const macro = detectMacro(bytes, filename);
    return {
      filename,
      contentType: att.mimeType,
      size,
      sha256: digest,
      ...(macro !== undefined ? { macroDetected: macro } : {}),
    };
  });

  const parts: EmailParts = {
    headers,
    ...(email.subject !== undefined ? { subject: email.subject } : {}),
    ...(email.text !== undefined ? { bodyText: email.text } : {}),
    ...(email.html !== undefined ? { bodyHtml: email.html } : {}),
    urls: collectMessageUrls(email.text, email.html, anchors),
    anchors,
    attachments,
    clientMeta,
  };
  return evidenceFromEmail(parts);
}

/** sha256 helper re-exported for CLI hashing of arbitrary input. */
export { sha256Hex };
