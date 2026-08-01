/**
 * i18n explanation templates (doc 07 §3.3: explanations rendered from i18n
 * templates; §11: EN only at MVP). Keys are the normative rule ids.
 */

import type { Finding } from "./verdict.js";

const EN: Record<string, (f: Finding) => string> = {
  "url.idn_homograph": () => "Domain uses look-alike (homoglyph) characters imitating a known brand",
  "url.typosquat": () => "Domain is a near-miss (typosquat) of a known brand domain",
  "url.ip_literal_host": () => "Link uses a raw IP address instead of a domain name",
  "url.at_sign_in_url": () => "URL contains '@' — the real host is hidden after it",
  "url.excess_subdomains": () => "URL has an excessive number of subdomains",
  "url.suspicious_tld": () => "Domain uses a high-risk top-level domain",
  "url.url_entropy": () => "URL contains high-entropy (random-looking) segments",
  "url.url_length": () => "URL is abnormally long",
  "url.shortener_known": () => "Link hides its destination behind a known URL shortener",
  "url.display_href_mismatch": () => "Displayed link text points to a different domain than the actual link",
  "url.port_nonstandard": () => "URL uses a non-standard port",
  "url.scheme_downgrade": () => "Secure page links to an insecure (http) resource",
  "auth.spf_fail": () => "Sender domain failed SPF authentication",
  "auth.dkim_fail": () => "Message failed DKIM signature verification",
  "auth.dmarc_fail": () => "Sender domain failed DMARC authentication",
  "auth.from_replyto_mismatch": () => "Replies would go to a different domain than the sender",
  "auth.from_display_spoof": () => "Display name claims a brand the sender address does not belong to",
  "auth.return_path_mismatch": () => "Bounce address (Return-Path) domain differs from the sender domain",
  "content.urgency_lexicon": () => "Message uses urgency/pressure language typical of phishing",
  "content.credential_request": () => "Message requests credentials (password, OTP, or seed phrase)",
  "content.attachment_risk": () => "Message carries a high-risk attachment",
  "dom.password_form_offdomain": () => "Password form submits credentials to a different origin",
  "dom.form_posts_http": () => "Form submits data over an insecure (http) connection",
  "dom.hidden_iframe": () => "Page contains a hidden iframe",
  "dom.overlay_clickjack": () => "Full-viewport overlay may hijack clicks (clickjacking)",
  "dom.title_brand_mismatch": () => "Page title claims a brand the domain does not belong to",
  "dom.blank_target_noopener_absent": () => "External links open new tabs without opener protection",
  "rep.domain_blocklisted": () => "Domain is on the current blocklist",
  "rep.url_blocklisted": () => "URL is on the current blocklist",
  "rep.sender_blocklisted": () => "Sender is on the current blocklist",
};

/** Render a finding to a human-readable explanation (EN; fallback = detail). */
export function explain(finding: Finding): string {
  const template = EN[finding.ruleId];
  if (!template) return finding.detail;
  const base = template(finding);
  return finding.detail ? `${base} — ${finding.detail}` : base;
}
