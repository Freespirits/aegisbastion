/**
 * Text extraction + the urgency/credential lexicons (doc 07 §3.2 content
 * family). EN at MVP (§11); the bundle may carry replacement/overlay
 * lexicons for i18n (`IntelReaders.urgencyLexicon`).
 */

/** Naive, allocation-light HTML → text (no DOM APIs — runs everywhere). */
export function htmlToText(html: string): string {
  return html
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/[ \t]+/g, " ")
    .trim();
}

/** Combined scannable text: subject + bodyText + stripped bodyHtml. */
export function messageText(subject: string | undefined, bodyText: string | undefined, bodyHtml: string | undefined): string {
  return [subject ?? "", bodyText ?? "", bodyHtml ? htmlToText(bodyHtml) : ""].join("\n").trim();
}

/**
 * Compiled-in EN urgency lexicon (phrase → weight). Each phrase counts once.
 * The intel bundle's lexicon overlays this (doc 07 §3.2: "lexicon in bundle
 * for i18n").
 */
export const DEFAULT_URGENCY_LEXICON: Readonly<Record<string, number>> = Object.freeze({
  "urgent": 3,
  "immediately": 2,
  "immediate action": 4,
  "action required": 4,
  "verify your account": 5,
  "verify your identity": 5,
  "confirm your identity": 5,
  "confirm your account": 4,
  "account suspended": 5,
  "account has been suspended": 6,
  "account will be closed": 6,
  "account will be suspended": 6,
  "account will be locked": 5,
  "unusual activity": 4,
  "unusual sign-in": 5,
  "suspicious activity": 4,
  "security alert": 3,
  "security warning": 3,
  "unauthorized access": 4,
  "within 24 hours": 4,
  "within 48 hours": 4,
  "24 hours": 2,
  "act now": 3,
  "final notice": 4,
  "last warning": 4,
  "failure to comply": 4,
  "limited time": 2,
  "expires today": 3,
  "dear customer": 2,
  "dear user": 2,
  "dear account holder": 3,
  "wire transfer": 3,
  "gift card": 4,
  "gift cards": 4,
  "itunes card": 4,
  "refund pending": 3,
  "tax refund": 3,
  "irs": 3,
  "arrest warrant": 5,
  "legal action": 3,
  "compromised": 3,
  "locked account": 4,
  "restore access": 4,
  "reactivate": 3,
  "billing problem": 3,
  "payment declined": 3,
  "update your payment": 4,
  "avoid interruption": 3,
});

/** Weighted phrase score over lowercased text; each phrase counts once. */
export function urgencyScore(text: string, lexicon: Readonly<Record<string, number>>): { score: number; matches: string[] } {
  const hay = `\n${text.toLowerCase()}\n`;
  let score = 0;
  const matches: string[] = [];
  for (const [phrase, weight] of Object.entries(lexicon)) {
    if (hay.includes(phrase.toLowerCase())) {
      score += weight;
      matches.push(phrase);
    }
  }
  return { score, matches };
}

/** Credential-request patterns (doc 07 §3.2 `content.credential_request`). */
export const CREDENTIAL_PATTERNS: ReadonlyArray<{ re: RegExp; label: string }> = [
  { re: /(?:enter|confirm|verify|update|re-?enter|provide)\s+(?:your\s|the\s)?(?:\w+\s){0,2}password/i, label: "password request" },
  { re: /(?:one[- ]time (?:pass)?code|otp|verification code|security code|2fa code|authentication code)/i, label: "OTP/verification-code request" },
  { re: /(?:seed phrase|recovery phrase|secret phrase|wallet (?:backup |recovery )?(?:phrase|words)|private key|keystore file)/i, label: "seed-phrase/private-key request" },
  { re: /(?:social security (?:number|no\.?)|\bssn\b)/i, label: "SSN request" },
  { re: /(?:credit|debit) card (?:number|details|information)|\bcvv\b|\bcvc\b|card verification/i, label: "payment-card request" },
  { re: /(?:login|log[- ]in|sign[- ]in) (?:credentials|details|information)/i, label: "credential request" },
  { re: /(?:bank(?:ing)? account|routing) (?:number|details|information)/i, label: "bank-account request" },
  { re: /(?:mother'?s maiden name|security questions? and answers?)/i, label: "security-question request" },
];

export function credentialRequestMatches(text: string): string[] {
  const labels: string[] = [];
  for (const { re, label } of CREDENTIAL_PATTERNS) {
    if (re.test(text)) labels.push(label);
  }
  return labels;
}
