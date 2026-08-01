/**
 * Auth + content family checks (doc 07 §3.2): header-trust auth parsing
 * (NO live DNS), urgency/credential lexicons, attachment risk.
 */

import { describe, expect, it } from "vitest";
import {
  spfFail,
  dkimFail,
  dmarcFail,
  fromReplyToMismatch,
  fromDisplaySpoof,
  returnPathMismatch,
  urgencyLexicon,
  credentialRequest,
  attachmentRisk,
  parseAuthenticationResults,
} from "../src/content/checks.js";
import { evidenceFromEmail } from "../src/core/normalize.js";
import { extractAnchorsFromHtml, extractUrlsFromText } from "../src/content/extract.js";
import { runCheck } from "./helpers.js";

const AR = (s: string) => ({ authenticationResults: s });

describe("auth header parsing", () => {
  it("parses Authentication-Results methods", () => {
    const results = parseAuthenticationResults("mx.example.org; spf=fail smtp.mailfrom=x.tk; dkim=pass header.d=x.com; dmarc=fail header.from=x.tk");
    expect(results.map((r) => `${r.method}=${r.result}`)).toEqual(["spf=fail", "dkim=pass", "dmarc=fail"]);
  });
});

describe("auth.spf_fail", () => {
  it("flags spf=fail from Authentication-Results", () => {
    const ev = evidenceFromEmail({ headers: AR("mx; spf=fail smtp.mailfrom=bad.tk") });
    expect(runCheck(spfFail, ev).length).toBe(1);
  });
  it("flags softfail at lower weight", () => {
    const ev = evidenceFromEmail({ headers: AR("mx; spf=softfail smtp.mailfrom=bad.tk") });
    const f = runCheck(spfFail, ev);
    expect(f.length).toBe(1);
    expect(f[0]?.weight).toBe(15);
  });
  it("falls back to Received-SPF (no DNS, doc 07 §3.2)", () => {
    const ev = evidenceFromEmail({ headers: { receivedSpf: "fail (mx: domain does not designate)" } });
    expect(runCheck(spfFail, ev).length).toBe(1);
  });
  it("does not flag spf=pass", () => {
    const ev = evidenceFromEmail({ headers: AR("mx; spf=pass smtp.mailfrom=example.com") });
    expect(runCheck(spfFail, ev)).toEqual([]);
  });
});

describe("auth.dkim_fail / auth.dmarc_fail", () => {
  it("flags dkim=fail in header-trust mode", () => {
    const ev = evidenceFromEmail({ headers: AR("mx; dkim=fail header.d=bad.tk") });
    const f = runCheck(dkimFail, ev);
    expect(f.length).toBe(1);
    expect(f[0]?.detail).toContain("header-trust mode");
  });
  it("flags dmarc=fail (hard-fail combo member)", () => {
    const ev = evidenceFromEmail({ headers: AR("mx; dmarc=fail header.from=bad.tk") });
    expect(runCheck(dmarcFail, ev).length).toBe(1);
  });
  it("does not flag passing auth", () => {
    const ev = evidenceFromEmail({ headers: AR("mx; dkim=pass header.d=example.com; dmarc=pass header.from=example.com") });
    expect(runCheck(dkimFail, ev)).toEqual([]);
    expect(runCheck(dmarcFail, ev)).toEqual([]);
  });
});

describe("auth.from_replyto_mismatch", () => {
  it("flags differing From/Reply-To domains", () => {
    const ev = evidenceFromEmail({
      headers: { from: "alerts@example.com", replyTo: "capture@evil.tk" },
    });
    expect(runCheck(fromReplyToMismatch, ev).length).toBe(1);
  });
  it("does not flag same-domain reply-to", () => {
    const ev = evidenceFromEmail({
      headers: { from: "alerts@example.com", replyTo: "support@example.com" },
    });
    expect(runCheck(fromReplyToMismatch, ev)).toEqual([]);
  });
});

describe("auth.from_display_spoof", () => {
  it("flags display name claiming a brand the address is not", () => {
    const ev = evidenceFromEmail({
      headers: { from: '"PayPal Security" <alert@evil-capture.tk>' },
    });
    expect(runCheck(fromDisplaySpoof, ev).length).toBe(1);
  });
  it("does not flag the brand's own address", () => {
    const ev = evidenceFromEmail({
      headers: { from: '"PayPal Security" <security@paypal.com>' },
    });
    expect(runCheck(fromDisplaySpoof, ev)).toEqual([]);
  });
});

describe("auth.return_path_mismatch", () => {
  it("flags differing From/Return-Path domains", () => {
    const ev = evidenceFromEmail({
      headers: { from: "alerts@example.com", returnPath: "<bounces@evil.tk>" },
    });
    expect(runCheck(returnPathMismatch, ev).length).toBe(1);
  });
  it("does not flag matching domains", () => {
    const ev = evidenceFromEmail({
      headers: { from: "alerts@example.com", returnPath: "<bounces@example.com>" },
    });
    expect(runCheck(returnPathMismatch, ev)).toEqual([]);
  });
});

describe("content.urgency_lexicon", () => {
  it("flags urgency pressure language", () => {
    const ev = evidenceFromEmail({
      headers: {},
      subject: "URGENT: your account has been suspended",
      bodyText: "Verify your account within 24 hours or it will be closed.",
    });
    const f = runCheck(urgencyLexicon, ev);
    expect(f.length).toBe(1);
    expect(f[0]?.detail).toContain("urgency score");
  });
  it("does not flag calm text", () => {
    const ev = evidenceFromEmail({
      headers: {},
      subject: "July product updates",
      bodyText: "Dark mode is now generally available. Thanks for reading.",
    });
    expect(runCheck(urgencyLexicon, ev)).toEqual([]);
  });
});

describe("content.credential_request", () => {
  it("flags password requests", () => {
    const ev = evidenceFromEmail({ headers: {}, bodyText: "Please confirm your password to continue." });
    expect(runCheck(credentialRequest, ev).length).toBe(1);
  });
  it("flags OTP and seed-phrase requests", () => {
    const otp = evidenceFromEmail({ headers: {}, bodyText: "Send us the verification code we texted you." });
    expect(runCheck(credentialRequest, otp).length).toBe(1);
    const seed = evidenceFromEmail({ headers: {}, bodyText: "Enter your wallet seed phrase to migrate." });
    expect(runCheck(credentialRequest, seed).length).toBe(1);
  });
  it("does not flag normal text", () => {
    const ev = evidenceFromEmail({ headers: {}, bodyText: "Your receipt is attached. Thanks for shopping." });
    expect(runCheck(credentialRequest, ev)).toEqual([]);
  });
});

describe("content.attachment_risk", () => {
  const ev = (filename: string, macroDetected?: boolean) =>
    evidenceFromEmail({
      headers: {},
      attachments: [{ filename, contentType: "application/octet-stream", size: 100, ...(macroDetected !== undefined ? { macroDetected } : {}) }],
    });

  it("flags double extensions", () => {
    expect(runCheck(attachmentRisk, ev("invoice.pdf.exe")).length).toBe(1);
  });
  it("flags macro-enabled types and macroDetected", () => {
    expect(runCheck(attachmentRisk, ev("report.docm")).length).toBe(1);
    expect(runCheck(attachmentRisk, ev("report.docx", true)).length).toBe(1);
  });
  it("flags ISO/HTA at critical", () => {
    const f = runCheck(attachmentRisk, ev("files.iso"));
    expect(f.length).toBe(1);
    expect(f[0]?.severity).toBe("critical");
  });
  it("flags executables", () => {
    expect(runCheck(attachmentRisk, ev("update.scr")).length).toBe(1);
  });
  it("does not flag benign attachments", () => {
    expect(runCheck(attachmentRisk, ev("photo.png"))).toEqual([]);
  });
});

describe("content extraction helpers", () => {
  it("extracts URLs from text without trailing punctuation", () => {
    const urls = extractUrlsFromText("see https://example.com/a, and http://x.tk/b. done");
    expect(urls).toEqual(["https://example.com/a", "http://x.tk/b"]);
  });
  it("extracts anchors with display text", () => {
    const anchors = extractAnchorsFromHtml('<a href="http://evil.tk/x"><b>paypal.com</b> login</a><a href="#top">top</a>');
    expect(anchors).toEqual([{ href: "http://evil.tk/x", displayText: "paypal.com login" }]);
  });
});
