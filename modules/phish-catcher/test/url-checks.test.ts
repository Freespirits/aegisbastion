/**
 * URL-family checks (doc 07 §3.2): true/false-positive fixtures per check.
 */

import { describe, expect, it } from "vitest";
import {
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
  evidenceFromUrl,
} from "../src/url/checks.js";
import { evidenceFromEmail, evidenceFromPage } from "../src/core/normalize.js";
import { fakeIntel, runCheck } from "./helpers.js";

describe("url.idn_homograph", () => {
  it("flags a Cyrillic-homoglyph brand lookalike", () => {
    // "раypal.com" with Cyrillic а (U+0430)
    const ev = evidenceFromUrl("https://\u0440ayp\u0430l.com/login");
    const findings = runCheck(idnHomograph, ev);
    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe("high");
  });

  it("does not flag the genuine brand domain", () => {
    const ev = evidenceFromUrl("https://paypal.com/signin");
    expect(runCheck(idnHomograph, ev)).toEqual([]);
  });

  it("does not flag unrelated Unicode domains", () => {
    const ev = evidenceFromUrl("https://münchen.de/");
    expect(runCheck(idnHomograph, ev)).toEqual([]);
  });
});

describe("url.typosquat", () => {
  it("flags edit-distance ≤ 2 to a brand", () => {
    const ev = evidenceFromUrl("https://paypa1.com/");
    const findings = runCheck(typosquat, ev);
    expect(findings.length).toBe(1);
  });

  it("flags a transposition typosquat", () => {
    const ev = evidenceFromUrl("https://payapl.com/");
    expect(runCheck(typosquat, ev).length).toBe(1);
  });

  it("does not flag the exact brand or unrelated domains", () => {
    expect(runCheck(typosquat, evidenceFromUrl("https://paypal.com/"))).toEqual([]);
    expect(runCheck(typosquat, evidenceFromUrl("https://totally-different-site.net/"))).toEqual([]);
  });
});

describe("url.ip_literal_host", () => {
  it("flags IPv4 literal hosts", () => {
    const ev = evidenceFromUrl("http://192.0.2.44/login");
    expect(runCheck(ipLiteralHost, ev).length).toBe(1);
  });
  it("does not flag hostname URLs", () => {
    expect(runCheck(ipLiteralHost, evidenceFromUrl("https://example.com/"))).toEqual([]);
  });
});

describe("url.at_sign_in_url", () => {
  it("flags userinfo obscuring the real host", () => {
    const ev = evidenceFromUrl("http://paypal.com@evil-capture.tk/");
    expect(runCheck(atSignInUrl, ev).length).toBe(1);
  });
  it("does not flag plain URLs", () => {
    expect(runCheck(atSignInUrl, evidenceFromUrl("https://example.com/u@x"))).toEqual([]);
  });
});

describe("url.excess_subdomains", () => {
  it("flags > 4 labels", () => {
    const ev = evidenceFromUrl("https://login.secure.verify.account.example.com/");
    expect(runCheck(excessSubdomains, ev).length).toBe(1);
  });
  it("does not flag normal hosts", () => {
    expect(runCheck(excessSubdomains, evidenceFromUrl("https://mail.example.com/"))).toEqual([]);
  });
});

describe("url.suspicious_tld", () => {
  it("flags a ranked risky TLD from the compiled table", () => {
    const ev = evidenceFromUrl("https://secure-login.tk/");
    expect(runCheck(suspiciousTld, ev).length).toBe(1);
  });
  it("prefers the bundle TLD table over the compiled one", () => {
    const ev = evidenceFromUrl("https://weird.aaa/");
    const intel = fakeIntel({ tldRiskTable: () => ({ aaa: 30 }) });
    expect(runCheck(suspiciousTld, ev, intel).length).toBe(1);
  });
  it("does not flag .com", () => {
    expect(runCheck(suspiciousTld, evidenceFromUrl("https://example.com/"))).toEqual([]);
  });
});

describe("url.url_entropy", () => {
  it("flags a high-entropy domain label", () => {
    const ev = evidenceFromUrl("https://a1b2c3d4e5f6g7h8.com/");
    expect(runCheck(urlEntropy, ev).length).toBe(1);
  });
  it("flags a high-entropy path segment", () => {
    const ev = evidenceFromUrl("https://example.com/zx9qw8er7ty6ui5op4as3df6gh");
    expect(runCheck(urlEntropy, ev).length).toBe(1);
  });
  it("does not flag readable URLs", () => {
    expect(runCheck(urlEntropy, evidenceFromUrl("https://example.com/account/login"))).toEqual([]);
  });
});

describe("url.url_length", () => {
  it("flags URLs longer than 75 chars", () => {
    const ev = evidenceFromUrl(`https://example.com/${"a".repeat(80)}`);
    expect(runCheck(urlLength, ev).length).toBe(1);
  });
  it("does not flag short URLs", () => {
    expect(runCheck(urlLength, evidenceFromUrl("https://example.com/login"))).toEqual([]);
  });
});

describe("url.shortener_known", () => {
  it("flags known shorteners (no live expansion, doc 07 §1)", () => {
    const ev = evidenceFromUrl("https://bit.ly/3xAb9Qz");
    const findings = runCheck(shortenerKnown, ev);
    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe("info");
  });
  it("does not flag non-shorteners", () => {
    expect(runCheck(shortenerKnown, evidenceFromUrl("https://example.com/"))).toEqual([]);
  });
});

describe("url.display_href_mismatch", () => {
  it("flags anchor text domain ≠ href domain", () => {
    const ev = evidenceFromEmail({
      headers: {},
      anchors: [{ href: "http://evil-capture.tk/steal", displayText: "https://paypal.com/signin" }],
      urls: ["http://evil-capture.tk/steal"],
    });
    expect(runCheck(displayHrefMismatch, ev).length).toBe(1);
  });
  it("does not flag matching anchors", () => {
    const ev = evidenceFromEmail({
      headers: {},
      anchors: [{ href: "https://paypal.com/signin", displayText: "paypal.com/signin" }],
      urls: ["https://paypal.com/signin"],
    });
    expect(runCheck(displayHrefMismatch, ev)).toEqual([]);
  });
});

describe("url.port_nonstandard", () => {
  it("flags non-standard ports", () => {
    expect(runCheck(portNonstandard, evidenceFromUrl("http://example.com:8443/x")).length).toBe(1);
  });
  it("does not flag default ports", () => {
    expect(runCheck(portNonstandard, evidenceFromUrl("https://example.com/x"))).toEqual([]);
  });
});

describe("url.scheme_downgrade", () => {
  it("flags http links embedded in an https page", () => {
    const ev = evidenceFromPage({
      origin: "https://example.com",
      url: "https://example.com/page",
      title: "Example",
      links: [{ href: "http://insecure.example.net/login", displayText: "login" }],
    });
    expect(runCheck(schemeDowngrade, ev).length).toBe(1);
  });
  it("does not flag https links or http pages", () => {
    const https = evidenceFromPage({
      origin: "https://example.com",
      url: "https://example.com/page",
      title: "Example",
      links: [{ href: "https://example.net/login", displayText: "login" }],
    });
    expect(runCheck(schemeDowngrade, https)).toEqual([]);
    const httpPage = evidenceFromPage({
      origin: "http://example.com",
      url: "http://example.com/page",
      title: "Example",
      links: [{ href: "http://example.net/login", displayText: "login" }],
    });
    expect(runCheck(schemeDowngrade, httpPage)).toEqual([]);
  });
});
