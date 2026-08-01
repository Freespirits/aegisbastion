/**
 * DOM-family checks (doc 07 §3.2, page-scan mode) + PageDom extraction
 * self-test (§9). Fixtures are structural PageEvidence/PageDom — no live DOM.
 */

import { describe, expect, it } from "vitest";
import {
  passwordFormOffdomain,
  formPostsHttp,
  hiddenIframe,
  overlayClickjack,
  titleBrandMismatch,
  blankTargetNoopenerAbsent,
  extractPageEvidence,
} from "../src/dom/checks.js";
import { evidenceFromPage } from "../src/core/normalize.js";
import type { PageDom } from "../src/dom/page-context.js";
import { runCheck } from "./helpers.js";

describe("dom.password_form_offdomain", () => {
  it("flags a password form posting off-origin", () => {
    const ev = evidenceFromPage({
      origin: "https://login-example.com",
      url: "https://login-example.com/",
      title: "Sign in",
      forms: [{ action: "https://evil-capture.tk/collect", method: "POST", hasPasswordField: true, actionOrigin: "https://evil-capture.tk" }],
    });
    expect(runCheck(passwordFormOffdomain, ev).length).toBe(1);
  });

  it("flags a password form posting to an IP literal", () => {
    const ev = evidenceFromPage({
      origin: "https://example-login.com",
      url: "https://example-login.com/",
      title: "Sign in",
      forms: [{ action: "http://198.51.100.9/x", method: "POST", hasPasswordField: true, actionOrigin: "http://198.51.100.9" }],
    });
    expect(runCheck(passwordFormOffdomain, ev).length).toBe(1);
  });

  it("carries the brand_host flag on brand-listed pages (hard fail, §3.3)", () => {
    const ev = evidenceFromPage({
      origin: "https://paypa1.com",
      url: "https://paypa1.com/",
      title: "PayPal",
      forms: [{ action: "https://evil.tk/x", method: "POST", hasPasswordField: true, actionOrigin: "https://evil.tk" }],
    });
    const f = runCheck(passwordFormOffdomain, ev);
    expect(f.length).toBe(1);
    expect(f[0]?.flags).toContain("brand_host");
  });

  it("does not flag same-origin password forms", () => {
    const ev = evidenceFromPage({
      origin: "https://example.com",
      url: "https://example.com/login",
      title: "Sign in",
      forms: [{ action: "https://example.com/session", method: "POST", hasPasswordField: true, actionOrigin: "https://example.com" }],
    });
    expect(runCheck(passwordFormOffdomain, ev)).toEqual([]);
  });
});

describe("dom.form_posts_http", () => {
  it("flags cleartext form actions", () => {
    const ev = evidenceFromPage({
      origin: "https://example.com",
      url: "https://example.com/",
      title: "x",
      forms: [{ action: "http://example.com/submit", method: "POST", hasPasswordField: false, actionOrigin: "http://example.com" }],
    });
    expect(runCheck(formPostsHttp, ev).length).toBe(1);
  });
  it("does not flag https actions", () => {
    const ev = evidenceFromPage({
      origin: "https://example.com",
      url: "https://example.com/",
      title: "x",
      forms: [{ action: "https://example.com/submit", method: "POST", hasPasswordField: false, actionOrigin: "https://example.com" }],
    });
    expect(runCheck(formPostsHttp, ev)).toEqual([]);
  });
});

describe("dom.hidden_iframe", () => {
  it("flags hidden iframes", () => {
    const ev = evidenceFromPage({
      origin: "https://example.com", url: "https://example.com/", title: "x",
      iframes: [{ src: "https://evil.tk/pixel", hidden: true }],
    });
    expect(runCheck(hiddenIframe, ev).length).toBe(1);
  });
  it("does not flag visible iframes", () => {
    const ev = evidenceFromPage({
      origin: "https://example.com", url: "https://example.com/", title: "x",
      iframes: [{ src: "https://example.com/embed", hidden: false }],
    });
    expect(runCheck(hiddenIframe, ev)).toEqual([]);
  });
});

describe("dom.overlay_clickjack", () => {
  it("flags a full-viewport transparent overlay", () => {
    const ev = evidenceFromPage({
      origin: "https://example.com", url: "https://example.com/", title: "x",
      hasFullscreenOverlay: true,
    });
    expect(runCheck(overlayClickjack, ev).length).toBe(1);
  });
  it("does not flag clean pages", () => {
    const ev = evidenceFromPage({ origin: "https://example.com", url: "https://example.com/", title: "x" });
    expect(runCheck(overlayClickjack, ev)).toEqual([]);
  });
});

describe("dom.title_brand_mismatch", () => {
  it("flags a title claiming a brand the domain is not", () => {
    const ev = evidenceFromPage({
      origin: "https://secure-login.tk",
      url: "https://secure-login.tk/",
      title: "PayPal — Sign In",
    });
    expect(runCheck(titleBrandMismatch, ev).length).toBe(1);
  });
  it("does not flag the brand's own domain", () => {
    const ev = evidenceFromPage({
      origin: "https://www.paypal.com",
      url: "https://www.paypal.com/signin",
      title: "PayPal — Sign In",
    });
    expect(runCheck(titleBrandMismatch, ev)).toEqual([]);
  });
});

describe("dom.blank_target_noopener_absent (signal weight only)", () => {
  it("flags multiple unprotected external target=_blank links", () => {
    const ev = evidenceFromPage({
      origin: "https://example.com", url: "https://example.com/", title: "x",
      links: [
        { href: "https://a.example.net/", displayText: "a", target: "_blank" },
        { href: "https://b.example.net/", displayText: "b", target: "_blank" },
      ],
    });
    const f = runCheck(blankTargetNoopenerAbsent, ev);
    expect(f.length).toBe(1);
    expect(f[0]?.severity).toBe("info");
  });
  it("does not flag noopener links", () => {
    const ev = evidenceFromPage({
      origin: "https://example.com", url: "https://example.com/", title: "x",
      links: [
        { href: "https://a.example.net/", displayText: "a", target: "_blank", rel: "noopener noreferrer" },
        { href: "https://b.example.net/", displayText: "b", target: "_blank", rel: "noopener" },
      ],
    });
    expect(runCheck(blankTargetNoopenerAbsent, ev)).toEqual([]);
  });
});

describe("extractPageEvidence (§9 selector self-test)", () => {
  const dom: PageDom = {
    url: "https://mail.example.com/inbox/msg-1",
    origin: "https://mail.example.com",
    title: "Inbox",
    forms: [],
    links: [],
    iframes: [],
    hasFullscreenOverlay: false,
  };

  it("flags extraction_degraded when a message view yields nothing", () => {
    const { extractionDegraded } = extractPageEvidence(dom, { expectContent: true });
    expect(extractionDegraded).toBe(true);
  });

  it("passes the self-test when content extracted", () => {
    const withLinks: PageDom = { ...dom, links: [{ href: "https://example.com/x", text: "x" }] };
    const { extractionDegraded } = extractPageEvidence(withLinks, { expectContent: true });
    expect(extractionDegraded).toBe(false);
  });

  it("resolves relative form actions to the page origin", () => {
    const withForm: PageDom = {
      ...dom,
      forms: [{ action: "/session", method: "post", inputs: [{ type: "password" }] }],
    };
    const { page } = extractPageEvidence(withForm);
    expect(page.forms?.[0]?.actionOrigin).toBe("https://mail.example.com");
    expect(page.forms?.[0]?.hasPasswordField).toBe(true);
    expect(page.forms?.[0]?.method).toBe("POST");
  });
});
