/**
 * Node .eml intake (phish-node): postal-mime → Evidence normalization on
 * fixture messages (phish + clean).
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { evidenceFromRawEml } from "../src/node/eml.js";
import { createPhishCatcher } from "../src/index.js";
import { fakeIntel } from "./helpers.js";

const fixture = (name: string) =>
  readFileSync(fileURLToPath(new URL(`fixtures/${name}`, import.meta.url)));

describe("evidenceFromRawEml (doc 07 §2.2 Node intake)", () => {
  it("normalizes a phishing .eml into Evidence", async () => {
    const ev = await evidenceFromRawEml(fixture("phish-credential.eml"));
    expect(ev.kind).toBe("email");
    expect(ev.message?.headers.from).toContain("paypa1-secure.tk");
    expect(ev.message?.headers.authenticationResults).toContain("dmarc=fail");
    expect(ev.message?.headers.replyTo).toContain("evil-capture.ru");
    expect(ev.message?.urls).toContain("http://198.51.100.23/paypal/login?session=a1b2c3d4e5f6g7h8i9j0");
    const att = ev.message?.attachments?.[0];
    expect(att?.filename).toBe("invoice.pdf.exe");
    expect(att?.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("scores the phishing fixture malicious end-to-end (hard fail)", async () => {
    const ev = await evidenceFromRawEml(fixture("phish-credential.eml"));
    const v = createPhishCatcher({ intel: fakeIntel() }).analyze(ev);
    expect(v.verdict).toBe("malicious");
    expect(v.hardFail).toBe(true); // dmarc_fail + credential_request
    const ids = v.findings.map((f) => f.ruleId);
    expect(ids).toContain("auth.dmarc_fail");
    expect(ids).toContain("content.credential_request");
    expect(ids).toContain("url.ip_literal_host");
    expect(ids).toContain("content.attachment_risk");
    expect(ids).toContain("content.urgency_lexicon");
    expect(ids).toContain("auth.from_display_spoof");
    expect(v.explanations.length).toBeGreaterThan(0);
  });

  it("scores the clean newsletter fixture clean", async () => {
    const ev = await evidenceFromRawEml(fixture("clean-newsletter.eml"));
    const v = createPhishCatcher({ intel: fakeIntel() }).analyze(ev);
    expect(v.verdict).toBe("clean");
    expect(v.score).toBeLessThan(35);
  });
});
