/**
 * JSON Schema conformance (doc 07 §4): Evidence, Verdict, PolicyConfig,
 * IntelBundle validate against the Draft 2020-12 schemas in schemas/.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { fileURLToPath } from "node:url";
import { evidenceFromEmail } from "../src/core/normalize.js";
import { evidenceFromUrl } from "../src/url/checks.js";
import { createPhishCatcher } from "../src/index.js";
import { buildSignedBundle, fakeIntel, makeKeypair, policyBody, signDocument } from "./helpers.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

function loadAjv() {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  for (const name of ["evidence", "verdict", "policy", "intel-bundle"]) {
    const schema = JSON.parse(readFileSync(join(ROOT, "schemas", name, "v1", "schema.json"), "utf8"));
    ajv.addSchema(schema, `https://aegisbastion.local/schemas/${name}/v1/schema.json`);
  }
  return ajv;
}

describe("JSON schemas (Draft 2020-12)", () => {
  const ajv = loadAjv();

  it("validates email Evidence", () => {
    const ev = evidenceFromEmail({
      headers: { from: "a@example.com", authenticationResults: "mx; spf=pass" },
      subject: "hi",
      bodyText: "hello",
      attachments: [{ filename: "a.pdf", contentType: "application/pdf", size: 12, sha256: "ab".repeat(32) }],
      urls: ["https://example.com/x"],
      anchors: [{ href: "https://example.com/x", displayText: "x" }],
    });
    const validate = ajv.getSchema("https://aegisbastion.local/schemas/evidence/v1/schema.json");
    expect(validate).toBeDefined();
    expect(validate!(JSON.parse(JSON.stringify(ev)))).toBe(true);
  });

  it("validates url Evidence", () => {
    const ev = evidenceFromUrl("https://example.com/x");
    const validate = ajv.getSchema("https://aegisbastion.local/schemas/evidence/v1/schema.json");
    expect(validate!(JSON.parse(JSON.stringify(ev)))).toBe(true);
  });

  it("validates a pipeline Verdict", () => {
    const v = createPhishCatcher({ intel: fakeIntel() }).analyzeUrl("https://paypa1.com/");
    const validate = ajv.getSchema("https://aegisbastion.local/schemas/verdict/v1/schema.json");
    const ok = validate!(JSON.parse(JSON.stringify(v)));
    if (!ok) console.error(validate!.errors);
    expect(ok).toBe(true);
  });

  it("validates a signed PolicyConfig", async () => {
    const keys = await makeKeypair();
    const policy = await signDocument(keys, policyBody());
    const validate = ajv.getSchema("https://aegisbastion.local/schemas/policy/v1/schema.json");
    expect(validate!(policy)).toBe(true);
  });

  it("validates a signed IntelBundle", async () => {
    const keys = await makeKeypair();
    const bundle = await buildSignedBundle(keys, { domains: ["evil.tk"] });
    const validate = ajv.getSchema("https://aegisbastion.local/schemas/intel-bundle/v1/schema.json");
    const ok = validate!(JSON.parse(JSON.stringify(bundle)));
    if (!ok) console.error(validate!.errors);
    expect(ok).toBe(true);
  });
});
