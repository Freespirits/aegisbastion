// Validates the AegisBastion JSON Schemas (draft 2020-12) and their example
// instances with ajv. Convention under schemas/examples/:
//   *.valid.json   — must validate against its schema
//   *.invalid.json — must be REJECTED by its schema (negative tests)
// Usage: node scripts/validate-schemas.mjs   (run `npm install` first)
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const schemasDir = join(root, "schemas");
const examplesDir = join(schemasDir, "examples");

// strictRequired is disabled: conditional `required` inside if/then (used for
// doc-mandated conditional requirements like authorization_token_id) is valid
// draft 2020-12 but trips ajv's strictRequired heuristic.
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);

// Register every schema so $ref between them resolves (relative $refs resolve
// against each schema's $id directory, so add them under their $id).
const schemaFiles = [
  "alert/v1/alert-event.schema.json",
  "alert/v1/cloudevents-alert-envelope.schema.json",
  "gatekeeper/v1/scope-token-claims.schema.json",
  "gatekeeper/v1/scope-manifest.schema.json",
];
const schemas = new Map();
for (const rel of schemaFiles) {
  const raw = JSON.parse(readFileSync(join(schemasDir, rel), "utf8"));
  schemas.set(raw.$id, { rel, raw });
  ajv.addSchema(raw);
}

// Map each example to the schema it must be tested against (by filename prefix).
const exampleBinding = [
  ["alert-event.", "https://aegisbastion.io/schemas/alert/v1/alert-event.schema.json"],
  ["cloudevents-envelope.", "https://aegisbastion.io/schemas/alert/v1/cloudevents-alert-envelope.schema.json"],
  ["scope-token-claims.", "https://aegisbastion.io/schemas/gatekeeper/v1/scope-token-claims.schema.json"],
  ["scope-manifest.", "https://aegisbastion.io/schemas/gatekeeper/v1/scope-manifest.schema.json"],
];

let failures = 0;

// 1) All schemas must compile.
for (const [id, { rel }] of schemas) {
  try {
    ajv.getSchema(id);
    console.log(`schema ok        ${rel}`);
  } catch (err) {
    failures++;
    console.error(`schema FAILED    ${rel}: ${err.message}`);
  }
}

// 2) Example instances.
for (const file of readdirSync(examplesDir).filter((f) => f.endsWith(".json")).sort()) {
  const binding = exampleBinding.find(([prefix]) => file.startsWith(prefix));
  if (!binding) {
    failures++;
    console.error(`example FAILED   ${file}: no schema binding for its prefix`);
    continue;
  }
  const expectValid = file.endsWith(".valid.json");
  const instance = JSON.parse(readFileSync(join(examplesDir, file), "utf8"));
  const validate = ajv.getSchema(binding[1]);
  const ok = validate(instance);
  if (ok === expectValid) {
    console.log(`example ok       ${file} (${expectValid ? "accepted" : "rejected"}, as expected)`);
  } else {
    failures++;
    const detail = expectValid ? ajv.errorsText(validate.errors) : "was accepted but must be rejected";
    console.error(`example FAILED   ${file}: ${detail}`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll schema and example checks passed.");
