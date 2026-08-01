// E2E verify: dashboard BFF → live herald (:8086) with X-AegisBastion-Actor threading.
// 1. dev-login "cai" (herald admin) → POST /api/alert-rules → expect 201
// 2. dev-login "mallory" (not admin) → POST /api/alert-rules → expect 403 from herald
// 3. GET /api/alert-rules → expect 200, created policy present (HERALD_URL wiring)
const BASE = "http://127.0.0.1:3100";
const ORG = "org_dash_verify";
let failures = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
};

async function login(principal) {
  const res = await fetch(`${BASE}/api/auth/dev-login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ principal, org_id: ORG, token: "e2e-verify-token" }),
  });
  const setCookie = res.headers.get("set-cookie") ?? "";
  const cookie = setCookie.split(";")[0];
  return { status: res.status, cookie, body: await res.json().catch(() => null) };
}

const policy = {
  org_id: ORG,
  priority: 50,
  match: { severity_gte: "info" },
  targets: [{ channel: "webhook", destination: "https://siem.dashverify.example/ingest", template: "raw_json" }],
};

// wait for server (any HTTP response — even a 401 — means it is listening)
let up = false;
for (let i = 0; i < 40 && !up; i++) {
  await new Promise((r) => setTimeout(r, 500));
  up = await fetch(`${BASE}/api/health`).then((r) => r.status > 0).catch(() => false);
}
if (!up) { console.log("FAIL  dashboard server did not come up on :3100"); process.exit(1); }

const cai = await login("cai");
check("dev-login cai (fallback role operator)", cai.status === 200 && cai.cookie.length > 0, JSON.stringify(cai.body));

const created = await fetch(`${BASE}/api/alert-rules`, {
  method: "POST",
  headers: { "content-type": "application/json", cookie: cai.cookie },
  body: JSON.stringify(policy),
});
const createdBody = await created.json().catch(() => null);
check("POST /api/alert-rules as cai → 201 (X-AegisBastion-Actor accepted by herald)", created.status === 201, `status=${created.status} ${JSON.stringify(createdBody)?.slice(0, 160)}`);
check("herald stamped createdBy from the forwarded actor", createdBody?.createdBy === "cai", `createdBy=${createdBody?.createdBy}`);

const mallory = await login("mallory");
check("dev-login mallory", mallory.status === 200);
const denied = await fetch(`${BASE}/api/alert-rules`, {
  method: "POST",
  headers: { "content-type": "application/json", cookie: mallory.cookie },
  body: JSON.stringify({ ...policy, priority: 51 }),
});
check("POST /api/alert-rules as mallory → 403 (principal forwarded, herald denies non-admin)", denied.status === 403, `status=${denied.status}`);

const list = await fetch(`${BASE}/api/alert-rules`, { headers: { cookie: cai.cookie } });
const listBody = await list.json().catch(() => null);
const found = Array.isArray(listBody?.policies) && listBody.policies.some((p) => p.orgId === ORG && p.createdBy === "cai");
check("GET /api/alert-rules lists the created policy (HERALD_URL wiring)", list.status === 200 && found, `status=${list.status}`);

console.log(failures === 0 ? "\nE2E OK" : `\nE2E FAILED (${failures})`);
console.log(`CREATED_POLICY_ID=${createdBody?.policyId ?? ""}`);
process.exit(failures === 0 ? 0 : 1);
