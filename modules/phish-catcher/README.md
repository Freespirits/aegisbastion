# @aegisbastion/phish-catcher

Phish-Catcher (design doc 07): a phishing-detection library that runs **entirely on the client** — in a browser, in a Chrome MV3 extension, or in Node.js — using a modular pipeline of deterministic heuristics. MVP-A ships it as a **standalone library**; the hub loop is MVP-B (doc 00 §4).

**The one inviolable rule: zero external transmission of inspected content.** No URL, email body, DOM, or hash thereof is ever sent anywhere as part of a detection lookup. All intelligence ships *to* the client as signed, versioned bundles; all verdicts are computed locally. The only permitted egress is an opt-in, consent-gated, redacted finding report (doc 07 §5.4) — and the hub transport behind it is feature-flagged and **inert by default**.

## Layout

Doc 07 §2.1's package layout is mapped onto `src/` subdirectories (one npm package, multiple entry points):

| Path | Doc 07 package | Contents |
|---|---|---|
| `src/core/` | `phish-core` | Pipeline engine, check registry, scorer, Evidence/Verdict/Policy schemas |
| `src/url/` | `phish-url` | URL parsing (PSL-lite), IDN/homograph skeletons, typosquat distance, TLD/shortener tables |
| `src/content/` | `phish-content` | Authentication-Results parsing, urgency/credential lexicons, attachment risk |
| `src/dom/` | `phish-dom` | PageDom extraction + DOM checks (100% shared check code, §12) |
| `src/intel/` | `phish-intel` | Signed bundle/policy verification, Bloom + exact-hash tables, IntelStore |
| `src/node/` | `phish-node` | `.eml` intake (postal-mime), batch CLI, audit log |
| `src/ext/` | `phish-ext` | MV3 service worker, content script, popup, options |
| `src/hub/` | hub seam | §5.2 message contracts, §8 scan-request gate, §5.4 redaction, transport interface (inert default) + SDK adapter (MVP-B) |

Entry points: `.` (neutral), `./node`, `./browser` (see `package.json` exports).

## Checks

All 30 MVP checks of doc 07 §3.2 are implemented with their normative rule IDs (12 URL + 6 auth + 3 content + 6 DOM + 3 reputation). The three Later checks (`content.qr_url`, `dom.favicon_brand_mismatch`, `rep.cert_age_suspicious`) are excluded per §11. Scoring is doc 07 §3.3 exactly: per-family caps (url 40, dom 35, content 30, auth 35, reputation 100), thresholds (≥70 malicious, ≥35 suspicious), and the three hard-fail rules (`rep.url_blocklisted` exact match; `dom.password_form_offdomain` on a brand-listed domain; `auth.dmarc_fail` + `content.credential_request` co-occurrence).

## Usage

```ts
import { createPhishCatcher, IntelStore } from "@aegisbastion/phish-catcher";

const store = new IntelStore({ pinnedKeys: [HUB_PUBLIC_KEY_B64URL] });
await store.applyBundle(signedBundle);          // signature + rollback + freshness checked
const catcher = createPhishCatcher({ intel: store, policy: store.policy() });

const v1 = catcher.analyzeUrl("https://paypa1.com/");      // → suspicious (typosquat)
const v2 = catcher.analyzeEmail({ headers, subject, bodyText, urls, anchors });
```

```ts
// Node: raw .eml intake
import { analyze } from "@aegisbastion/phish-catcher/node";
const verdict = await analyze(rawEmlBuffer);
```

```ts
// Browser: live DOM page scan
import { analyzePage } from "@aegisbastion/phish-catcher/browser";
const { verdict, extractionDegraded } = analyzePage(document);
```

### CLI

```
phish-catcher scan ./samples/*.eml --json        # exit 2 on any malicious (CI-friendly)
phish-catcher scan urls.txt --bundle intel.sb --pin <b64url-key>
phish-catcher verify-bundle intel.sb --pin <b64url-key>
phish-catcher agent                              # hub loop — MVP-B; requires PHISH_HUB=on
```

Inputs: `.eml` files, URL-list files (`.txt`/`.urls`/`.list`/`.lst`, one per line, `#` comments), literal URLs. Exit codes: 0 clean · 1 suspicious · 2 malicious · 3 error.

### Chrome MV3 extension

```
npm run build:ext     # tsup → extension/dist/*.js (IIFE, no remote code)
npm run pack:ext      # validate manifest + copy to release/phish-ext/
```

Load `release/phish-ext/` unpacked. Content scripts run ISOLATED on the allowlisted webmail origins only (Gmail, Outlook Web); the service worker owns the signed intel bundle (rehydrates from IndexedDB on wake); the popup shows the current-tab verdict, top explanations, and the consent-gated "report this phish" action; the options page has telemetry opt-in (default **off**), local brand additions, and signed bundle/policy application against pinned hub keys. Dev mode (unsigned policies) is compiled out unless built with `PHISH_DEV=on` (`__PHISH_DEV__`).

## Signed intel & policy bundles (doc 07 §4.3/§4.4)

- Signature: **Ed25519 over JCS (RFC 8785, doc 01 §10.2)** of the document minus its `signature` field — the platform's single canonicalization.
- Verified against **pinned hub public keys** (two pinned for rotation).
- **Monotonic versions** — rollback rejected; last good retained (`INTEGRITY_FAILURE` surfaced for audit).
- **Freshness** — a bundle older than 14 days (or past `expiresAt`) applies in `degraded_mode`: heuristics continue, reputation family weight → 0 (§9).
- **Rotation** — `nextKey` must be dual-signed by the same pinned key that signed the bundle (§8.6); anything else is rejected and the fleet stays on last good.
- Reputation answers are local: Bloom filter + exact-hash confirmation table (fp ≤ 0.1%, residual FPs removed before any verdict, §3.2).

JSON Schemas (Draft 2020-12) for Evidence, Verdict, PolicyConfig, and IntelBundle live in `schemas/`.

## Hub transport seam (Ruling C10; doc 00 §4)

`src/hub/` defines the §5.2 message contracts and a `HubTransport` interface. MVP-A default is `InertHubTransport` — zero egress, zero hub coupling. Behind the feature flag (`PHISH_HUB=on` + wiring env vars), `AgentSdkHubTransport` runs the batch agent over the **platform TS agent SDK** (`@aegisbastion/agent-sdk`, bus / `StreamTasks` — there is no bespoke WSS `/v1/agent-bus`). The §8 authorization gate (`ScanRequestGate`) is real and tested offline: gatekeeper Scope Token verification (injected from the SDK's `verifyScopeToken` + `JwksCache`), scope allowlist, per-scope rate cap (default 600/min, compiled-in ceiling 5 000/min, token `rate_caps` wins when tighter), browser-mode unconditional `UNSUPPORTED_IN_MODE`. Finding reports are redacted per §5.4 (salted SHA-256 URLs/sender/message-id; body, subject, and attachment content never leave) and queued locally (ring buffer 500, drop-oldest) until the MVP-B report-ingest contract lands.

## Verification

```
npm install
npm run typecheck     # tsc --noEmit (strict)
npm test              # vitest — 157 tests
npm run build         # tsup library bundles (dist/)
npm run build:ext     # tsup MV3 bundles (extension/dist/)
npm run pack:ext      # manifest validation + release/phish-ext/
```

The test suite covers: every heuristic check with true/false-positive fixtures; pipeline composability (custom registries, disabled checks, weight overrides, family caps, hard fails, degraded mode, time-boxing, exception containment); bundle/policy signature verify/reject/rollback/stale/rotation; JSON Schema conformance; MV3 manifest validation; CLI batch runs on fixture lists (.eml + URL lists) with exit codes; the §8 scan gate; §5.4 redaction; and the **zero-egress attestation** (§7.1) — a static dependency-graph gate plus a runtime network-mocked sandbox proving no egress during `analyze*`.

## Deviations from doc 07 (all deliberate, MVP-A)

1. **ESLint `no-restricted-imports` gate → vitest dependency-graph gate.** eslint is not in the dependency tree; `test/no-egress.test.ts` statically scans `src/{core,url,content,dom,intel}` for network APIs/imports on every `npm test` (same enforcement point: CI).
2. **Report salt.** §5.4's hub-issued salt has no hub in MVP-A; the extension generates a per-install salt and rotates it every 24 h, same rotation cadence. The `RedactionContext` takes the salt as a parameter, so the hub-issued salt drops in unchanged at MVP-B.
3. **Popup "page scan on any tab"** is implemented as a paste-a-URL check plus inline verdicts on webmail tabs — this preserves the minimal permission set (`activeTab`, `storage`, `alarms`); adding arbitrary-tab scanning would require the `scripting` permission, which the doc's permission list does not grant.
4. **mbox intake** is not implemented (§11 MVP lists `.eml` batch only; mbox is trivial to add on top of `evidenceFromRawEml`).
5. **Doc 07 §6.3's "IndexedDB report queue"** is implemented (`src/ext/idb.ts`); `chrome.storage` is used only where Chrome requires it. Bundle/policy persistence is IndexedDB per the doc.
