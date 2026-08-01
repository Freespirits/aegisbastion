/**
 * Batch CLI (doc 07 §6.1): bulk scoring of .eml files, URL-list files, and
 * literal URLs, with JSON output and CI-friendly exit codes:
 *   0 — every input clean
 *   1 — at least one suspicious (none malicious)
 *   2 — at least one malicious
 *   3 — usage / configuration error
 *
 * All scoring is local (§7). `--bundle`/`--policy` are verified against
 * pinned hub keys before application (§4.3/§4.4) — unsigned or tampered
 * intel is rejected, never trusted.
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { PhishCatcher } from "../index.js";
import { IntelStore } from "../intel/store.js";
import type { ApplyResult } from "../intel/store.js";
import type { Verdict, VerdictLabel } from "../core/verdict.js";
import { evidenceFromRawEml } from "./eml.js";

export interface CliIo {
  stdout: (line: string) => void;
  stderr: (line: string) => void;
  cwd: string;
  env: Record<string, string | undefined>;
}

export const EXIT_CLEAN = 0;
export const EXIT_SUSPICIOUS = 1;
export const EXIT_MALICIOUS = 2;
export const EXIT_ERROR = 3;

const URL_LIST_EXTENSIONS = new Set([".txt", ".urls", ".list", ".lst"]);

interface ScanArgs {
  inputs: string[];
  bundlePath?: string;
  policyPath?: string;
  pins: string[];
  json: boolean;
}

interface ItemResult {
  input: string;
  kind: "email" | "url";
  verdict: VerdictLabel;
  score: number;
  familyScores: Verdict["familyScores"];
  hardFail: boolean;
  explanations: string[];
  findings: Verdict["findings"];
  hints: Verdict["hints"];
  timingMs: number;
  error?: string;
}

function usage(io: CliIo): number {
  io.stderr(
    [
      "phish-catcher — client-side phishing detection (doc 07; zero external transmission)",
      "",
      "Usage:",
      "  phish-catcher scan <inputs...> [--bundle f --pin k] [--policy f] [--json]",
      "      inputs: .eml files, URL-list files (.txt/.urls/.list/.lst), literal URLs",
      "  phish-catcher verify-bundle <file> --pin <b64url pubkey> [--pin <key2>]",
      "  phish-catcher agent [--enroll <token>]   (hub loop — MVP-B; requires PHISH_HUB=on)",
      "",
      "Exit codes: 0 clean · 1 suspicious · 2 malicious · 3 error",
    ].join("\n"),
  );
  return EXIT_ERROR;
}

function extname(p: string): string {
  const m = /\.[A-Za-z0-9]+$/.exec(p);
  return m ? m[0].toLowerCase() : "";
}

function looksLikeUrl(s: string): boolean {
  return /^https?:\/\//i.test(s) || (!/[/\\]/.test(s) && /^(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/?#:]|$)/i.test(s));
}

function parseScanArgs(args: string[], io: CliIo): ScanArgs | null {
  const out: ScanArgs = { inputs: [], pins: [], json: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === "--json") out.json = true;
    else if (a === "--bundle") {
      const v = args[++i];
      if (!v) { io.stderr("--bundle requires a path"); return null; }
      out.bundlePath = v;
    } else if (a === "--policy") {
      const v = args[++i];
      if (!v) { io.stderr("--policy requires a path"); return null; }
      out.policyPath = v;
    } else if (a === "--pin") {
      const v = args[++i];
      if (!v) { io.stderr("--pin requires a base64url public key"); return null; }
      out.pins.push(v);
    } else if (a.startsWith("--")) {
      io.stderr(`unknown option: ${a}`);
      return null;
    } else {
      out.inputs.push(a);
    }
  }
  if (out.inputs.length === 0) {
    io.stderr("scan requires at least one input");
    return null;
  }
  return out;
}

async function loadIntel(args: ScanArgs, io: CliIo): Promise<IntelStore | null> {
  if (args.bundlePath === undefined && args.policyPath === undefined) return null;
  if (args.pins.length === 0) {
    io.stderr("error: --bundle/--policy require at least one --pin (signed intel only, doc 07 §4.3/§4.4)");
    return null;
  }
  const store = new IntelStore({ pinnedKeys: args.pins });
  if (args.bundlePath !== undefined) {
    const path = resolve(io.cwd, args.bundlePath);
    let raw: unknown;
    try {
      raw = JSON.parse(await readFile(path, "utf8"));
    } catch (err) {
      io.stderr(`error: cannot read bundle ${path}: ${(err as Error).message}`);
      return null;
    }
    const res: ApplyResult = await store.applyBundle(raw);
    if (!res.applied) {
      io.stderr(`error: bundle rejected (${res.reason ?? "unknown"}) — refusing to score with untrusted intel`);
      return null;
    }
    if (res.stale === true) {
      io.stderr(`warning: bundle ${store.bundleVersion()} is stale — degraded mode (reputation weight 0, doc 07 §9)`);
    } else {
      io.stderr(`bundle ${store.bundleVersion()} applied`);
    }
  }
  if (args.policyPath !== undefined) {
    const path = resolve(io.cwd, args.policyPath);
    let raw: unknown;
    try {
      raw = JSON.parse(await readFile(path, "utf8"));
    } catch (err) {
      io.stderr(`error: cannot read policy ${path}: ${(err as Error).message}`);
      return null;
    }
    const res = await store.applyPolicy(raw);
    if (!res.applied) {
      io.stderr(`error: policy rejected (${res.reason ?? "unknown"}) — using compiled-in safe defaults`);
    }
  }
  return store;
}

async function scanOne(catcher: PhishCatcher, input: string, io: CliIo): Promise<ItemResult> {
  const path = resolve(io.cwd, input);
  if (existsSync(path)) {
    if (URL_LIST_EXTENSIONS.has(extname(path))) {
      throw new Error(`URL-list file must be expanded by the caller: ${input}`);
    }
    const raw = await readFile(path);
    const ev = await evidenceFromRawEml(new Uint8Array(raw));
    const v = catcher.analyze(ev);
    return {
      input, kind: "email", verdict: v.verdict, score: v.score,
      familyScores: v.familyScores, hardFail: v.hardFail, explanations: v.explanations,
      findings: v.findings, hints: v.hints, timingMs: v.timingMs,
    };
  }
  if (looksLikeUrl(input)) {
    const v = catcher.analyzeUrl(input);
    return {
      input, kind: "url", verdict: v.verdict, score: v.score,
      familyScores: v.familyScores, hardFail: v.hardFail, explanations: v.explanations,
      findings: v.findings, hints: v.hints, timingMs: v.timingMs,
    };
  }
  throw new Error(`input is neither a file nor a URL: ${input}`);
}

/** Expand URL-list files into individual URL inputs (one per line). */
async function expandInputs(inputs: string[], io: CliIo): Promise<string[]> {
  const out: string[] = [];
  for (const input of inputs) {
    const path = resolve(io.cwd, input);
    if (existsSync(path) && URL_LIST_EXTENSIONS.has(extname(path))) {
      const text = await readFile(path, "utf8");
      for (const line of text.split(/\r?\n/)) {
        const t = line.trim();
        if (t === "" || t.startsWith("#")) continue;
        out.push(t);
      }
    } else {
      out.push(input);
    }
  }
  return out;
}

function rank(v: VerdictLabel): number {
  return v === "malicious" ? 2 : v === "suspicious" ? 1 : 0;
}

async function scanCommand(args: string[], io: CliIo): Promise<number> {
  const parsed = parseScanArgs(args, io);
  if (!parsed) return EXIT_ERROR;
  const store = await loadIntel(parsed, io);
  if ((parsed.bundlePath !== undefined || parsed.policyPath !== undefined) && store === null) {
    return EXIT_ERROR;
  }
  const catcher = new PhishCatcher(store ? { intel: store, policy: store.policy() } : {});
  const inputs = await expandInputs(parsed.inputs, io);

  const results: ItemResult[] = [];
  let worst = EXIT_CLEAN;
  for (const input of inputs) {
    try {
      const r = await scanOne(catcher, input, io);
      results.push(r);
      if (rank(r.verdict) === 2) worst = EXIT_MALICIOUS;
      else if (rank(r.verdict) === 1 && worst < EXIT_SUSPICIOUS) worst = EXIT_SUSPICIOUS;
      if (!parsed.json) {
        io.stdout(`${r.verdict.toUpperCase().padEnd(10)} score=${String(r.score).padStart(3)} ${r.input}`);
        for (const e of r.explanations) io.stdout(`           - ${e}`);
      }
    } catch (err) {
      results.push({
        input, kind: "url", verdict: "clean", score: 0,
        familyScores: { url: 0, dom: 0, content: 0, auth: 0, reputation: 0 },
        hardFail: false, explanations: [], findings: [], hints: [], timingMs: 0,
        error: (err as Error).message,
      });
      io.stderr(`error scoring ${input}: ${(err as Error).message}`);
      worst = Math.max(worst, EXIT_ERROR) as number;
    }
  }

  if (parsed.json) {
    io.stdout(JSON.stringify({ schemaVersion: 1, results }, null, 2));
  }
  return worst;
}

async function verifyBundleCommand(args: string[], io: CliIo): Promise<number> {
  const pins: string[] = [];
  let file: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === "--pin") {
      const v = args[++i];
      if (!v) { io.stderr("--pin requires a base64url public key"); return EXIT_ERROR; }
      pins.push(v);
    } else if (!a.startsWith("--")) file = a;
    else { io.stderr(`unknown option: ${a}`); return EXIT_ERROR; }
  }
  if (file === undefined || pins.length === 0) {
    io.stderr("verify-bundle requires a file and at least one --pin");
    return EXIT_ERROR;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(resolve(io.cwd, file), "utf8"));
  } catch (err) {
    io.stderr(`error: cannot read bundle: ${(err as Error).message}`);
    return EXIT_ERROR;
  }
  const store = new IntelStore({ pinnedKeys: pins });
  const res = await store.applyBundle(raw);
  if (!res.applied) {
    io.stdout(`REJECTED (${res.reason ?? "unknown"})`);
    return EXIT_ERROR;
  }
  io.stdout(`OK bundle=${store.bundleVersion()} stale=${res.stale === true ? "yes (degraded)" : "no"}`);
  return EXIT_CLEAN;
}

async function agentCommand(_args: string[], io: CliIo): Promise<number> {
  // Doc 00 §4: the hub loop is MVP-B; MVP-A ships standalone. The transport
  // seam (src/hub/) is feature-flagged — PHISH_HUB=on + SDK wiring config.
  if (io.env.PHISH_HUB !== "on") {
    io.stderr(
      "hub agent mode is disabled (MVP-A ships the standalone library; hub loop is MVP-B, doc 00 §4). " +
        "Set PHISH_HUB=on and provide hub wiring to enable the @aegisbastion/agent-sdk transport.",
    );
    return EXIT_ERROR;
  }
  try {
    const { startHubAgent } = await import("../hub/agent-sdk-transport.js");
    await startHubAgent({ env: io.env, stderr: io.stderr, stdout: io.stdout });
    return EXIT_CLEAN;
  } catch (err) {
    io.stderr(`hub agent failed: ${(err as Error).message}`);
    return EXIT_ERROR;
  }
}

/** CLI entry — returns the process exit code. */
export async function runCli(argv: string[], io: CliIo): Promise<number> {
  const [command, ...rest] = argv;
  switch (command) {
    case "scan":
      return scanCommand(rest, io);
    case "verify-bundle":
      return verifyBundleCommand(rest, io);
    case "agent":
      return agentCommand(rest, io);
    default:
      return usage(io);
  }
}
