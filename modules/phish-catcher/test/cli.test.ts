/**
 * Batch CLI (doc 07 §6.1): bulk URL scoring + .eml scanning with JSON
 * output and CI exit codes (0 clean / 1 suspicious / 2 malicious / 3 error),
 * signed intel via --bundle/--pin.
 */

import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runCli, EXIT_CLEAN, EXIT_SUSPICIOUS, EXIT_MALICIOUS, EXIT_ERROR, type CliIo } from "../src/node/cli.js";
import { normalizeUrlForHash } from "../src/url/parse.js";
import { buildSignedBundle, makeKeypair } from "./helpers.js";

function io(cwd: string): CliIo & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    stdout: (l) => out.push(l),
    stderr: (l) => err.push(l),
    cwd,
    env: {},
  };
}

const FIXTURES = fileURLToPath(new URL("fixtures", import.meta.url));

describe("phish-catcher scan CLI", () => {
  it("scores a URL-list file with JSON output (signed bundle supplies the brand list)", async () => {
    const keys = await makeKeypair();
    const dir = mkdtempSync(join(tmpdir(), "phish-cli-"));
    writeFileSync(join(dir, "intel.sb"), JSON.stringify(await buildSignedBundle(keys, {})));
    writeFileSync(join(dir, "urls.txt"), "# comment\nhttps://example.com/\nhttps://paypa1.com/\n\n");
    const cli = io(dir);
    const code = await runCli(["scan", "urls.txt", "--bundle", "intel.sb", "--pin", keys.publicKey, "--json"], cli);
    expect(code).toBe(EXIT_SUSPICIOUS); // paypa1.com typosquat → suspicious
    const report = JSON.parse(cli.out.join("\n"));
    expect(report.schemaVersion).toBe(1);
    expect(report.results).toHaveLength(2);
    expect(report.results[0].verdict).toBe("clean");
    expect(report.results[1].verdict).toBe("suspicious");
    expect(report.results[1].findings.map((f: { ruleId: string }) => f.ruleId)).toContain("url.typosquat");
  });

  it("exits 0 when everything is clean", async () => {
    const dir = mkdtempSync(join(tmpdir(), "phish-cli-"));
    writeFileSync(join(dir, "urls.txt"), "https://nodejs.org/\nhttps://www.rfc-editor.org/rfc\n");
    const cli = io(dir);
    expect(await runCli(["scan", "urls.txt"], cli)).toBe(EXIT_CLEAN);
  });

  it("exits 2 on a blocklisted URL (signed bundle intel)", async () => {
    const keys = await makeKeypair();
    const dir = mkdtempSync(join(tmpdir(), "phish-cli-"));
    const bundle = await buildSignedBundle(keys, {
      urls: [normalizeUrlForHash("http://evil.tk/steal")],
    });
    writeFileSync(join(dir, "intel.sb"), JSON.stringify(bundle));
    writeFileSync(join(dir, "urls.txt"), "https://example.com/\nhttp://evil.tk/steal\n");
    const cli = io(dir);
    const code = await runCli(["scan", "urls.txt", "--bundle", "intel.sb", "--pin", keys.publicKey, "--json"], cli);
    expect(code).toBe(EXIT_MALICIOUS);
    const report = JSON.parse(cli.out.join("\n"));
    const hit = report.results.find((r: { input: string }) => r.input === "http://evil.tk/steal");
    expect(hit.verdict).toBe("malicious");
    expect(hit.hardFail).toBe(true);
    expect(hit.findings.map((f: { ruleId: string }) => f.ruleId)).toContain("rep.url_blocklisted");
  });

  it("refuses unsigned intel (exit 3, fail-closed)", async () => {
    const keys = await makeKeypair();
    const attacker = await makeKeypair();
    const dir = mkdtempSync(join(tmpdir(), "phish-cli-"));
    const bundle = await buildSignedBundle(attacker, {});
    writeFileSync(join(dir, "intel.sb"), JSON.stringify(bundle));
    writeFileSync(join(dir, "urls.txt"), "https://example.com/\n");
    const cli = io(dir);
    expect(await runCli(["scan", "urls.txt", "--bundle", "intel.sb", "--pin", keys.publicKey], cli)).toBe(EXIT_ERROR);
    expect(cli.err.join("\n")).toContain("SIGNATURE_INVALID");
  });

  it("requires --pin with --bundle", async () => {
    const dir = mkdtempSync(join(tmpdir(), "phish-cli-"));
    writeFileSync(join(dir, "urls.txt"), "https://example.com/\n");
    const cli = io(dir);
    expect(await runCli(["scan", "urls.txt", "--bundle", "x.sb"], cli)).toBe(EXIT_ERROR);
  });

  it("scans .eml fixtures (malicious → exit 2, clean → exit 0)", async () => {
    const cliPhish = io(FIXTURES);
    expect(await runCli(["scan", "phish-credential.eml", "--json"], cliPhish)).toBe(EXIT_MALICIOUS);
    const cliClean = io(FIXTURES);
    expect(await runCli(["scan", "clean-newsletter.eml"], cliClean)).toBe(EXIT_CLEAN);
  });

  it("scores literal URLs passed on argv", async () => {
    const dir = mkdtempSync(join(tmpdir(), "phish-cli-"));
    const cli = io(dir);
    expect(await runCli(["scan", "https://example.com/"], cli)).toBe(EXIT_CLEAN);
  });

  it("verify-bundle validates signatures", async () => {
    const keys = await makeKeypair();
    const dir = mkdtempSync(join(tmpdir(), "phish-cli-"));
    writeFileSync(join(dir, "intel.sb"), JSON.stringify(await buildSignedBundle(keys, {})));
    const ok = io(dir);
    expect(await runCli(["verify-bundle", "intel.sb", "--pin", keys.publicKey], ok)).toBe(EXIT_CLEAN);
    const bad = io(dir);
    const other = await makeKeypair();
    expect(await runCli(["verify-bundle", "intel.sb", "--pin", other.publicKey], bad)).toBe(EXIT_ERROR);
  });

  it("agent mode is inert without PHISH_HUB=on (MVP-A standalone, doc 00 §4)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "phish-cli-"));
    const cli = io(dir);
    expect(await runCli(["agent"], cli)).toBe(EXIT_ERROR);
    expect(cli.err.join("\n")).toContain("MVP-B");
  });

  it("usage error on unknown command", async () => {
    const cli = io(mkdtempSync(join(tmpdir(), "phish-cli-")));
    expect(await runCli(["frobnicate"], cli)).toBe(EXIT_ERROR);
  });
});
