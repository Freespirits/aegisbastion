/**
 * Minimal HTTPS JSON POST over node:https with SSRF-pinned DNS (doc 05
 * §13.4: resolved at config time, re-pinned at send time) and NO redirect
 * following — a 3xx is surfaced to the caller as a failure, never chased.
 * Zero dependencies so the SSRF guarantees are auditable in one place.
 */

import https from "node:https";
import type { IncomingMessage } from "node:http";

export interface PostJsonOptions {
  headers?: Record<string, string>;
  timeoutMs: number;
  /** Pinned resolver from the SSRF guard (dispatch/ssrf.ts). */
  lookup?: https.RequestOptions["lookup"];
  /** Extra headers merged AFTER content defaults (e.g. signatures). */
}

export interface PostJsonResult {
  status: number;
  retryAfterMs?: number;
  body: string;
}

export function postJson(url: URL, body: string, opts: PostJsonOptions): Promise<PostJsonResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const req = https.request(
      {
        method: "POST",
        hostname: url.hostname,
        port: url.port === "" ? 443 : Number(url.port),
        path: `${url.pathname}${url.search}`,
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
          "user-agent": "aegisbastion-herald/0.1",
          ...opts.headers,
        },
        timeout: opts.timeoutMs,
        ...(opts.lookup ? { lookup: opts.lookup } : {}),
      },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const retryAfter = res.headers["retry-after"];
          const retryAfterMs =
            retryAfter !== undefined && /^\d+$/.test(String(retryAfter)) ? Number(retryAfter) * 1000 : undefined;
          resolvePromise({
            status: res.statusCode ?? 0,
            ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
            body: Buffer.concat(chunks).toString("utf8").slice(0, 4096),
          });
        });
      },
    );
    req.on("timeout", () => {
      req.destroy(new Error(`request timed out after ${opts.timeoutMs}ms`));
    });
    req.on("error", rejectPromise);
    req.write(body);
    req.end();
  });
}

export function classifyStatus(status: number): "ok" | "retry" | "redirect-refused" {
  if (status >= 200 && status < 300) return "ok";
  if (status >= 300 && status < 400) return "redirect-refused";
  return "retry";
}
