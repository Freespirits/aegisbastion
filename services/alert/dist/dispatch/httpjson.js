/**
 * Minimal HTTPS JSON POST over node:https with SSRF-pinned DNS (doc 05
 * §13.4: resolved at config time, re-pinned at send time) and NO redirect
 * following — a 3xx is surfaced to the caller as a failure, never chased.
 * Zero dependencies so the SSRF guarantees are auditable in one place.
 */
import https from "node:https";
export function postJson(url, body, opts) {
    return new Promise((resolvePromise, rejectPromise) => {
        const req = https.request({
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
        }, (res) => {
            const chunks = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => {
                const retryAfter = res.headers["retry-after"];
                const retryAfterMs = retryAfter !== undefined && /^\d+$/.test(String(retryAfter)) ? Number(retryAfter) * 1000 : undefined;
                resolvePromise({
                    status: res.statusCode ?? 0,
                    ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
                    body: Buffer.concat(chunks).toString("utf8").slice(0, 4096),
                });
            });
        });
        req.on("timeout", () => {
            req.destroy(new Error(`request timed out after ${opts.timeoutMs}ms`));
        });
        req.on("error", rejectPromise);
        req.write(body);
        req.end();
    });
}
export function classifyStatus(status) {
    if (status >= 200 && status < 300)
        return "ok";
    if (status >= 300 && status < 400)
        return "redirect-refused";
    return "retry";
}
