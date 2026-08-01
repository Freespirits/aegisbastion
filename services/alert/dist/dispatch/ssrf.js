/**
 * SSRF guard for outbound webhook destinations (doc 05 §13.4 — ships in MVP):
 *  - HTTPS only.
 *  - DNS-resolved at config time and RE-PINNED at send time: the same
 *    validated address list is handed to the connect phase via a custom
 *    `lookup`, so a DNS rebinding cannot swap in a private address between
 *    validation and connect.
 *  - RFC1918 / loopback / link-local / CGNAT / benchmark / unspecified
 *    ranges are blocked, IPv4 AND IPv6 (incl. IPv4-mapped IPv6), unless the
 *    destination is flagged `internal: true` by an admin in the org egress
 *    policy.
 *  - No redirects are followed by callers of this guard (enforced in the
 *    webhook adapter: 3xx responses fail the delivery).
 */
import { lookup as dnsLookup } from "node:dns";
import { isIP } from "node:net";
import { promisify } from "node:util";
import { parseCidr, ipv4InCidr, ipv6InCidr, parseIpv4, parseIpv6 } from "@aegisbastion/agent-sdk";
const lookupAll = promisify(dnsLookup);
/** Blocked ranges (no documentation prefixes — those are simply unroutable). */
const BLOCKED_V4 = [
    "0.0.0.0/8", // unspecified / "this host"
    "10.0.0.0/8", // RFC1918
    "100.64.0.0/10", // CGNAT RFC6598
    "127.0.0.0/8", // loopback
    "169.254.0.0/16", // link-local
    "172.16.0.0/12", // RFC1918
    "192.0.0.0/24", // IETF protocol assignments
    "192.168.0.0/16", // RFC1918
    "198.18.0.0/15", // benchmark RFC2544
    "224.0.0.0/4", // multicast
    "240.0.0.0/4", // reserved
];
const BLOCKED_V6 = [
    "::/128", // unspecified
    "::1/128", // loopback
    "fe80::/10", // link-local
    "fc00::/7", // ULA
    "ff00::/8", // multicast
    "::ffff:0:0/96", // IPv4-mapped (handled explicitly below too)
];
const blockedV4 = BLOCKED_V4.map((s) => parseCidr(s)).filter((c) => c.family === 4);
const blockedV6 = BLOCKED_V6.map((s) => parseCidr(s)).filter((c) => c.family === 6);
export function isBlockedIp(address) {
    const v4 = parseIpv4(address);
    if (v4 !== null) {
        return blockedV4.some((c) => c.family === 4 && ipv4InCidr(v4, c));
    }
    const v6 = parseIpv6(address);
    if (v6 !== null) {
        // IPv4-mapped IPv6 (::ffff:a.b.c.d) is judged by the embedded IPv4.
        if (v6.slice(0, 12).every((b, i) => (i < 10 ? b === 0 : b === 0xff))) {
            const embedded = (v6[12] << 24) | (v6[13] << 16) | (v6[14] << 8) | v6[15];
            return blockedV4.some((c) => c.family === 4 && ipv4InCidr(embedded >>> 0, c));
        }
        return blockedV6.some((c) => c.family === 6 && ipv6InCidr(v6, c));
    }
    return true; // unparseable → blocked (fail-closed)
}
/**
 * Validate a webhook/splunk destination URL and return the PINNED address
 * list the sender must use. Fail-closed on any anomaly.
 */
export async function guardDestination(rawUrl, opts = {}) {
    let url;
    try {
        url = new URL(rawUrl);
    }
    catch {
        return { allow: false, reason: `unparseable destination URL: ${rawUrl}` };
    }
    if (url.protocol !== "https:") {
        return { allow: false, reason: "destination must be HTTPS (doc 05 §13.4)" };
    }
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    if (hostname === "") {
        return { allow: false, reason: "destination has no hostname" };
    }
    let addresses;
    try {
        if (isIP(hostname) !== 0) {
            addresses = [{ address: hostname, family: isIP(hostname) }];
        }
        else if (opts.resolveAll) {
            addresses = await opts.resolveAll(hostname);
        }
        else {
            addresses = await lookupAll(hostname, { all: true, verbatim: true });
        }
    }
    catch (err) {
        return { allow: false, reason: `DNS resolution failed for ${hostname}: ${err.message}` };
    }
    if (addresses.length === 0) {
        return { allow: false, reason: `DNS resolution returned no addresses for ${hostname}` };
    }
    if (!opts.allowInternal) {
        const blocked = addresses.filter((a) => isBlockedIp(a.address));
        if (blocked.length > 0) {
            return {
                allow: false,
                reason: `destination ${hostname} resolves to blocked private/reserved range(s): ${blocked.map((b) => b.address).join(", ")}`,
            };
        }
    }
    return { allow: true, addresses };
}
/** Node `lookup` callback that returns ONLY the pre-validated pinned addresses. */
export function pinnedLookup(addresses) {
    return (_hostname, options, callback) => {
        if (options?.all) {
            callback(null, addresses);
        }
        else {
            const first = addresses[0];
            callback(null, first.address, first.family);
        }
    };
}
