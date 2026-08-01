/**
 * Runtime-neutral base64/base64url helpers (no Buffer/atob assumptions —
 * phish-intel runs in Node, service workers, and content scripts).
 */

export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/[\r\n\s]/g, "");
  if (typeof globalThis.atob === "function") {
    const bin = globalThis.atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // Node fallback (Buffer is ambient under @types/node but not imported).
  const g = globalThis as { Buffer?: { from(s: string, e: string): { length: number; [i: number]: number } } };
  if (g.Buffer) {
    const buf = g.Buffer.from(clean, "base64");
    const out = new Uint8Array(buf.length);
    for (let i = 0; i < buf.length; i++) out[i] = buf[i] ?? 0;
    return out;
  }
  throw new Error("no base64 decoder available in this runtime");
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof globalThis.btoa === "function") {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return globalThis.btoa(bin);
  }
  const g = globalThis as { Buffer?: { from(b: Uint8Array): { toString(e: string): string } } };
  if (g.Buffer) return g.Buffer.from(bytes).toString("base64");
  throw new Error("no base64 encoder available in this runtime");
}

export function base64urlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return base64ToBytes(padded);
}

export function bytesToBase64url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
