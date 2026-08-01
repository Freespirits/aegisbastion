/**
 * Bloom filter membership (doc 07 §3.2 reputation family): local Bloom +
 * exact-hash confirm table — "the privacy property (no lookup oracle) and
 * the availability property (works offline) are the same property" (§7.2).
 *
 * Wire format (base64 payload in the bundle):
 *   "PCB1" (4B magic) | mBits u32 LE | k u8 | flags u8 | reserved u16 | bits
 * Hashing: FNV-1a 64-bit, double hashing h_i = (h1 + i*h2) mod m.
 * Target fp rate ≤ 0.1% at build; the exact table removes residual FPs
 * before any verdict (§3.2, §9).
 */

import { base64ToBytes, bytesToBase64, utf8ToBytes } from "./base64.js";

const MAGIC = [0x50, 0x43, 0x42, 0x31] as const; // "PCB1"
const FNV_OFFSET = 14695981039346656037n;
const FNV_PRIME = 1099511628211n;
const MASK64 = 0xffffffffffffffffn;

export function fnv1a64(data: Uint8Array): bigint {
  let h = FNV_OFFSET;
  for (const b of data) {
    h ^= BigInt(b);
    h = (h * FNV_PRIME) & MASK64;
  }
  return h;
}

export class BloomFilter {
  constructor(
    /** Bit count. */
    readonly mBits: number,
    /** Hash function count. */
    readonly k: number,
    private readonly bits: Uint8Array,
  ) {}

  static create(expectedItems: number, fpRate = 0.001): BloomFilter {
    const n = Math.max(1, expectedItems);
    const m = Math.max(64, Math.ceil((-n * Math.log(fpRate)) / (Math.LN2 * Math.LN2)));
    const k = Math.max(1, Math.min(30, Math.round((m / n) * Math.LN2)));
    return new BloomFilter(m, k, new Uint8Array(Math.ceil(m / 8)));
  }

  private positions(item: string): number[] {
    const h = fnv1a64(utf8ToBytes(item));
    const h1 = Number(h & 0xffffffffn) >>> 0;
    let h2 = Number((h >> 32n) & 0xffffffffn) >>> 0;
    if (h2 === 0) h2 = 0x9e3779b9; // golden-ratio fallback keeps probes spread
    const out = new Array<number>(this.k);
    for (let i = 0; i < this.k; i++) out[i] = (h1 + i * h2) % this.mBits;
    return out;
  }

  add(item: string): void {
    for (const pos of this.positions(item)) {
      const byte = pos >> 3;
      this.bits[byte] = (this.bits[byte] ?? 0) | (1 << (pos & 7));
    }
  }

  has(item: string): boolean {
    for (const pos of this.positions(item)) {
      const byte = pos >> 3;
      if (((this.bits[byte] ?? 0) & (1 << (pos & 7))) === 0) return false;
    }
    return true;
  }

  /** Serialize to the wire format (builder/tooling side). */
  toBase64(): string {
    const header = new Uint8Array(12);
    header.set(MAGIC);
    const dv = new DataView(header.buffer);
    dv.setUint32(4, this.mBits, true);
    dv.setUint8(8, this.k);
    const out = new Uint8Array(12 + this.bits.length);
    out.set(header);
    out.set(this.bits, 12);
    return bytesToBase64(out);
  }

  /** Parse the wire format (reader side). Throws on malformed input. */
  static fromBase64(b64: string): BloomFilter {
    const raw = base64ToBytes(b64);
    if (raw.length < 12) throw new Error("bloom payload too short");
    for (let i = 0; i < 4; i++) if (raw[i] !== MAGIC[i]) throw new Error("bad bloom magic");
    const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const mBits = dv.getUint32(4, true);
    const k = dv.getUint8(8);
    const bits = raw.slice(12);
    if (bits.length !== Math.ceil(mBits / 8)) throw new Error("bloom bit-array length mismatch");
    if (k < 1 || k > 64) throw new Error("bloom k out of range");
    return new BloomFilter(mBits, k, bits);
  }
}

/**
 * Exact-hash confirmation table: sorted concatenated 32-byte SHA-256
 * digests, binary-searched. On a Bloom positive, membership here removes
 * false positives before the verdict (doc 07 §3.2).
 */
export class ExactHashTable {
  /** digests: length must be a multiple of 32, sorted ascending. */
  constructor(private readonly digests: Uint8Array) {
    if (digests.length % 32 !== 0) throw new Error("exact table must be a multiple of 32 bytes");
  }

  static fromHexList(hexDigests: string[]): ExactHashTable {
    const sorted = [...hexDigests].map((h) => h.toLowerCase()).sort();
    const out = new Uint8Array(sorted.length * 32);
    for (const [i, h] of sorted.entries()) {
      if (!/^[0-9a-f]{64}$/.test(h)) throw new Error(`bad digest in exact table: ${h}`);
      for (let j = 0; j < 32; j++) out[i * 32 + j] = parseInt(h.slice(j * 2, j * 2 + 2), 16);
    }
    return new ExactHashTable(out);
  }

  static fromBase64(b64: string): ExactHashTable {
    return new ExactHashTable(base64ToBytes(b64));
  }

  toBase64(): string {
    return bytesToBase64(this.digests);
  }

  get size(): number {
    return this.digests.length / 32;
  }

  /** Binary-search a 32-byte digest. */
  hasDigest(digest: Uint8Array): boolean {
    if (digest.length !== 32) return false;
    let lo = 0;
    let hi = this.size - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      let cmp = 0;
      for (let j = 0; j < 32; j++) {
        cmp = (this.digests[mid * 32 + j] ?? 0) - (digest[j] ?? 0);
        if (cmp !== 0) break;
      }
      if (cmp === 0) return true;
      if (cmp < 0) lo = mid + 1;
      else hi = mid - 1;
    }
    return false;
  }
}

/** Canonical blocklist entry encodings (single bloom+table for all kinds). */
export const blocklistEntry = {
  domain: (registeredDomainOrHost: string) => `d:${registeredDomainOrHost.toLowerCase()}`,
  url: (normalizedUrl: string) => `u:${normalizedUrl}`,
  sender: (address: string) => `s:${address.toLowerCase()}`,
};
