/**
 * Minimal RFC 3492 Punycode decoder (bootstring) — pure TypeScript, no
 * `node:punycode` (deprecated, Node-only). Needed by `url.idn_homograph`
 * (doc 07 §3.2) to turn `xn--*` labels back into Unicode for skeleton
 * matching, in every runtime (Node, browser, service worker).
 */

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

function decodeDigit(cp: number): number {
  // a-z → 0-25, A-Z → 0-25, 0-9 → 26-35
  if (cp >= 48 && cp <= 57) return cp - 48 + 26;
  if (cp >= 97 && cp <= 122) return cp - 97;
  if (cp >= 65 && cp <= 90) return cp - 65;
  throw new Error("invalid punycode digit");
}

/** Decode one `xn--`-stripped label. Throws on malformed input. */
export function decodePunycodeLabel(input: string): string {
  const output: number[] = [];
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;

  const delim = input.lastIndexOf("-");
  const basic = delim < 0 ? input : input.slice(0, delim);
  for (const ch of basic) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp >= 0x80) throw new Error("non-basic char in punycode basic segment");
    output.push(cp);
  }

  let index = delim < 0 ? 0 : delim + 1;
  while (index < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (index >= input.length) throw new Error("truncated punycode");
      const digit = decodeDigit(input.charCodeAt(index++));
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const outLen = output.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    output.splice(i, 0, n);
    i++;
  }

  return String.fromCodePoint(...output);
}

/** True when a label carries the `xn--` ACE prefix. */
export function isPunycodeLabel(label: string): boolean {
  return label.toLowerCase().startsWith("xn--");
}

/**
 * Decode every `xn--` label in a hostname back to Unicode. Non-ACE labels
 * pass through unchanged; malformed ACE labels are left as-is (fail-open for
 * display — the IDN presence itself is still signal).
 */
export function decodeHostLabels(host: string): string {
  return host
    .split(".")
    .map((label) => {
      if (!isPunycodeLabel(label)) return label;
      try {
        return decodePunycodeLabel(label.slice(4));
      } catch {
        return label;
      }
    })
    .join(".");
}
