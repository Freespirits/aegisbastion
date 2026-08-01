/**
 * ULID generation (doc 01 §8.2: every envelope event_id is a ULID).
 * Crockford base32, 48-bit time + 80-bit randomness, monotonic within a tick.
 */

const ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

let lastTime = -1;
let lastRandom: Uint8Array = new Uint8Array(10);

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

function encodeTime(now: number, length: number): string {
  let str = "";
  for (let i = length - 1; i >= 0; i--) {
    str = ENCODING[now % 32] + str;
    now = Math.floor(now / 32);
  }
  return str;
}

function encodeRandom(bytes: Uint8Array): string {
  // 80 bits → 16 base32 chars, big-endian bit stream.
  let str = "";
  let bitBuffer = 0;
  let bitCount = 0;
  for (const byte of bytes) {
    bitBuffer = (bitBuffer << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      str += ENCODING[(bitBuffer >> bitCount) & 31];
    }
  }
  if (bitCount > 0) {
    str += ENCODING[(bitBuffer << (5 - bitCount)) & 31];
  }
  return str;
}

/** Increment the 80-bit random part by one (monotonic ULIDs within one ms). */
function incrementRandom(bytes: Uint8Array): Uint8Array {
  const next = new Uint8Array(bytes);
  for (let i = next.length - 1; i >= 0; i--) {
    if (next[i] === 0xff) {
      next[i] = 0;
    } else {
      next[i]!++;
      return next;
    }
  }
  // Overflow: fall back to fresh randomness.
  return randomBytes(bytes.length);
}

export function ulid(now: number = Date.now()): string {
  if (now === lastTime) {
    lastRandom = incrementRandom(lastRandom);
  } else {
    lastTime = now;
    lastRandom = randomBytes(10);
  }
  return encodeTime(now, 10) + encodeRandom(lastRandom);
}
