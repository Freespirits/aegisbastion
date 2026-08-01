/**
 * Ed25519 signature verification over JCS-canonical JSON (doc 07 §4.3/§4.4:
 * "signature: Ed25519 over JCS-canonical JSON (doc 01 §10.2)"), on WebCrypto
 * — zero crypto dependencies, runtime-neutral (Node ≥ 20, modern Chrome).
 * Key custody (§8.6): hub public keys pinned at build; rotation requires a
 * dual-signed (old+new) bundle — see `nextKey` in the bundle schema.
 */

import { base64urlToBytes, bytesToBase64url, utf8ToBytes } from "./base64.js";

function subtle(): SubtleCrypto {
  const c = globalThis.crypto?.subtle;
  if (!c) throw new Error("WebCrypto SubtleCrypto unavailable in this runtime");
  return c;
}

export interface Ed25519Keypair {
  /** base64url raw 32-byte public key (the pinnable form). */
  publicKey: string;
  /** base64url PKCS#8 private key (tooling/signing side only). */
  privateKeyPkcs8: string;
}

/** Generate a keypair (tooling/tests; agents generate at install per §5.1). */
export async function generateEd25519Keypair(): Promise<Ed25519Keypair> {
  const pair = await subtle().generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const keys = pair as { publicKey: CryptoKey; privateKey: CryptoKey };
  const rawPub = new Uint8Array(await subtle().exportKey("raw", keys.publicKey));
  const pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", keys.privateKey));
  return { publicKey: bytesToBase64url(rawPub), privateKeyPkcs8: bytesToBase64url(pkcs8) };
}

/** Import a pinned raw public key (base64url). */
export async function importPinnedPublicKey(base64urlRawKey: string): Promise<CryptoKey> {
  const bytes = base64urlToBytes(base64urlRawKey);
  if (bytes.length !== 32) throw new Error("pinned Ed25519 public key must be 32 bytes");
  return subtle().importKey("raw", bytes as BufferSource, { name: "Ed25519" }, false, ["verify"]);
}

/** Import a PKCS#8 private key (signing tooling only — never shipped). */
export async function importPrivateKeyPkcs8(base64urlPkcs8: string): Promise<CryptoKey> {
  return subtle().importKey("pkcs8", base64urlToBytes(base64urlPkcs8) as BufferSource, { name: "Ed25519" }, false, ["sign"]);
}

/** Sign bytes → base64url signature (tooling/tests). */
export async function signBytes(privateKey: CryptoKey, data: Uint8Array): Promise<string> {
  const sig = await subtle().sign({ name: "Ed25519" }, privateKey, data as BufferSource);
  return bytesToBase64url(new Uint8Array(sig));
}

/** Verify a base64url signature over bytes. Returns false — never throws. */
export async function verifyBytes(publicKey: CryptoKey, signatureBase64url: string, data: Uint8Array): Promise<boolean> {
  try {
    return await subtle().verify(
      { name: "Ed25519" },
      publicKey,
      base64urlToBytes(signatureBase64url) as BufferSource,
      data as BufferSource,
    );
  } catch {
    return false;
  }
}

/** Convenience: verify a JCS-canonical payload string. */
export async function verifyJcs(publicKey: CryptoKey, signatureBase64url: string, jcsPayload: string): Promise<boolean> {
  return verifyBytes(publicKey, signatureBase64url, utf8ToBytes(jcsPayload));
}
