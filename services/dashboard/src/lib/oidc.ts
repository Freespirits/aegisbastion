// Minimal OIDC discovery document client (server-side, cached 5 min).

export interface OidcDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  issuer: string;
}

let cache: { issuer: string; at: number; doc: OidcDiscovery } | null = null;
const CACHE_MS = 5 * 60 * 1000;

export async function discover(issuer: string): Promise<OidcDiscovery> {
  if (cache && cache.issuer === issuer && Date.now() - cache.at < CACHE_MS) {
    return cache.doc;
  }
  const res = await fetch(`${issuer}/.well-known/openid-configuration`, {
    cache: "no-store",
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`OIDC discovery failed: HTTP ${res.status}`);
  const doc = (await res.json()) as OidcDiscovery;
  cache = { issuer, at: Date.now(), doc };
  return doc;
}
