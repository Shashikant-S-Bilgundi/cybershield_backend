import { createPublicKey, createSign, createVerify, type JsonWebKey } from 'node:crypto';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');

/** Signs a JWT with RS256 (Google service accounts). */
export function signRs256(claims: object, privateKeyPem: string, kid?: string) {
  const body = `${b64({ alg: 'RS256', typ: 'JWT', ...(kid ? { kid } : {}) })}.${b64(claims)}`;
  return `${body}.${createSign('RSA-SHA256').update(body).sign(privateKeyPem).toString('base64url')}`;
}

const jwksCache = new Map<string, { keys: (JsonWebKey & { kid?: string })[]; at: number }>();

async function jwks(url: string, refresh = false) {
  const c = jwksCache.get(url);
  if (c && !refresh && Date.now() - c.at < 3_600_000) return c.keys;
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`could not load signing keys (${res.status})`);
  const keys = ((await res.json()) as { keys: (JsonWebKey & { kid?: string })[] }).keys;
  jwksCache.set(url, { keys, at: Date.now() });
  return keys;
}

/**
 * Verifies an RS256 JWT against the provider's published keys (refetched once if the key id is new,
 * since providers rotate keys) and returns its claims. Checks issuer, audience and expiry.
 */
export async function verifyRs256(token: string, opts: { jwksUrl: string; issuers: string[]; audience: string }) {
  const [h, p, s] = token.split('.');
  if (!s) throw new Error('malformed token');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString()) as { alg: string; kid?: string };
  if (header.alg !== 'RS256') throw new Error(`unexpected algorithm ${header.alg}`);
  let key = (await jwks(opts.jwksUrl)).find((k) => k.kid === header.kid);
  if (!key) key = (await jwks(opts.jwksUrl, true)).find((k) => k.kid === header.kid);
  if (!key) throw new Error('unknown signing key');
  const ok = createVerify('RSA-SHA256').update(`${h}.${p}`).verify(createPublicKey({ key, format: 'jwk' }), Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('bad signature');
  const claims = JSON.parse(Buffer.from(p, 'base64url').toString()) as Record<string, unknown>;
  const now = Math.floor(Date.now() / 1000);
  if (!opts.issuers.includes(String(claims.iss))) throw new Error(`unexpected issuer ${claims.iss}`);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(opts.audience)) throw new Error('token was issued for another application');
  if (typeof claims.exp !== 'number' || claims.exp < now - 60) throw new Error('token expired');
  if (typeof claims.iat === 'number' && claims.iat > now + 300) throw new Error('token issued in the future');
  return claims;
}