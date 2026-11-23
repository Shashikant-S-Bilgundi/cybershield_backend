import { createHash } from 'node:crypto';
import { config } from '../config.js';
import { decrypt, randomToken, sha256 } from '../lib/crypto.js';
import { verifyRs256 } from '../lib/jwt.js';
import { SsoState } from '../models/Cloud.js';
import { getSettingsDoc } from './settings.js';

type Provider = 'google' | 'entra';

/**
 * Provider endpoints. SSO_ENDPOINT_BASE replaces all of them with one test server (development only).
 * Entra uses your domain as the tenant, so only accounts in your directory can sign in.
 */
function endpoints(provider: Provider, domain: string) {
  const base = process.env.SSO_ENDPOINT_BASE;
  if (base) return { auth: `${base}/authorize`, token: `${base}/token`, jwks: `${base}/jwks`, issuers: [base] };
  if (provider === 'google') return { auth: 'https://accounts.google.com/o/oauth2/v2/auth', token: 'https://oauth2.googleapis.com/token', jwks: 'https://www.googleapis.com/oauth2/v3/certs', issuers: ['https://accounts.google.com', 'accounts.google.com'] };
  const t = encodeURIComponent(domain);
  return { auth: `https://login.microsoftonline.com/${t}/oauth2/v2.0/authorize`, token: `https://login.microsoftonline.com/${t}/oauth2/v2.0/token`, jwks: `https://login.microsoftonline.com/${t}/discovery/v2.0/keys`, issuers: [] as string[] };
}

export const callbackUrl = () => `${config.appUrl}/api/v1/auth/sso/callback`;

export class SsoError extends Error {
  constructor(public reason: string, message: string) {
    super(message);
  }
}

/** Starts a sign-in: a one-time state (also set as a cookie), a nonce, and a PKCE verifier. */
export async function startSso(provider: Provider) {
  const s = (await getSettingsDoc()).sso!;
  if (!s.enabled || s.provider !== provider) throw new SsoError('disabled', 'Single sign-on with this provider is not turned on.');
  const state = randomToken(24);
  const nonce = randomToken(16);
  const verifier = randomToken(48);
  await SsoState.create({ stateHash: sha256(state), nonce, verifier, provider, expiresAt: new Date(Date.now() + 10 * 60_000) });
  const e = endpoints(provider, s.domain!);
  const q = new URLSearchParams({
    client_id: s.clientId!, redirect_uri: callbackUrl(), response_type: 'code', scope: 'openid email profile', state, nonce,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', prompt: 'select_account',
    ...(provider === 'google' ? { hd: s.domain! } : {}),
  });
  return { state, redirectUrl: `${e.auth}?${q}` };
}

/**
 * Finishes a sign-in: checks the state matches this browser, swaps the code for tokens, verifies the
 * ID token's signature, issuer, audience, expiry and nonce, and returns the verified email.
 */
export async function finishSso(code: string, state: string, cookieState: string | undefined) {
  if (!state || state !== cookieState) throw new SsoError('expired', 'The sign-in did not start in this browser, or took too long.');
  const st = await SsoState.findOneAndDelete({ stateHash: sha256(state) });
  if (!st || st.expiresAt.getTime() < Date.now()) throw new SsoError('expired', 'The sign-in took too long. Try again.');
  const s = (await getSettingsDoc()).sso!;
  const provider = st.provider as Provider;
  if (!s.enabled || s.provider !== provider) throw new SsoError('disabled', 'Single sign-on was turned off.');
  const e = endpoints(provider, s.domain!);
  const res = await fetch(e.token, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: callbackUrl(), client_id: s.clientId!, client_secret: decrypt(s.clientSecretEnc!), code_verifier: st.verifier! }),
    signal: AbortSignal.timeout(15_000),
  }).catch(() => null);
  const body = (await res?.json().catch(() => ({}))) as { id_token?: string; error?: string; error_description?: string };
  if (!res?.ok || !body.id_token) throw new SsoError('provider', `The identity provider refused the sign-in${body.error ? `: ${body.error}` : ''}.`);
  let claims: Record<string, unknown>;
  try {
    // Entra's issuer names the tenant id, which is only known from the token itself; it is checked against the token's tid.
    const peek = JSON.parse(Buffer.from(body.id_token.split('.')[1] ?? '', 'base64url').toString() || '{}') as { tid?: string };
    const issuers = e.issuers.length ? e.issuers : [`https://login.microsoftonline.com/${peek.tid}/v2.0`];
    claims = await verifyRs256(body.id_token, { jwksUrl: e.jwks, issuers, audience: s.clientId! });
  } catch (err) {
    throw new SsoError('invalid', `The sign-in token could not be verified: ${(err as Error).message}.`);
  }
  if (claims.nonce !== st.nonce) throw new SsoError('invalid', 'The sign-in token was not issued for this sign-in.');
  const email = String(claims.email ?? claims.preferred_username ?? '').toLowerCase();
  if (provider === 'google' && claims.email_verified !== true) throw new SsoError('unverified', 'Google has not verified this email address.');
  const domain = s.domain!.toLowerCase();
  if (!email.endsWith(`@${domain}`) || (provider === 'google' && claims.hd !== domain)) throw new SsoError('domain', `Only ${domain} accounts can sign in here.`);
  return email;
}