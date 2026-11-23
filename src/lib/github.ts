import { createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { config } from '../config.js';
import { ApiError } from './errors.js';

/** The GitHub App's private key, from the environment (with \n escapes) or a file. */
function privateKey(): string {
  if (config.GITHUB_APP_PRIVATE_KEY_FILE) return readFileSync(config.GITHUB_APP_PRIVATE_KEY_FILE, 'utf8');
  return config.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g, '\n');
}

export const githubConfigured = () => !!(config.GITHUB_APP_ID && config.GITHUB_APP_SLUG && (config.GITHUB_APP_PRIVATE_KEY || config.GITHUB_APP_PRIVATE_KEY_FILE));

/** A 9-minute JWT signed with the app's private key (RS256), as GitHub requires for app-level calls. */
export function appJwt(): string {
  const now = Math.floor(Date.now() / 1000);
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const body = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ iat: now - 60, exp: now + 9 * 60, iss: config.GITHUB_APP_ID })}`;
  const sig = createSign('RSA-SHA256').update(body).sign(privateKey()).toString('base64url');
  return `${body}.${sig}`;
}

export async function gh<T>(path: string, opts: { token?: string; jwt?: boolean; method?: string; body?: object } = {}): Promise<T> {
  const auth = opts.jwt ? `Bearer ${appJwt()}` : opts.token ? `token ${opts.token}` : undefined;
  const res = await fetch(`${config.GITHUB_API_URL.replace(/\/$/, '')}${path}`, {
    method: opts.method ?? 'GET',
    headers: { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'ShieldOps', ...(auth ? { authorization: auth } : {}), ...(opts.body ? { 'content-type': 'application/json' } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    signal: AbortSignal.timeout(15_000),
  }).catch((e: Error) => {
    throw new ApiError(502, 'GITHUB_UNREACHABLE', `Could not reach GitHub: ${e.message}`);
  });
  if (res.status === 204) return undefined as T;
  const data = (await res.json().catch(() => ({}))) as T & { message?: string };
  if (!res.ok) throw new ApiError(res.status === 404 ? 404 : 502, 'GITHUB_ERROR', `GitHub answered ${res.status}: ${data.message ?? 'error'}`);
  return data;
}

const tokens = new Map<number, { token: string; expires: number }>();

/**
 * A 1-hour installation token limited to read-only permissions, cached until 5 minutes before it expires.
 * Even if the app was granted more, ShieldOps asks only for what scanning needs.
 */
export async function installationToken(installationId: number): Promise<string> {
  const cached = tokens.get(installationId);
  if (cached && cached.expires - Date.now() > 5 * 60_000) return cached.token;
  const r = await gh<{ token: string; expires_at: string }>(`/app/installations/${installationId}/access_tokens`, {
    jwt: true,
    method: 'POST',
    body: { permissions: { contents: 'read', metadata: 'read', packages: 'read' } },
  });
  tokens.set(installationId, { token: r.token, expires: Date.parse(r.expires_at) });
  return r.token;
}

export const forgetInstallation = (installationId: number) => tokens.delete(installationId);

export interface GhRepo {
  id: number;
  full_name: string;
  private: boolean;
  default_branch: string;
  language: string | null;
}

/** Every repository the installation can see (the ones you chose when installing the app). */
export async function installationRepos(installationId: number): Promise<GhRepo[]> {
  const token = await installationToken(installationId);
  const all: GhRepo[] = [];
  for (let page = 1; page <= 20; page++) {
    const r = await gh<{ repositories: GhRepo[]; total_count: number }>(`/installation/repositories?per_page=100&page=${page}`, { token });
    all.push(...r.repositories);
    if (all.length >= r.total_count || !r.repositories.length) break;
  }
  return all;
}