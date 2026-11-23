import type { Request } from 'express';
import { randomBytes } from 'node:crypto';
import { sha256 } from '../lib/crypto.js';
import { ApiError } from '../lib/errors.js';
import { IngestionKey, KeyUsage, type IngestionKeyDoc } from '../models/IngestionKey.js';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

/** so_live_… for servers, so_pub_… for browsers; 32 random characters after the prefix. */
export function newKeySecret(kind: 'server' | 'browser') {
  const bytes = randomBytes(32);
  const body = Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]).join('');
  const secret = `${kind === 'browser' ? 'so_pub_' : 'so_live_'}${body}`;
  return { secret, prefix: secret.slice(0, kind === 'browser' ? 11 : 12), hash: sha256(secret) };
}

export const scopesFor = (kind: 'server' | 'browser') => (kind === 'browser' ? ['errors'] : ['errors', 'performance', 'security_events']);

/** Finds the key in the request (Authorization: Bearer, or X-ShieldOps-Key) and checks it may send this kind of data. */
/** scope 'server' accepts any server key (releases, logs): browser keys can only send errors. */
export async function authenticateKey(req: Request, scope: 'errors' | 'performance' | 'security_events' | 'server'): Promise<IngestionKeyDoc> {
  const raw = (req.get('authorization')?.replace(/^Bearer\s+/i, '') || req.get('x-shieldops-key') || '').trim();
  if (!/^so_(live|pub)_[A-Za-z0-9]{20,64}$/.test(raw)) throw new ApiError(401, 'INVALID_KEY', 'Missing or malformed ingestion key.');
  const hash = sha256(raw);
  const key = (await IngestionKey.findOne({ hash, status: 'active' })) ?? (await IngestionKey.findOne({ previousHash: hash, status: 'active', previousExpiresAt: { $gt: new Date() } }));
  if (!key) throw new ApiError(401, 'INVALID_KEY', 'This ingestion key is unknown or revoked.');
  if (scope === 'server' ? key.kind !== 'server' : !key.scopes.includes(scope)) throw new ApiError(403, 'SCOPE_NOT_ALLOWED', key.kind === 'browser' ? 'Browser keys can only send errors.' : 'This key cannot send this kind of data.');
  return key;
}

/** Counts events for "events in the last 24 hours" and notes when the key was last used (at most once a minute). */
export async function recordUsage(key: IngestionKeyDoc, events: number) {
  const now = new Date();
  const hour = new Date(Math.floor(now.getTime() / 3_600_000) * 3_600_000);
  await KeyUsage.updateOne({ keyId: key._id, hour }, { $inc: { count: events } }, { upsert: true });
  if (!key.lastUsedAt || now.getTime() - key.lastUsedAt.getTime() > 60_000) await IngestionKey.updateOne({ _id: key._id }, { lastUsedAt: now });
}

export async function eventsLast24h(keyIds: IngestionKeyDoc['_id'][]) {
  const rows = await KeyUsage.aggregate<{ _id: unknown; n: number }>([
    { $match: { keyId: { $in: keyIds }, hour: { $gte: new Date(Date.now() - 24 * 3_600_000) } } },
    { $group: { _id: '$keyId', n: { $sum: '$count' } } },
  ]);
  return new Map(rows.map((r) => [String(r._id), r.n]));
}