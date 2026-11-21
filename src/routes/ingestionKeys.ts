import { Router } from 'express';
import { ApiError, notFound } from '../lib/errors.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { Application } from '../models/Application.js';
import { IngestionKey, type IngestionKeyDoc } from '../models/IngestionKey.js';
import { audit } from '../services/audit.js';
import { eventsLast24h, newKeySecret, scopesFor } from '../services/ingestKeys.js';
import { notifyAll } from '../services/notify.js';

export const ingestionKeysRouter = Router();
ingestionKeysRouter.use('/ingestion-keys', requireAuth);

async function views(keys: IngestionKeyDoc[]) {
  const usage = await eventsLast24h(keys.map((k) => k._id));
  return keys.map((k) => ({ ...k.toJSON(), eventsLast24h: k.status === 'active' ? usage.get(k.id) ?? 0 : 0 }));
}

ingestionKeysRouter.get('/ingestion-keys', async (req, res) => {
  const q = parse(z.object({ applicationId: objectId.optional(), environmentId: objectId.optional() }), req.query);
  const keys = await IngestionKey.find(q).sort({ status: 1, name: 1 });
  res.json(await views(keys));
});

/** The full key is returned only here, once. Only its hash is stored. */
ingestionKeysRouter.post('/ingestion-keys', requireReauth, async (req, res) => {
  const input = parse(z.object({ name: z.string().trim().min(1, 'Give the key a name, like "Payments API server".').max(120), kind: z.enum(['server', 'browser']), applicationId: objectId, environmentId: objectId }), req.body);
  const app = await Application.findOne({ _id: input.applicationId, deletedAt: null });
  if (!app?.environments.some((e) => e.id === input.environmentId)) throw new ApiError(422, 'INVALID_SCOPE', 'Choose an application and environment.');
  const { secret, prefix, hash } = newKeySecret(input.kind);
  const key = await IngestionKey.create({ ...input, prefix, hash, scopes: scopesFor(input.kind), createdBy: req.user!._id });
  await audit(req, 'ingestion_key.create', 'ingestion_key', key.id, `Created ${key.kind} key ${key.name} (${prefix}…) for ${app.name}`);
  await notifyAll('An ingestion key was created', `${req.user!.name} created the ${key.kind} key "${key.name}" for ${app.name}.`);
  res.status(201).json({ key: (await views([key]))[0], secret });
});

const findKey = async (id: unknown) => {
  const k = await IngestionKey.findById(parse(objectId, id));
  if (!k) throw notFound('Key');
  return k;
};

/** A new secret; the old one keeps working for 24 hours so apps can be updated without losing data. */
ingestionKeysRouter.post('/ingestion-keys/:id/rotate', requireReauth, async (req, res) => {
  const key = await findKey(req.params.id);
  if (key.status !== 'active') throw new ApiError(409, 'KEY_REVOKED', 'This key is revoked. Create a new one instead.');
  const old = key.prefix;
  const { secret, prefix, hash } = newKeySecret(key.kind as 'server' | 'browser');
  key.previousHash = key.hash;
  key.previousExpiresAt = new Date(Date.now() + 24 * 3_600_000);
  key.hash = hash;
  key.prefix = prefix;
  await key.save();
  await audit(req, 'ingestion_key.rotate', 'ingestion_key', key.id, `Rotated key ${key.name}: ${old}… keeps working for 24 hours, new key ${prefix}…`);
  await notifyAll('An ingestion key was rotated', `${req.user!.name} rotated "${key.name}". The old key stops working in 24 hours.`);
  res.json({ key: (await views([key]))[0], secret });
});

ingestionKeysRouter.post('/ingestion-keys/:id/revoke', requireReauth, async (req, res) => {
  const key = await findKey(req.params.id);
  key.status = 'revoked';
  key.revokedAt = new Date();
  key.previousHash = null;
  await key.save();
  await audit(req, 'ingestion_key.revoke', 'ingestion_key', key.id, `Revoked key ${key.name} (${key.prefix}…)`);
  await notifyAll('An ingestion key was revoked', `${req.user!.name} revoked "${key.name}". Data sent with it is now refused.`);
  res.json((await views([key]))[0]);
});