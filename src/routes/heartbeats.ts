import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../config.js';
import { randomToken } from '../lib/crypto.js';
import { isValidCron } from '../lib/cron.js';
import { ApiError, notFound } from '../lib/errors.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { Application } from '../models/Application.js';
import { Heartbeat, type HeartbeatDoc } from '../models/Heartbeat.js';
import { autoResolve } from '../services/alerts.js';
import { audit } from '../services/audit.js';
import { nextDue, recordPing } from '../services/heartbeats.js';
import { getSettingsDoc } from '../services/settings.js';

export const heartbeatsRouter = Router();

const view = (h: HeartbeatDoc) => ({
  ...h.toJSON(),
  status: h.paused ? 'paused' : h.status,
  pingUrl: `${config.appUrl}/api/v1/hb/${h.token}`,
  schedule: h.schedule!.kind === 'interval' ? { kind: 'interval', seconds: h.schedule!.seconds } : { kind: 'cron', expression: h.schedule!.expression },
});

/* ───────────── public: the job pings this URL ───────────── */

// Many jobs can share one server, so this limit is generous but still stops floods.
const pingLimiter = rateLimit({ windowMs: 60_000, limit: 600, standardHeaders: 'draft-7', legacyHeaders: false });

for (const [suffix, kind] of [['', 'success'], ['/start', 'start'], ['/fail', 'fail']] as const) {
  heartbeatsRouter.all(`/hb/:token${suffix}`, pingLimiter, async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'POST' && req.method !== 'HEAD') return void res.status(405).end();
    const token = String(req.params.token);
    if (!/^[\w-]{20,64}$/.test(token)) return void res.status(404).type('text').send('Unknown ping URL\n');
    const h = await recordPing(token, kind);
    if (!h) return void res.status(404).type('text').send('Unknown ping URL\n');
    res.type('text').send('OK\n');
  });
}

/* ───────────── signed-in management ───────────── */

heartbeatsRouter.use('/heartbeats', requireAuth);

const heartbeatInput = z.object({
  name: z.string().trim().min(1, 'Give the job a name.').max(120),
  applicationId: objectId,
  environmentId: objectId,
  schedule: z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('interval'), seconds: z.number().int().min(60, 'Jobs must run at most once a minute.').max(31 * 86_400) }),
    z.object({ kind: z.literal('cron'), expression: z.string().trim().max(100) }),
  ]),
  graceSec: z.number().int().min(60, 'Allow at least one minute of grace.').max(7 * 86_400),
});

const findHb = async (id: unknown) => {
  const h = await Heartbeat.findOne({ _id: parse(objectId, id), deletedAt: null });
  if (!h) throw notFound('Heartbeat');
  return h;
};

heartbeatsRouter.get('/heartbeats', async (req, res) => {
  const q = parse(z.object({ applicationId: objectId.optional(), environmentId: objectId.optional() }), req.query);
  const list = await Heartbeat.find({ deletedAt: null, ...q }).sort({ name: 1 });
  res.json(list.map(view));
});

heartbeatsRouter.post('/heartbeats', async (req, res) => {
  const input = parse(heartbeatInput, req.body);
  const app = await Application.findOne({ _id: input.applicationId, deletedAt: null });
  if (!app?.environments.some((e) => e.id === input.environmentId)) throw new ApiError(422, 'INVALID_SCOPE', 'Choose an application and environment.');
  if (input.schedule.kind === 'cron' && !isValidCron(input.schedule.expression, (await getSettingsDoc()).timezone ?? 'Asia/Kolkata')) {
    throw new ApiError(422, 'INVALID_CRON', 'Use a 5-part cron expression, like 0 2 * * *.');
  }
  const h = new Heartbeat({ ...input, token: randomToken(24) });
  h.nextDueAt = await nextDue(h, new Date());
  await h.save();
  await audit(req, 'heartbeat.create', 'heartbeat', h.id, `Created heartbeat ${h.name}`);
  res.status(201).json(view(h));
});

heartbeatsRouter.patch('/heartbeats/:id/paused', async (req, res) => {
  const h = await findHb(req.params.id);
  const { paused } = parse(z.object({ paused: z.boolean() }), req.body);
  h.paused = paused;
  if (!paused) h.nextDueAt = await nextDue(h, new Date());
  if (paused) await autoResolve(`heartbeat:${h.id}`);
  await h.save();
  await audit(req, paused ? 'heartbeat.pause' : 'heartbeat.resume', 'heartbeat', h.id, `${paused ? 'Paused' : 'Resumed'} heartbeat ${h.name}`);
  res.json(view(h));
});

heartbeatsRouter.delete('/heartbeats/:id', requireReauth, async (req, res) => {
  const h = await findHb(req.params.id);
  h.deletedAt = new Date();
  await h.save();
  await autoResolve(`heartbeat:${h.id}`);
  await audit(req, 'heartbeat.delete', 'heartbeat', h.id, `Deleted heartbeat ${h.name}`);
  res.status(204).end();
});