import { Router } from 'express';
import { ApiError, notFound } from '../lib/errors.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { Alert } from '../models/Alert.js';
import { audit } from '../services/audit.js';
import { wakeSnoozed } from '../services/alerts.js';

export const alertsRouter = Router();
alertsRouter.use('/alerts', requireAuth);

const SEVERITY = ['critical', 'high', 'medium', 'low', 'info'] as const;
const STATUS_ORDER = { open: 0, acknowledged: 1, snoozed: 2, resolved: 3 } as const;

alertsRouter.get('/alerts', async (req, res) => {
  const f = parse(
    z.object({
      status: z.enum(['open', 'acknowledged', 'snoozed', 'resolved', 'active']).optional(),
      severity: z.enum(SEVERITY).optional(),
      source: z.string().max(40).optional(),
      applicationId: objectId.optional(),
      environmentId: objectId.optional(),
    }),
    req.query,
  );
  await wakeSnoozed();
  const { status, ...rest } = f;
  const q = { ...rest, ...(status === 'active' ? { status: { $ne: 'resolved' } } : status ? { status } : {}) };
  const alerts = await Alert.find(q).sort({ lastAt: -1 }).limit(500);
  alerts.sort((a, b) => STATUS_ORDER[a.status as keyof typeof STATUS_ORDER] - STATUS_ORDER[b.status as keyof typeof STATUS_ORDER] || SEVERITY.indexOf(a.severity as never) - SEVERITY.indexOf(b.severity as never));
  res.json(alerts.map((a) => a.toJSON()));
});

const findAlert = async (id: unknown) => {
  const a = await Alert.findById(parse(objectId, id));
  if (!a) throw notFound('Alert');
  if (a.status === 'resolved') throw new ApiError(409, 'ALREADY_RESOLVED', 'This alert is already resolved.');
  return a;
};

alertsRouter.post('/alerts/:id/acknowledge', async (req, res) => {
  const a = await findAlert(req.params.id);
  a.status = 'acknowledged';
  a.acknowledgedBy = req.user!._id;
  a.acknowledgedAt = new Date();
  a.snoozedUntil = null;
  await a.save();
  await audit(req, 'alert.acknowledge', 'alert', a.id, `Acknowledged: ${a.title}`);
  res.json(a.toJSON());
});

alertsRouter.post('/alerts/:id/snooze', async (req, res) => {
  const a = await findAlert(req.params.id);
  const { minutes } = parse(z.object({ minutes: z.number().int().min(5).max(7 * 24 * 60) }), req.body);
  a.status = 'snoozed';
  a.snoozedUntil = new Date(Date.now() + minutes * 60_000);
  await a.save();
  await audit(req, 'alert.snooze', 'alert', a.id, `Snoozed for ${minutes} minutes: ${a.title}`);
  res.json(a.toJSON());
});

alertsRouter.post('/alerts/:id/resolve', async (req, res) => {
  const a = await findAlert(req.params.id);
  a.status = 'resolved';
  a.resolvedAt = new Date();
  a.autoResolved = false;
  await a.save();
  await audit(req, 'alert.resolve', 'alert', a.id, `Resolved: ${a.title}`);
  res.json(a.toJSON());
});