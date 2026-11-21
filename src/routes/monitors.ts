import { Router } from 'express';
import { ApiError, notFound } from '../lib/errors.js';
import { hostOf } from '../lib/net.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { Asset } from '../models/Asset.js';
import { CheckResult } from '../models/CheckResult.js';
import { Monitor, type MonitorDoc } from '../models/Monitor.js';
import { autoResolve } from '../services/alerts.js';
import { audit } from '../services/audit.js';
import { uptimeFor } from '../services/health.js';
import { runMonitor } from '../services/monitors.js';
import { notifyAll } from '../services/notify.js';

export const monitorsRouter = Router();
monitorsRouter.use('/monitors', requireAuth);

const FITS: Record<string, string[]> = { http: ['website', 'api', 'domain'], tcp: ['server', 'database'], dns: ['domain', 'website', 'api'] };
const TARGET: Record<string, { rx: RegExp; hint: string }> = {
  http: { rx: /^https?:\/\/\S+$/i, hint: 'a full URL starting with https://' },
  tcp: { rx: /^[\w.-]+:\d{1,5}$/, hint: 'host:port, like 10.0.2.15:5432' },
  dns: { rx: /^([a-z0-9-]+\.)+[a-z]{2,63}$/i, hint: 'a hostname, like pay.example.com' },
};

const monitorInput = z.object({
  name: z.string().trim().min(1, 'Give the monitor a name.').max(120),
  type: z.enum(['http', 'tcp', 'dns']),
  assetId: objectId,
  target: z.string().trim().min(1).max(2000),
  intervalSec: z.number().int().min(30, 'Check at most every 30 seconds.').max(3600),
  timeoutMs: z.number().int().min(1000).max(30_000),
  downAfterFailures: z.number().int().min(1).max(10),
  expectedStatus: z.string().trim().regex(/^\d{3}(-\d{3})?(,\s*\d{3}(-\d{3})?)*$/, 'Use a status like 200 or a range like 200-399.').optional().or(z.literal('').transform(() => undefined)),
  keyword: z.string().max(200).optional(),
  recordType: z.enum(['A', 'AAAA', 'CNAME', 'MX']).optional(),
});

/** The target must belong to the asset whose ownership was proved, so a monitor cannot point anywhere else. */
async function validate(input: z.infer<typeof monitorInput>, exceptId?: string) {
  if (!TARGET[input.type].rx.test(input.target)) throw new ApiError(422, 'INVALID_TARGET', `Enter ${TARGET[input.type].hint}.`);
  const asset = await Asset.findOne({ _id: input.assetId, deletedAt: null });
  if (!asset) throw notFound('Asset');
  if (!['verified', 'approved'].includes(asset.authorization!.status)) throw new ApiError(422, 'ASSET_NOT_AUTHORIZED', 'Verify or approve this asset before monitoring it.');
  if (!FITS[input.type].includes(asset.type)) throw new ApiError(422, 'TYPE_MISMATCH', 'That check type does not fit this asset.');
  const targetHost = input.type === 'tcp' ? input.target.slice(0, input.target.lastIndexOf(':')) : hostOf(input.target);
  if (targetHost.toLowerCase() !== hostOf(asset.identifier).toLowerCase()) {
    throw new ApiError(422, 'TARGET_NOT_ASSET', `The target must be on ${hostOf(asset.identifier)}, the asset you proved you own.`);
  }
  const dup = await Monitor.findOne({ type: input.type, target: input.target, deletedAt: null });
  if (dup && dup.id !== exceptId) throw new ApiError(409, 'DUPLICATE_MONITOR', 'A monitor for this address already exists.');
  return asset;
}

const findMonitor = async (id: unknown) => {
  const m = await Monitor.findOne({ _id: parse(objectId, id), deletedAt: null });
  if (!m) throw notFound('Monitor');
  return m;
};

async function views(monitors: MonitorDoc[]) {
  const up = await uptimeFor(monitors.map((m) => m._id));
  return monitors.map((m) => ({ ...m.toJSON(), status: m.paused ? 'paused' : m.status, uptime: up.get(m.id) ?? { d1: null, d7: null, d30: null } }));
}

async function detail(m: MonitorDoc) {
  const [view] = await views([m]);
  const results = (await CheckResult.find({ monitorId: m._id }).sort({ at: -1 }).limit(240)).reverse().map((r) => r.toJSON());
  return { ...view, results, events: m.events.map((e) => ({ at: e.at, from: e.from, to: e.to, reason: e.reason })) };
}

monitorsRouter.get('/monitors', async (req, res) => {
  const q = parse(z.object({ applicationId: objectId.optional(), environmentId: objectId.optional() }), req.query);
  const list = await Monitor.find({ deletedAt: null, ...q }).sort({ name: 1 });
  res.json(await views(list));
});

monitorsRouter.get('/monitors/:id', async (req, res) => {
  res.json(await detail(await findMonitor(req.params.id)));
});

monitorsRouter.post('/monitors', async (req, res) => {
  const input = parse(monitorInput, req.body);
  const asset = await validate(input);
  const m = await Monitor.create({ ...input, applicationId: asset.applicationId, environmentId: asset.environmentId, nextCheckAt: new Date() });
  await audit(req, 'monitor.create', 'monitor', m.id, `Created ${m.type.toUpperCase()} monitor ${m.name} for ${m.target}`);
  res.status(201).json((await views([m]))[0]);
});

monitorsRouter.patch('/monitors/:id', async (req, res) => {
  const m = await findMonitor(req.params.id);
  const input = parse(monitorInput.partial(), req.body);
  const merged = { ...m.toObject(), assetId: String(m.assetId), ...input } as z.infer<typeof monitorInput>;
  await validate(merged, m.id);
  m.set(input);
  await m.save();
  await audit(req, 'monitor.update', 'monitor', m.id, `Updated monitor ${m.name}`);
  res.json((await views([m]))[0]);
});

monitorsRouter.patch('/monitors/:id/paused', async (req, res) => {
  const m = await findMonitor(req.params.id);
  const { paused } = parse(z.object({ paused: z.boolean() }), req.body);
  m.paused = paused;
  if (!paused) m.nextCheckAt = new Date();
  await m.save();
  if (paused) await autoResolve(`uptime:${m.id}`);
  await audit(req, paused ? 'monitor.pause' : 'monitor.resume', 'monitor', m.id, `${paused ? 'Paused' : 'Resumed'} monitor ${m.name}`);
  res.json((await views([m]))[0]);
});

monitorsRouter.post('/monitors/:id/run', async (req, res) => {
  const m = await findMonitor(req.params.id);
  if (m.paused) throw new ApiError(409, 'PAUSED', 'Resume the monitor before running it.');
  await runMonitor(m);
  res.json(await detail(m));
});

monitorsRouter.delete('/monitors/:id', requireReauth, async (req, res) => {
  const m = await findMonitor(req.params.id);
  m.deletedAt = new Date();
  await m.save();
  await autoResolve(`uptime:${m.id}`);
  await autoResolve(`latency:${m.id}`);
  await audit(req, 'monitor.delete', 'monitor', m.id, `Deleted monitor ${m.name}`);
  await notifyAll('A monitor was deleted', `${req.user!.name} deleted the uptime monitor ${m.name} (${m.target}).`);
  res.status(204).end();
});