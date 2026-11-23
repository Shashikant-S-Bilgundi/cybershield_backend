import { Router } from 'express';
import { ApiError, notFound } from '../lib/errors.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { Application } from '../models/Application.js';
import { EscalationPolicy, Probe, ProbeResult } from '../models/Advanced.js';
import { Monitor } from '../models/Monitor.js';
import { User } from '../models/User.js';
import { anomalyViews } from '../services/anomalies.js';
import { audit } from '../services/audit.js';
import { escalationViews } from '../services/escalation.js';
import { searchLogs } from '../services/logs.js';
import { notifyAll } from '../services/notify.js';
import { newProbeSecret, probeResultsFor, probeViews } from '../services/probes.js';
import { releaseViews } from '../services/releases.js';

export const advancedRouter = Router();
advancedRouter.use(['/releases', '/logs', '/probes', '/escalation-policies', '/alerts/escalations', '/anomalies', '/monitors/:id/probe-results'], requireAuth);

const liveApps = async (applicationId?: string) => (await Application.find({ deletedAt: null, ...(applicationId ? { _id: applicationId } : {}) }, { _id: 1 }).lean()).map((a) => a._id);

/* ───────────── releases ───────────── */

advancedRouter.get('/releases', async (req, res) => {
  const { applicationId } = parse(z.object({ applicationId: objectId.optional() }), req.query);
  res.json(await releaseViews({ applicationId: { $in: await liveApps(applicationId) } }));
});

/* ───────────── logs ───────────── */

advancedRouter.get('/logs', async (req, res) => {
  const q = parse(
    z.object({
      applicationId: objectId.optional(),
      environmentId: objectId.optional(),
      search: z.string().max(200).optional(),
      levels: z.string().max(40).optional(),
      range: z.enum(['15m', '1h', '24h', '7d']).default('1h'),
      page: z.coerce.number().int().min(1).max(1000).default(1),
      pageSize: z.coerce.number().int().min(1).max(200).default(50),
    }),
    req.query,
  );
  const levels = q.levels?.split(',').filter((l) => ['debug', 'info', 'warn', 'error'].includes(l));
  res.json(await searchLogs({ scope: { applicationId: { $in: await liveApps(q.applicationId) }, ...(q.environmentId ? { environmentId: q.environmentId } : {}) }, search: q.search, levels, range: q.range, page: q.page, pageSize: q.pageSize }));
});

/* ───────────── probe locations ───────────── */

advancedRouter.get('/probes', async (_req, res) => {
  res.json(await probeViews());
});

advancedRouter.post('/probes', requireReauth, async (req, res) => {
  const input = parse(z.object({ name: z.string().trim().min(2, 'Name the location, for example "Mumbai VPS".').max(80), region: z.string().trim().max(80).default('') }), req.body);
  if ((await Probe.countDocuments()) >= 5) throw new ApiError(409, 'TOO_MANY_PROBES', 'Five probe locations at most.');
  const { secret, prefix, hash } = newProbeSecret();
  const p = await Probe.create({ name: input.name, region: input.region, prefix, hash });
  await audit(req, 'probe.create', 'probe', p.id, `Added probe location ${p.name}`);
  await notifyAll('A probe location was added', `${req.user!.name} added the probe location ${p.name}.`);
  // The token is shown once.
  res.status(201).json({ probe: (await probeViews()).find((x) => x.id === p.id), secret });
});

advancedRouter.delete('/probes/:id', requireReauth, async (req, res) => {
  const id = String(req.params.id);
  if (id === 'local') throw new ApiError(409, 'BUILT_IN', 'The built-in probe on this server cannot be removed.');
  const p = await Probe.findByIdAndDelete(parse(objectId, id));
  if (!p) throw notFound('Probe');
  await ProbeResult.deleteMany({ probeId: p._id });
  await audit(req, 'probe.delete', 'probe', p.id, `Removed probe location ${p.name}; its token stopped working`);
  await notifyAll('A probe location was removed', `${req.user!.name} removed the probe location ${p.name}.`);
  res.status(204).end();
});

advancedRouter.get('/monitors/:id/probe-results', async (req, res) => {
  const m = await Monitor.findOne({ _id: parse(objectId, req.params.id), deletedAt: null });
  if (!m) throw notFound('Monitor');
  res.json(await probeResultsFor(m._id));
});

/* ───────────── escalation policies ───────────── */

const SEV = ['critical', 'high', 'medium', 'low', 'info'] as const;
const policyInput = z.object({
  name: z.string().trim().min(1, 'Name the policy.').max(120),
  severities: z.array(z.enum(SEV)).min(1, 'Choose at least one severity.'),
  steps: z.array(z.object({ afterMinutes: z.number().int().min(0).max(1440), targets: z.array(z.string().max(24)).min(1, 'Each step needs someone to notify.'), channels: z.array(z.enum(['in_app', 'email', 'slack', 'webhook'])).min(1, 'Each step needs at least one channel.') })).min(1).max(6),
  repeat: z.boolean().default(false),
  enabled: z.boolean().default(true),
});

async function validatePolicy(input: z.infer<typeof policyInput>, selfId?: string) {
  if (input.steps[0].afterMinutes !== 0) throw new ApiError(422, 'FIRST_STEP', 'The first step notifies straight away (0 minutes).');
  for (let i = 1; i < input.steps.length; i++) if (input.steps[i].afterMinutes <= input.steps[i - 1].afterMinutes) throw new ApiError(422, 'STEP_ORDER', 'Each step must come later than the one before.');
  const ids = [...new Set(input.steps.flatMap((s) => s.targets).filter((t) => t !== 'all'))];
  if (ids.some((t) => !/^[0-9a-f]{24}$/.test(t)) || (await User.countDocuments({ _id: { $in: ids }, status: 'active' })) !== ids.length) throw new ApiError(422, 'INVALID_TARGET', 'Choose active team members (or everyone).');
  if (input.enabled) {
    const clash = await EscalationPolicy.findOne({ enabled: true, severities: { $in: input.severities }, ...(selfId ? { _id: { $ne: selfId } } : {}) });
    if (clash) throw new ApiError(409, 'SEVERITY_TAKEN', `"${clash.name}" already handles ${clash.severities.filter((s) => input.severities.includes(s as never)).join(' and ')} alerts.`);
  }
}

advancedRouter.get('/escalation-policies', async (_req, res) => {
  res.json((await EscalationPolicy.find().sort({ name: 1 })).map((p) => p.toJSON()));
});

advancedRouter.post('/escalation-policies', async (req, res) => {
  const input = parse(policyInput, req.body);
  await validatePolicy(input);
  const p = await EscalationPolicy.create(input);
  await audit(req, 'escalation.create', 'escalation', p.id, `Created escalation policy ${p.name}`);
  res.status(201).json(p.toJSON());
});

advancedRouter.put('/escalation-policies/:id', async (req, res) => {
  const p = await EscalationPolicy.findById(parse(objectId, req.params.id));
  if (!p) throw notFound('Escalation policy');
  const input = parse(policyInput, req.body);
  await validatePolicy(input, p.id);
  p.set(input);
  await p.save();
  await audit(req, 'escalation.update', 'escalation', p.id, `Updated escalation policy ${p.name}`);
  res.json(p.toJSON());
});

advancedRouter.delete('/escalation-policies/:id', async (req, res) => {
  const p = await EscalationPolicy.findByIdAndDelete(parse(objectId, req.params.id));
  if (p) await audit(req, 'escalation.delete', 'escalation', p.id, `Deleted escalation policy ${p.name}`);
  res.status(204).end();
});

advancedRouter.get('/alerts/escalations', async (_req, res) => {
  res.json(await escalationViews());
});

/* ───────────── anomalies ───────────── */

advancedRouter.get('/anomalies', async (req, res) => {
  const { applicationId } = parse(z.object({ applicationId: objectId.optional() }), req.query);
  res.json(await anomalyViews({ applicationId: { $in: await liveApps(applicationId) } }));
});