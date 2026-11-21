import { Router } from 'express';
import { ApiError, notFound } from '../lib/errors.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { AlertRule, SIGNALS } from '../models/AlertRule.js';
import { MaintenanceWindow } from '../models/MaintenanceWindow.js';
import { audit } from '../services/audit.js';
import { notifyAll } from '../services/notify.js';
import { getSettingsDoc } from '../services/settings.js';

export const alertRulesRouter = Router();
alertRulesRouter.use(['/alert-rules', '/notification-channels', '/maintenance-windows'], requireAuth);

const ruleInput = z.object({
  name: z.string().trim().min(1, 'Give the rule a name.').max(120),
  signal: z.enum(SIGNALS),
  threshold: z.number().min(0).max(1_000_000).nullable(),
  durationMin: z.number().int().min(1).max(1440).nullable(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  scope: z.object({ applicationId: objectId.nullable(), environmentType: z.enum(['production', 'staging', 'development', 'custom']).nullable() }),
  channels: z.array(z.enum(['in_app', 'email', 'slack', 'webhook'])).min(1, 'Choose at least one channel.'),
  enabled: z.boolean(),
});

alertRulesRouter.get('/alert-rules', async (_req, res) => {
  const rules = await AlertRule.find().sort({ builtIn: -1, signal: 1, threshold: -1 });
  res.json(rules.map((r) => r.toJSON()));
});

alertRulesRouter.post('/alert-rules', async (req, res) => {
  const input = parse(ruleInput, req.body);
  const rule = await AlertRule.create({ ...input, builtIn: false });
  await audit(req, 'alert_rule.create', 'alert_rule', rule.id, `Created alert rule ${rule.name}`);
  res.status(201).json(rule.toJSON());
});

alertRulesRouter.patch('/alert-rules/:id', async (req, res) => {
  const rule = await AlertRule.findById(parse(objectId, req.params.id));
  if (!rule) throw notFound('Rule');
  const input = parse(ruleInput.partial(), req.body);
  if (rule.builtIn && input.signal && input.signal !== rule.signal) throw new ApiError(409, 'BUILT_IN_RULE', 'The signal of a built-in rule cannot change.');
  rule.set(input);
  await rule.save();
  await audit(req, 'alert_rule.update', 'alert_rule', rule.id, `Updated alert rule ${rule.name}${input.enabled === false ? ' (turned off)' : input.enabled ? ' (turned on)' : ''}`);
  res.json(rule.toJSON());
});

alertRulesRouter.delete('/alert-rules/:id', async (req, res) => {
  const rule = await AlertRule.findById(parse(objectId, req.params.id));
  if (!rule) throw notFound('Rule');
  if (rule.builtIn) throw new ApiError(409, 'BUILT_IN_RULE', 'Built-in rules can be turned off but not deleted.');
  await rule.deleteOne();
  await audit(req, 'alert_rule.delete', 'alert_rule', rule.id, `Deleted alert rule ${rule.name}`);
  res.status(204).end();
});

/* ───────────── channels ───────────── */

const channelsInput = z.object({
  emailRecipients: z.array(z.string().trim().toLowerCase()).max(50),
  criticalRenotifyMin: z.number().int().min(5, 'Re-notify at most every 5 minutes.').max(1440),
  maxRenotify: z.number().int().min(0).max(20),
});

alertRulesRouter.get('/notification-channels', async (_req, res) => {
  const c = (await getSettingsDoc()).channels!;
  res.json({ emailRecipients: c.emailRecipients, criticalRenotifyMin: c.criticalRenotifyMin, maxRenotify: c.maxRenotify });
});

alertRulesRouter.put('/notification-channels', requireReauth, async (req, res) => {
  const input = parse(channelsInput, req.body);
  const bad = input.emailRecipients.find((e) => !/^\S+@\S+\.\S+$/.test(e));
  if (bad) throw new ApiError(422, 'INVALID_EMAIL', `${bad} is not a valid email address.`);
  const doc = await getSettingsDoc();
  doc.channels = input as never;
  await doc.save();
  await audit(req, 'channels.update', 'settings', null, `Alert email recipients: ${input.emailRecipients.join(', ') || 'none'}; critical re-notify every ${input.criticalRenotifyMin} min, up to ${input.maxRenotify} times`);
  await notifyAll('Alert recipients changed', `${req.user!.name} changed who receives alert emails.`);
  res.json(input);
});

/* ───────────── maintenance windows ───────────── */

alertRulesRouter.get('/maintenance-windows', async (_req, res) => {
  const list = await MaintenanceWindow.find({ endsAt: { $gt: new Date(Date.now() - 7 * 86_400_000) } }).sort({ startsAt: 1 });
  res.json(list.map((w) => w.toJSON()));
});

alertRulesRouter.post('/maintenance-windows', async (req, res) => {
  const input = parse(
    z.object({
      title: z.string().trim().min(1, 'Describe the maintenance.').max(200),
      applicationId: objectId.nullable(),
      environmentId: objectId.nullable(),
      startsAt: z.iso.datetime({ offset: true }),
      endsAt: z.iso.datetime({ offset: true }),
    }),
    req.body,
  );
  if (Date.parse(input.endsAt) <= Date.parse(input.startsAt)) throw new ApiError(422, 'INVALID_RANGE', 'The end must be after the start.');
  if (Date.parse(input.endsAt) <= Date.now()) throw new ApiError(422, 'IN_PAST', 'This window has already ended.');
  const w = await MaintenanceWindow.create({ ...input, createdBy: req.user!._id });
  await audit(req, 'maintenance.create', 'maintenance', w.id, `Scheduled maintenance: ${w.title}`);
  res.status(201).json(w.toJSON());
});

alertRulesRouter.delete('/maintenance-windows/:id', async (req, res) => {
  const w = await MaintenanceWindow.findByIdAndDelete(parse(objectId, req.params.id));
  if (w) await audit(req, 'maintenance.delete', 'maintenance', w.id, `Cancelled maintenance: ${w.title}`);
  res.status(204).end();
});