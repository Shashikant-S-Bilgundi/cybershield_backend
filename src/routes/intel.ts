import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { ApiError, notFound } from '../lib/errors.js';
import { randomHex } from '../lib/crypto.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { Application } from '../models/Application.js';
import { Attestation, FrameworkState, RecDismissal, Report, ReportSchedule } from '../models/Intel.js';
import { askAi } from '../services/ai.js';
import { audit } from '../services/audit.js';
import { compliance, controlIds, FRAMEWORKS, frameworks, type FrameworkId } from '../services/compliance.js';
import { recommendations } from '../services/recommendations.js';
import { createReport, nextRunAfter, TYPE_TITLE } from '../services/reports.js';

export const intelRouter = Router();
intelRouter.use(['/ai', '/recommendations', '/reports', '/report-schedules', '/compliance'], requireAuth);

const DAY = 86_400_000;
const REPORT_TYPES = ['posture', 'health', 'vulnerabilities', 'ssl_domains', 'incidents', 'compliance'] as const;
const FW = z.enum(['iso27001', 'soc2', 'certin', 'dpdp']);

/* ───────────── AI analyst ───────────── */

// Each question costs money at the provider: a per-person limit keeps a stuck page or script from running up a bill.
const aiLimiter = rateLimit({ windowMs: 60_000, limit: 10, keyGenerator: (req) => String(req.user?._id ?? req.ip), standardHeaders: 'draft-7', legacyHeaders: false, handler: (_q, _s, next) => next(new ApiError(429, 'TOO_MANY_QUESTIONS', 'Ten questions a minute at most. Try again shortly.')) });

intelRouter.post('/ai/ask', aiLimiter, async (req, res) => {
  const input = parse(z.object({ question: z.string().max(2000).default(''), context: z.object({ type: z.enum(['finding', 'incident', 'error_group', 'alert']), id: objectId }).nullable().optional() }), req.body);
  const answer = await askAi(input.question, input.context ?? null);
  await audit(req, 'ai.ask', 'ai', input.context?.id ?? null, `Asked the AI analyst${answer.contextTitle ? ` about ${answer.contextTitle}` : ''} (${answer.sent.length} masked fields sent to ${answer.model})`);
  res.json({ id: `ai_${randomHex(12)}`, question: input.question, context: input.context ?? null, generatedAt: new Date().toISOString(), ...answer });
});

/* ───────────── recommendations ───────────── */

intelRouter.get('/recommendations', async (req, res) => {
  const f = parse(z.object({ applicationId: objectId.optional(), includeDismissed: z.enum(['true']).optional() }), req.query);
  const recs = await recommendations({ applicationId: f.applicationId });
  res.json(recs.filter((r) => f.includeDismissed || !r.dismissed));
});

const findRec = async (id: string) => {
  const r = (await recommendations()).find((x) => x.id === id);
  if (!r) throw notFound('Recommendation');
  return r;
};

intelRouter.post('/recommendations/:id/dismiss', async (req, res) => {
  const id = String(req.params.id);
  const { reason } = parse(z.object({ reason: z.string().trim().max(500) }), req.body);
  if (reason.length < 5) throw new ApiError(422, 'REASON_REQUIRED', 'Say why, so others know it was considered.');
  const rec = await findRec(id);
  await RecDismissal.updateOne({ recId: id }, { reason, by: req.user!._id, at: new Date() }, { upsert: true });
  await audit(req, 'recommendation.dismiss', 'recommendation', id, `Dismissed "${rec.title}": ${reason}`);
  res.json({ ...rec, dismissed: true, dismissedReason: reason });
});

intelRouter.post('/recommendations/:id/restore', async (req, res) => {
  const id = String(req.params.id);
  const rec = await findRec(id);
  await RecDismissal.deleteOne({ recId: id });
  await audit(req, 'recommendation.restore', 'recommendation', id, `Restored "${rec.title}"`);
  res.json({ ...rec, dismissed: false, dismissedReason: null });
});

/* ───────────── reports ───────────── */

intelRouter.get('/reports', async (_req, res) => {
  const list = await Report.find({}, { sections: 0 }).sort({ generatedAt: -1 }).limit(100);
  res.json(list.map((r) => r.toJSON()));
});

intelRouter.post('/reports', async (req, res) => {
  const input = parse(z.object({ type: z.enum(REPORT_TYPES), from: z.iso.datetime({ offset: true }), to: z.iso.datetime({ offset: true }), applicationId: objectId.nullable() }), req.body);
  const from = new Date(input.from);
  const to = new Date(input.to);
  if (from >= to) throw new ApiError(422, 'INVALID_RANGE', 'The start date must be before the end date.');
  if (to.getTime() - from.getTime() > 400 * DAY) throw new ApiError(422, 'RANGE_TOO_LONG', 'Choose a period of at most a year.');
  if (input.applicationId && !(await Application.exists({ _id: input.applicationId, deletedAt: null }))) throw notFound('Application');
  const r = await createReport({ type: input.type, from, to, applicationId: input.applicationId }, req.user!._id);
  await audit(req, 'report.generate', 'report', r.id, `Generated ${r.title} for ${input.from.slice(0, 10)} to ${input.to.slice(0, 10)}`);
  res.status(201).json(r.toJSON());
});

intelRouter.get('/reports/:id', async (req, res) => {
  const r = await Report.findById(parse(objectId, req.params.id));
  if (!r) throw notFound('Report');
  res.json(r.toJSON());
});

intelRouter.get('/reports/:id/pdf', async (req, res) => {
  const r = await Report.findById(parse(objectId, req.params.id)).select('+pdf');
  if (!r) throw notFound('Report');
  if (r.status !== 'ready' || !r.pdf) throw new ApiError(409, r.status === 'failed' ? 'REPORT_FAILED' : 'NOT_READY', r.status === 'failed' ? 'This report could not be generated. Generate it again.' : 'The report is still being generated.');
  await audit(req, 'report.download', 'report', r.id, `Downloaded ${r.title}`);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="shieldops-${r.type}-${r.to.toISOString().slice(0, 10)}.pdf"`);
  res.send(r.pdf);
});

/* ───────────── schedules ───────────── */

intelRouter.get('/report-schedules', async (_req, res) => {
  res.json((await ReportSchedule.find().sort({ nextRunAt: 1 })).map((s) => s.toJSON()));
});

intelRouter.post('/report-schedules', async (req, res) => {
  const input = parse(z.object({ type: z.enum(REPORT_TYPES), frequency: z.enum(['weekly', 'monthly']), recipients: z.array(z.string().trim().toLowerCase()).max(50), applicationId: objectId.nullable() }), req.body);
  const bad = input.recipients.find((e) => !/^\S+@\S+\.\S+$/.test(e));
  if (!input.recipients.length || bad) throw new ApiError(422, 'INVALID_RECIPIENTS', bad ? `${bad} is not a valid email address.` : 'Add at least one recipient.');
  const s = await ReportSchedule.create({ ...input, nextRunAt: await nextRunAfter(input.frequency), createdBy: req.user!._id });
  await audit(req, 'report.schedule', 'report', s.id, `Scheduled a ${input.frequency} ${TYPE_TITLE[input.type]} report to ${input.recipients.join(', ')}`);
  res.status(201).json(s.toJSON());
});

intelRouter.delete('/report-schedules/:id', async (req, res) => {
  const s = await ReportSchedule.findByIdAndDelete(parse(objectId, req.params.id));
  if (s) await audit(req, 'report.unschedule', 'report', s.id, `Stopped the ${s.frequency} ${TYPE_TITLE[s.type as keyof typeof TYPE_TITLE]} report`);
  res.status(204).end();
});

/* ───────────── compliance ───────────── */

intelRouter.get('/compliance/frameworks', async (_req, res) => {
  res.json(await frameworks());
});

intelRouter.patch('/compliance/frameworks/:id', async (req, res) => {
  const id = parse(FW, req.params.id);
  const { enabled } = parse(z.object({ enabled: z.boolean() }), req.body);
  await FrameworkState.updateOne({ _id: id }, { enabled }, { upsert: true });
  await audit(req, 'compliance.framework', 'compliance', id, `${enabled ? 'Turned on' : 'Turned off'} ${FRAMEWORKS.find((f) => f.id === id)!.name}`);
  res.json((await frameworks()).find((f) => f.id === id));
});

intelRouter.get('/compliance/frameworks/:id/controls', async (req, res) => {
  res.json(await compliance(parse(FW, req.params.id)));
});

intelRouter.put('/compliance/frameworks/:id/controls/:controlId/attestation', async (req, res) => {
  const fw = parse(FW, req.params.id) as FrameworkId;
  const controlId = String(req.params.controlId);
  if (!controlIds(fw).includes(controlId)) throw notFound('Control');
  const input = parse(z.object({ status: z.enum(['met', 'not_met']), note: z.string().trim().max(2000) }).nullable(), req.body ?? null);
  if (!input) {
    await Attestation.deleteOne({ framework: fw, controlId });
    await audit(req, 'compliance.attest_remove', 'compliance', `${fw}:${controlId}`, `Removed the evidence for ${fw} ${controlId}`);
  } else {
    if (input.note.length < 10) throw new ApiError(422, 'NOTE_REQUIRED', 'Describe the evidence (at least 10 characters), for example where the document lives.');
    await Attestation.updateOne({ framework: fw, controlId }, { status: input.status, note: input.note, by: req.user!._id, at: new Date() }, { upsert: true });
    await audit(req, 'compliance.attest', 'compliance', `${fw}:${controlId}`, `Recorded ${fw} ${controlId} as ${input.status.replace('_', ' ')}: ${input.note}`);
  }
  res.json(await compliance(fw));
});