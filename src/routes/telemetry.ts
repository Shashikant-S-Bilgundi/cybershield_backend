import { Router } from 'express';
import { ApiError, notFound } from '../lib/errors.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { Application } from '../models/Application.js';
import { AuditLog } from '../models/AuditLog.js';
import { Detection, ErrorEvent, ErrorGroup, SECURITY_TYPES, SecurityEvent, type ErrorGroupDoc } from '../models/Telemetry.js';
import { User } from '../models/User.js';
import { audit } from '../services/audit.js';
import { closeGroupAlerts, trends } from '../services/errors.js';
import { report, summaries } from '../services/perf.js';
import { stats } from '../services/security.js';

export const telemetryRouter = Router();
telemetryRouter.use(['/error-groups', '/performance', '/security-events', '/detections', '/auth/sign-ins'], requireAuth);

const scopeQuery = z.object({ applicationId: objectId.optional(), environmentId: objectId.optional() });

/** Telemetry of deleted applications stays hidden while they wait out their 30 days. */
async function live(f: { applicationId?: string; environmentId?: string }) {
  const ids = (await Application.find({ deletedAt: null, ...(f.applicationId ? { _id: f.applicationId } : {}) }, { _id: 1 }).lean()).map((a) => a._id);
  return { applicationId: { $in: ids }, ...(f.environmentId ? { environmentId: f.environmentId } : {}) };
}
const unescapeRelease = (k: string) => k.replace(/\uff0e/g, '.');

function groupView(g: ErrorGroupDoc, trend: number[] | undefined) {
  return {
    id: g.id, applicationId: String(g.applicationId), environmentId: String(g.environmentId), fingerprint: g.fingerprint,
    type: g.type, message: g.message, culprit: g.culprit, platform: g.platform, status: g.status,
    firstSeen: g.firstSeen, lastSeen: g.lastSeen, count: g.count, usersAffected: g.usersAffected,
    assigneeId: g.assigneeId ? String(g.assigneeId) : null, lastRelease: g.lastRelease, resolvedAt: g.resolvedAt, trend: trend ?? Array(24).fill(0),
  };
}

async function groupDetail(g: ErrorGroupDoc) {
  const [trend] = [(await trends([g._id])).get(g.id)];
  const events = await ErrorEvent.find({ groupId: g._id }).sort({ at: -1 }).limit(20).lean();
  const releases = [...(g.releases?.entries() ?? [])].map(([release, count]) => ({ release: unescapeRelease(release), count })).sort((a, b) => b.count - a.count);
  return {
    ...groupView(g, trend),
    stack: g.stack,
    events: events.map((e) => ({ id: String(e._id), groupId: g.id, at: e.at, release: e.release, message: e.message, request: e.request, userHash: e.userHash, tags: e.tags ?? {} })),
    releases,
    history: g.history,
  };
}

/* ───────────── errors ───────────── */

telemetryRouter.get('/error-groups', async (req, res) => {
  const f = parse(scopeQuery.extend({ status: z.enum(['unresolved', 'resolved', 'ignored', 'regressed', 'open']).optional(), platform: z.enum(['node', 'browser', 'react-native']).optional(), search: z.string().trim().max(200).optional() }), req.query);
  const { status, search, ...rest } = f;
  const q: Record<string, unknown> = await live(rest);
  if (status) q.status = status === 'open' ? { $in: ['unresolved', 'regressed'] } : status;
  if (search) {
    const rx = { $regex: search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' };
    q.$or = [{ type: rx }, { message: rx }, { culprit: rx }];
  }
  const groups = await ErrorGroup.find(q).sort({ lastSeen: -1 }).limit(500);
  const t = await trends(groups.map((g) => g._id));
  res.json(groups.map((g) => groupView(g, t.get(g.id))));
});

const findGroup = async (id: unknown) => {
  const g = await ErrorGroup.findById(parse(objectId, id));
  if (!g) throw notFound('Error group');
  return g;
};

telemetryRouter.get('/error-groups/:id', async (req, res) => {
  res.json(await groupDetail(await findGroup(req.params.id)));
});

telemetryRouter.patch('/error-groups/:id', async (req, res) => {
  const g = await findGroup(req.params.id);
  const input = parse(z.object({ status: z.enum(['unresolved', 'resolved', 'ignored', 'regressed']).optional(), assigneeId: objectId.nullable().optional() }), req.body);
  const now = new Date();
  if (input.status && input.status !== g.status) {
    if (input.status === 'regressed') throw new ApiError(422, 'INVALID_STATUS', 'Only ShieldOps can mark an error as regressed.');
    const text = { resolved: 'Marked resolved', ignored: 'Ignored future events', unresolved: 'Reopened' }[input.status];
    g.status = input.status;
    if (input.status === 'resolved') g.resolvedAt = now;
    g.history.unshift({ at: now, actorName: req.user!.name, text });
    if (input.status !== 'unresolved') await closeGroupAlerts(g.id);
    await audit(req, `error_group.${input.status}`, 'error_group', g.id, `${text}: ${g.type}: ${g.message.slice(0, 120)}`);
  }
  if (input.assigneeId !== undefined && String(input.assigneeId) !== String(g.assigneeId)) {
    const who = input.assigneeId ? await User.findOne({ _id: input.assigneeId, status: 'active' }) : null;
    if (input.assigneeId && !who) throw new ApiError(422, 'INVALID_ASSIGNEE', 'Choose an active team member.');
    g.assigneeId = (who?._id ?? null) as never;
    g.history.unshift({ at: now, actorName: req.user!.name, text: `Assigned to ${who?.name ?? 'nobody'}` });
  }
  await g.save();
  res.json(await groupDetail(g));
});

/* ───────────── performance ───────────── */

telemetryRouter.get('/performance', async (req, res) => {
  const f = parse(scopeQuery, req.query);
  const allowed = new Set(((await live(f)).applicationId.$in).map(String));
  res.json((await summaries(f)).filter((s) => allowed.has(s.applicationId)));
});

telemetryRouter.get('/performance/:applicationId/:environmentId', async (req, res) => {
  const applicationId = parse(objectId, req.params.applicationId);
  const environmentId = parse(objectId, req.params.environmentId);
  const { range } = parse(z.object({ range: z.enum(['1h', '24h', '7d']).default('24h') }), req.query);
  const app = await Application.findOne({ _id: applicationId, deletedAt: null });
  if (!app?.environments.some((e) => e.id === environmentId)) throw notFound('Environment');
  const r = await report(applicationId, environmentId, range);
  if (!r.requests && !r.lastSampleAt) throw new ApiError(404, 'NO_DATA', 'No performance data for this environment yet. Install the SDK to start sending it.');
  res.json(r);
});

/* ───────────── security events ───────────── */

telemetryRouter.get('/security-events', async (req, res) => {
  const f = parse(
    scopeQuery.extend({
      types: z.string().max(300).optional(),
      result: z.enum(['success', 'failure', 'blocked']).optional(),
      ip: z.string().trim().max(64).optional(),
      page: z.coerce.number().int().min(1).default(1),
      pageSize: z.coerce.number().int().min(1).max(200).default(50),
    }),
    req.query,
  );
  const types = f.types?.split(',').filter((t) => (SECURITY_TYPES as readonly string[]).includes(t));
  const q: Record<string, unknown> = { ...(await live(f)), at: { $gte: new Date(Date.now() - 24 * 3_600_000) } };
  if (types?.length) q.type = { $in: types };
  if (f.result) q.result = f.result;
  if (f.ip) q.ip = { $regex: f.ip.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') };
  const [items, total] = await Promise.all([SecurityEvent.find(q).sort({ at: -1 }).skip((f.page - 1) * f.pageSize).limit(f.pageSize), SecurityEvent.countDocuments(q)]);
  res.json({ items: items.map((i) => i.toJSON()), total, page: f.page, pageSize: f.pageSize });
});

telemetryRouter.get('/security-events/stats', async (req, res) => {
  res.json(await stats(await live(parse(scopeQuery, req.query))));
});

telemetryRouter.get('/detections', async (req, res) => {
  const f = parse(scopeQuery, req.query);
  const rows = await Detection.find({ ...(await live(f)), lastAt: { $gte: new Date(Date.now() - 24 * 3_600_000) } }).sort({ lastAt: -1 }).limit(100);
  res.json(rows.map((r) => r.toJSON()));
});

/* ───────────── ShieldOps's own sign-ins, from the audit log ───────────── */

const SIGN_IN: Record<string, { result: 'success' | 'failed'; detail: string }> = {
  'auth.login': { result: 'success', detail: 'Password accepted' },
  'auth.login_failed': { result: 'failed', detail: 'Wrong email or password' },
  'setup.complete': { result: 'success', detail: 'First account created' },
  'user.join': { result: 'success', detail: 'Joined by invitation' },
};

telemetryRouter.get('/auth/sign-ins', async (req, res) => {
  const { page, pageSize } = parse(z.object({ page: z.coerce.number().int().min(1).default(1), pageSize: z.coerce.number().int().min(1).max(200).default(50) }), req.query);
  const q = { action: { $in: Object.keys(SIGN_IN) } };
  const [rows, total] = await Promise.all([AuditLog.find(q).sort({ at: -1 }).skip((page - 1) * pageSize).limit(pageSize).lean(), AuditLog.countDocuments(q)]);
  res.json({
    items: rows.map((l) => ({ id: String(l._id), at: l.at, name: l.actorId ? l.actorName : null, ip: l.ip, ...SIGN_IN[l.action] })),
    total,
    page,
    pageSize,
  });
});