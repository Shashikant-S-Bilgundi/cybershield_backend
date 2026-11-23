import { Router } from 'express';
import { ApiError, notFound } from '../lib/errors.js';
import { SLA_DAYS, type Priority } from '../lib/risk.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { Alert } from '../models/Alert.js';
import { Application } from '../models/Application.js';
import { Finding } from '../models/Finding.js';
import { INCIDENT_STATUSES, Incident, RemediationTask, nextSeq, type IncidentDoc, type TaskDoc } from '../models/Ops.js';
import { ErrorGroup } from '../models/Telemetry.js';
import { User } from '../models/User.js';
import { audit } from '../services/audit.js';
import { sendToChannel } from '../services/channels.js';
import { notifyAll } from '../services/notify.js';
import { startVerification } from '../services/verification.js';
import { Integration } from '../models/Code.js';

export const opsRouter = Router();
opsRouter.use(['/incidents', '/remediation-tasks', '/sla', '/integrations/:type/test'], requireAuth);

const DAY = 86_400_000;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const SEV_PRIORITY: Record<string, Priority> = { critical: 'P1', high: 'P2', medium: 'P3', low: 'P4', info: 'P4' };
const ACTIVE = ['new', 'acknowledged', 'investigating', 'remediating', 'reopened'];
const OPEN_TASK = ['todo', 'in_progress', 'ready_for_verification'];

/** Which status changes the workflow allows (same as the frontend). */
const NEXT: Record<string, string[]> = {
  new: ['acknowledged', 'investigating', 'resolved'],
  acknowledged: ['investigating', 'remediating', 'resolved'],
  investigating: ['remediating', 'resolved'],
  remediating: ['investigating', 'resolved'],
  reopened: ['acknowledged', 'investigating', 'remediating', 'resolved'],
  resolved: ['closed', 'reopened'],
  closed: ['reopened'],
};
const STATUS_TEXT: Record<string, string> = { new: 'new', acknowledged: 'acknowledged', investigating: 'investigating', remediating: 'remediation in progress', resolved: 'resolved', closed: 'closed', reopened: 'reopened' };

async function liveAppIds(applicationId?: string) {
  return (await Application.find({ deletedAt: null, ...(applicationId ? { _id: applicationId } : {}) }, { _id: 1 }).lean()).map((a) => a._id);
}

async function activeUser(id: string | null | undefined) {
  if (!id) return null;
  const u = await User.findOne({ _id: id, status: 'active' });
  if (!u) throw new ApiError(422, 'INVALID_OWNER', 'Choose an active team member.');
  return u;
}

/** Title and severity of something linked to an incident, read from the item itself. */
async function describeLink(type: string, id: string) {
  if (type === 'alert') {
    const a = await Alert.findById(id).lean();
    if (!a) throw notFound('Alert');
    return { type, id, title: a.title, severity: a.severity };
  }
  if (type === 'finding') {
    const f = await Finding.findById(id).lean();
    if (!f) throw notFound('Finding');
    return { type, id, title: f.title, severity: f.severity };
  }
  const g = await ErrorGroup.findById(id).lean();
  if (!g) throw notFound('Error group');
  return { type, id, title: `${g.type}: ${g.message}`.slice(0, 200), severity: null };
}

const linkInput = z.object({ type: z.enum(['alert', 'finding', 'error_group']), id: objectId });

/* ───────────── incidents ───────────── */

opsRouter.get('/incidents', async (req, res) => {
  const f = parse(z.object({ status: z.enum([...INCIDENT_STATUSES, 'active']).optional(), applicationId: objectId.optional(), severity: z.enum(SEVERITIES).optional() }), req.query);
  const q: Record<string, unknown> = {};
  if (f.status) q.status = f.status === 'active' ? { $in: ACTIVE } : f.status;
  if (f.severity) q.severity = f.severity;
  if (f.applicationId) q.applicationIds = f.applicationId;
  const list = await Incident.find(q).sort({ openedAt: -1 }).limit(300);
  const order = (i: IncidentDoc) => (ACTIVE.includes(i.status) ? 0 : i.status === 'resolved' ? 1 : 2);
  list.sort((a, b) => order(a) - order(b) || SEVERITIES.indexOf(a.severity as never) - SEVERITIES.indexOf(b.severity as never));
  res.json(list.map((i) => i.toJSON()));
});

const findIncident = async (id: unknown) => {
  const i = await Incident.findById(parse(objectId, id));
  if (!i) throw notFound('Incident');
  return i;
};

opsRouter.get('/incidents/:id', async (req, res) => {
  res.json((await findIncident(req.params.id)).toJSON());
});

opsRouter.post('/incidents', async (req, res) => {
  const input = parse(
    z.object({
      title: z.string().trim().min(1, 'Give the incident a short title.').max(200),
      summary: z.string().trim().max(5000).default(''),
      severity: z.enum(SEVERITIES),
      applicationIds: z.array(objectId).min(1, 'Choose at least one affected application.').max(20),
      ownerId: objectId.nullable(),
      links: z.array(linkInput).max(50).default([]),
    }),
    req.body,
  );
  const apps = await Application.find({ _id: { $in: input.applicationIds }, deletedAt: null });
  if (!apps.length) throw new ApiError(422, 'APP_REQUIRED', 'Choose at least one affected application.');
  const owner = await activeUser(input.ownerId);
  const linked = [];
  for (const l of input.links) linked.push(await describeLink(l.type, l.id));
  const ref = `INC-${String(await nextSeq('incident')).padStart(4, '0')}`;
  const now = new Date();
  const me = req.user!;
  const inc = await Incident.create({
    ref, title: input.title, summary: input.summary, severity: input.severity, ownerId: owner?._id ?? null, applicationIds: apps.map((a) => a._id), linked, openedAt: now, createdBy: me._id,
    timeline: [
      ...linked.map((l) => ({ at: now, actorName: me.name, kind: 'link', text: `Linked ${l.type.replace('_', ' ')}: ${l.title}` })),
      ...(owner ? [{ at: now, actorName: me.name, kind: 'status', text: `Owner: ${owner.name}` }] : []),
      { at: now, actorName: me.name, kind: 'status', text: `Opened ${ref}` },
    ],
  });
  await audit(req, 'incident.create', 'incident', inc.id, `Opened ${ref}: ${inc.title}`);
  if (inc.severity === 'critical' || inc.severity === 'high') await notifyAll(`${ref} opened: ${inc.title}`, `${me.name} opened a ${inc.severity} incident affecting ${apps.map((a) => a.name).join(', ')}.`);
  res.status(201).json(inc.toJSON());
});

opsRouter.patch('/incidents/:id', async (req, res) => {
  const inc = await findIncident(req.params.id);
  const input = parse(
    z.object({ status: z.enum(INCIDENT_STATUSES).optional(), ownerId: objectId.nullable().optional(), severity: z.enum(SEVERITIES).optional(), rootCause: z.string().max(10000).optional(), postIncident: z.string().max(20000).optional(), note: z.string().trim().max(5000).optional() }),
    req.body,
  );
  const me = req.user!;
  const now = new Date();
  const log = (text: string, kind = 'status') => inc.timeline.unshift({ at: now, actorName: me.name, kind, text } as never);
  if (input.rootCause !== undefined && input.rootCause !== inc.rootCause) {
    inc.rootCause = input.rootCause.trim();
    log('Updated the root cause', 'note');
  }
  if (input.postIncident !== undefined && input.postIncident !== inc.postIncident) {
    inc.postIncident = input.postIncident.trim();
    log('Updated the post-incident summary', 'note');
  }
  if (input.status && input.status !== inc.status) {
    if (!NEXT[inc.status].includes(input.status)) throw new ApiError(409, 'INVALID_TRANSITION', `An incident that is ${STATUS_TEXT[inc.status]} cannot move to ${STATUS_TEXT[input.status]}.`);
    if (input.status === 'closed' && inc.severity === 'critical' && inc.postIncident.trim().length < 40) {
      throw new ApiError(422, 'SUMMARY_REQUIRED', 'Critical incidents need a post-incident summary (what happened, impact, what changed) before they can be closed.');
    }
    if (['acknowledged', 'investigating', 'remediating'].includes(input.status) && !inc.acknowledgedAt) inc.acknowledgedAt = now;
    if (input.status === 'resolved') inc.resolvedAt = now;
    if (input.status === 'closed') inc.closedAt = now;
    if (input.status === 'reopened') {
      inc.resolvedAt = null;
      inc.closedAt = null;
    }
    log(`Status: ${STATUS_TEXT[inc.status]} → ${STATUS_TEXT[input.status]}`);
    inc.status = input.status;
    await audit(req, `incident.${input.status}`, 'incident', inc.id, `${inc.ref} ${STATUS_TEXT[input.status]}`);
  }
  if (input.severity && input.severity !== inc.severity) {
    log(`Severity: ${inc.severity} → ${input.severity}`);
    inc.severity = input.severity;
  }
  if (input.ownerId !== undefined && String(input.ownerId) !== String(inc.ownerId)) {
    const owner = await activeUser(input.ownerId);
    inc.ownerId = (owner?._id ?? null) as never;
    log(`Owner: ${owner?.name ?? 'nobody'}`);
  }
  if (input.note) log(input.note, 'note');
  await inc.save();
  res.json(inc.toJSON());
});

opsRouter.post('/incidents/:id/links', async (req, res) => {
  const inc = await findIncident(req.params.id);
  const item = parse(linkInput, req.body);
  if (inc.linked.some((l) => l.type === item.type && l.id === item.id)) throw new ApiError(409, 'ALREADY_LINKED', 'This is already linked.');
  const link = await describeLink(item.type, item.id);
  inc.linked.push(link as never);
  inc.timeline.unshift({ at: new Date(), actorName: req.user!.name, kind: 'link', text: `Linked ${link.type.replace('_', ' ')}: ${link.title}` } as never);
  await inc.save();
  res.json(inc.toJSON());
});

opsRouter.delete('/incidents/:id/links/:type/:itemId', async (req, res) => {
  const inc = await findIncident(req.params.id);
  const type = parse(linkInput.shape.type, req.params.type);
  const id = parse(objectId, req.params.itemId);
  const link = inc.linked.find((l) => l.type === type && l.id === id);
  if (!link) throw notFound('Link');
  inc.linked = inc.linked.filter((l) => l !== link) as never;
  inc.timeline.unshift({ at: new Date(), actorName: req.user!.name, kind: 'link', text: `Unlinked ${type.replace('_', ' ')}: ${link.title}` } as never);
  await inc.save();
  res.json(inc.toJSON());
});

/* ───────────── remediation tasks ───────────── */

const isOverdue = (t: TaskDoc) => OPEN_TASK.includes(t.status) && !!t.dueAt && t.dueAt.getTime() < Date.now();

opsRouter.get('/remediation-tasks', async (req, res) => {
  const f = parse(z.object({ status: z.enum(['todo', 'in_progress', 'ready_for_verification', 'verified', 'wont_fix', 'open']).optional(), ownerId: objectId.optional(), overdue: z.enum(['true']).optional(), applicationId: objectId.optional(), linkedId: objectId.optional() }), req.query);
  const q: Record<string, unknown> = { applicationId: { $in: await liveAppIds(f.applicationId) } };
  if (f.status) q.status = f.status === 'open' ? { $in: OPEN_TASK } : f.status;
  if (f.ownerId) q.ownerId = f.ownerId;
  if (f.linkedId) q.linkedId = f.linkedId;
  let tasks = await RemediationTask.find(q).limit(500);
  if (f.overdue) tasks = tasks.filter(isOverdue);
  tasks.sort((a, b) => Number(isOverdue(b)) - Number(isOverdue(a)) || Number(OPEN_TASK.includes(b.status)) - Number(OPEN_TASK.includes(a.status)) || (a.dueAt?.getTime() ?? 9e15) - (b.dueAt?.getTime() ?? 9e15));
  res.json(tasks.map((t) => t.toJSON()));
});

opsRouter.post('/remediation-tasks', async (req, res) => {
  const input = parse(
    z.object({ title: z.string().trim().min(1, 'Describe what needs doing.').max(200), details: z.string().trim().max(5000).default(''), linkedType: z.enum(['finding', 'incident', 'error_group']), linkedId: objectId, ownerId: objectId.nullable(), dueAt: z.iso.datetime({ offset: true }).nullable().optional() }),
    req.body,
  );
  const owner = await activeUser(input.ownerId);
  const me = req.user!;
  let priority: Priority | null = null;
  let applicationId: unknown;
  let linkedTitle = '';
  let dueAt: Date | null = input.dueAt ? new Date(input.dueAt) : null;
  if (input.linkedType === 'finding') {
    const f = await Finding.findById(input.linkedId);
    if (!f) throw notFound('Finding');
    priority = f.priority as Priority;
    applicationId = f.applicationId;
    linkedTitle = f.title;
    dueAt ??= f.dueAt ?? null;
    if (['open', 'acknowledged', 'reopened'].includes(f.status)) f.status = 'in_progress';
    f.history.unshift({ at: new Date(), actorName: me.name, text: `Remediation task created: ${input.title}` });
    await f.save();
  } else if (input.linkedType === 'incident') {
    const inc = await Incident.findById(input.linkedId);
    if (!inc) throw notFound('Incident');
    priority = SEV_PRIORITY[inc.severity];
    applicationId = inc.applicationIds[0];
    linkedTitle = `${inc.ref} ${inc.title}`;
    dueAt ??= new Date(Date.now() + SLA_DAYS[priority] * DAY);
    inc.timeline.unshift({ at: new Date(), actorName: me.name, kind: 'task', text: `Task added: ${input.title}` } as never);
    await inc.save();
  } else {
    const g = await ErrorGroup.findById(input.linkedId);
    if (!g) throw notFound('Error group');
    applicationId = g.applicationId;
    linkedTitle = `${g.type}: ${g.message}`.slice(0, 200);
    g.history.unshift({ at: new Date(), actorName: me.name, text: `Remediation task created: ${input.title}` } as never);
    await g.save();
  }
  const task = await RemediationTask.create({ title: input.title, details: input.details, linkedType: input.linkedType, linkedId: input.linkedId, linkedTitle, applicationId, ownerId: owner?._id ?? null, priority, dueAt, createdBy: me._id });
  await audit(req, 'task.create', 'task', task.id, `Created task "${task.title}" for ${linkedTitle}`);
  res.status(201).json(task.toJSON());
});

opsRouter.patch('/remediation-tasks/:id', async (req, res) => {
  const t = await RemediationTask.findById(parse(objectId, req.params.id));
  if (!t) throw notFound('Task');
  const input = parse(z.object({ status: z.enum(['todo', 'in_progress', 'ready_for_verification', 'verified', 'wont_fix']).optional(), ownerId: objectId.nullable().optional(), dueAt: z.iso.datetime({ offset: true }).nullable().optional(), note: z.string().trim().max(5000).optional(), wontFixReason: z.string().trim().max(2000).optional() }), req.body);
  const me = req.user!;
  const note = (text: string) => t.notes.unshift({ at: new Date(), actorName: me.name, text } as never);

  if (input.status && input.status !== t.status) {
    if (input.status === 'verified') throw new ApiError(422, 'VERIFY_BY_RECHECK', 'Tasks are verified by a recheck. Move it to "Ready for verification" instead.');
    if (input.status === 'wont_fix' && (input.wontFixReason?.length ?? 0) < 10) throw new ApiError(422, 'REASON_REQUIRED', "Explain why this won't be fixed (at least 10 characters).");
    if (t.status === 'ready_for_verification' && input.status !== 'in_progress' && input.status !== 'wont_fix') throw new ApiError(409, 'VERIFYING', 'Wait for the recheck to finish, or move the task back to in progress.');
    if (t.status === 'verified' || t.status === 'wont_fix') {
      if (input.status !== 'in_progress' && input.status !== 'todo') throw new ApiError(409, 'TASK_DONE', 'Reopen the task first.');
      t.completedAt = null;
      t.wontFixReason = null;
    }
    if (input.status === 'wont_fix') {
      t.wontFixReason = input.wontFixReason!;
      t.completedAt = new Date();
      t.status = 'wont_fix';
      note(`Won't fix: ${input.wontFixReason}`);
    } else if (input.status === 'ready_for_verification') {
      note('Marked ready for verification');
      await startVerification(t);
    } else {
      if (t.status === 'ready_for_verification') {
        t.verification = null;
        t.watchUntil = null;
      }
      t.status = input.status;
      note(`Status: ${input.status.replace(/_/g, ' ')}`);
    }
    await audit(req, `task.${input.status}`, 'task', t.id, `Task "${t.title}": ${input.status.replace(/_/g, ' ')}`);
  }
  if (input.ownerId !== undefined && String(input.ownerId) !== String(t.ownerId)) {
    const owner = await activeUser(input.ownerId);
    t.ownerId = (owner?._id ?? null) as never;
    note(`Owner: ${owner?.name ?? 'nobody'}`);
  }
  if (input.dueAt !== undefined) {
    t.dueAt = input.dueAt ? new Date(input.dueAt) : null;
    note(`Due ${input.dueAt ? input.dueAt.slice(0, 10) : 'date removed'}`);
  }
  if (input.note) note(input.note);
  await t.save();
  res.json((await RemediationTask.findById(t._id))!.toJSON());
});

/* ───────────── SLA ───────────── */

opsRouter.get('/sla', async (req, res) => {
  const { applicationId } = parse(z.object({ applicationId: objectId.optional() }), req.query);
  const apps = await liveAppIds(applicationId);
  const now = Date.now();
  const tasks = await RemediationTask.find({ applicationId: { $in: apps } });
  const open = tasks.filter((t) => OPEN_TASK.includes(t.status));
  const recent = tasks.filter((t) => t.status === 'verified' && t.completedAt && now - t.completedAt.getTime() <= 30 * DAY);
  const onTime = recent.filter((t) => !t.dueAt || t.completedAt! <= t.dueAt).length;
  const mean = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
  const acked = await Alert.find({ applicationId: { $in: apps }, acknowledgedAt: { $gte: new Date(now - 30 * DAY) } }, { firstAt: 1, acknowledgedAt: 1 }).lean();
  const resolved = await Incident.find({ applicationIds: { $in: apps }, resolvedAt: { $gte: new Date(now - 30 * DAY) } }, { openedAt: 1, resolvedAt: 1 }).lean();
  const mtta = mean(acked.map((a) => (a.acknowledgedAt!.getTime() - a.firstAt.getTime()) / 60_000));
  const mttr = mean(resolved.map((i) => (i.resolvedAt!.getTime() - i.openedAt.getTime()) / 3_600_000));
  res.json({
    openTasks: open.length,
    overdue: open.filter(isOverdue).length,
    dueThisWeek: open.filter((t) => t.dueAt && t.dueAt.getTime() >= now && t.dueAt.getTime() <= now + 7 * DAY).length,
    verifiedLast30d: recent.length,
    onTimeRate: recent.length ? Math.round((onTime / recent.length) * 100) : null,
    byPriority: (['P1', 'P2', 'P3', 'P4'] as Priority[]).map((p) => ({ priority: p, open: open.filter((t) => t.priority === p).length, overdue: open.filter((t) => t.priority === p && isOverdue(t)).length })),
    mttaMinutes: mtta === null ? null : Math.round(mtta),
    mttrHours: mttr === null ? null : Math.round(mttr * 10) / 10,
  });
});

/* ───────────── test message for Slack and the webhook ───────────── */

opsRouter.post('/integrations/:type/test', async (req, res) => {
  const type = parse(z.enum(['github', 'ghcr', 'dockerhub', 'smtp', 'slack', 'webhook', 'jira', 'cloudflare', 'aws', 'google', 'entra']), req.params.type);
  if (type !== 'slack' && type !== 'webhook') throw new ApiError(400, 'NOT_SUPPORTED', 'Test messages are only for Slack and webhooks.');
  if ((await Integration.findOne({ type }))?.status !== 'connected') throw new ApiError(409, 'NOT_CONNECTED', 'Connect it first.');
  const r = await sendToChannel(type, { id: `test_${Date.now().toString(36)}`, title: 'Test message from ShieldOps', message: `${req.user!.name} sent this test. If you can read it, alerts will arrive here.`, severity: 'info', applicationId: null, environmentId: null }, 'test');
  await audit(req, 'integration.test', 'integration', type, `Sent a test message to ${type}: ${r.ok ? 'delivered' : 'failed'}`);
  res.json({ ok: r.ok, detail: r.ok && type === 'webhook' ? `${r.detail} The request was signed with your secret.` : r.ok ? `Test message posted to ${r.recipient}.` : r.detail });
});