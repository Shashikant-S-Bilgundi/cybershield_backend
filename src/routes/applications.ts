import { Router } from 'express';
import { ApiError, notFound } from '../lib/errors.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { Application } from '../models/Application.js';
import { Asset } from '../models/Asset.js';
import { User } from '../models/User.js';
import { audit } from '../services/audit.js';
import { notifyAll } from '../services/notify.js';
import { stopMonitoringFor } from '../services/cleanup.js';

export const applicationsRouter = Router();
applicationsRouter.use('/applications', requireAuth);

const envInput = z.object({ name: z.string().trim().min(1).max(60), type: z.enum(['production', 'staging', 'development', 'custom']) });
const appInput = z.object({
  name: z.string().trim().min(2).max(120),
  description: z.string().trim().max(2000).default(''),
  ownerId: objectId,
  criticality: z.enum(['critical', 'high', 'medium', 'low']),
  techStack: z.array(z.string().trim().min(1).max(60)).max(30).default([]),
  tags: z.array(z.string().trim().min(1).max(60)).max(30).default([]),
  environments: z
    .array(envInput)
    .min(1, 'Add at least one environment.')
    .max(10)
    .refine((envs) => new Set(envs.map((e) => e.name.toLowerCase())).size === envs.length, 'Environment names must be different.'),
});

const findApp = async (id: unknown) => {
  const app = await Application.findOne({ _id: parse(objectId, id), deletedAt: null });
  if (!app) throw notFound('Application');
  return app;
};

async function assertOwner(ownerId: string) {
  if (!(await User.exists({ _id: ownerId, status: 'active' }))) throw new ApiError(422, 'INVALID_OWNER', 'Choose an active team member as the owner.');
}

async function assertUniqueName(name: string, exceptId?: string) {
  const clash = await Application.findOne({ deletedAt: null, name: { $regex: `^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, $options: 'i' } });
  if (clash && clash.id !== exceptId) throw new ApiError(409, 'DUPLICATE_NAME', 'An application with this name already exists.');
}

applicationsRouter.get('/applications', async (_req, res) => {
  const apps = await Application.find({ deletedAt: null }).sort({ name: 1 });
  res.json(apps.map((a) => a.toJSON()));
});

applicationsRouter.get('/applications/:id', async (req, res) => {
  res.json((await findApp(req.params.id)).toJSON());
});

applicationsRouter.post('/applications', async (req, res) => {
  const input = parse(appInput, req.body);
  await assertOwner(input.ownerId);
  await assertUniqueName(input.name);
  const app = await Application.create({ ...input, memberIds: [input.ownerId] });
  await audit(req, 'application.create', 'application', app.id, `Created application ${app.name}`);
  res.status(201).json(app.toJSON());
});

applicationsRouter.patch('/applications/:id', async (req, res) => {
  const app = await findApp(req.params.id);
  const input = parse(appInput.partial(), req.body);
  if (input.ownerId) await assertOwner(input.ownerId);
  if (input.name) await assertUniqueName(input.name, app.id);
  const { environments, ...rest } = input;
  app.set(rest);
  if (input.ownerId && !app.memberIds.some((m) => String(m) === input.ownerId)) app.memberIds.push(input.ownerId as never);
  if (environments) {
    // Environments are matched by name: kept ones keep their id, so assets stay attached.
    const kept = app.environments.filter((e) => environments.some((n) => n.name.toLowerCase() === e.name.toLowerCase()));
    const removed = app.environments.filter((e) => !kept.includes(e));
    if (removed.length && (await Asset.exists({ deletedAt: null, environmentId: { $in: removed.map((e) => e._id) } }))) {
      throw new ApiError(409, 'ENVIRONMENT_IN_USE', 'Move or delete the assets in an environment before removing it.');
    }
    kept.forEach((e) => (e.type = environments.find((n) => n.name.toLowerCase() === e.name.toLowerCase())!.type));
    const added = environments.filter((n) => !kept.some((e) => e.name.toLowerCase() === n.name.toLowerCase()));
    app.environments.splice(0, app.environments.length, ...kept, ...(added as never[]));
  }
  await app.save();
  await audit(req, 'application.update', 'application', app.id, `Updated application ${app.name}`);
  res.json(app.toJSON());
});

applicationsRouter.patch('/applications/:id/status', async (req, res) => {
  const app = await findApp(req.params.id);
  const { status } = parse(z.object({ status: z.enum(['active', 'archived']) }), req.body);
  app.status = status;
  await app.save();
  await audit(req, status === 'archived' ? 'application.archive' : 'application.restore', 'application', app.id, `${status === 'archived' ? 'Archived' : 'Restored'} application ${app.name}`);
  res.json(app.toJSON());
});

/** Soft delete: the application and its assets are hidden now and purged after 30 days. */
applicationsRouter.delete('/applications/:id', requireReauth, async (req, res) => {
  const app = await findApp(req.params.id);
  const now = new Date();
  app.deletedAt = now;
  await app.save();
  await Asset.updateMany({ applicationId: app._id, deletedAt: null }, { deletedAt: now });
  await stopMonitoringFor({ applicationId: app._id });
  await audit(req, 'application.delete', 'application', app.id, `Deleted application ${app.name} (restorable for 30 days)`);
  await notifyAll('An application was deleted', `${req.user!.name} deleted ${app.name} and its assets. It can be restored for 30 days.`);
  res.status(204).end();
});