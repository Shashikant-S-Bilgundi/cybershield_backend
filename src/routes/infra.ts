import { Router } from 'express';
import { encrypt } from '../lib/crypto.js';
import { ApiError, notFound } from '../lib/errors.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { Application } from '../models/Application.js';
import { Asset } from '../models/Asset.js';
import { AgentToken, DbCheck, Server, ServerSample, type AgentTokenDoc } from '../models/Infra.js';
import { autoResolve } from '../services/alerts.js';
import { audit } from '../services/audit.js';
import { runDbCheck } from '../services/dbChecks.js';
import { notifyAll } from '../services/notify.js';
import { markTokenServersOffline, newAgentSecret, serverMetrics, serverView } from '../services/servers.js';

export const infraRouter = Router();
infraRouter.use(['/servers', '/agent-tokens', '/db-checks'], requireAuth);

const scopeQuery = z.object({ applicationId: objectId.optional(), environmentId: objectId.optional() });
async function live(f: { applicationId?: string; environmentId?: string }) {
  const ids = (await Application.find({ deletedAt: null, ...(f.applicationId ? { _id: f.applicationId } : {}) }, { _id: 1 }).lean()).map((a) => a._id);
  return { applicationId: { $in: ids }, ...(f.environmentId ? { environmentId: f.environmentId } : {}) };
}

/* ───────────── servers ───────────── */

const ORDER = { offline: 0, new: 1, online: 2 } as const;

infraRouter.get('/servers', async (req, res) => {
  const servers = await Server.find(await live(parse(scopeQuery, req.query)));
  servers.sort((a, b) => ORDER[a.status as keyof typeof ORDER] - ORDER[b.status as keyof typeof ORDER] || a.hostname.localeCompare(b.hostname));
  res.json(servers.map(serverView));
});

const findServer = async (id: unknown) => {
  const s = await Server.findById(parse(objectId, id));
  if (!s) throw notFound('Server');
  return s;
};

infraRouter.get('/servers/:id', async (req, res) => {
  const s = await findServer(req.params.id);
  res.json({ ...serverView(s), kernel: s.kernel, disks: s.disks, events: s.events });
});

infraRouter.get('/servers/:id/metrics', async (req, res) => {
  const s = await findServer(req.params.id);
  const { range } = parse(z.object({ range: z.enum(['1h', '24h', '7d']).default('24h') }), req.query);
  res.json(await serverMetrics(s._id, range));
});

/** For hosts that no longer exist. If the agent still runs, the server simply reappears. */
infraRouter.delete('/servers/:id', requireReauth, async (req, res) => {
  const s = await findServer(req.params.id);
  await ServerSample.deleteMany({ serverId: s._id });
  await s.deleteOne();
  for (const k of ['offline', 'cpu', 'memory']) await autoResolve(`srv:${k}:${s.id}`);
  await audit(req, 'server.remove', 'server', s.id, `Removed server ${s.hostname}`);
  await notifyAll('A server was removed', `${req.user!.name} removed ${s.hostname} from ShieldOps.`);
  res.status(204).end();
});

/* ───────────── agent tokens ───────────── */

async function tokenViews(tokens: AgentTokenDoc[]) {
  const counts = await Server.aggregate<{ _id: unknown; n: number; last: Date | null }>([{ $match: { agentTokenId: { $in: tokens.map((t) => t._id) } } }, { $group: { _id: '$agentTokenId', n: { $sum: 1 }, last: { $max: '$lastSeenAt' } } }]);
  const by = new Map(counts.map((c) => [String(c._id), c]));
  return tokens.map((t) => ({
    id: t.id, name: t.name, applicationId: String(t.applicationId), environmentId: String(t.environmentId), prefix: t.prefix, status: t.status,
    createdAt: (t as unknown as { createdAt: Date }).createdAt, createdBy: String(t.createdBy), servers: by.get(t.id)?.n ?? 0, lastSeenAt: by.get(t.id)?.last ?? null, revokedAt: t.revokedAt,
  }));
}

infraRouter.get('/agent-tokens', async (req, res) => {
  const tokens = await AgentToken.find(await live(parse(scopeQuery, req.query))).sort({ status: 1, name: 1 });
  res.json(await tokenViews(tokens));
});

infraRouter.post('/agent-tokens', requireReauth, async (req, res) => {
  const input = parse(z.object({ name: z.string().trim().min(1, 'Give the token a name.').max(120), applicationId: objectId, environmentId: objectId }), req.body);
  const app = await Application.findOne({ _id: input.applicationId, deletedAt: null });
  if (!app?.environments.some((e) => e.id === input.environmentId)) throw new ApiError(422, 'INVALID_SCOPE', 'Choose an application and environment.');
  const { secret, prefix, hash } = newAgentSecret();
  const t = await AgentToken.create({ ...input, prefix, hash, createdBy: req.user!._id });
  await audit(req, 'agent_token.create', 'agent_token', t.id, `Created agent token ${t.name} (${prefix}…) for ${app.name}`);
  await notifyAll('An agent token was created', `${req.user!.name} created the agent token "${t.name}" for ${app.name}.`);
  res.status(201).json({ token: (await tokenViews([t]))[0], secret });
});

const findToken = async (id: unknown) => {
  const t = await AgentToken.findById(parse(objectId, id));
  if (!t) throw notFound('Agent token');
  return t;
};

infraRouter.post('/agent-tokens/:id/rotate', requireReauth, async (req, res) => {
  const t = await findToken(req.params.id);
  if (t.status !== 'active') throw new ApiError(409, 'TOKEN_REVOKED', 'This token is revoked. Create a new one instead.');
  const { secret, prefix, hash } = newAgentSecret();
  t.previousHash = t.hash;
  t.previousExpiresAt = new Date(Date.now() + 24 * 3_600_000);
  t.hash = hash;
  t.prefix = prefix;
  await t.save();
  await audit(req, 'agent_token.rotate', 'agent_token', t.id, `Rotated agent token ${t.name}; the old one works for 24 hours`);
  await notifyAll('An agent token was rotated', `${req.user!.name} rotated "${t.name}". Update /etc/shieldops/agent.env on its servers within 24 hours.`);
  res.json({ token: (await tokenViews([t]))[0], secret });
});

infraRouter.post('/agent-tokens/:id/revoke', requireReauth, async (req, res) => {
  const t = await findToken(req.params.id);
  t.status = 'revoked';
  t.revokedAt = new Date();
  t.previousHash = null;
  await t.save();
  await markTokenServersOffline(t._id);
  await audit(req, 'agent_token.revoke', 'agent_token', t.id, `Revoked agent token ${t.name}`);
  await notifyAll('An agent token was revoked', `${req.user!.name} revoked "${t.name}". Its servers stop reporting now.`);
  res.json((await tokenViews([t]))[0]);
});

/* ───────────── database checks ───────────── */

infraRouter.get('/db-checks', async (req, res) => {
  const checks = await DbCheck.find({ ...(await live(parse(scopeQuery, req.query))), deletedAt: null }).sort({ name: 1 });
  res.json(checks.map((c) => c.toJSON()));
});

infraRouter.post('/db-checks', async (req, res) => {
  const input = parse(
    z.object({
      name: z.string().trim().min(1, 'Give the check a name.').max(120),
      engine: z.enum(['postgresql', 'mysql', 'mongodb', 'redis']),
      assetId: objectId,
      host: z.string().trim().min(1).max(253),
      port: z.number().int().min(1, 'Enter a port between 1 and 65535.').max(65535, 'Enter a port between 1 and 65535.'),
      database: z.string().trim().max(120).default(''),
      username: z.string().trim().max(120).default(''),
      password: z.string().max(500),
      intervalSec: z.number().int().min(30).max(3600),
    }),
    req.body,
  );
  const asset = await Asset.findOne({ _id: input.assetId, deletedAt: null });
  if (!asset || asset.type !== 'database') throw new ApiError(422, 'NOT_A_DATABASE', 'Choose a database asset.');
  if (!['verified', 'approved'].includes(asset.authorization!.status)) throw new ApiError(422, 'ASSET_NOT_AUTHORIZED', 'Verify or approve this database before checking it.');
  if (input.engine !== 'redis' && (!input.username || !input.password)) throw new ApiError(422, 'CREDENTIALS_REQUIRED', 'Enter the read-only username and password.');
  if (await DbCheck.exists({ host: input.host.toLowerCase(), port: input.port, engine: input.engine, deletedAt: null })) throw new ApiError(409, 'DUPLICATE_CHECK', 'This database is already being checked.');
  const { password, ...rest } = input;
  const d = await DbCheck.create({ ...rest, host: input.host.toLowerCase(), passwordEnc: encrypt(password), applicationId: asset.applicationId, environmentId: asset.environmentId, nextCheckAt: new Date() });
  await audit(req, 'db_check.create', 'db_check', d.id, `Created ${d.engine} check ${d.name} for ${d.host}:${d.port}`);
  await runDbCheck(d);
  res.status(201).json(d.toJSON());
});

const findCheck = async (id: unknown) => {
  const d = await DbCheck.findOne({ _id: parse(objectId, id), deletedAt: null });
  if (!d) throw notFound('Database check');
  return d;
};

infraRouter.post('/db-checks/:id/run', async (req, res) => {
  const d = await findCheck(req.params.id);
  if (d.paused) throw new ApiError(409, 'PAUSED', 'Resume the check before running it.');
  res.json((await runDbCheck(d)).toJSON());
});

infraRouter.patch('/db-checks/:id/paused', async (req, res) => {
  const d = await findCheck(req.params.id);
  const { paused } = parse(z.object({ paused: z.boolean() }), req.body);
  d.paused = paused;
  if (!paused) d.nextCheckAt = new Date();
  else await autoResolve(`db:${d.id}`);
  await d.save();
  await audit(req, paused ? 'db_check.pause' : 'db_check.resume', 'db_check', d.id, `${paused ? 'Paused' : 'Resumed'} database check ${d.name}`);
  res.json(d.toJSON());
});

/** The stored password is removed with the check, not kept for the 30 days. */
infraRouter.delete('/db-checks/:id', requireReauth, async (req, res) => {
  const d = await findCheck(req.params.id);
  await DbCheck.deleteOne({ _id: d._id });
  await autoResolve(`db:${d.id}`);
  await audit(req, 'db_check.delete', 'db_check', d.id, `Deleted database check ${d.name} and its stored password`);
  res.status(204).end();
});