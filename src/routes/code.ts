import { createHmac, timingSafeEqual } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import type { Types } from 'mongoose';
import { config } from '../config.js';
import { encrypt, randomHex, randomToken, sha256 } from '../lib/crypto.js';
import { resolveSafe } from '../lib/net.js';
import { getAllowlist } from '../services/settings.js';
import { encryptCreds, runCloudChecks, verifyCloud } from '../services/cloud.js';
import { verifyJira } from '../services/jira.js';
import { inBackground } from '../services/background.js';
import { ApiError, notFound } from '../lib/errors.js';
import { forgetInstallation, gh, githubConfigured, installationRepos } from '../lib/github.js';
import { logger } from '../lib/logger.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { Application } from '../models/Application.js';
import { Asset } from '../models/Asset.js';
import { ContainerImage, GithubInstallState, Integration, Repository, ScanJob, type ImageDoc, type IntegrationDoc, type RepositoryDoc } from '../models/Code.js';
import { Finding } from '../models/Finding.js';
import { audit } from '../services/audit.js';
import { notifyAll } from '../services/notify.js';
import { queueScan } from '../services/scans.js';
import { compareVersions } from '../services/scanners.js';
import { getSettingsDoc } from '../services/settings.js';

export const codeRouter = Router();
codeRouter.use(['/integrations', '/repositories', '/images', '/scans', '/dependencies'], requireAuth);

/* ───────────── integrations ───────────── */

const TYPES = ['github', 'ghcr', 'dockerhub', 'smtp', 'slack', 'webhook', 'jira', 'cloudflare', 'aws', 'google', 'entra'] as const;
type IType = (typeof TYPES)[number];
const LATER: Partial<Record<IType, number>> = {};
const NAME: Record<string, string> = { github: 'GitHub', ghcr: 'GitHub Container Registry', dockerhub: 'Docker Hub', slack: 'Slack', webhook: 'the alert webhook', jira: 'Jira', cloudflare: 'Cloudflare', aws: 'AWS', google: 'Google Workspace', entra: 'Microsoft Entra' };

async function integrationView(type: IType, doc: IntegrationDoc | null) {
  if (type === 'smtp') {
    const s = (await getSettingsDoc()).smtp!;
    return { type, status: s.host ? 'connected' : 'not_connected', availableInPhase: null, account: s.host ? `${s.host}:${s.port}` : null, scopes: [], connectedAt: null, connectedBy: null, lastSyncAt: null, error: null };
  }
  return {
    type, status: doc?.status ?? 'not_connected', availableInPhase: LATER[type] ?? null, account: doc?.account ?? null, scopes: doc?.scopes ?? [],
    connectedAt: doc?.connectedAt ?? null, connectedBy: doc?.connectedBy ? String(doc.connectedBy) : null, lastSyncAt: doc?.lastSyncAt ?? null, error: doc?.error ?? null,
  };
}

codeRouter.get('/integrations', async (_req, res) => {
  const docs = new Map((await Integration.find()).map((d) => [d.type, d]));
  res.json(await Promise.all(TYPES.map((t) => integrationView(t, docs.get(t) ?? null))));
});

const typeParam = (req: Request) => parse(z.enum(TYPES), req.params.type);

codeRouter.post('/integrations/:type/connect', requireReauth, async (req, res) => {
  const type = typeParam(req);
  if (type === 'smtp') throw new ApiError(400, 'NOT_SUPPORTED', 'Set up email delivery in System settings.');
  if (LATER[type]) throw new ApiError(409, 'NOT_AVAILABLE_YET', `This integration arrives in backend phase ${LATER[type]}.`);

  if (type === 'github') {
    if (!githubConfigured()) throw new ApiError(409, 'GITHUB_APP_NOT_SET_UP', 'The GitHub App is not set up on this server yet. Create it and set GITHUB_APP_ID, GITHUB_APP_SLUG and GITHUB_APP_PRIVATE_KEY (see the README).');
    const state = randomToken(24);
    await GithubInstallState.create({ stateHash: sha256(state), userId: req.user!._id, expiresAt: new Date(Date.now() + 15 * 60_000) });
    return void res.json({ ...(await integrationView('github', await Integration.findOne({ type: 'github' }))), redirectUrl: `${config.GITHUB_WEB_URL.replace(/\/$/, '')}/apps/${config.GITHUB_APP_SLUG}/installations/new?state=${state}` });
  }
  if (type === 'ghcr') {
    if ((await Integration.findOne({ type: 'github' }))?.status !== 'connected') throw new ApiError(409, 'GITHUB_REQUIRED', 'GitHub Container Registry uses the GitHub App. Connect GitHub first.');
    return void res.json(await integrationView('ghcr', await Integration.findOne({ type: 'ghcr' })));
  }
  if (type === 'jira' || type === 'cloudflare' || type === 'aws' || type === 'google' || type === 'entra') {
    const c = parse(z.record(z.string().max(40), z.string().trim().max(8000)), req.body ?? {});
    // Each check is read-only; nothing is stored unless the provider accepts the credentials.
    const v = type === 'jira' ? await verifyJira(c as never) : await verifyCloud(type, c);
    const doc = await Integration.findOneAndUpdate({ type }, { status: 'connected', account: v.account, scopes: v.scopes, credentialsEnc: encryptCreds(c), connectedAt: new Date(), connectedBy: req.user!._id, lastSyncAt: null, error: null }, { upsert: true, new: true });
    await audit(req, 'integration.connect', 'integration', type, `Connected ${NAME[type]} (${v.account}; credentials stored encrypted)`);
    await notifyAll(`${NAME[type]} was connected`, `${req.user!.name} connected ${NAME[type]} (${v.account}).`);
    if (type !== 'jira') inBackground(runCloudChecks(type), `${type} checks`);
    return void res.json(await integrationView(type, doc));
  }
  if (type === 'slack' || type === 'webhook') {
    const input = parse(z.object({ url: z.string().trim().max(500), channel: z.string().trim().max(80).optional() }), req.body);
    if (type === 'slack' && !/^https:\/\/hooks\.slack\.com\/services\/\S+$/.test(input.url)) throw new ApiError(422, 'INVALID_URL', 'Paste the incoming webhook URL from Slack. It starts with https://hooks.slack.com/services/.');
    if (type === 'webhook') {
      if (!/^https:\/\/\S+$/.test(input.url) || !URL.canParse(input.url)) throw new ApiError(422, 'INVALID_URL', 'Enter an https:// URL. Plain http is not allowed for alerts.');
      // Alerts must not be aimed at internal services outside the allowlist.
      await resolveSafe(new URL(input.url).hostname, await getAllowlist());
    }
    const secret = type === 'webhook' ? `whsec_${randomHex(48)}` : undefined;
    const account = type === 'slack' ? `#${(input.channel || 'alerts').replace(/^#/, '')}` : new URL(input.url).host;
    const doc = await Integration.findOneAndUpdate(
      { type },
      { status: 'connected', account, scopes: type === 'slack' ? ['Incoming webhook: post messages'] : ['POST JSON, signed with HMAC-SHA256'], credentialsEnc: encrypt(JSON.stringify({ url: input.url, secret })), connectedAt: new Date(), connectedBy: req.user!._id, error: null },
      { upsert: true, new: true },
    );
    await audit(req, 'integration.connect', 'integration', type, `Connected ${NAME[type]} (${account}; URL${secret ? ' and signing secret' : ''} stored encrypted)`);
    await notifyAll(`${type === 'slack' ? 'Slack' : 'An alert webhook'} was connected`, `${req.user!.name} connected ${type === 'slack' ? `Slack ${account}` : `the webhook ${account}`} for alerts.`);
    // The signing secret is shown once, here.
    return void res.json({ ...(await integrationView(type, doc)), ...(secret ? { secret } : {}) });
  }
  // Docker Hub: a read-only access token, checked against Docker's token service before it is stored.
  const { username, token } = parse(z.object({ username: z.string().trim().min(1, 'Enter your Docker Hub username and a read-only access token.').max(100), token: z.string().trim().min(1, 'Enter your Docker Hub username and a read-only access token.').max(500) }), req.body);
  const authUrl = process.env.DOCKERHUB_AUTH_URL ?? 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull';
  const check = await fetch(authUrl, { headers: { authorization: `Basic ${Buffer.from(`${username}:${token}`).toString('base64')}` }, signal: AbortSignal.timeout(10_000) }).catch(() => null);
  if (!check) throw new ApiError(422, 'DOCKERHUB_UNREACHABLE', 'Could not reach Docker Hub to check the token. Try again in a moment.');
  if (check.status === 401) throw new ApiError(422, 'INVALID_CREDENTIALS', 'Docker Hub rejected that username and token.');
  const doc = await Integration.findOneAndUpdate(
    { type: 'dockerhub' },
    { status: 'connected', account: username, scopes: ['Public repo read-only'], credentialsEnc: encrypt(JSON.stringify({ username, token })), connectedAt: new Date(), connectedBy: req.user!._id, error: null },
    { upsert: true, new: true },
  );
  await audit(req, 'integration.connect', 'integration', 'dockerhub', `Connected Docker Hub as ${username} (token stored encrypted)`);
  await notifyAll('Docker Hub was connected', `${req.user!.name} connected Docker Hub as ${username}.`);
  res.json(await integrationView('dockerhub', doc));
});

/** GitHub sends the browser here after the app is installed (set this as the app's Setup URL). */
codeRouter.get('/integrations/github/callback', async (req, res) => {
  const back = (q: string) => res.redirect(`${config.appUrl}/integrations?github=${q}`);
  const q = parse(z.object({ installation_id: z.coerce.number().int().positive().optional(), state: z.string().max(100).optional(), setup_action: z.string().max(40).optional() }), req.query);
  const state = q.state ? await GithubInstallState.findOneAndDelete({ stateHash: sha256(q.state) }) : null;
  // The state proves this installation was started from ShieldOps by this person, not by someone else's link.
  if (!state || String(state.userId) !== req.user!.id || state.expiresAt.getTime() < Date.now()) return back('expired');
  if (!q.installation_id) return back(q.setup_action === 'request' ? 'requested' : 'cancelled');
  try {
    const inst = await gh<{ id: number; account: { login: string }; permissions: Record<string, string> }>(`/app/installations/${q.installation_id}`, { jwt: true });
    const scopes = Object.entries(inst.permissions).map(([k, v]) => `${k[0].toUpperCase()}${k.slice(1).replace(/_/g, ' ')}: ${v}`);
    const base = { status: 'connected', account: inst.account.login, connectedAt: new Date(), connectedBy: req.user!._id, lastSyncAt: new Date(), error: null };
    await Integration.updateOne({ type: 'github' }, { ...base, scopes, installationId: inst.id }, { upsert: true });
    await Integration.updateOne({ type: 'ghcr' }, { ...base, scopes: ['Packages: read (through the GitHub App)'] }, { upsert: true });
    await audit(req, 'integration.connect', 'integration', 'github', `Connected GitHub (installation ${inst.id} on ${inst.account.login})`);
    await notifyAll('GitHub was connected', `${req.user!.name} installed the ShieldOps GitHub App on ${inst.account.login}.`);
    back('connected');
  } catch (err) {
    logger.warn({ err: (err as Error).message }, 'GitHub installation check failed');
    back('error');
  }
});

codeRouter.post('/integrations/:type/disconnect', requireReauth, async (req, res) => {
  const type = typeParam(req);
  const doc = await Integration.findOne({ type });
  if (!doc || doc.status !== 'connected') throw new ApiError(409, 'NOT_CONNECTED', 'This integration is not connected.');
  if (type === 'github' && doc.installationId) {
    // Uninstall the app on GitHub too, so no access is left behind.
    await gh(`/app/installations/${doc.installationId}`, { jwt: true, method: 'DELETE' }).catch((e) => logger.warn({ err: (e as Error).message }, 'Could not uninstall the GitHub App; remove it on GitHub'));
    forgetInstallation(doc.installationId);
    await Integration.updateOne({ type: 'ghcr' }, { status: 'not_connected', account: null, scopes: [], connectedAt: null, connectedBy: null });
  }
  doc.set({ status: 'not_connected', account: null, scopes: [], connectedAt: null, connectedBy: null, installationId: null, credentialsEnc: null, error: null });
  await doc.save();
  await audit(req, 'integration.disconnect', 'integration', type, `Disconnected ${NAME[type] ?? type}`);
  await notifyAll(`${NAME[type] ?? type} was disconnected`, `${req.user!.name} disconnected ${NAME[type] ?? type}.`);
  res.json(await integrationView(type, doc));
});

/* ───────────── GitHub webhook: POST /api/v1/webhooks/github (raw body) ───────────── */

export async function githubWebhook(req: Request, res: Response) {
  const raw = req.body as Buffer;
  const sig = req.get('x-hub-signature-256') ?? '';
  if (!config.GITHUB_WEBHOOK_SECRET) return void res.status(503).json({ error: { code: 'NOT_CONFIGURED', message: 'GITHUB_WEBHOOK_SECRET is not set.' } });
  const expected = `sha256=${createHmac('sha256', config.GITHUB_WEBHOOK_SECRET).update(raw).digest('hex')}`;
  if (sig.length !== expected.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return void res.status(401).json({ error: { code: 'BAD_SIGNATURE', message: 'Signature does not match.' } });
  const event = req.get('x-github-event');
  const body = JSON.parse(raw.toString('utf8')) as { ref?: string; repository?: { id: number; default_branch: string }; action?: string; installation?: { id: number } };
  if (event === 'push' && body.repository) {
    const repo = await Repository.findOne({ githubId: body.repository.id });
    if (repo?.scanOnPush && body.ref === `refs/heads/${repo.defaultBranch}`) await queueScan('repository', repo._id, 'push').catch(() => {});
  } else if (event === 'installation' && body.action === 'deleted' && body.installation) {
    // Someone uninstalled the app on GitHub: reflect it, so scans fail clearly instead of mysteriously.
    await Integration.updateMany({ type: { $in: ['github', 'ghcr'] }, $or: [{ installationId: body.installation.id }, { type: 'ghcr' }] }, { status: 'not_connected', error: 'The GitHub App was uninstalled on GitHub.', installationId: null });
    forgetInstallation(body.installation.id);
  }
  res.status(202).json({ ok: true });
}

/* ───────────── repositories ───────────── */

const scopeQuery = z.object({ applicationId: objectId.optional(), environmentId: objectId.optional() });
async function live(f: { applicationId?: string; environmentId?: string }) {
  const ids = (await Application.find({ deletedAt: null, ...(f.applicationId ? { _id: f.applicationId } : {}) }, { _id: 1 }).lean()).map((a) => a._id);
  return { applicationId: { $in: ids }, ...(f.environmentId ? { environmentId: f.environmentId } : {}) };
}

async function lastScans(ids: Types.ObjectId[]) {
  const rows = await ScanJob.aggregate<{ _id: Types.ObjectId; doc: Record<string, unknown> }>([{ $match: { targetId: { $in: ids } } }, { $sort: { queuedAt: -1 } }, { $group: { _id: '$targetId', doc: { $first: '$$ROOT' } } }]);
  return new Map(rows.map((r) => [String(r._id), ScanJob.hydrate(r.doc).toJSON()]));
}

async function repoViews(repos: RepositoryDoc[]) {
  const scans = await lastScans(repos.map((r) => r._id));
  return repos.map((r) => ({
    id: r.id, assetId: String(r.assetId), fullName: r.fullName, applicationId: String(r.applicationId), environmentId: String(r.environmentId), private: r.private, defaultBranch: r.defaultBranch,
    language: r.language, scanOnPush: r.scanOnPush, dailyScan: r.dailyScan, dependencies: r.dependencies, openSecrets: r.openSecrets, vulns: r.vulns, lastScan: scans.get(r.id) ?? null, addedAt: r.addedAt,
  }));
}

const githubInstallation = async () => {
  const g = await Integration.findOne({ type: 'github', status: 'connected' });
  if (!g?.installationId) throw new ApiError(409, 'GITHUB_NOT_CONNECTED', 'Connect GitHub first.');
  return g.installationId;
};

codeRouter.get('/repositories', async (req, res) => {
  const repos = await Repository.find(await live(parse(scopeQuery, req.query))).sort({ fullName: 1 });
  res.json(await repoViews(repos));
});

codeRouter.get('/repositories/available', async (_req, res) => {
  const all = await installationRepos(await githubInstallation());
  const added = new Set((await Repository.find({}, { githubId: 1 }).lean()).map((r) => r.githubId));
  res.json(all.filter((r) => !added.has(r.id)).map((r) => ({ fullName: r.full_name, private: r.private, defaultBranch: r.default_branch, language: r.language ?? '' })));
});

const findRepo = async (id: unknown) => {
  const r = await Repository.findById(parse(objectId, id));
  if (!r) throw notFound('Repository');
  return r;
};

codeRouter.get('/repositories/:id', async (req, res) => {
  res.json((await repoViews([await findRepo(req.params.id)]))[0]);
});

codeRouter.post('/repositories', async (req, res) => {
  const input = parse(z.object({ fullNames: z.array(z.string().regex(/^[\w.-]+\/[\w.-]+$/)).min(1, 'Choose at least one repository.').max(100), applicationId: objectId, environmentId: objectId }), req.body);
  const installationId = await githubInstallation();
  const app = await Application.findOne({ _id: input.applicationId, deletedAt: null });
  if (!app?.environments.some((e) => e.id === input.environmentId)) throw new ApiError(422, 'INVALID_SCOPE', 'Choose an application and environment.');
  const visible = new Map((await installationRepos(installationId)).map((r) => [r.full_name.toLowerCase(), r]));
  const gh = await Integration.findOne({ type: 'github' });
  const created: RepositoryDoc[] = [];
  for (const name of input.fullNames) {
    const meta = visible.get(name.toLowerCase());
    if (!meta) throw new ApiError(404, 'NOT_FOUND', `${name} is not visible to the GitHub App. Add it to the app's repository access on GitHub.`);
    if (await Repository.exists({ githubId: meta.id })) throw new ApiError(409, 'ALREADY_ADDED', `${meta.full_name} is already added.`);
    // Access through our own GitHub App installation proves ownership, so the asset is approved at once.
    const asset = await Asset.create({
      type: 'repository', identifier: meta.full_name, identifierKey: meta.full_name.toLowerCase(), label: meta.full_name, applicationId: app._id, environmentId: input.environmentId, exposure: meta.private ? 'internal' : 'internet',
      authorization: { status: 'approved', method: 'approval', justification: `Visible through the ShieldOps GitHub App installed on ${gh?.account}.`, approvedBy: req.user!._id, at: new Date() },
    });
    const repo = await Repository.create({ githubId: meta.id, assetId: asset._id, fullName: meta.full_name, applicationId: app._id, environmentId: input.environmentId, private: meta.private, defaultBranch: meta.default_branch, language: meta.language ?? '' });
    await queueScan('repository', repo._id, 'initial');
    created.push(repo);
  }
  await audit(req, 'repository.add', 'repository', null, `Added ${created.map((r) => r.fullName).join(', ')} to ${app.name}`);
  res.status(201).json(await repoViews(created));
});

codeRouter.patch('/repositories/:id', async (req, res) => {
  const repo = await findRepo(req.params.id);
  const input = parse(z.object({ scanOnPush: z.boolean().optional(), dailyScan: z.boolean().optional() }), req.body);
  repo.set(input);
  await repo.save();
  await audit(req, 'repository.update', 'repository', repo.id, `Scan settings for ${repo.fullName}: on push ${repo.scanOnPush ? 'on' : 'off'}, daily ${repo.dailyScan ? 'on' : 'off'}`);
  res.json((await repoViews([repo]))[0]);
});

/** Removing a target closes its open findings: nobody is scanning for them any more. */
async function closeTargetFindings(assetId: Types.ObjectId, why: string) {
  await Finding.updateMany({ assetId, status: { $nin: ['resolved', 'verified', 'accepted_risk', 'false_positive'] } }, { status: 'resolved', $push: { history: { $each: [{ at: new Date(), actorName: 'ShieldOps', text: why }], $position: 0 } } });
  await Asset.updateOne({ _id: assetId }, { deletedAt: new Date() });
}

codeRouter.delete('/repositories/:id', requireReauth, async (req, res) => {
  const repo = await findRepo(req.params.id);
  await ScanJob.updateMany({ targetId: repo._id, status: 'queued' }, { status: 'cancelled', finishedAt: new Date() });
  await closeTargetFindings(repo.assetId, 'Closed: the repository was removed from ShieldOps');
  await repo.deleteOne();
  await audit(req, 'repository.remove', 'repository', repo.id, `Removed ${repo.fullName}`);
  await notifyAll('A repository was removed', `${req.user!.name} removed ${repo.fullName}; its findings were closed.`);
  res.status(204).end();
});

/* ───────────── images ───────────── */

async function imageViews(imgs: ImageDoc[]) {
  const scans = await lastScans(imgs.map((i) => i._id));
  return imgs.map((i) => ({
    id: i.id, assetId: String(i.assetId), applicationId: String(i.applicationId), environmentId: String(i.environmentId), registry: i.registry, repository: i.repository, tag: i.tag,
    digest: i.digest, os: i.os, sizeMb: i.sizeMb, dailyScan: i.dailyScan, vulns: i.vulns, lastScan: scans.get(i.id) ?? null, addedAt: i.addedAt,
  }));
}

codeRouter.get('/images', async (req, res) => {
  const imgs = await ContainerImage.find(await live(parse(scopeQuery, req.query))).sort({ repository: 1, tag: 1 });
  res.json(await imageViews(imgs));
});

codeRouter.post('/images', async (req, res) => {
  const input = parse(z.object({ registry: z.enum(['ghcr.io', 'docker.io']), repository: z.string().trim().toLowerCase(), tag: z.string().trim(), applicationId: objectId, environmentId: objectId }), req.body);
  const reg = await Integration.findOne({ type: input.registry === 'ghcr.io' ? 'ghcr' : 'dockerhub' });
  if (reg?.status !== 'connected') throw new ApiError(409, 'REGISTRY_NOT_CONNECTED', `Connect ${input.registry === 'ghcr.io' ? 'GitHub Container Registry' : 'Docker Hub'} in Integrations first.`);
  if (!/^[a-z0-9._/-]+$/.test(input.repository) || !/^[\w.-]+$/.test(input.tag)) throw new ApiError(422, 'INVALID_IMAGE', 'Enter an image like your-org/app and a tag like 1.4.2.');
  if (await ContainerImage.exists({ registry: input.registry, repository: input.repository, tag: input.tag })) throw new ApiError(409, 'ALREADY_ADDED', 'This image is already added.');
  const app = await Application.findOne({ _id: input.applicationId, deletedAt: null });
  if (!app?.environments.some((e) => e.id === input.environmentId)) throw new ApiError(422, 'INVALID_SCOPE', 'Choose an application and environment.');
  const identifier = `${input.registry}/${input.repository}:${input.tag}`;
  const asset = await Asset.create({
    type: 'image', identifier, identifierKey: identifier, label: identifier, applicationId: app._id, environmentId: input.environmentId, exposure: 'internal',
    authorization: { status: 'approved', method: 'approval', justification: `Pulled with the connected ${input.registry === 'ghcr.io' ? 'GitHub App' : `Docker Hub account ${reg.account}`}.`, approvedBy: req.user!._id, at: new Date() },
  });
  const img = await ContainerImage.create({ ...input, assetId: asset._id, applicationId: app._id });
  await queueScan('image', img._id, 'initial');
  await audit(req, 'image.add', 'image', img.id, `Added image ${identifier} to ${app.name}`);
  res.status(201).json((await imageViews([img]))[0]);
});

codeRouter.delete('/images/:id', requireReauth, async (req, res) => {
  const img = await ContainerImage.findById(parse(objectId, req.params.id));
  if (!img) throw notFound('Image');
  await ScanJob.updateMany({ targetId: img._id, status: 'queued' }, { status: 'cancelled', finishedAt: new Date() });
  await closeTargetFindings(img.assetId, 'Closed: the image was removed from ShieldOps');
  await img.deleteOne();
  await audit(req, 'image.remove', 'image', img.id, `Removed image ${img.registry}/${img.repository}:${img.tag}`);
  res.status(204).end();
});

/* ───────────── scans ───────────── */

codeRouter.get('/scans', async (req, res) => {
  const q = parse(z.object({ targetType: z.enum(['repository', 'image']), targetId: objectId }), req.query);
  const scans = await ScanJob.find(q).sort({ queuedAt: -1 }).limit(30);
  res.json(scans.map((s) => s.toJSON()));
});

codeRouter.post('/scans', async (req, res) => {
  const { targetType, targetId } = parse(z.object({ targetType: z.enum(['repository', 'image']), targetId: objectId }), req.body);
  const exists = targetType === 'repository' ? await Repository.exists({ _id: targetId }) : await ContainerImage.exists({ _id: targetId });
  if (!exists) throw notFound(targetType === 'repository' ? 'Repository' : 'Image');
  if (targetType === 'repository') await githubInstallation().catch(() => {
    throw new ApiError(409, 'GITHUB_NOT_CONNECTED', 'GitHub is disconnected, so repositories cannot be cloned. Reconnect it in Integrations.');
  });
  const job = await queueScan(targetType, targetId, 'manual');
  await audit(req, 'scan.start', 'scan', job.id, `Started a ${targetType} scan`);
  res.status(201).json(job.toJSON());
});

/* ───────────── dependencies: one row per vulnerable package ───────────── */

const SEV = ['critical', 'high', 'medium', 'low', 'info'];

codeRouter.get('/dependencies', async (req, res) => {
  const scope = await live(parse(scopeQuery, req.query));
  const rows = await Finding.find({ ...scope, key: { $regex: "^vuln:" }, status: { $nin: ['resolved', 'verified', 'accepted_risk', 'false_positive'] } }, { code: 1, severity: 1, knownExploited: 1, applicationId: 1 }).lean();
  const by = new Map<string, { package: string; ecosystem: string; installed: Set<string>; fixes: string[]; vulns: Set<string>; worst: string; knownExploited: boolean; noFix: boolean; targets: Map<string, { type: string; name: string; applicationId: string }> }>();
  for (const f of rows) {
    const c = f.code as { package: string; ecosystem: string; installed: string; fixedIn: string | null; vulnId: string; targetType: string; targetName: string } | undefined;
    if (!c) continue;
    const k = `${c.ecosystem}:${c.package}`;
    const e = by.get(k) ?? { package: c.package, ecosystem: c.ecosystem, installed: new Set<string>(), fixes: [] as string[], vulns: new Set<string>(), worst: 'info', knownExploited: false, noFix: false, targets: new Map() };
    e.installed.add(c.installed);
    if (c.fixedIn) e.fixes.push(c.fixedIn);
    else e.noFix = true;
    e.vulns.add(c.vulnId);
    if (SEV.indexOf(f.severity) < SEV.indexOf(e.worst)) e.worst = f.severity;
    e.knownExploited ||= !!f.knownExploited;
    e.targets.set(`${c.targetType}:${c.targetName}`, { type: c.targetType, name: c.targetName, applicationId: String(f.applicationId) });
    by.set(k, e);
  }
  res.json(
    [...by.values()]
      .map((e) => ({
        package: e.package, ecosystem: e.ecosystem, installed: [...e.installed].sort(compareVersions),
        // The lowest version that fixes every known vulnerability is the highest "fixed in"; none if any has no fix yet.
        upgradeTo: e.noFix ? null : e.fixes.sort(compareVersions).at(-1) ?? null,
        vulns: e.vulns.size, worst: e.worst, knownExploited: e.knownExploited, targets: [...e.targets.values()],
      }))
      .sort((a, b) => Number(b.knownExploited) - Number(a.knownExploited) || SEV.indexOf(a.worst) - SEV.indexOf(b.worst) || b.vulns - a.vulns),
  );
});