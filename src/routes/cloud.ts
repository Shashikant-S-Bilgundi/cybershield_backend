import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../config.js';
import { notFound } from '../lib/errors.js';
import { logger } from '../lib/logger.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth, startSession } from '../middleware/auth.js';
import { Application } from '../models/Application.js';
import { Asset } from '../models/Asset.js';
import { User } from '../models/User.js';
import { audit } from '../services/audit.js';
import { cloudCheckViews, discover } from '../services/cloud.js';
import { createIssue } from '../services/jira.js';
import { finishSso, SsoError, startSso } from '../services/sso.js';
import { ApiError } from '../lib/errors.js';

export const cloudRouter = Router();

/* ───────────── single sign-on ───────────── */

const ssoLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false });
const STATE_COOKIE = 'so_sso_state';

cloudRouter.post('/auth/sso/:provider/start', ssoLimiter, async (req, res) => {
  const provider = parse(z.enum(['google', 'entra']), req.params.provider);
  try {
    const { state, redirectUrl } = await startSso(provider);
    // Lax so the cookie comes back on the provider's redirect (a top-level GET), but not on cross-site POSTs.
    res.cookie(STATE_COOKIE, state, { httpOnly: true, sameSite: 'lax', secure: config.COOKIE_SECURE, path: '/api/v1/auth/sso', maxAge: 10 * 60_000 });
    res.json({ redirectUrl });
  } catch (err) {
    if (err instanceof SsoError) throw new ApiError(409, 'SSO_DISABLED', err.message);
    throw err;
  }
});

/** The identity provider sends the browser here. Success signs in; anything else goes back to the sign-in page with a reason. */
cloudRouter.get('/auth/sso/callback', ssoLimiter, async (req, res) => {
  const back = (reason: string) => res.redirect(`${config.appUrl}/login?sso=${reason}`);
  const q = parse(z.object({ code: z.string().max(4000).optional(), state: z.string().max(200).optional(), error: z.string().max(200).optional() }), req.query);
  const cookieState = req.cookies?.[STATE_COOKIE] as string | undefined;
  res.clearCookie(STATE_COOKIE, { path: '/api/v1/auth/sso' });
  if (q.error || !q.code) return back('cancelled');
  try {
    const email = await finishSso(q.code, q.state ?? '', cookieState);
    // Single sign-on never creates accounts: only people already invited to ShieldOps get in.
    const user = await User.findOne({ email, status: 'active' });
    if (!user) {
      await audit(req, 'auth.sso_refused', 'session', null, `SSO refused for ${email}: not a ShieldOps member`, null);
      return back('not_member');
    }
    user.lastLoginAt = new Date();
    await user.save();
    await startSession(req, res, user, 'sso');
    req.user = user;
    await audit(req, 'auth.login', 'session', null, 'Signed in with single sign-on');
    res.redirect(`${config.appUrl}/`);
  } catch (err) {
    if (err instanceof SsoError) {
      logger.warn({ reason: err.reason, msg: err.message }, 'SSO sign-in refused');
      return back(err.reason);
    }
    throw err;
  }
});

/* ───────────── asset import, cloud checks, Jira ───────────── */

cloudRouter.use(['/asset-import', '/cloud-checks', '/integrations/jira/issues'], requireAuth);

cloudRouter.get('/asset-import/:source', async (req, res) => {
  const source = parse(z.enum(['cloudflare', 'aws']), req.params.source);
  const found = await discover(source);
  const existing = new Set((await Asset.find({ deletedAt: null, identifierKey: { $in: found.map((f) => f.identifier.toLowerCase()) } }, { identifierKey: 1 }).lean()).map((a) => a.identifierKey));
  res.json(found.map((f) => ({ ...f, alreadyAdded: existing.has(f.identifier.toLowerCase()) })));
});

cloudRouter.post('/asset-import/:source', async (req, res) => {
  const source = parse(z.enum(['cloudflare', 'aws']), req.params.source);
  const input = parse(z.object({ externalIds: z.array(z.string().max(300)).min(1, 'Choose at least one asset.').max(500), applicationId: objectId, environmentId: objectId }), req.body);
  const app = await Application.findOne({ _id: input.applicationId, deletedAt: null });
  if (!app?.environments.some((e) => e.id === input.environmentId)) throw notFound('Application');
  // Rediscover rather than trust the browser: only assets really in the connected account are imported.
  const found = new Map((await discover(source)).map((f) => [f.externalId, f]));
  let imported = 0;
  for (const id of input.externalIds) {
    const f = found.get(id);
    if (!f || (await Asset.exists({ identifierKey: f.identifier.toLowerCase(), deletedAt: null }))) continue;
    await Asset.create({
      type: f.type, identifier: f.identifier, identifierKey: f.identifier.toLowerCase(), label: f.label.slice(0, 120), applicationId: app._id, environmentId: input.environmentId, exposure: f.exposure,
      authorization: { status: 'approved', method: 'approval', justification: `Imported from the connected ${source === 'aws' ? 'AWS' : 'Cloudflare'} account (${f.details}).`, approvedBy: req.user!._id, at: new Date() },
    });
    imported++;
  }
  await audit(req, 'asset.import', 'asset', null, `Imported ${imported} asset(s) from ${source === 'aws' ? 'AWS' : 'Cloudflare'} into ${app.name}`);
  res.json({ imported });
});

cloudRouter.get('/cloud-checks', async (_req, res) => {
  res.json(await cloudCheckViews());
});

cloudRouter.post('/integrations/jira/issues', async (req, res) => {
  const target = parse(z.object({ type: z.enum(['incident', 'task']), id: objectId }), req.body);
  const ref = await createIssue(target, req.user!.name);
  await audit(req, 'jira.create', target.type, target.id, `Created Jira issue ${ref.key}`);
  res.status(201).json(ref);
});