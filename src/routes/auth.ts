import { Router } from 'express';
import { config } from '../config.js';
import { ApiError } from '../lib/errors.js';
import { hashPassword, passwordProblem, verifyPassword } from '../lib/password.js';
import { email, parse, z } from '../lib/validate.js';
import { clearSessionCookie, requireAuth, startSession } from '../middleware/auth.js';
import { reauthLimiter, loginLimiter, publicLimiter } from '../middleware/security.js';
import { Session } from '../models/Session.js';
import { SetupLock } from '../models/Settings.js';
import { User, type UserDoc } from '../models/User.js';
import { audit } from '../services/audit.js';
import { getSettingsDoc } from '../services/settings.js';

export const authRouter = Router();

const sessionBody = (user: UserDoc, reauthUntil: Date | null | undefined) => ({ user: user.toJSON(), reauthUntil: reauthUntil?.toISOString() ?? null });

/* ───────────── first-time setup ───────────── */

authRouter.get('/setup/status', publicLimiter, async (_req, res) => {
  res.json({ needsSetup: (await User.estimatedDocumentCount()) === 0 });
});

authRouter.post('/setup', publicLimiter, async (req, res) => {
  const body = parse(z.object({ name: z.string().trim().min(1).max(120), email, password: z.string() }), req.body);
  const problem = passwordProblem(body.password);
  if (problem) throw new ApiError(422, 'WEAK_PASSWORD', problem);
  if ((await User.estimatedDocumentCount()) > 0) throw new ApiError(409, 'ALREADY_SET_UP', 'ShieldOps is already set up.');
  // The lock makes setup succeed exactly once, even if two requests arrive together.
  await SetupLock.create({ _id: 'setup' }).catch(() => {
    throw new ApiError(409, 'ALREADY_SET_UP', 'ShieldOps is already set up.');
  });
  const user = await User.create({ name: body.name, email: body.email, passwordHash: await hashPassword(body.password), lastLoginAt: new Date() });
  await audit(req, 'setup.complete', 'user', user.id, `Set up ShieldOps; first user ${user.email}`, { id: user._id, name: user.name });
  const session = await startSession(req, res, user);
  res.status(201).json(sessionBody(user, session.reauthUntil));
});

/* ───────────── sign-in ───────────── */

authRouter.post('/auth/login', loginLimiter, async (req, res) => {
  const sso = (await getSettingsDoc()).sso!;
  // With single sign-on on and the password route switched off, only SSO signs people in.
  if (sso.enabled && !sso.allowPasswordFallback) throw new ApiError(403, 'SSO_REQUIRED', `Sign in with ${sso.provider === 'google' ? 'Google' : 'Microsoft'} instead.`);
  const body = parse(z.object({ email: z.string().trim().toLowerCase().max(254), password: z.string().max(256) }), req.body);
  const user = await User.findOne({ email: body.email });
  const ok = await verifyPassword(user?.passwordHash, body.password);
  if (!user || !ok || user.status !== 'active') {
    await audit(req, 'auth.login_failed', 'session', null, `Failed sign-in for ${body.email.slice(0, 254)}`, null);
    throw new ApiError(401, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
  }
  user.lastLoginAt = new Date();
  await user.save();
  const session = await startSession(req, res, user);
  req.user = user;
  await audit(req, 'auth.login', 'session', null, 'Signed in');
  res.json(sessionBody(user, session.reauthUntil));
});

authRouter.get('/auth/me', requireAuth, async (req, res) => {
  res.json(sessionBody(req.user!, req.authSession!.reauthUntil));
});

authRouter.post('/auth/logout', requireAuth, async (req, res) => {
  req.authSession!.revokedAt = new Date();
  await req.authSession!.save();
  clearSessionCookie(res);
  await audit(req, 'auth.logout', 'session', null, 'Signed out');
  res.status(204).end();
});

/** The password again; opens the critical-action window. */
authRouter.post('/auth/reauth', reauthLimiter, requireAuth, async (req, res) => {
  const body = parse(z.object({ password: z.string().min(1).max(256) }), req.body);
  if (!(await verifyPassword(req.user!.passwordHash, body.password))) {
    await audit(req, 'auth.reauth_failed', 'session', null, 'Failed re-authentication');
    throw new ApiError(401, 'INVALID_REAUTH', 'That password is not correct.');
  }
  const session = req.authSession!;
  session.reauthUntil = new Date(Date.now() + config.reauthMs);
  await session.save();
  await audit(req, 'auth.reauth', 'session', null, 'Re-authenticated for a critical action');
  res.json({ reauthUntil: session.reauthUntil.toISOString() });
});

/** Public: whether the sign-in page should offer single sign-on (phase 8). */
authRouter.get('/auth/sso/config', publicLimiter, async (_req, res) => {
  const s = (await getSettingsDoc()).sso!;
  res.json({ enabled: s.enabled, provider: s.provider, allowPasswordFallback: s.allowPasswordFallback });
});

/** Revokes every session for a user, e.g. when they are disabled. */
export const revokeSessions = (userId: unknown) => Session.updateMany({ userId, revokedAt: null }, { revokedAt: new Date() });