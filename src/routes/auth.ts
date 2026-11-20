import { Router } from 'express';
import { config } from '../config.js';
import { decrypt, sha256 } from '../lib/crypto.js';
import { ApiError } from '../lib/errors.js';
import { hashPassword, passwordProblem, verifyPassword } from '../lib/password.js';
import { totpStep } from '../lib/totp.js';
import { email, parse, z } from '../lib/validate.js';
import { clearSessionCookie, requireAuth, startSession } from '../middleware/auth.js';
import { codeLimiter, loginLimiter, publicLimiter } from '../middleware/security.js';
import { LoginChallenge } from '../models/LoginChallenge.js';
import { Session } from '../models/Session.js';
import { SetupLock } from '../models/Settings.js';
import { User, type UserDoc } from '../models/User.js';
import { audit } from '../services/audit.js';
import { startChallenge } from '../services/challenges.js';
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
  const user = await User.create({ name: body.name, email: body.email, passwordHash: await hashPassword(body.password) });
  await audit(req, 'setup.complete', 'user', user.id, `Set up ShieldOps; first user ${user.email}`, { id: user._id, name: user.name });
  res.status(201).json(await startChallenge(user));
});

/* ───────────── sign-in ───────────── */

authRouter.post('/auth/login', loginLimiter, async (req, res) => {
  const body = parse(z.object({ email: z.string().trim().toLowerCase().max(254), password: z.string().max(256) }), req.body);
  const user = await User.findOne({ email: body.email });
  const ok = await verifyPassword(user?.passwordHash, body.password);
  if (!user || !ok || user.status !== 'active') {
    await audit(req, 'auth.login_failed', 'session', null, `Failed sign-in for ${body.email.slice(0, 254)}`, null);
    throw new ApiError(401, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
  }
  res.json(await startChallenge(user));
});

authRouter.post('/auth/mfa/verify', codeLimiter, async (req, res) => {
  const body = parse(z.object({ challengeId: z.string().min(10).max(100), code: z.string().max(10) }), req.body);
  const ch = await LoginChallenge.findOne({ idHash: sha256(body.challengeId) });
  if (!ch || ch.expiresAt.getTime() < Date.now()) throw new ApiError(400, 'CHALLENGE_EXPIRED', 'This sign-in attempt expired. Start again.');
  const user = await User.findById(ch.userId);
  if (!user || user.status !== 'active') throw new ApiError(400, 'CHALLENGE_EXPIRED', 'This sign-in attempt expired. Start again.');

  const secret = decrypt((ch.enroll ? ch.pendingSecretEnc : user.totpSecretEnc)!);
  const step = totpStep(secret, body.code.trim());
  if (step === null || (!ch.enroll && step <= user.totpLastStep)) {
    ch.attempts += 1;
    if (ch.attempts >= 5) await ch.deleteOne();
    else await ch.save();
    await audit(req, 'auth.login_failed', 'session', user.id, 'Wrong two-factor code', { id: user._id, name: user.name });
    throw new ApiError(401, 'INVALID_CODE', ch.attempts >= 5 ? 'Too many wrong codes. Start signing in again.' : 'That code is not valid. Check your authenticator app.');
  }

  await ch.deleteOne();
  if (ch.enroll) {
    user.totpSecretEnc = ch.pendingSecretEnc;
    user.mfaEnabled = true;
  }
  user.totpLastStep = step;
  user.lastLoginAt = new Date();
  await user.save();
  const session = await startSession(req, res, user);
  req.user = user;
  await audit(req, ch.enroll ? 'auth.mfa_enrolled' : 'auth.login', 'session', null, ch.enroll ? 'Set up two-factor and signed in' : 'Signed in');
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

/** Password or current two-factor code; opens the critical-action window. */
authRouter.post('/auth/reauth', codeLimiter, requireAuth, async (req, res) => {
  const body = parse(z.object({ password: z.string().max(256).optional(), code: z.string().max(10).optional() }), req.body);
  const user = req.user!;
  let ok = false;
  if (body.password) ok = await verifyPassword(user.passwordHash, body.password);
  else if (body.code && user.totpSecretEnc) {
    const step = totpStep(decrypt(user.totpSecretEnc), body.code.trim());
    if (step !== null && step > user.totpLastStep) {
      user.totpLastStep = step;
      await user.save();
      ok = true;
    }
  }
  if (!ok) {
    await audit(req, 'auth.reauth_failed', 'session', null, 'Failed re-authentication');
    throw new ApiError(401, 'INVALID_REAUTH', 'That password or code is not correct.');
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