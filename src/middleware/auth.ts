import type { NextFunction, Request, Response } from 'express';
import { config } from '../config.js';
import { randomToken, sha256 } from '../lib/crypto.js';
import { ApiError } from '../lib/errors.js';
import { Session } from '../models/Session.js';
import { User, type UserDoc } from '../models/User.js';

export const COOKIE = 'so_session';

const cookieOptions = () => ({
  httpOnly: true,
  secure: config.COOKIE_SECURE,
  sameSite: 'lax' as const,
  path: '/',
  domain: config.COOKIE_DOMAIN || undefined,
});

/** Starts a session once the password is accepted. A fresh sign-in counts as a re-authentication. */
export async function startSession(req: Request, res: Response, user: UserDoc) {
  const token = randomToken(32);
  const now = Date.now();
  const session = await Session.create({
    tokenHash: sha256(token),
    userId: user._id,
    expiresAt: new Date(now + config.sessionIdleMs),
    absoluteExpiresAt: new Date(now + config.sessionMaxMs),
    reauthUntil: new Date(now + config.reauthMs),
    ip: req.ip,
    userAgent: (req.get('user-agent') ?? '').slice(0, 300),
  });
  res.cookie(COOKIE, token, { ...cookieOptions(), maxAge: config.sessionMaxMs });
  return session;
}

export function clearSessionCookie(res: Response) {
  res.clearCookie(COOKIE, cookieOptions());
}

/** Loads the signed-in user, or answers 401. Extends the idle timeout at most once a minute. */
export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies?.[COOKIE] as string | undefined;
  if (!token) throw new ApiError(401, 'UNAUTHENTICATED', 'Sign in to continue.');
  const session = await Session.findOne({ tokenHash: sha256(token) });
  const now = Date.now();
  if (!session || session.revokedAt || session.expiresAt.getTime() < now || session.absoluteExpiresAt.getTime() < now) {
    clearSessionCookie(res);
    throw new ApiError(401, 'UNAUTHENTICATED', 'Your session has ended. Sign in again.');
  }
  const user = await User.findById(session.userId);
  if (!user || user.status !== 'active') {
    await Session.updateOne({ _id: session._id }, { revokedAt: new Date() });
    clearSessionCookie(res);
    throw new ApiError(401, 'UNAUTHENTICATED', 'Sign in to continue.');
  }
  if (session.expiresAt.getTime() - now < config.sessionIdleMs - 60_000) {
    session.expiresAt = new Date(Math.min(now + config.sessionIdleMs, session.absoluteExpiresAt.getTime()));
    await session.save();
  }
  req.user = user;
  req.authSession = session;
  next();
}

/** Critical actions need a password or code entered in the last few minutes (section 5). */
export function requireReauth(req: Request, _res: Response, next: NextFunction) {
  const until = req.authSession?.reauthUntil?.getTime() ?? 0;
  if (until < Date.now()) throw new ApiError(403, 'REAUTH_REQUIRED', 'Confirm your identity to continue.');
  next();
}