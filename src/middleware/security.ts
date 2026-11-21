import type { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../config.js';
import { ApiError } from '../lib/errors.js';

/**
 * CSRF protection: the session cookie is SameSite=Lax, and every request that changes
 * something must come from the ShieldOps frontend's own origin.
 */
export function checkOrigin(req: Request, _res: Response, next: NextFunction) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  if (origin && !config.allowedOrigins.includes(origin)) throw new ApiError(403, 'BAD_ORIGIN', 'This request did not come from ShieldOps.');
  if (!origin && req.get('sec-fetch-site') === 'cross-site') throw new ApiError(403, 'BAD_ORIGIN', 'This request did not come from ShieldOps.');
  next();
}

const limited = (code: string, message: string) => (_req: Request, _res: Response, next: NextFunction) => next(new ApiError(429, code, message));

/** Sign-in attempts per IP and email: 10 per 15 minutes. */
export const loginLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => `${req.ip}|${String(req.body?.email ?? '').toLowerCase()}`,
  handler: limited('TOO_MANY_ATTEMPTS', 'Too many sign-in attempts. Wait 15 minutes and try again.'),
});

/** Re-authentication attempts per IP: 20 per 15 minutes. */
export const reauthLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: limited('TOO_MANY_ATTEMPTS', 'Too many password attempts. Wait 15 minutes and try again.'),
});

/** Public endpoints such as invite lookups: 60 per 15 minutes per IP. */
export const publicLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 60,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: limited('TOO_MANY_REQUESTS', 'Too many requests. Try again shortly.'),
});