import type { NextFunction, Request, Response } from 'express';
import mongoose from 'mongoose';
import { ZodError } from 'zod';
import { ApiError } from '../lib/errors.js';
import { logger } from '../lib/logger.js';

/** Every error leaves as { error: { code, message, details? } }. Internals never reach the browser. */
export function errorHandler(err: unknown, req: Request, res: Response, next: NextFunction) {
  if (res.headersSent) return next(err);
  if (err instanceof ApiError) return void res.status(err.status).json({ error: { code: err.code, message: err.message, details: err.details } });
  if (err instanceof ZodError) {
    const first = err.issues[0];
    return void res.status(422).json({
      error: { code: 'VALIDATION', message: first ? `${first.path.join('.') || 'Input'}: ${first.message}` : 'Invalid input.', details: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })) },
    });
  }
  if (err instanceof mongoose.Error.CastError) return void res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found.' } });
  if ((err as { code?: number }).code === 11000) return void res.status(409).json({ error: { code: 'DUPLICATE', message: 'This already exists.' } });
  if ((err as { type?: string }).type === 'entity.too.large') return void res.status(413).json({ error: { code: 'TOO_LARGE', message: 'The request is too large.' } });
  if ((err as { type?: string }).type === 'entity.parse.failed') return void res.status(400).json({ error: { code: 'BAD_JSON', message: 'The request body is not valid JSON.' } });
  logger.error({ err, path: req.path }, 'Unhandled error');
  res.status(500).json({ error: { code: 'INTERNAL', message: 'Something went wrong on the server. It has been logged.' } });
}