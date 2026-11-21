import cors from 'cors';
import { Router, type Request } from 'express';
import rateLimit from 'express-rate-limit';
import { BUCKETS } from '../lib/histogram.js';
import { parse, z } from '../lib/validate.js';
import { SECURITY_TYPES } from '../models/Telemetry.js';
import { ingestErrors } from '../services/errors.js';
import { authenticateKey, recordUsage } from '../services/ingestKeys.js';
import { ingestMetrics } from '../services/perf.js';
import { ingestSecurity } from '../services/security.js';

/**
 * Where apps send telemetry: /ingest/v1. Authenticated by an ingestion key, never by cookies,
 * so any origin may call it (browser SDKs run on your own sites' domains).
 */
export const ingestRouter = Router();
ingestRouter.use(cors({ origin: true, credentials: false, methods: ['POST'], allowedHeaders: ['content-type', 'authorization', 'x-shieldops-key'], maxAge: 86_400 }));

const keyOf = (req: Request) => (req.get('authorization') ?? req.get('x-shieldops-key') ?? req.ip ?? '').slice(-24);
ingestRouter.use(rateLimit({ windowMs: 60_000, limit: 600, keyGenerator: keyOf, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: { code: 'RATE_LIMITED', message: 'Too many requests for this key. The SDK will retry.' } } }));

const frame = z.object({ file: z.string().max(500), fn: z.string().max(200), line: z.number().int().min(0), column: z.number().int().min(0), inApp: z.boolean(), code: z.string().max(300).optional() });
const errorsBody = z.object({
  events: z
    .array(
      z.object({
        type: z.string().min(1).max(200),
        message: z.string().max(5000).default(''),
        platform: z.enum(['node', 'browser', 'react-native']),
        release: z.string().max(100).optional(),
        timestamp: z.string().max(40).optional(),
        stack: z.array(frame).max(100).default([]),
        request: z.object({ method: z.string().max(10), route: z.string().max(300), status: z.number().int().min(0).max(999) }).optional(),
        userId: z.string().max(200).optional(),
        tags: z.record(z.string().max(50), z.string().max(500)).optional(),
        fingerprint: z.string().max(200).optional(),
      }),
    )
    .min(1)
    .max(50),
});

ingestRouter.post('/errors', async (req, res) => {
  const key = await authenticateKey(req, 'errors');
  const { events } = parse(errorsBody, req.body);
  await ingestErrors(key, events);
  await recordUsage(key, events.length);
  res.status(202).json({ accepted: events.length });
});

const metricsBody = z.object({
  windowStart: z.iso.datetime({ offset: true }),
  windowSec: z.number().int().min(1).max(600),
  routes: z
    .array(
      z.object({
        method: z.string().min(1).max(10),
        route: z.string().min(1).max(300),
        count: z.number().int().min(0).max(10_000_000),
        errors: z.number().int().min(0).max(10_000_000),
        sumMs: z.number().min(0),
        buckets: z.array(z.number().int().min(0)).length(BUCKETS),
      }),
    )
    .max(500),
});

ingestRouter.post('/metrics', async (req, res) => {
  const key = await authenticateKey(req, 'performance');
  const body = parse(metricsBody, req.body);
  const start = new Date(body.windowStart);
  if (Math.abs(start.getTime() - Date.now()) > 24 * 3_600_000) return void res.status(422).json({ error: { code: 'STALE', message: 'windowStart is more than a day away from now.' } });
  await ingestMetrics(key, start, body.routes);
  await recordUsage(key, 1);
  res.status(202).json({ accepted: body.routes.length });
});

const securityBody = z.object({
  events: z
    .array(
      z.object({
        type: z.enum(SECURITY_TYPES),
        timestamp: z.string().max(40).optional(),
        account: z.string().max(254).optional(),
        accountHash: z.string().regex(/^[a-f0-9]{16,64}$/).optional(),
        userId: z.string().max(200).optional(),
        ip: z.string().max(64).optional(),
        method: z.string().max(10).optional(),
        route: z.string().max(300).optional(),
        status: z.number().int().min(0).max(999).optional(),
        result: z.enum(['success', 'failure', 'blocked']).optional(),
      }),
    )
    .min(1)
    .max(100),
});

ingestRouter.post('/security', async (req, res) => {
  const key = await authenticateKey(req, 'security_events');
  const { events } = parse(securityBody, req.body);
  await ingestSecurity(key, events);
  await recordUsage(key, events.length);
  res.status(202).json({ accepted: events.length });
});

ingestRouter.post('/releases', (_req, res) => {
  res.status(501).json({ error: { code: 'NOT_IMPLEMENTED', message: 'Release tracking arrives in backend phase 8.' } });
});