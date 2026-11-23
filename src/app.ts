import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { type Express } from 'express';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import { config } from './config.js';
import { logger } from './lib/logger.js';
import { errorHandler } from './middleware/errors.js';
import { checkOrigin } from './middleware/security.js';
import { applicationsRouter } from './routes/applications.js';
import { assetsRouter } from './routes/assets.js';
import { auditRouter } from './routes/audit.js';
import { authRouter } from './routes/auth.js';
import { dashboardRouter } from './routes/dashboard.js';
import { settingsRouter } from './routes/settings.js';
import { teamRouter } from './routes/team.js';
import { alertRulesRouter } from './routes/alertRules.js';
import { alertsRouter } from './routes/alerts.js';
import { checksRouter } from './routes/checks.js';
import { findingsRouter } from './routes/findings.js';
import { heartbeatsRouter } from './routes/heartbeats.js';
import { monitorsRouter } from './routes/monitors.js';
import { ingestRouter } from './routes/ingest.js';
import { ingestionKeysRouter } from './routes/ingestionKeys.js';
import { telemetryRouter } from './routes/telemetry.js';
import { agentDownloadRouter, agentReportRouter } from './routes/agent.js';
import { infraRouter } from './routes/infra.js';
import { codeRouter, githubWebhook } from './routes/code.js';
import { opsRouter } from './routes/ops.js';
import { intelRouter } from './routes/intel.js';
import { advancedRouter } from './routes/advanced.js';
import { cloudRouter } from './routes/cloud.js';

export function createApp(): Express {
  const app = express();
  app.set('trust proxy', config.TRUST_PROXY);
  app.disable('x-powered-by');

  app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } }, crossOriginResourcePolicy: false }));
  // One short line per request: method, full path, status and time. No headers, so no cookies or tokens in logs.
  // Real server faults are logged with their stack by the error handler; here, 5xx answers stay one line.
  app.use(
    pinoHttp({
      logger,
      autoLogging: { ignore: (req) => req.url === '/health' || req.url === '/api/v1/health' },
      quietReqLogger: true,
      serializers: { req: () => undefined, res: () => undefined, err: () => undefined },
      customLogLevel: (_req, res) => (res.statusCode >= 500 && res.statusCode !== 501 ? 'error' : res.statusCode >= 400 && res.statusCode !== 401 && res.statusCode !== 501 ? 'warn' : 'info'),
      customSuccessMessage: (req, res, ms) => `${req.method} ${req.originalUrl} ${res.statusCode} ${Math.round(ms)}ms`,
      customErrorMessage: (req, res) => `${req.method} ${req.originalUrl} ${res.statusCode}`,
    }),
  );

  // GitHub webhooks need the exact bytes to verify their signature, and push payloads can be large.
  app.post('/api/v1/webhooks/github', express.raw({ type: 'application/json', limit: '5mb' }), githubWebhook);
  app.use(express.json({ limit: '256kb' }));

  // Telemetry from your apps: key-authenticated, open to any origin, no cookies. Mounted before the
  // console's CORS policy, which only allows the ShieldOps frontend.
  app.use('/ingest/v1', agentReportRouter, ingestRouter);
  app.use('/ingest/agent', agentDownloadRouter);

  app.use(cors({ origin: config.allowedOrigins, credentials: true, methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'] }));
  app.use(cookieParser());

  app.get(['/health', '/api/v1/health'], (_req, res) => res.json({ ok: true }));

  const api = express.Router();
  api.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  api.use(checkOrigin);
  api.use(authRouter, teamRouter, applicationsRouter, checksRouter, assetsRouter, auditRouter, settingsRouter, dashboardRouter);
  api.use(monitorsRouter, heartbeatsRouter, alertsRouter, findingsRouter, alertRulesRouter);
  api.use(telemetryRouter, ingestionKeysRouter, infraRouter, codeRouter, opsRouter, intelRouter, advancedRouter, cloudRouter);
  api.use((_req, res) => res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No such endpoint.' } }));
  app.use('/api/v1', api);

  app.use(errorHandler);
  return app;
}