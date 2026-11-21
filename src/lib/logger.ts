import { createRequire } from 'node:module';
import { pino } from 'pino';
import { config } from '../config.js';

/** pino-pretty is a dev dependency; if it is not installed, fall back to plain JSON instead of crashing. */
function prettyAvailable(): boolean {
  try {
    createRequire(import.meta.url).resolve('pino-pretty');
    return true;
  } catch {
    return false;
  }
}

const pretty = config.NODE_ENV === 'development' && prettyAvailable();

/**
 * Development: short coloured lines (pino-pretty). Production: one JSON line per event, for log tools.
 * Secrets are redacted either way.
 */
export const logger = pino({
  level: config.NODE_ENV === 'test' ? 'silent' : config.LOG_LEVEL,
  redact: ['req.headers.cookie', 'req.headers.authorization', 'res.headers["set-cookie"]', '*.password', '*.code', '*.token'],
  transport: pretty ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'SYS:HH:MM:ss', ignore: 'pid,hostname,reqId,responseTime,err' } } : undefined,
});

if (config.NODE_ENV === 'development' && !pretty) {
  logger.info('Tip: run "npm install" to get readable development logs (pino-pretty).');
}