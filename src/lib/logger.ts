import { pino } from 'pino';
import { config } from '../config.js';

/**
 * Development: short coloured lines (pino-pretty). Production: one JSON line per event, for log tools.
 * Secrets are redacted either way.
 */
export const logger = pino({
  level: config.NODE_ENV === 'test' ? 'silent' : config.LOG_LEVEL,
  redact: ['req.headers.cookie', 'req.headers.authorization', 'res.headers["set-cookie"]', '*.password', '*.code', '*.token'],
  transport: config.NODE_ENV === 'development' ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'SYS:HH:MM:ss', ignore: 'pid,hostname,reqId,responseTime,err' } } : undefined,
});