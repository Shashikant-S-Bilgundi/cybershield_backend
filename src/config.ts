import 'dotenv/config';
import { z } from 'zod';

const bool = z.enum(['true', 'false']).transform((v) => v === 'true');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  MONGODB_URI: z.string().min(1),
  APP_URL: z.url(),
  EXTRA_ORIGINS: z.string().default(''),
  ENCRYPTION_KEY: z
    .string()
    .refine((k) => Buffer.from(k, 'base64').length === 32, 'ENCRYPTION_KEY must be 32 bytes, base64 encoded'),
  COOKIE_SECURE: bool.default(true),
  COOKIE_DOMAIN: z.string().default(''),
  SESSION_IDLE_HOURS: z.coerce.number().positive().default(12),
  SESSION_MAX_DAYS: z.coerce.number().positive().default(7),
  REAUTH_MINUTES: z.coerce.number().positive().default(10),
  TRUST_PROXY: z.coerce.number().int().min(0).default(1),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  // GitHub App (phase 5). Optional until you connect GitHub.
  GITHUB_APP_ID: z.string().default(''),
  GITHUB_APP_SLUG: z.string().default(''),
  GITHUB_APP_PRIVATE_KEY: z.string().default(''),
  GITHUB_APP_PRIVATE_KEY_FILE: z.string().default(''),
  GITHUB_WEBHOOK_SECRET: z.string().default(''),
  GITHUB_API_URL: z.url().default('https://api.github.com'),
  GITHUB_WEB_URL: z.url().default('https://github.com'),
  // Scanners (phase 5)
  SCANNER_BIN_DIR: z.string().default(''),
  SCAN_TIMEOUT_SEC: z.coerce.number().int().min(60).max(7200).default(900),
  SCAN_CACHE_DIR: z.string().default(''),
  // Alert webhooks (phase 6): an extra CA bundle for internal endpoints with a private certificate authority.
  WEBHOOK_CA_FILE: z.string().default(''),
  // AI analyst (phase 7). Keys live only here, never in the database. Choose the provider in System settings.
  OPENAI_API_KEY: z.string().default(''),
  OPENAI_BASE_URL: z.url().default('https://api.openai.com'),
  ANTHROPIC_API_KEY: z.string().default(''),
  ANTHROPIC_BASE_URL: z.url().default('https://api.anthropic.com'),
  AZURE_OPENAI_ENDPOINT: z.string().default(''),
  AZURE_OPENAI_API_KEY: z.string().default(''),
  AZURE_OPENAI_API_VERSION: z.string().default('2024-10-21'),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error('Invalid configuration:\n' + parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n'));
  process.exit(1);
}

const env = parsed.data;

export const config = {
  ...env,
  isProd: env.NODE_ENV === 'production',
  appUrl: env.APP_URL.replace(/\/$/, ''),
  allowedOrigins: [new URL(env.APP_URL).origin, ...env.EXTRA_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean)],
  encryptionKey: Buffer.from(env.ENCRYPTION_KEY, 'base64'),
  sessionIdleMs: env.SESSION_IDLE_HOURS * 3_600_000,
  sessionMaxMs: env.SESSION_MAX_DAYS * 86_400_000,
  reauthMs: env.REAUTH_MINUTES * 60_000,
};

if (config.isProd && !config.COOKIE_SECURE) {
  console.error('COOKIE_SECURE must be true in production.');
  process.exit(1);
}