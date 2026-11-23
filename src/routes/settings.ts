import { Router } from 'express';
import { encrypt } from '../lib/crypto.js';
import { ApiError } from '../lib/errors.js';
import { isValidCidr } from '../lib/net.js';
import { parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { audit } from '../services/audit.js';
import { notifyAll } from '../services/notify.js';
import { getSettingsDoc, publicSettings } from '../services/settings.js';

export const settingsRouter = Router();
settingsRouter.use('/settings', requireAuth);

const validTimezone = (tz: string) => {
  try {
    new Intl.DateTimeFormat('en', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
};

const updateInput = z
  .object({
    timezone: z.string().refine(validTimezone, 'Unknown time zone'),
    monitoring: z
      .object({
        uptimeIntervalSec: z.number().int().min(30).max(3600),
        downAfterFailures: z.number().int().min(1).max(5),
        sslCheckHours: z.number().int().min(1).max(168),
        dnsCheckHours: z.number().int().min(1).max(168),
      })
      .partial(),
    retention: z
      .object({
        checkResultsDays: z.number().int().min(7).max(3650),
        metricSamplesDays: z.number().int().min(1).max(3650),
        errorEventsDays: z.number().int().min(7).max(3650),
        securityEventsDays: z.number().int().min(30).max(3650),
        auditLogsDays: z.number().int().min(365).max(3650),
      })
      .partial(),
    smtp: z
      .object({
        host: z.string().trim().max(253),
        port: z.number().int().min(1).max(65535),
        username: z.string().trim().max(254),
        fromAddress: z.string().trim().max(254),
        password: z.string().max(500),
      })
      .partial(),
    internalAllowlist: z
      .array(z.object({ cidr: z.string().trim().refine(isValidCidr, 'Not a valid CIDR range, like 10.0.0.0/16'), note: z.string().trim().max(200).default('') }))
      .max(100),
    ai: z.object({ enabled: z.boolean(), provider: z.enum(['openai', 'anthropic', 'azure_openai']), model: z.string().trim().min(1).max(100), shareApproved: z.boolean() }).partial(),
    sso: z
      .object({
        enabled: z.boolean(),
        provider: z.enum(['google', 'entra']),
        domain: z.string().trim().toLowerCase().max(253),
        clientId: z.string().trim().max(300),
        clientSecret: z.string().max(500),
        allowPasswordFallback: z.boolean(),
      })
      .partial(),
  })
  .partial()
  .strict();

settingsRouter.get('/settings', async (_req, res) => {
  res.json(publicSettings(await getSettingsDoc()));
});

/** Every setting is critical: re-authentication, an audit record listing the changes, and a notice to everyone. */
settingsRouter.patch('/settings', requireReauth, async (req, res) => {
  const input = parse(updateInput, req.body);
  const doc = await getSettingsDoc();
  const changes: string[] = [];
  const note = (path: string, before: unknown, after: unknown) => {
    if (JSON.stringify(before) !== JSON.stringify(after)) changes.push(`${path}: ${JSON.stringify(before)} → ${JSON.stringify(after)}`);
  };

  if (input.timezone) {
    note('timezone', doc.timezone, input.timezone);
    doc.timezone = input.timezone;
  }
  for (const group of ['monitoring', 'retention'] as const) {
    const patch = input[group];
    if (!patch) continue;
    for (const [k, v] of Object.entries(patch)) {
      const target = doc[group] as unknown as Record<string, unknown>;
      note(`${group}.${k}`, target[k], v);
      target[k] = v;
    }
  }
  if (input.smtp) {
    const { password, ...rest } = input.smtp;
    for (const [k, v] of Object.entries(rest)) {
      note(`smtp.${k}`, (doc.smtp as unknown as Record<string, unknown>)[k], v);
      (doc.smtp as unknown as Record<string, unknown>)[k] = v;
    }
    if (password) {
      doc.smtp!.passwordEnc = encrypt(password);
      changes.push('smtp.password: changed');
    }
  }
  if (input.internalAllowlist) {
    note('internalAllowlist', doc.internalAllowlist.map((r) => r.cidr), input.internalAllowlist.map((r) => r.cidr));
    doc.internalAllowlist = input.internalAllowlist as never;
  }
  if (input.ai) {
    for (const [k, v] of Object.entries(input.ai)) {
      note(`ai.${k}`, (doc.ai as unknown as Record<string, unknown>)[k], v);
      (doc.ai as unknown as Record<string, unknown>)[k] = v;
    }
  }
  if (input.sso) {
    const { clientSecret, ...rest } = input.sso;
    const next = { ...doc.toObject().sso, ...rest };
    if (next.enabled && (!/^[\w.-]+\.[a-z]{2,}$/i.test(next.domain ?? '') || !next.clientId || !(clientSecret || next.clientSecretEnc))) {
      throw new ApiError(422, 'SSO_INCOMPLETE', 'Enter the allowed domain, client ID and client secret before turning on single sign-on.');
    }
    // Switching off password sign-in could lock everyone out if SSO is misconfigured: only someone who has just
    // signed in through SSO, proving it works, may do it.
    if (next.enabled && next.allowPasswordFallback === false && doc.sso!.allowPasswordFallback !== false && req.authSession!.method !== 'sso') {
      throw new ApiError(409, 'SSO_NOT_PROVEN', 'Sign in once with single sign-on first, so you know it works, then turn off the password route.');
    }
    for (const [k, v] of Object.entries(rest)) {
      note(`sso.${k}`, (doc.sso as unknown as Record<string, unknown>)[k], v);
      (doc.sso as unknown as Record<string, unknown>)[k] = v;
    }
    if (clientSecret) {
      doc.sso!.clientSecretEnc = encrypt(clientSecret);
      changes.push('sso.clientSecret: changed');
    }
  }

  await doc.save();
  if (changes.length) {
    await audit(req, 'settings.update', 'settings', null, `Changed settings. ${changes.join('; ')}`);
    await notifyAll('System settings changed', `${req.user!.name} changed: ${changes.map((c) => c.split(':')[0]).join(', ')}.`);
  }
  res.json(publicSettings(doc));
});