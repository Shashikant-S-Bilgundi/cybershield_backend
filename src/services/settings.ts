import { Settings } from '../models/Settings.js';

/** The settings document, created with defaults the first time it is read. */
export async function getSettingsDoc() {
  return (await Settings.findById('system')) ?? (await Settings.create({ _id: 'system' }));
}

/** Settings as the frontend sees them: secrets replaced by "is set" flags. */
export function publicSettings(doc: Awaited<ReturnType<typeof getSettingsDoc>>) {
  const s = doc.toObject();
  return {
    timezone: s.timezone,
    monitoring: s.monitoring,
    retention: s.retention,
    smtp: { host: s.smtp!.host, port: s.smtp!.port, username: s.smtp!.username, fromAddress: s.smtp!.fromAddress, passwordSet: !!s.smtp!.passwordEnc },
    internalAllowlist: s.internalAllowlist,
    ai: s.ai,
    sso: { enabled: s.sso!.enabled, provider: s.sso!.provider, domain: s.sso!.domain, clientId: s.sso!.clientId, clientSecretSet: !!s.sso!.clientSecretEnc, allowPasswordFallback: s.sso!.allowPasswordFallback },
  };
}

/** The Internal Network Allowlist as plain ranges, for the network guard. */
export async function getAllowlist(): Promise<{ cidr: string; note: string }[]> {
  const doc = await getSettingsDoc();
  return doc.internalAllowlist.map((r) => ({ cidr: r.cidr ?? '', note: r.note ?? '' })).filter((r) => r.cidr);
}