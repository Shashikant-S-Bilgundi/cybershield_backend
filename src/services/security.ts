import type { Types } from 'mongoose';
import { createHash } from 'node:crypto';
import { hashUser, maskEmail } from '../lib/scrub.js';
import type { IngestionKeyDoc } from '../models/IngestionKey.js';
import { Detection, SECURITY_TYPES, SecurityEvent } from '../models/Telemetry.js';
import { pickRule, raiseAlert } from './alerts.js';

const MIN = 60_000;
type SecType = (typeof SECURITY_TYPES)[number];

export interface IncomingSecurityEvent {
  type: SecType;
  timestamp?: string;
  /** Masked by the SDK, e.g. r***@example.com. Masked again here in case it was not. */
  account?: string;
  /** SHA-256 of the lower-cased account name, from the SDK; lets detection count distinct accounts without seeing them. */
  accountHash?: string;
  userId?: string;
  ip?: string;
  method?: string;
  route?: string;
  status?: number;
  result?: 'success' | 'failure' | 'blocked';
}

const FAILED: SecType[] = ['login_failure', 'mfa_failure'];
const DEFAULT_RESULT: Record<SecType, 'success' | 'failure' | 'blocked'> = {
  login_success: 'success', login_failure: 'failure', logout: 'success', mfa_failure: 'failure', password_reset: 'success',
  authz_failure: 'failure', rate_limited: 'blocked', admin_action: 'success', permission_change: 'success', input_rejected: 'blocked',
};

/** Stores security events for the key's environment, then looks for attacks around the IPs involved. */
export async function ingestSecurity(key: IngestionKeyDoc, events: IncomingSecurityEvent[]) {
  const now = Date.now();
  const docs = events.map((e) => {
    const at = e.timestamp && Math.abs(Date.parse(e.timestamp) - now) < 86_400_000 ? new Date(e.timestamp) : new Date();
    const account = e.account ? maskEmail(e.account).slice(0, 254) : null;
    // Prefer the SDK's hash; fall back to hashing the masked value so detection still works with older SDKs.
    const accountKey = e.accountHash?.slice(0, 64) ?? (e.account ? createHash('sha256').update(e.account.trim().toLowerCase()).digest('hex').slice(0, 32) : null);
    return {
      at, applicationId: key.applicationId, environmentId: key.environmentId, type: e.type,
      actorHash: e.userId ? hashUser(e.userId) : null, account, accountKey,
      ip: (e.ip ?? '').slice(0, 64), country: null,
      method: e.method?.toUpperCase().slice(0, 10) ?? null, route: e.route?.slice(0, 300) ?? null, status: e.status ?? null,
      result: e.result ?? DEFAULT_RESULT[e.type],
    };
  });
  await SecurityEvent.insertMany(docs);

  const ips = [...new Set(docs.filter((d) => FAILED.includes(d.type) && d.ip).map((d) => d.ip))];
  for (const ip of ips) await detectForIp(key.applicationId, key.environmentId, ip);
  if (docs.some((d) => d.type === 'authz_failure')) await detectAuthSpike(key.applicationId, key.environmentId);
}

async function record(rule: 'failed_logins' | 'credential_stuffing' | 'auth_failure_spike', app: Types.ObjectId, env: Types.ObjectId, subject: string, windowMin: number, count: number, distinctAccounts: number | null, firstAt: Date, alert: { signal: string; value: number; title: string; message: string }) {
  const now = new Date();
  let d = await Detection.findOne({ rule, environmentId: env, subject, lastAt: { $gte: new Date(now.getTime() - 2 * windowMin * MIN) } });
  if (d) d.set({ count: Math.max(d.count, count), distinctAccounts, lastAt: now });
  else d = new Detection({ rule, applicationId: app, environmentId: env, subject, count, distinctAccounts, windowMin, firstAt, lastAt: now });
  const a = await raiseAlert({ key: `sec:${rule}:${env}:${subject}`, signal: alert.signal, value: alert.value, applicationId: app, environmentId: env, source: 'security_events', title: alert.title, message: alert.message });
  if (a) d.alertId = a._id;
  await d.save();
}

/** Brute force (many failures from one IP) and credential stuffing (one IP failing across many accounts). */
async function detectForIp(app: Types.ObjectId, env: Types.ObjectId, ip: string) {
  const now = Date.now();
  const recent = await SecurityEvent.find({ environmentId: env, ip, type: { $in: FAILED }, at: { $gte: new Date(now - 10 * MIN) } }, { at: 1, accountKey: 1, account: 1 }).lean();
  const last5 = recent.filter((e) => e.at.getTime() >= now - 5 * MIN);
  const accounts = new Set(recent.map((e) => e.accountKey).filter(Boolean));
  const brute = await pickRule({ signal: 'failed_logins', key: '', applicationId: app, environmentId: env, source: 'security_events', title: '', message: '', value: last5.length });
  if (brute && last5.length >= (brute.threshold ?? 10)) {
    const first = last5.reduce((m, e) => (e.at < m ? e.at : m), last5[0].at);
    const names = [...new Set(last5.map((e) => e.account).filter(Boolean))].slice(0, 3).join(', ');
    await record('failed_logins', app, env, ip, 5, last5.length, new Set(last5.map((e) => e.accountKey).filter(Boolean)).size, first, {
      signal: 'failed_logins', value: last5.length, title: `${last5.length} failed logins from ${ip} in 5 minutes`, message: `Accounts tried: ${names || 'not reported'}. Consider blocking the IP and checking those accounts.`,
    });
  }
  const stuffing = await pickRule({ signal: 'credential_stuffing', key: '', applicationId: app, environmentId: env, source: 'security_events', title: '', message: '', value: accounts.size });
  if (stuffing && accounts.size >= (stuffing.threshold ?? 10)) {
    const first = recent.reduce((m, e) => (e.at < m ? e.at : m), recent[0].at);
    await record('credential_stuffing', app, env, ip, 10, recent.length, accounts.size, first, {
      signal: 'credential_stuffing', value: accounts.size, title: `Credential stuffing from ${ip}: ${accounts.size} accounts in 10 minutes`, message: `${recent.length} failed logins across ${accounts.size} different accounts. This usually means a leaked password list is being tried. Block the IP, and add per-account rate limits.`,
    });
  }
}

/** 401/403 responses in the last 5 minutes against the usual rate for the hour before. */
async function detectAuthSpike(app: Types.ObjectId, env: Types.ObjectId) {
  const now = Date.now();
  const last5 = await SecurityEvent.find({ environmentId: env, type: 'authz_failure', at: { $gte: new Date(now - 5 * MIN) } }, { method: 1, route: 1 }).lean();
  if (last5.length < 20) return;
  const before = await SecurityEvent.countDocuments({ environmentId: env, type: 'authz_failure', at: { $gte: new Date(now - 65 * MIN), $lt: new Date(now - 5 * MIN) } });
  const baseline = Math.max(before / 12, 1);
  const rule = await pickRule({ signal: 'auth_failure_spike', key: '', applicationId: app, environmentId: env, source: 'security_events', title: '', message: '', value: last5.length / baseline });
  if (!rule?.threshold || last5.length < rule.threshold * baseline) return;
  const routes = new Map<string, number>();
  last5.forEach((e) => routes.set(`${e.method ?? ''} ${e.route ?? ''}`.trim(), (routes.get(`${e.method ?? ''} ${e.route ?? ''}`.trim()) ?? 0) + 1));
  const top = [...routes.entries()].sort((a, b) => b[1] - a[1])[0][0] || 'all routes';
  await record('auth_failure_spike', app, env, top, 5, last5.length, null, new Date(now - 5 * MIN), {
    signal: 'auth_failure_spike', value: last5.length / baseline, title: `401/403 responses ${Math.round(last5.length / baseline)}× the usual rate`, message: `${last5.length} in 5 minutes, mostly on ${top}. Someone may be probing for pages they cannot access.`,
  });
}

/** Counts per type, failures per hour, and distinct IPs, over the last 24 hours. */
export async function stats(filter: Record<string, unknown>) {
  const now = Date.now();
  const since = new Date(now - 24 * 60 * MIN);
  const match = { ...filter, at: { $gte: since } };
  const [byType, hourly, ips] = await Promise.all([
    SecurityEvent.aggregate<{ _id: SecType; n: number }>([{ $match: match }, { $group: { _id: '$type', n: { $sum: 1 } } }]),
    SecurityEvent.aggregate<{ _id: number; n: number }>([{ $match: { ...match, result: { $ne: 'success' } } }, { $group: { _id: { $floor: { $divide: [{ $subtract: [new Date(now), '$at'] }, 3_600_000] } }, n: { $sum: 1 } } }]),
    SecurityEvent.distinct('ip', match),
  ]);
  const counts = Object.fromEntries(SECURITY_TYPES.map((t) => [t, 0])) as Record<SecType, number>;
  byType.forEach((r) => (counts[r._id] = r.n));
  const failuresHourly = Array(24).fill(0);
  hourly.forEach((r) => {
    const i = 23 - r._id;
    if (i >= 0 && i < 24) failuresHourly[i] = r.n;
  });
  return { byType: counts, failuresHourly, uniqueIps: ips.filter(Boolean).length };
}