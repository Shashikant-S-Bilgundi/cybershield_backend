import type { Types } from 'mongoose';
import { logger } from '../lib/logger.js';
import { Alert, type AlertDoc } from '../models/Alert.js';
import { AlertRule, type AlertRuleDoc } from '../models/AlertRule.js';
import { Application } from '../models/Application.js';
import { MaintenanceWindow } from '../models/MaintenanceWindow.js';
import { Notification } from '../models/Notification.js';
import { User } from '../models/User.js';
import { inBackground } from './background.js';
import { sendToChannel } from './channels.js';
import { sendMail } from './mailer.js';
import { getSettingsDoc } from './settings.js';

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
type Sev = keyof typeof SEV_RANK;

export interface Signal {
  signal: string;
  /** What the alert is about, e.g. "uptime:<monitorId>". One open alert per key. */
  key: string;
  applicationId: Types.ObjectId | string;
  environmentId: Types.ObjectId | string;
  assetId?: Types.ObjectId | string | null;
  source: string;
  title: string;
  message: string;
  /** For threshold rules: failures, milliseconds or days left. Lower days = more urgent. */
  value?: number;
}

/** Thresholds that fire when the value is at or below them (days left). Everything else fires at or above. */
const BELOW = new Set(['ssl_expiry', 'domain_expiry']);

/**
 * The single rule that applies: enabled, in scope, threshold met. Among several,
 * the most urgent threshold wins, then the most specific scope, then the highest severity.
 */
export async function pickRule(sig: Signal): Promise<AlertRuleDoc | null> {
  const app = await Application.findById(sig.applicationId);
  const env = app?.environments.find((e) => String(e._id) === String(sig.environmentId));
  const rules = await AlertRule.find({ signal: sig.signal, enabled: true });
  const fits = rules.filter((r) => {
    if (r.scope?.applicationId && String(r.scope.applicationId) !== String(sig.applicationId)) return false;
    if (r.scope?.environmentType && r.scope.environmentType !== env?.type) return false;
    if (r.threshold == null || sig.value === undefined) return true;
    return BELOW.has(sig.signal) ? sig.value <= r.threshold : sig.value >= r.threshold;
  });
  const specificity = (r: AlertRuleDoc) => (r.scope?.applicationId ? 2 : 0) + (r.scope?.environmentType ? 1 : 0);
  fits.sort(
    (a, b) =>
      (BELOW.has(sig.signal) ? (a.threshold ?? 1e9) - (b.threshold ?? 1e9) : 0) ||
      specificity(b) - specificity(a) ||
      SEV_RANK[a.severity as Sev] - SEV_RANK[b.severity as Sev],
  );
  return fits[0] ?? null;
}

async function inMaintenance(applicationId: unknown, environmentId: unknown) {
  const now = new Date();
  return !!(await MaintenanceWindow.exists({
    startsAt: { $lte: now },
    endsAt: { $gt: now },
    $and: [{ $or: [{ applicationId: null }, { applicationId }] }, { $or: [{ environmentId: null }, { environmentId }] }],
  }));
}

/** Sends the alert on the rule's channels. During a maintenance window nothing is sent. */
async function deliver(alert: AlertDoc, rule: AlertRuleDoc) {
  if (await inMaintenance(alert.applicationId, alert.environmentId)) return;
  const now = new Date();
  const deliveries: { channel: string; recipient: string; status: string; at: Date; attempts: number }[] = [];
  if (rule.channels.includes('in_app')) {
    const users = await User.find({ status: 'active' }, { _id: 1 }).lean();
    await Notification.insertMany(users.map((u) => ({ userId: u._id, title: alert.title, body: alert.message })));
    deliveries.push({ channel: 'in_app', recipient: 'All members', status: 'sent', at: now, attempts: 1 });
  }
  if (rule.channels.includes('email')) {
    const { channels } = await getSettingsDoc();
    const to = channels?.emailRecipients ?? [];
    if (!to.length) deliveries.push({ channel: 'email', recipient: 'No recipients set in Alert rules', status: 'failed', at: now, attempts: 0 });
    else {
      const ok = await sendMail(to, `[ShieldOps ${alert.severity.toUpperCase()}] ${alert.title}`, `${alert.message}\n\nOpen ShieldOps to acknowledge it.`);
      deliveries.push({ channel: 'email', recipient: to.join(', '), status: ok ? 'sent' : 'failed', at: now, attempts: 1 });
    }
  }
  const remote = rule.channels.filter((c): c is 'slack' | 'webhook' => c === 'slack' || c === 'webhook');
  for (const ch of remote) deliveries.push({ channel: ch, recipient: '', status: 'pending', at: now, attempts: 0 });
  alert.deliveries.push(...(deliveries as never[]));
  alert.lastNotifiedAt = now;
  await alert.save();
  // Slack and webhooks can take seconds (and retry), so they finish in the background and update the delivery record.
  for (const ch of remote) {
    inBackground(
      (async () => {
        const r = await sendToChannel(ch, { id: alert.id, title: alert.title, message: alert.message, severity: alert.severity, applicationId: alert.applicationId, environmentId: alert.environmentId });
        await Alert.updateOne(
          { _id: alert._id, 'deliveries.channel': ch, 'deliveries.status': 'pending' },
          { $set: { 'deliveries.$.status': r.ok ? 'sent' : 'failed', 'deliveries.$.recipient': r.recipient || r.detail, 'deliveries.$.attempts': r.attempts, 'deliveries.$.at': new Date() } },
        );
      })(),
      `${ch} delivery for alert ${alert.id}`,
    );
  }
}

/** Opens an alert, or adds an occurrence to the open one with the same key. Escalation re-notifies. */
export async function raiseAlert(sig: Signal): Promise<AlertDoc | null> {
  const rule = await pickRule(sig);
  if (!rule) return null;
  const now = new Date();
  const open = await Alert.findOne({ key: sig.key, status: { $ne: 'resolved' } });
  if (open) {
    const escalated = SEV_RANK[rule.severity as Sev] < SEV_RANK[open.severity as Sev];
    open.occurrences += 1;
    open.lastAt = now;
    open.title = sig.title;
    open.message = sig.message;
    if (escalated) {
      open.severity = rule.severity;
      open.ruleId = rule._id;
      if (open.status !== 'open') open.status = 'open';
      await deliver(open, rule);
    } else await open.save();
    return open;
  }
  const alert = await Alert.create({
    key: sig.key,
    title: sig.title,
    message: sig.message,
    severity: rule.severity,
    source: sig.source,
    applicationId: sig.applicationId,
    environmentId: sig.environmentId,
    assetId: sig.assetId ?? null,
    ruleId: rule._id,
    firstAt: now,
    lastAt: now,
  });
  await deliver(alert, rule);
  logger.info({ alert: alert.id, title: alert.title }, 'Alert opened');
  return alert;
}

/** Closes the open alert for a key because the condition cleared. */
export async function autoResolve(key: string) {
  await Alert.updateMany({ key, status: { $ne: 'resolved' } }, { status: 'resolved', resolvedAt: new Date(), autoResolved: true });
}

export async function wakeSnoozed() {
  await Alert.updateMany({ status: 'snoozed', snoozedUntil: { $lte: new Date() } }, { status: 'open', snoozedUntil: null });
}

/** Critical alerts nobody has acknowledged are emailed again, up to the configured limit. */
export async function renotifyCritical() {
  const { channels } = await getSettingsDoc();
  const every = (channels?.criticalRenotifyMin ?? 15) * 60_000;
  const max = channels?.maxRenotify ?? 4;
  const due = await Alert.find({ status: 'open', severity: 'critical', renotified: { $lt: max }, lastNotifiedAt: { $lte: new Date(Date.now() - every) } });
  for (const a of due) {
    const rule = a.ruleId ? await AlertRule.findById(a.ruleId) : null;
    if (!rule) continue;
    a.renotified += 1;
    await deliver(a, rule);
  }
}

export const activeAlertCount = () => Alert.countDocuments({ status: { $in: ['open', 'acknowledged'] } });