import { logger } from '../lib/logger.js';
import { Alert, type AlertDoc } from '../models/Alert.js';
import { EscalationPolicy, type PolicyDoc } from '../models/Advanced.js';
import { Notification } from '../models/Notification.js';
import { User } from '../models/User.js';
import { sendToChannel } from './channels.js';
import { sendMail } from './mailer.js';

const MIN = 60_000;

const policyFor = async (severity: string) => EscalationPolicy.findOne({ enabled: true, severities: severity });

/** Notifies one step: in-app and email to its people (or everyone), and Slack or the webhook if listed. */
async function notifyStep(alert: AlertDoc, policy: PolicyDoc, stepIndex: number, repeat: boolean) {
  const step = policy.steps[stepIndex];
  const everyone = step.targets.includes('all');
  const users = await User.find({ status: 'active', ...(everyone ? {} : { _id: { $in: step.targets } }) }, { name: 1, email: 1 }).lean();
  const who = everyone ? 'All members' : users.map((u) => u.name).join(', ') || 'nobody (people were removed)';
  const title = `Not acknowledged: ${alert.title}`;
  const body = `Escalation step ${stepIndex + 1} of ${policy.steps.length} (${policy.name})${repeat ? ', repeated' : ''}. ${alert.message}`;
  const now = new Date();
  for (const ch of step.channels) {
    let ok = true;
    if (ch === 'in_app') await Notification.insertMany(users.map((u) => ({ userId: u._id, title, body })));
    else if (ch === 'email') ok = users.length > 0 && (await sendMail(users.map((u) => u.email), `[ShieldOps ${alert.severity.toUpperCase()}] ${title}`, `${body}\n\nAcknowledge it in ShieldOps to stop further escalation.`));
    else if (ch === 'slack' || ch === 'webhook') ok = (await sendToChannel(ch, { id: alert.id, title, message: body, severity: alert.severity, applicationId: alert.applicationId, environmentId: alert.environmentId }, 'alert.escalated')).ok;
    alert.deliveries.push({ channel: ch, recipient: `${who} (escalation step ${stepIndex + 1})`, status: ok ? 'sent' : 'failed', at: now, attempts: 1 } as never);
  }
}

/**
 * Run by the scheduler. For each open, unacknowledged alert with a policy for its severity, notifies
 * every step that has come due since the alert opened. The first step (0 minutes) is the alert's own
 * notification, already sent by its rule. With "repeat", the last step repeats until someone acknowledges.
 */
export async function runEscalations() {
  const open = await Alert.find({ status: 'open' });
  const now = Date.now();
  for (const a of open) {
    try {
      const policy = await policyFor(a.severity);
      if (!policy || policy.steps.length < 2) continue;
      const elapsed = (now - a.firstAt.getTime()) / MIN;
      const due = policy.steps.filter((s) => (s.afterMinutes ?? 0) <= elapsed).length;
      let changed = false;
      if (!a.escalationStep) {
        a.escalationStep = 1;
        a.escalationPolicyId = policy._id;
        a.escalationLastAt = a.firstAt;
        changed = true;
      }
      while (a.escalationStep < due) {
        await notifyStep(a, policy, a.escalationStep, false);
        a.escalationStep += 1;
        a.escalationLastAt = new Date();
        changed = true;
      }
      const last = policy.steps.at(-1)!;
      const gap = Math.max(5, (last.afterMinutes ?? 0) - (policy.steps.at(-2)?.afterMinutes ?? 0));
      if (policy.repeat && a.escalationStep === policy.steps.length && a.escalationRepeats < 10 && a.escalationLastAt && now - a.escalationLastAt.getTime() >= gap * MIN) {
        await notifyStep(a, policy, policy.steps.length - 1, true);
        a.escalationRepeats += 1;
        a.escalationLastAt = new Date();
        changed = true;
      }
      const next = policy.steps[a.escalationStep];
      a.escalationNextAt = next ? new Date(a.firstAt.getTime() + (next.afterMinutes ?? 0) * MIN) : policy.repeat && a.escalationRepeats < 10 ? new Date((a.escalationLastAt?.getTime() ?? now) + gap * MIN) : null;
      if (changed) await a.save();
      else await Alert.updateOne({ _id: a._id }, { escalationNextAt: a.escalationNextAt });
    } catch (err) {
      logger.error({ err, alert: a.id }, 'Escalation failed');
    }
  }
}

/** Where each open alert is in its escalation, for the Alerts page. */
export async function escalationViews() {
  const open = await Alert.find({ status: 'open' });
  const out = [];
  for (const a of open) {
    const p = await policyFor(a.severity);
    if (!p || p.steps.length < 2) continue;
    const elapsed = (Date.now() - a.firstAt.getTime()) / MIN;
    const step = Math.max(a.escalationStep, p.steps.filter((s) => (s.afterMinutes ?? 0) <= elapsed).length, 1);
    const next = p.steps[step];
    out.push({
      alertId: a.id, policyId: p.id, policyName: p.name, step, totalSteps: p.steps.length,
      lastNotifiedAt: a.escalationLastAt ?? new Date(a.firstAt.getTime() + (p.steps[step - 1].afterMinutes ?? 0) * MIN),
      nextAt: next ? new Date(a.firstAt.getTime() + (next.afterMinutes ?? 0) * MIN) : a.escalationNextAt ?? null,
    });
  }
  return out;
}