import { nextCronRun } from '../lib/cron.js';
import { Heartbeat, type HeartbeatDoc } from '../models/Heartbeat.js';
import { autoResolve, raiseAlert } from './alerts.js';
import { getSettingsDoc } from './settings.js';

/** When the job should next check in, counting from `from`. */
export async function nextDue(h: Pick<HeartbeatDoc, 'schedule'>, from: Date): Promise<Date> {
  if (h.schedule!.kind === 'interval') return new Date(from.getTime() + h.schedule!.seconds! * 1000);
  const { timezone } = await getSettingsDoc();
  return nextCronRun(h.schedule!.expression!, from, timezone ?? 'Asia/Kolkata');
}

const alertKey = (h: HeartbeatDoc) => `heartbeat:${h.id}`;

/** A ping from the job. "start" only records that it began; "fail" means the job itself reported failure. */
export async function recordPing(token: string, kind: 'success' | 'start' | 'fail') {
  const h = await Heartbeat.findOne({ token, deletedAt: null });
  if (!h) return null;
  const now = new Date();
  const late = !!h.nextDueAt && now.getTime() > h.nextDueAt.getTime();
  h.recent.unshift({ at: now, kind, late } as never);
  h.recent.splice(20);
  if (h.paused) {
    await h.save();
    return h;
  }
  if (kind === 'success') {
    h.lastPingAt = now;
    h.status = 'up';
    h.nextDueAt = await nextDue(h, now);
    await h.save();
    await autoResolve(alertKey(h));
  } else if (kind === 'fail') {
    h.lastPingAt = now;
    h.status = 'down';
    h.nextDueAt = await nextDue(h, now);
    await h.save();
    await raiseAlert({ key: alertKey(h), signal: 'heartbeat_missed', applicationId: h.applicationId, environmentId: h.environmentId, source: 'heartbeat', title: `${h.name} reported a failure`, message: `The job called its fail URL at ${now.toISOString()}.` });
  } else await h.save();
  return h;
}

/** Marks jobs late once due, and down (with an alert) once the grace period has also passed. */
export async function evaluateHeartbeats() {
  const now = Date.now();
  const due = await Heartbeat.find({ paused: false, deletedAt: null, nextDueAt: { $lte: new Date(now) }, status: { $ne: 'down' } });
  for (const h of due) {
    const overdueMs = now - h.nextDueAt!.getTime();
    if (overdueMs > h.graceSec * 1000) {
      h.status = 'down';
      await h.save();
      await raiseAlert({ key: alertKey(h), signal: 'heartbeat_missed', applicationId: h.applicationId, environmentId: h.environmentId, source: 'heartbeat', title: `${h.name} didn't run`, message: `It was due at ${h.nextDueAt!.toISOString()} and has not checked in, even after ${Math.round(h.graceSec / 60)} minutes of grace.` });
    } else if (h.status !== 'late') {
      h.status = 'late';
      await h.save();
    }
  }
}