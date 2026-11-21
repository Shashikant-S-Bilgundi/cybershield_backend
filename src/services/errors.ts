import { createHash } from 'node:crypto';
import { hashUser, normalizeMessage, scrubTags, scrubText } from '../lib/scrub.js';
import { Application } from '../models/Application.js';
import type { IngestionKeyDoc } from '../models/IngestionKey.js';
import { ErrorEvent, ErrorGroup, ErrorHourly, ErrorUser, type ErrorGroupDoc } from '../models/Telemetry.js';
import { autoResolve, pickRule, raiseAlert } from './alerts.js';

export interface IncomingFrame {
  file: string;
  fn: string;
  line: number;
  column: number;
  inApp: boolean;
  code?: string;
}

export interface IncomingError {
  type: string;
  message: string;
  platform: 'node' | 'browser' | 'react-native';
  release?: string;
  timestamp?: string;
  stack: IncomingFrame[];
  request?: { method: string; route: string; status: number };
  userId?: string;
  tags?: Record<string, string>;
  fingerprint?: string;
}

const HOUR = 3_600_000;
const hourOf = (d: Date) => new Date(Math.floor(d.getTime() / HOUR) * HOUR);
/** Up to this many events per group per hour are stored in full; beyond that they are only counted. */
const SAMPLE_PER_HOUR = 100;

/** Same bug = same type, same message once numbers and ids are removed, same first frame of your own code. */
export function fingerprintOf(e: IncomingError) {
  if (e.fingerprint) return createHash('sha1').update(`custom:${e.fingerprint}`).digest('hex');
  const top = e.stack.find((f) => f.inApp) ?? e.stack[0];
  return createHash('sha1').update([e.platform, e.type, normalizeMessage(e.message), top ? `${top.fn}@${top.file}` : ''].join('|')).digest('hex');
}

const culpritOf = (stack: IncomingFrame[]) => {
  const top = stack.find((f) => f.inApp) ?? stack[0];
  return top ? `${top.fn || '<anonymous>'} in ${top.file}` : '';
};

async function appName(id: unknown) {
  return (await Application.findById(id, { name: 1 }).lean())?.name ?? 'an application';
}

/** Stores a batch of errors for the key's environment: groups them, counts users, opens alerts. */
export async function ingestErrors(key: IngestionKeyDoc, events: IncomingError[]) {
  for (const e of events) {
    const at = e.timestamp && Math.abs(Date.parse(e.timestamp) - Date.now()) < 7 * 86_400_000 ? new Date(e.timestamp) : new Date();
    const message = scrubText(e.message || '(no message)', 2000);
    const fingerprint = fingerprintOf({ ...e, message });
    const release = (e.release ?? '').slice(0, 100);
    const stack = e.stack.slice(0, 50).map((f) => ({ ...f, code: f.code ? scrubText(f.code, 300) : undefined }));

    const existing = await ErrorGroup.findOne({ environmentId: key.environmentId, fingerprint });
    let group: ErrorGroupDoc;
    let isNew = false;
    if (!existing) {
      try {
        group = await ErrorGroup.create({
          applicationId: key.applicationId, environmentId: key.environmentId, fingerprint, type: e.type.slice(0, 200), message, culprit: culpritOf(stack), platform: e.platform,
          firstSeen: at, lastSeen: at, count: 1, lastRelease: release, stack, releases: release ? { [release.replace(/\./g, '\uff0e')]: 1 } : {},
          history: [{ at, actorName: 'ShieldOps', text: 'First seen' }],
        });
        isNew = true;
      } catch {
        // Another request created it at the same moment; count against that one.
        group = (await ErrorGroup.findOne({ environmentId: key.environmentId, fingerprint }))!;
      }
    } else group = existing;

    if (!isNew) {
      const relKey = release ? `releases.${release.replace(/\./g, '\uff0e')}` : null;
      group = (await ErrorGroup.findByIdAndUpdate(
        group._id,
        { $inc: { count: 1, ...(relKey ? { [relKey]: 1 } : {}) }, $max: { lastSeen: at }, $set: { message, stack, ...(release ? { lastRelease: release } : {}) } },
        { new: true },
      ))!;
    }

    const hour = hourOf(at);
    const hourly = await ErrorHourly.findOneAndUpdate({ groupId: group._id, hour }, { $inc: { count: 1 } }, { upsert: true, new: true });
    const userHash = e.userId ? hashUser(e.userId) : null;
    if (userHash) {
      const r = await ErrorUser.updateOne({ groupId: group._id, userHash }, { $setOnInsert: { groupId: group._id, userHash } }, { upsert: true });
      if (r.upsertedCount) await ErrorGroup.updateOne({ _id: group._id }, { $inc: { usersAffected: 1 } });
    }
    if (hourly.count <= SAMPLE_PER_HOUR) {
      await ErrorEvent.create({ groupId: group._id, at, release, message, request: e.request ?? null, userHash, tags: scrubTags(e.tags) });
    }

    const where = { applicationId: group.applicationId, environmentId: group.environmentId, source: 'errors' };
    const title = `${group.type}: ${group.message}`.slice(0, 160);
    if (isNew) {
      await raiseAlert({ ...where, key: `error:new:${group.id}`, signal: 'error_new', title: `New error on ${await appName(group.applicationId)}: ${title}`, message: `First seen in ${group.culprit || 'unknown code'}${release ? ` (${release})` : ''}.` });
    } else if (group.status === 'resolved') {
      // A resolved error that happens again is a regression, never silently reopened.
      group.status = 'regressed';
      group.history.unshift({ at, actorName: 'ShieldOps', text: `Happened again after being resolved${release ? `, in ${release}` : ''}` });
      await group.save();
      await raiseAlert({ ...where, key: `error:regressed:${group.id}`, signal: 'error_regression', title: `${group.type} is back on ${await appName(group.applicationId)}`, message: `Marked resolved ${group.resolvedAt?.toISOString().slice(0, 10) ?? 'earlier'}; it has happened again${release ? ` in ${release}` : ''}.` });
    }
    if (group.status !== 'ignored') await checkSpike(group, hour, hourly.count, where, title);
  }
}

/** A spike: this hour's count is at least the rule's multiple of the average hour over the last day. */
async function checkSpike(group: ErrorGroupDoc, hour: Date, thisHour: number, where: { applicationId: unknown; environmentId: unknown; source: string }, title: string) {
  if (thisHour < 20 || thisHour % 10 !== 0) return;
  const rule = await pickRule({ signal: 'error_spike', key: '', applicationId: group.applicationId, environmentId: group.environmentId, source: 'errors', title: '', message: '' });
  if (!rule?.threshold) return;
  const rows = await ErrorHourly.find({ groupId: group._id, hour: { $gte: new Date(hour.getTime() - 24 * HOUR), $lt: hour } }).lean();
  const baseline = rows.reduce((n, r) => n + r.count, 0) / 24;
  if (thisHour >= rule.threshold * Math.max(baseline, 1)) {
    await raiseAlert({ ...where, applicationId: group.applicationId as never, environmentId: group.environmentId as never, key: `error:spike:${group.id}:${hour.getTime()}`, signal: 'error_spike', title: `Error spike: ${title}`, message: `${thisHour} events this hour against a usual ${baseline.toFixed(1)} per hour.` });
  }
}

/** Resolving or ignoring a group closes the alerts about it. */
export async function closeGroupAlerts(groupId: string) {
  await autoResolve(`error:new:${groupId}`);
  await autoResolve(`error:regressed:${groupId}`);
}

/** Events per hour for the last 24 hours, oldest first. */
export async function trends(groupIds: ErrorGroupDoc['_id'][]) {
  const now = Date.now();
  const start = hourOf(new Date(now - 23 * HOUR));
  const rows = await ErrorHourly.find({ groupId: { $in: groupIds }, hour: { $gte: start } }).lean();
  const map = new Map<string, number[]>();
  for (const r of rows) {
    const arr = map.get(String(r.groupId)) ?? Array(24).fill(0);
    const i = Math.round((r.hour.getTime() - start.getTime()) / HOUR);
    if (i >= 0 && i < 24) arr[i] += r.count;
    map.set(String(r.groupId), arr);
  }
  return map;
}