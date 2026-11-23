import type { Types } from 'mongoose';
import { percentile, BUCKETS, mergeInto } from '../lib/histogram.js';
import { Alert } from '../models/Alert.js';
import { Release, type ReleaseDoc } from '../models/Advanced.js';
import { ErrorGroup, PerfMinute } from '../models/Telemetry.js';

const HOUR = 3_600_000;

/** Records a deploy. The same version twice is one release (the first time it was seen). */
export async function recordRelease(applicationId: Types.ObjectId, environmentId: Types.ObjectId, version: string, extra: { commit?: string; deployedBy?: string; at?: Date } = {}) {
  const v = version.trim().slice(0, 100);
  if (!v) return null;
  return Release.findOneAndUpdate(
    { environmentId, version: v },
    { $setOnInsert: { applicationId, environmentId, version: v, deployedAt: extra.at ?? new Date(), commit: (extra.commit ?? '').slice(0, 40), deployedBy: (extra.deployedBy ?? '').slice(0, 100) } },
    { upsert: true, new: true },
  );
}

async function window(environmentId: Types.ObjectId, from: Date, to: Date) {
  const rows = await PerfMinute.find({ environmentId, minute: { $gte: from, $lt: to } }, { count: 1, serverErrors: 1, buckets: 1 }).lean();
  const b = Array(BUCKETS).fill(0);
  let count = 0;
  let errors = 0;
  for (const r of rows) {
    count += r.count ?? 0;
    errors += r.serverErrors ?? 0;
    mergeInto(b, r.buckets ?? []);
  }
  return count ? { errorRate: Math.round((errors / count) * 1000) / 10, p95: percentile(b, 0.95), count } : null;
}

/**
 * Each release compared with the 24 hours before it: new error groups, alerts, 5xx rate and p95.
 * "Possible regression" if it brought new errors or alerts, or made either number clearly worse.
 */
export async function releaseView(r: ReleaseDoc, next: ReleaseDoc | undefined) {
  const start = r.deployedAt;
  const end = new Date(Math.min(start.getTime() + 24 * HOUR, next?.deployedAt.getTime() ?? Infinity, Date.now()));
  const [before, after, newErrorGroups, alertsAfter] = await Promise.all([
    window(r.environmentId, new Date(start.getTime() - 24 * HOUR), start),
    end.getTime() - start.getTime() >= 15 * 60_000 ? window(r.environmentId, start, end) : Promise.resolve(null),
    ErrorGroup.countDocuments({ environmentId: r.environmentId, firstSeen: { $gte: start, $lt: end } }),
    Alert.countDocuments({ environmentId: r.environmentId, firstAt: { $gte: start, $lt: end }, source: { $in: ['uptime', 'errors', 'performance', 'infrastructure'] } }),
  ]);
  const worse = !!(before && after && (after.errorRate > before.errorRate * 1.15 + 0.2 || after.p95 > before.p95 * 1.15 + 20));
  const young = Date.now() - start.getTime() < 24 * HOUR;
  const verdict = newErrorGroups > 0 || alertsAfter > 0 || worse ? 'regression' : young ? 'watching' : 'healthy';
  return {
    id: r.id, applicationId: String(r.applicationId), environmentId: String(r.environmentId), version: r.version, commit: r.commit, deployedAt: r.deployedAt, deployedBy: r.deployedBy || 'SDK',
    newErrorGroups, alertsAfter, before: before ? { errorRate: before.errorRate, p95: before.p95 } : { errorRate: 0, p95: 0 }, after: after ? { errorRate: after.errorRate, p95: after.p95 } : null, verdict,
  };
}

export async function releaseViews(filter: Record<string, unknown>) {
  const rels = await Release.find(filter).sort({ deployedAt: -1 }).limit(100);
  // The next release in the same environment cuts the "after" window short.
  return Promise.all(rels.map((r) => releaseView(r, rels.filter((x) => String(x.environmentId) === String(r.environmentId) && x.deployedAt > r.deployedAt).at(-1))));
}