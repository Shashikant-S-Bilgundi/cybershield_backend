import type { Types } from 'mongoose';
import type { ApplicationDoc } from '../models/Application.js';
import { CheckResult } from '../models/CheckResult.js';
import { Monitor } from '../models/Monitor.js';

const DAY = 86_400_000;
const WORST = ['down', 'degraded', 'unknown', 'up', 'paused'];

/** Share of checks that passed (degraded counts as up) over 1, 7 and 30 days, per monitor. */
export async function uptimeFor(ids: Types.ObjectId[]) {
  const now = Date.now();
  const rows = await CheckResult.aggregate<{ _id: Types.ObjectId; t1: number; u1: number; t7: number; u7: number; t30: number; u30: number }>([
    { $match: { monitorId: { $in: ids }, at: { $gte: new Date(now - 30 * DAY) } } },
    {
      $group: {
        _id: '$monitorId',
        t30: { $sum: 1 },
        u30: { $sum: { $cond: [{ $ne: ['$status', 'down'] }, 1, 0] } },
        t7: { $sum: { $cond: [{ $gte: ['$at', new Date(now - 7 * DAY)] }, 1, 0] } },
        u7: { $sum: { $cond: [{ $and: [{ $gte: ['$at', new Date(now - 7 * DAY)] }, { $ne: ['$status', 'down'] }] }, 1, 0] } },
        t1: { $sum: { $cond: [{ $gte: ['$at', new Date(now - DAY)] }, 1, 0] } },
        u1: { $sum: { $cond: [{ $and: [{ $gte: ['$at', new Date(now - DAY)] }, { $ne: ['$status', 'down'] }] }, 1, 0] } },
      },
    },
  ]);
  const pct = (u: number, t: number) => (t ? Math.round((u / t) * 10_000) / 100 : null);
  return new Map(rows.map((r) => [String(r._id), { d1: pct(r.u1, r.t1), d7: pct(r.u7, r.t7), d30: pct(r.u30, r.t30) }]));
}

/** Production health of one application: the worst monitor wins; ticks are the main monitor's last 60 checks. */
export async function appHealth(app: ApplicationDoc) {
  const prod = app.environments.find((e) => e.type === 'production') ?? app.environments[0];
  const monitors = await Monitor.find({ environmentId: prod?._id, deletedAt: null, paused: false });
  const primary = monitors.find((m) => m.type === 'http') ?? monitors[0];
  const state = app.status === 'archived' ? 'paused' : monitors.length ? [...monitors.map((m) => m.status)].sort((a, b) => WORST.indexOf(a) - WORST.indexOf(b))[0] : 'unknown';
  const ticks = primary ? (await CheckResult.find({ monitorId: primary._id }).sort({ at: -1 }).limit(60).lean()).reverse().map((r) => ({ at: r.at.toISOString(), state: r.status, latencyMs: r.latencyMs })) : [];
  const uptime = primary ? (await uptimeFor([primary._id])).get(primary.id) : undefined;
  return { applicationId: app.id, environmentId: prod ? String(prod._id) : '', state, uptime30d: uptime?.d30 ?? null, ticks };
}