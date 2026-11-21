import type { Types } from 'mongoose';
import { BUCKETS, mergeInto, percentile } from '../lib/histogram.js';
import type { IngestionKeyDoc } from '../models/IngestionKey.js';
import { PerfMinute } from '../models/Telemetry.js';
import { autoResolve, pickRule, raiseAlert } from './alerts.js';

const MIN = 60_000;

export interface IncomingRoute {
  method: string;
  route: string;
  count: number;
  errors: number;
  sumMs: number;
  buckets: number[];
}

/** Adds one SDK report (usually one minute) into per-minute, per-route totals. */
export async function ingestMetrics(key: IngestionKeyDoc, windowStart: Date, routes: IncomingRoute[]) {
  const minute = new Date(Math.floor(windowStart.getTime() / MIN) * MIN);
  for (const r of routes) {
    const inc: Record<string, number> = { count: r.count, serverErrors: r.errors, sumMs: r.sumMs };
    r.buckets.slice(0, BUCKETS).forEach((n, i) => (inc[`buckets.${i}`] = n));
    await PerfMinute.updateOne(
      { environmentId: key.environmentId, minute, method: r.method.toUpperCase().slice(0, 10), route: r.route.slice(0, 300) },
      { $inc: inc, $setOnInsert: { applicationId: key.applicationId } },
      { upsert: true },
    );
  }
  await autoResolve(`perf:traffic:${key.environmentId}`);
  await checkErrorRate(key.applicationId, key.environmentId);
}

interface Agg {
  count: number;
  errors: number;
  buckets: number[];
}
const empty = (): Agg => ({ count: 0, errors: 0, buckets: Array(BUCKETS).fill(0) });
const add = (a: Agg, r: { count?: number | null; serverErrors?: number | null; buckets?: number[] }) => {
  a.count += r.count ?? 0;
  a.errors += r.serverErrors ?? 0;
  mergeInto(a.buckets, r.buckets ?? []);
  return a;
};
const rate = (a: Agg) => (a.count ? Math.round((a.errors / a.count) * 10_000) / 100 : 0);

/** 5xx share over the rule's window; opens an alert above the threshold (with enough traffic to mean something). */
async function checkErrorRate(applicationId: Types.ObjectId, environmentId: Types.ObjectId) {
  const rule = await pickRule({ signal: 'error_rate', key: '', applicationId, environmentId, source: 'performance', title: '', message: '' });
  if (!rule?.threshold) return;
  const since = new Date(Date.now() - (rule.durationMin ?? 5) * MIN);
  const rows = await PerfMinute.find({ environmentId, minute: { $gte: since } }, { count: 1, serverErrors: 1 }).lean();
  const a = rows.reduce((acc, r) => add(acc, r), empty());
  const key = `perf:5xx:${environmentId}`;
  if (a.count >= 20 && rate(a) > rule.threshold) {
    await raiseAlert({ key, signal: 'error_rate', value: rate(a), applicationId, environmentId, source: 'performance', title: `5xx rate above ${rule.threshold}%: ${rate(a)}%`, message: `${a.errors} of ${a.count} requests failed with a server error in the last ${rule.durationMin ?? 5} minutes.` });
  } else if (a.count >= 20) await autoResolve(key);
}

/** Environments that had steady traffic in the last hour but none in the last N minutes. Run by the scheduler. */
export async function checkTrafficDrops() {
  const now = Date.now();
  const recent = await PerfMinute.aggregate<{ _id: Types.ObjectId; app: Types.ObjectId; total: number; last: Date }>([
    { $match: { minute: { $gte: new Date(now - 70 * MIN) } } },
    { $group: { _id: '$environmentId', app: { $first: '$applicationId' }, total: { $sum: '$count' }, last: { $max: '$minute' } } },
  ]);
  for (const env of recent) {
    const rule = await pickRule({ signal: 'traffic_drop', key: '', applicationId: env.app, environmentId: env._id, source: 'performance', title: '', message: '' });
    if (!rule?.threshold || env.total < 100) continue;
    const quietMin = (now - env.last.getTime()) / MIN - 1;
    if (quietMin >= rule.threshold) {
      await raiseAlert({ key: `perf:traffic:${env._id}`, signal: 'traffic_drop', value: rule.threshold, applicationId: env.app, environmentId: env._id, source: 'performance', title: `No traffic for ${Math.floor(quietMin)} minutes`, message: `The SDK has reported no requests since ${env.last.toISOString()}, after ${env.total} in the hour before. The app or its SDK may have stopped.` });
    }
  }
}

/** Summary over the last 5 minutes: requests per minute, 5xx share and p95. */
export async function summaries(filter: { applicationId?: string; environmentId?: string }) {
  const since = new Date(Date.now() - 15 * MIN);
  const rows = await PerfMinute.find({ minute: { $gte: since }, ...filter }).lean();
  const byEnv = new Map<string, { app: string; recent: Agg; last: Date }>();
  for (const r of rows) {
    const k = String(r.environmentId);
    const e = byEnv.get(k) ?? { app: String(r.applicationId), recent: empty(), last: r.minute };
    if (r.minute.getTime() >= Date.now() - 5 * MIN) add(e.recent, r);
    if (r.minute > e.last) e.last = r.minute;
    byEnv.set(k, e);
  }
  return [...byEnv.entries()].map(([environmentId, e]) => ({
    applicationId: e.app,
    environmentId,
    rpm: Math.round((e.recent.count / 5) * 10) / 10,
    errorRate: rate(e.recent),
    p95: percentile(e.recent.buckets, 0.95),
    lastSampleAt: new Date(e.last.getTime() + MIN).toISOString(),
  }));
}

const RANGES = { '1h': { points: 60, step: MIN }, '24h': { points: 96, step: 15 * MIN }, '7d': { points: 84, step: 120 * MIN } } as const;

/** Chart points, totals and per-route figures for one environment over 1 hour, 24 hours or 7 days. */
export async function report(applicationId: string, environmentId: string, range: keyof typeof RANGES) {
  const { points, step } = RANGES[range];
  const end = Math.ceil(Date.now() / step) * step;
  const start = end - points * step;
  const rows = await PerfMinute.find({ environmentId, minute: { $gte: new Date(start) } }).lean();
  const series = Array.from({ length: points }, () => empty());
  const routes = new Map<string, Agg & { method: string; route: string }>();
  const total = empty();
  for (const r of rows) {
    const i = Math.floor((r.minute.getTime() - start) / step);
    if (i >= 0 && i < points) add(series[i], r);
    add(total, r);
    const k = `${r.method} ${r.route}`;
    const cur = routes.get(k) ?? { ...empty(), method: r.method, route: r.route };
    add(cur, r);
    routes.set(k, cur);
  }
  const [s] = await summaries({ environmentId });
  return {
    applicationId,
    environmentId,
    range,
    rpm: s?.rpm ?? 0,
    errorRate: rate(total),
    p95: percentile(total.buckets, 0.95),
    lastSampleAt: s?.lastSampleAt ?? null,
    requests: total.count,
    p50: percentile(total.buckets, 0.5),
    p99: percentile(total.buckets, 0.99),
    series: series.map((a, i) => ({ at: new Date(start + (i + 1) * step).toISOString(), rpm: Math.round((a.count / (step / MIN)) * 10) / 10, errorRate: rate(a), p50: percentile(a.buckets, 0.5), p95: percentile(a.buckets, 0.95) })),
    routes: [...routes.values()]
      .map((r) => ({ method: r.method, route: r.route, requests: r.count, errorRate: rate(r), p50: percentile(r.buckets, 0.5), p95: percentile(r.buckets, 0.95), p99: percentile(r.buckets, 0.99) }))
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 200),
  };
}