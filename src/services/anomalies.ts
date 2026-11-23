import type { Types } from 'mongoose';
import { BUCKETS, percentile } from '../lib/histogram.js';
import { logger } from '../lib/logger.js';
import { Anomaly, type AnomalyDoc } from '../models/Advanced.js';
import { Application } from '../models/Application.js';
import { ErrorEvent, ErrorGroup, PerfMinute, SecurityEvent } from '../models/Telemetry.js';
import { autoResolve, pickRule, raiseAlert } from './alerts.js';

type Metric = 'requests' | 'error_rate' | 'p95' | 'login_failures' | 'error_events';
const STEP = 10 * 60_000;
const DAY = 86_400_000;
const floorStep = (t: number) => Math.floor(t / STEP) * STEP;

const META: Record<Metric, { unit: string; up: string; down: string; minMean: number; minValue: number; floor: number; directions: ('up' | 'down')[] }> = {
  requests: { unit: 'requests/min', up: 'Traffic far above normal', down: 'Traffic dropped', minMean: 5, minValue: 10, floor: 3, directions: ['up', 'down'] },
  error_rate: { unit: '% 5xx', up: '5xx rate far above normal', down: '', minMean: 0, minValue: 2, floor: 1, directions: ['up'] },
  p95: { unit: 'ms', up: 'Responses slower than usual', down: '', minMean: 0, minValue: 300, floor: 100, directions: ['up'] },
  login_failures: { unit: 'failures/10 min', up: 'Failed logins spiked', down: '', minMean: 0, minValue: 10, floor: 3, directions: ['up'] },
  error_events: { unit: 'events/10 min', up: 'Error events far above normal', down: '', minMean: 0, minValue: 10, floor: 3, directions: ['up'] },
};

/** Value per 10-minute block, computed inside MongoDB. Blocks with too little traffic for a rate are left out. */
async function blocks(environmentId: Types.ObjectId, metric: Metric, from: number, to: number): Promise<Map<number, number>> {
  const out = new Map<number, number>();
  const block = (field: string) => ({ $subtract: [{ $toLong: field }, { $mod: [{ $toLong: field }, STEP] }] });
  if (metric === 'requests' || metric === 'error_rate') {
    const rows = await PerfMinute.aggregate<{ _id: number; count: number; errors: number }>([
      { $match: { environmentId, minute: { $gte: new Date(from), $lt: new Date(to) } } },
      { $group: { _id: block('$minute'), count: { $sum: '$count' }, errors: { $sum: '$serverErrors' } } },
    ]);
    for (const r of rows) {
      if (metric === 'requests') out.set(r._id, Math.round((r.count / 10) * 10) / 10);
      else if (r.count >= 20) out.set(r._id, Math.round((r.errors / r.count) * 1000) / 10);
    }
  } else if (metric === 'p95') {
    const rows = await PerfMinute.aggregate<{ _id: { b: number; i: number }; n: number }>([
      { $match: { environmentId, minute: { $gte: new Date(from), $lt: new Date(to) } } },
      { $project: { b: block('$minute'), buckets: 1 } },
      { $unwind: { path: '$buckets', includeArrayIndex: 'i' } },
      { $group: { _id: { b: '$b', i: '$i' }, n: { $sum: '$buckets' } } },
    ]);
    const hist = new Map<number, number[]>();
    for (const r of rows) {
      const h = hist.get(r._id.b) ?? Array(BUCKETS).fill(0);
      h[r._id.i] = r.n;
      hist.set(r._id.b, h);
    }
    for (const [b, h] of hist) if (h.reduce((a, c) => a + c, 0) >= 20) out.set(b, percentile(h, 0.95));
  } else if (metric === 'login_failures') {
    const rows = await SecurityEvent.aggregate<{ _id: number; n: number }>([
      { $match: { environmentId, type: { $in: ['login_failure', 'mfa_failure'] }, at: { $gte: new Date(from), $lt: new Date(to) } } },
      { $group: { _id: block('$at'), n: { $sum: 1 } } },
    ]);
    rows.forEach((r) => out.set(r._id, r.n));
  } else {
    const groups = (await ErrorGroup.find({ environmentId }, { _id: 1 }).lean()).map((g) => g._id);
    const rows = await ErrorEvent.aggregate<{ _id: number; n: number }>([{ $match: { groupId: { $in: groups }, at: { $gte: new Date(from), $lt: new Date(to) } } }, { $group: { _id: block('$at'), n: { $sum: 1 } } }]);
    rows.forEach((r) => out.set(r._id, r.n));
  }
  return out;
}

/**
 * The usual range for a block: the same time of day on each of the previous 7 days, plus the blocks either
 * side, so a quiet Sunday night is compared with other nights. Needs at least 5 samples.
 * Missing blocks count as 0 for counts (no traffic is a real value) but are skipped for rates.
 */
function band(map: Map<number, number>, at: number, metric: Metric, k: number, hasHistory: boolean) {
  const samples: number[] = [];
  for (let d = 1; d <= 7; d++) {
    for (const off of [-STEP, 0, STEP]) {
      const t = at - d * DAY + off;
      const v = map.get(t);
      if (v !== undefined) samples.push(v);
      else if (hasHistory && (metric === 'requests' || metric === 'login_failures' || metric === 'error_events')) samples.push(0);
    }
  }
  if (samples.length < 5) return null;
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
  const sd = Math.sqrt(samples.reduce((a, b) => a + (b - mean) ** 2, 0) / samples.length);
  const width = Math.max(k * sd, META[metric].floor, mean * 0.25);
  const r = (n: number) => Math.round(n * 10) / 10;
  return { mean, low: r(Math.max(0, mean - width)), high: r(mean + width) };
}

const SENSITIVITY: Record<number, number> = { 1: 4, 2: 3, 3: 2.5 };

/** Run by the scheduler every few minutes: checks the last complete block of each metric in each environment. */
export async function detectAnomalies() {
  const now = Date.now();
  const current = floorStep(now) - STEP;
  const envs = new Map<string, Types.ObjectId>();
  for (const id of [...(await PerfMinute.distinct('environmentId', { minute: { $gte: new Date(now - 8 * DAY) } })), ...(await SecurityEvent.distinct('environmentId', { at: { $gte: new Date(now - 8 * DAY) } })), ...(await ErrorGroup.distinct('environmentId', { lastSeen: { $gte: new Date(now - 8 * DAY) } }))]) envs.set(String(id), id as Types.ObjectId);
  for (const environmentId of envs.values()) {
    const app = await Application.findOne({ 'environments._id': environmentId, deletedAt: null }, { name: 1 });
    if (!app) continue;
    const rule = await pickRule({ signal: 'anomaly', key: '', applicationId: app._id, environmentId, source: 'anomaly', title: '', message: '' });
    const k = SENSITIVITY[rule?.threshold ?? 2] ?? 3;
    for (const metric of Object.keys(META) as Metric[]) {
      try {
        const map = await blocks(environmentId, metric, current - 8 * DAY, current + STEP);
        const hasHistory = [...map.keys()].some((t) => t < current - DAY);
        const b = band(map, current, metric, k, hasHistory);
        const value = map.get(current) ?? (metric === 'requests' || metric === 'login_failures' || metric === 'error_events' ? 0 : undefined);
        const open = await Anomaly.findOne({ environmentId, metric, endedAt: null });
        const m = META[metric];
        const dir = !b || value === undefined ? null : value > b.high && value >= m.minValue && m.directions.includes('up') ? 'up' : value < b.low && b.mean >= m.minMean && m.directions.includes('down') ? 'down' : null;
        const key = `anomaly:${environmentId}:${metric}`;
        if (dir && b && value !== undefined) {
          const title = `${dir === 'up' ? m.up : m.down} on ${app.name}`;
          const a = open ?? new Anomaly({ applicationId: app._id, environmentId, metric, direction: dir, startedAt: new Date(current), title, unit: m.unit, actual: value, expectedLow: b.low, expectedHigh: b.high });
          a.set({ actual: value, expectedLow: b.low, expectedHigh: b.high, direction: dir, title });
          if (rule) {
            const alert = await raiseAlert({ key, signal: 'anomaly', applicationId: app._id, environmentId, source: 'anomaly', title, message: `${value} ${m.unit}, against a usual ${b.low} to ${b.high} at this time of day.` });
            if (alert) a.alertId = alert._id;
          }
          await a.save();
        } else if (open && value !== undefined) {
          open.endedAt = new Date();
          await open.save();
          await autoResolve(key);
        }
      } catch (err) {
        logger.error({ err, metric }, 'Anomaly check failed');
      }
    }
  }
}

/** Anomalies of the last 30 days, ongoing first, each with 8 hours of actual values against the usual range. */
export async function anomalyViews(filter: Record<string, unknown>) {
  const list = (await Anomaly.find(filter).sort({ startedAt: -1 }).limit(50)) as AnomalyDoc[];
  list.sort((a, b) => Number(!!a.endedAt) - Number(!!b.endedAt));
  const now = floorStep(Date.now());
  const out = [];
  for (const a of list) {
    const map = await blocks(a.environmentId, a.metric as Metric, now - 8 * 3_600_000 - 8 * DAY, now + STEP);
    const hasHistory = [...map.keys()].some((t) => t < now - DAY);
    const series = Array.from({ length: 48 }, (_, i) => {
      const at = now - (47 - i) * STEP;
      const b = band(map, at, a.metric as Metric, 3, hasHistory);
      return { at: new Date(at).toISOString(), actual: map.get(at) ?? 0, low: b?.low ?? 0, high: b?.high ?? 0 };
    });
    out.push({
      id: a.id, applicationId: String(a.applicationId), environmentId: String(a.environmentId), metric: a.metric, title: a.title, direction: a.direction, actual: a.actual,
      expectedLow: a.expectedLow, expectedHigh: a.expectedHigh, unit: a.unit, startedAt: a.startedAt, endedAt: a.endedAt, alertId: a.alertId ? String(a.alertId) : null, series,
    });
  }
  return out;
}