import { remoteSaysUp } from './probes.js';
import { classify, guardedGet, guardedTcp, lookupRecords, type CheckError } from '../lib/probe.js';
import { logger } from '../lib/logger.js';
import { AlertRule } from '../models/AlertRule.js';
import { CheckResult } from '../models/CheckResult.js';
import { Monitor, type MonitorDoc } from '../models/Monitor.js';
import { autoResolve, raiseAlert } from './alerts.js';
import { getAllowlist } from './settings.js';

/** A response slower than this counts as "degraded" (still up). */
const SLOW_MS = 2000;

interface Outcome {
  status: 'up' | 'degraded' | 'down';
  latencyMs: number | null;
  statusCode?: number;
  error?: CheckError;
}

function statusMatches(code: number, expected?: string | null) {
  const spec = (expected ?? '').trim() || '200-399';
  return spec.split(',').some((part) => {
    const [a, b] = part.trim().split('-').map(Number);
    return b ? code >= a && code <= b : code === a;
  });
}

/** Runs one check. Network failures become a result, never an exception. */
export async function probe(m: Pick<MonitorDoc, 'type' | 'target' | 'timeoutMs' | 'expectedStatus' | 'keyword' | 'recordType'>): Promise<Outcome> {
  const allow = await getAllowlist();
  const started = performance.now();
  try {
    if (m.type === 'http') {
      const r = await guardedGet(m.target, allow, { timeoutMs: m.timeoutMs, readBody: !!m.keyword, maxBytes: 1024 * 1024 });
      if (!statusMatches(r.status, m.expectedStatus)) return { status: 'down', latencyMs: r.latencyMs, statusCode: r.status, error: 'UNEXPECTED_STATUS' };
      if (m.keyword && !r.body.includes(m.keyword)) return { status: 'down', latencyMs: r.latencyMs, statusCode: r.status, error: 'KEYWORD_MISSING' };
      return { status: r.latencyMs > SLOW_MS ? 'degraded' : 'up', latencyMs: r.latencyMs, statusCode: r.status };
    }
    if (m.type === 'tcp') {
      const i = m.target.lastIndexOf(':');
      const ms = await guardedTcp(m.target.slice(0, i), Number(m.target.slice(i + 1)), allow, m.timeoutMs);
      return { status: ms > SLOW_MS ? 'degraded' : 'up', latencyMs: ms };
    }
    const records = await Promise.race([
      lookupRecords(m.target, (m.recordType ?? 'A') as 'A'),
      new Promise<never>((_, rej) => setTimeout(() => rej(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })), m.timeoutMs)),
    ]);
    const ms = Math.round(performance.now() - started);
    return records.length ? { status: 'up', latencyMs: ms } : { status: 'down', latencyMs: ms, error: 'DNS_ERROR' };
  } catch (err) {
    return { status: 'down', latencyMs: null, error: classify(err) };
  }
}

const REASON: Record<CheckError, string> = {
  TIMEOUT: 'No response before the timeout',
  DNS_ERROR: 'The name did not resolve',
  TLS_ERROR: 'The TLS connection failed',
  CONNECTION_REFUSED: 'The connection was refused',
  UNEXPECTED_STATUS: 'Unexpected HTTP status',
  KEYWORD_MISSING: 'The expected text was missing',
  WORKER_ERROR: 'The check could not run',
};

/** Runs a monitor, stores the result, moves its status and opens or closes alerts. */
export async function runMonitor(m: MonitorDoc) {
  const out = await probe(m);
  const now = new Date();
  await CheckResult.create({ monitorId: m._id, at: now, status: out.status, latencyMs: out.latencyMs, statusCode: out.statusCode, error: out.error });

  const before = m.status;
  m.lastCheckAt = now;
  m.lastLatencyMs = out.latencyMs;
  // A failure here but success from another location points at the network near ShieldOps, not an outage.
  const otherSide = out.status === 'down' ? await remoteSaysUp(m._id, m.intervalSec) : null;
  if (out.status === 'down' && otherSide) {
    m.consecutiveFailures = 0;
    m.status = 'degraded';
    if (before !== 'degraded') {
      m.events.unshift({ at: now, from: before, to: 'degraded', reason: `Failed from this server (${REASON[out.error!]}) but reachable from ${otherSide}: not counted as down` } as never);
      m.events.splice(50);
    }
    await m.save();
    return out;
  }
  if (out.status === 'down') {
    m.consecutiveFailures += 1;
    if (m.consecutiveFailures >= m.downAfterFailures) m.status = 'down';
    else if (before === 'unknown' || before === 'up') m.status = before === 'unknown' ? 'unknown' : 'degraded';
  } else {
    m.consecutiveFailures = 0;
    m.status = out.status;
  }
  if (m.status !== before) {
    const reason = out.status === 'down' ? `${REASON[out.error!]}${out.statusCode ? ` (${out.statusCode})` : ''}` : before === 'down' ? 'Recovered' : out.status === 'degraded' ? `Slow response: ${out.latencyMs} ms` : 'Checks passing';
    m.events.unshift({ at: now, from: before, to: m.status, reason } as never);
    m.events.splice(50);
  }
  await m.save();

  const where = { key: `uptime:${m.id}`, applicationId: m.applicationId, environmentId: m.environmentId, assetId: m.assetId, source: 'uptime' };
  if (m.status === 'down') {
    await raiseAlert({ ...where, signal: 'uptime_down', value: m.consecutiveFailures, title: `${m.name} is down`, message: `${m.target}: ${REASON[out.error ?? 'WORKER_ERROR']}${out.statusCode ? ` (HTTP ${out.statusCode})` : ''}. ${m.consecutiveFailures} failed checks in a row.` });
  } else if (out.status !== 'down') await autoResolve(where.key);

  if (m.type === 'http') await checkLatency(m);
  return out;
}

/** p95 over the rule's window; opens a "slow responses" alert above the threshold, closes it below. */
async function checkLatency(m: MonitorDoc) {
  const rule = await AlertRule.findOne({ signal: 'latency_p95', enabled: true }).sort({ threshold: 1 });
  const key = `latency:${m.id}`;
  if (!rule?.threshold) return;
  const since = new Date(Date.now() - (rule.durationMin ?? 5) * 60_000);
  const rows = await CheckResult.find({ monitorId: m._id, at: { $gte: since }, latencyMs: { $ne: null } }, { latencyMs: 1 }).lean();
  if (rows.length < 3) return;
  const sorted = rows.map((r) => r.latencyMs!).sort((a, b) => a - b);
  const p95 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))];
  if (p95 > rule.threshold) {
    await raiseAlert({ key, signal: 'latency_p95', value: p95, applicationId: m.applicationId, environmentId: m.environmentId, assetId: m.assetId, source: 'uptime', title: `${m.name} responses slower than ${rule.threshold.toLocaleString('en-IN')} ms`, message: `p95 response time is ${p95} ms over the last ${rule.durationMin ?? 5} minutes.` });
  } else await autoResolve(key);
}

/** Claims and runs monitors that are due. The claim moves nextCheckAt first, so a check never runs twice. */
export async function runDueMonitors(limit = 20) {
  const jobs: Promise<unknown>[] = [];
  for (let i = 0; i < limit; i++) {
    const now = new Date();
    const m = await Monitor.findOneAndUpdate(
      { paused: false, deletedAt: null, nextCheckAt: { $lte: now } },
      [{ $set: { nextCheckAt: { $add: [now, { $multiply: ['$intervalSec', 1000] }] } } }],
      { new: true },
    );
    if (!m) break;
    jobs.push(runMonitor(m).catch((err) => logger.error({ err, monitor: m.id }, 'Monitor check failed')));
  }
  await Promise.all(jobs);
}