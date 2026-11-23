import type { Request } from 'express';
import type { Types } from 'mongoose';
import { randomBytes } from 'node:crypto';
import { sha256 } from '../lib/crypto.js';
import { ApiError } from '../lib/errors.js';
import { Asset } from '../models/Asset.js';
import { CheckResult } from '../models/CheckResult.js';
import { Probe, ProbeResult, type ProbeDoc } from '../models/Advanced.js';
import { Monitor } from '../models/Monitor.js';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
const ONLINE_MS = 3 * 60_000;

export function newProbeSecret() {
  const secret = `so_probe_${Array.from(randomBytes(32), (b) => ALPHABET[b % ALPHABET.length]).join('')}`;
  return { secret, prefix: secret.slice(0, 13), hash: sha256(secret) };
}

export async function authenticateProbe(req: Request): Promise<ProbeDoc> {
  const raw = (req.get('authorization')?.replace(/^Bearer\s+/i, '') ?? '').trim();
  if (!/^so_probe_[A-Za-z0-9]{20,64}$/.test(raw)) throw new ApiError(401, 'INVALID_TOKEN', 'Missing or malformed probe token.');
  const p = await Probe.findOne({ hash: sha256(raw) });
  if (!p) throw new ApiError(401, 'INVALID_TOKEN', 'This probe token is unknown or the probe was removed.');
  return p;
}

export const isOnline = (p: { lastSeenAt?: Date | null }) => !!p.lastSeenAt && Date.now() - p.lastSeenAt.getTime() < ONLINE_MS;

export const BUILT_IN = { id: 'local', name: 'This server', region: 'Where ShieldOps runs', kind: 'built_in' as const };

export async function probeViews() {
  const remote = await Probe.find().sort({ createdAt: 1 });
  return [
    { ...BUILT_IN, status: 'online', lastSeenAt: new Date(), prefix: null, createdAt: null },
    ...remote.map((p) => ({ id: p.id, name: p.name, region: p.region, kind: 'remote', status: isOnline(p) ? 'online' : 'offline', lastSeenAt: p.lastSeenAt, prefix: p.prefix, createdAt: (p as unknown as { createdAt: Date }).createdAt })),
  ];
}

/**
 * What a remote probe should check: active monitors on assets marked as reachable from the internet.
 * Internal assets are never handed to a probe outside your network.
 */
export async function probeWork() {
  const internet = (await Asset.find({ deletedAt: null, exposure: 'internet' }, { _id: 1 }).lean()).map((a) => a._id);
  const ms = await Monitor.find({ deletedAt: null, paused: false, assetId: { $in: internet } }).lean();
  return ms.map((m) => ({ id: String(m._id), type: m.type, target: m.target, intervalSec: m.intervalSec, timeoutMs: m.timeoutMs, expectedStatus: m.expectedStatus ?? '', keyword: m.keyword ?? '', recordType: m.recordType ?? 'A' }));
}

export async function recordProbeResults(p: ProbeDoc, results: { monitorId: string; at?: string; status: 'up' | 'degraded' | 'down'; latencyMs: number | null; error?: string }[]) {
  const allowed = new Set((await probeWork()).map((w) => w.id));
  for (const r of results) {
    if (!allowed.has(r.monitorId)) continue;
    await ProbeResult.updateOne(
      { probeId: p._id, monitorId: r.monitorId },
      { at: r.at && Math.abs(Date.parse(r.at) - Date.now()) < 10 * 60_000 ? new Date(r.at) : new Date(), status: r.status, latencyMs: r.latencyMs, error: r.error?.slice(0, 200) ?? null },
      { upsert: true },
    );
  }
}

/**
 * Before a monitor is marked down: did an online remote probe reach it successfully in the last two intervals?
 * Returns that probe's name, so the event can say why the outage was not counted.
 */
export async function remoteSaysUp(monitorId: Types.ObjectId, intervalSec: number): Promise<string | null> {
  const since = new Date(Date.now() - Math.max(2 * intervalSec * 1000, 90_000));
  const ok = await ProbeResult.find({ monitorId, at: { $gte: since }, status: { $in: ['up', 'degraded'] } }).lean();
  for (const r of ok) {
    const p = await Probe.findById(r.probeId);
    if (p && isOnline(p)) return p.name;
  }
  return null;
}

/** Latest result per location for one monitor: this server's last check, then each remote probe. */
export async function probeResultsFor(monitorId: Types.ObjectId) {
  const last = await CheckResult.findOne({ monitorId }).sort({ at: -1 }).lean();
  const out = [{ probeId: BUILT_IN.id, probeName: BUILT_IN.name, status: last?.status ?? 'unknown', latencyMs: last?.latencyMs ?? null, at: last?.at ?? new Date(), error: last?.error ?? null }];
  for (const p of await Probe.find().sort({ createdAt: 1 })) {
    const r = await ProbeResult.findOne({ probeId: p._id, monitorId }).lean();
    if (!isOnline(p)) out.push({ probeId: p.id, probeName: p.name, status: 'unknown', latencyMs: null, at: p.lastSeenAt ?? new Date(), error: 'Probe is offline' });
    else if (!r) out.push({ probeId: p.id, probeName: p.name, status: 'unknown', latencyMs: null, at: new Date(), error: 'Not checked by this probe (internal asset, or not yet)' });
    else out.push({ probeId: p.id, probeName: p.name, status: r.status, latencyMs: r.latencyMs ?? null, at: r.at, error: r.error ?? null });
  }
  return out;
}