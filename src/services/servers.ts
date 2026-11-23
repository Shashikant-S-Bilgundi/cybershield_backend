import type { Request } from 'express';
import type { Types } from 'mongoose';
import { randomBytes } from 'node:crypto';
import { sha256 } from '../lib/crypto.js';
import { ApiError } from '../lib/errors.js';
import { AgentToken, Server, ServerSample, type AgentTokenDoc, type ServerDoc } from '../models/Infra.js';
import { autoResolve, pickRule, raiseAlert } from './alerts.js';

const MIN = 60_000;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

export function newAgentSecret() {
  const body = Array.from(randomBytes(32), (b) => ALPHABET[b % ALPHABET.length]).join('');
  const secret = `so_agent_${body}`;
  return { secret, prefix: secret.slice(0, 13), hash: sha256(secret) };
}

export async function authenticateAgent(req: Request): Promise<AgentTokenDoc> {
  const raw = (req.get('authorization')?.replace(/^Bearer\s+/i, '') ?? '').trim();
  if (!/^so_agent_[A-Za-z0-9]{20,64}$/.test(raw)) throw new ApiError(401, 'INVALID_TOKEN', 'Missing or malformed agent token.');
  const hash = sha256(raw);
  const t = (await AgentToken.findOne({ hash, status: 'active' })) ?? (await AgentToken.findOne({ previousHash: hash, status: 'active', previousExpiresAt: { $gt: new Date() } }));
  if (!t) throw new ApiError(401, 'INVALID_TOKEN', 'This agent token is unknown or revoked.');
  return t;
}

export interface AgentReport {
  agentVersion: string;
  machineId: string;
  hostname: string;
  os: string;
  kernel: string;
  cpuCores: number;
  memoryGb: number;
  ips: string[];
  uptimeSec: number;
  intervalSec: number;
  usage: { cpu: number; memory: number; disk: number; load1: number; netInKbps: number; netOutKbps: number };
  disks: { mount: string; usedGb: number; totalGb: number }[];
  services: { name: string; manager: 'systemd' | 'pm2'; status: 'running' | 'stopped' | 'failed'; restarts10m: number; cpu: number; memoryMb: number }[];
  containers: { id: string; name: string; image: string; state: 'running' | 'restarting' | 'exited' | 'paused'; restarts10m: number; cpu: number; memoryMb: number; startedAt: string }[];
}

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';
const event = (s: ServerDoc, text: string, severity: Sev = 'info') => {
  s.events.unshift({ at: new Date(), text, severity } as never);
  s.events.splice(50);
};

/** Stores a report: host details, the latest state, a usage sample; then events and alerts from what changed. */
export async function ingestReport(token: AgentTokenDoc, r: AgentReport) {
  const now = new Date();
  let s = await Server.findOne({ agentTokenId: token._id, machineId: r.machineId });
  const isNew = !s;
  s ??= new Server({ agentTokenId: token._id, applicationId: token.applicationId, environmentId: token.environmentId, machineId: r.machineId, hostname: r.hostname });
  const prevServices = new Map(s.services.map((x) => [`${x.manager}:${x.name}`, x]));
  const prevContainers = new Map(s.containers.map((x) => [x.name ?? x.id, x]));

  if (isNew) event(s, `Agent ${r.agentVersion} connected`);
  else if (s.status === 'offline') event(s, 'Reporting again');
  if (!isNew && s.agentVersion && s.agentVersion !== r.agentVersion) event(s, `Agent updated to ${r.agentVersion}`);
  if (!isNew && r.uptimeSec < s.uptimeSec && r.uptimeSec < 600) event(s, 'Server rebooted', 'medium');

  s.set({
    hostname: r.hostname, os: r.os, kernel: r.kernel, cpuCores: r.cpuCores, memoryGb: r.memoryGb, ips: r.ips, agentVersion: r.agentVersion,
    status: 'online', lastSeenAt: now, uptimeSec: r.uptimeSec, intervalSec: r.intervalSec, usage: r.usage, disks: r.disks, services: r.services, containers: r.containers,
  });

  const where = { applicationId: s.applicationId, environmentId: s.environmentId, source: 'infrastructure' };
  const procRule = await pickRule({ signal: 'process_down', key: '', ...where, title: '', message: '' });
  const restartLimit = procRule?.threshold ?? 3;
  const procAlerts: { key: string; down: boolean; title: string; message: string }[] = [];

  for (const svc of r.services) {
    const k = `${svc.manager}:${svc.name}`;
    const prev = prevServices.get(k);
    const key = `srv:proc:${s.id ?? 'new'}:${k}`;
    if (prev && prev.status === 'running' && svc.status !== 'running') event(s, `${svc.name} (${svc.manager}) ${svc.status === 'failed' ? 'failed' : 'stopped'}`, svc.status === 'failed' ? 'high' : 'medium');
    if (prev && prev.status !== 'running' && svc.status === 'running') event(s, `${svc.name} (${svc.manager}) is running again`);
    const flapping = svc.restarts10m >= restartLimit;
    const down = svc.status === 'failed' || (svc.status === 'stopped' && prev?.status === 'running');
    procAlerts.push({ key, down: down || flapping, title: flapping && !down ? `${svc.name} restarted ${svc.restarts10m} times in 10 minutes on ${r.hostname}` : `${svc.name} is ${svc.status} on ${r.hostname}`, message: `${svc.manager === 'pm2' ? 'PM2 process' : 'systemd service'} ${svc.name}. Check its logs${svc.manager === 'systemd' ? ` with: journalctl -u ${svc.name} -n 100` : ` with: pm2 logs ${svc.name}`}.` });
  }
  for (const c of r.containers) {
    const prev = prevContainers.get(c.name || c.id);
    const key = `srv:proc:${s.id ?? 'new'}:docker:${c.name || c.id}`;
    if (prev && prev.state === 'running' && c.state !== 'running') event(s, `Container ${c.name} ${c.state}`, c.state === 'restarting' ? 'high' : 'medium');
    if (prev && prev.state !== 'running' && c.state === 'running') event(s, `Container ${c.name} is running again`);
    const flapping = c.restarts10m >= restartLimit;
    const down = c.state === 'restarting' || (c.state === 'exited' && prev?.state === 'running');
    procAlerts.push({ key, down: down || flapping, title: flapping ? `Container ${c.name} restarted ${c.restarts10m} times in 10 minutes on ${r.hostname}` : `Container ${c.name} ${c.state} on ${r.hostname}`, message: `Image ${c.image}. Check it with: docker logs --tail 100 ${c.name}` });
  }

  await s.save();
  await ServerSample.create({ serverId: s._id, at: now, ...r.usage });
  await autoResolve(`srv:offline:${s.id}`);

  for (const p of procAlerts) {
    const key = p.key.replace(':new:', `:${s.id}:`);
    if (p.down) await raiseAlert({ key, signal: 'process_down', value: restartLimit, ...where, title: p.title, message: p.message });
    else await autoResolve(key);
  }
  // Processes that disappeared from the report (removed, renamed) close their alerts.
  for (const [k] of prevServices) if (!r.services.some((x) => `${x.manager}:${x.name}` === k)) await autoResolve(`srv:proc:${s.id}:${k}`);
  for (const [k] of prevContainers) if (!r.containers.some((x) => (x.name || x.id) === k)) await autoResolve(`srv:proc:${s.id}:docker:${k}`);

  await checkUsage(s, r);
  if (isNew) await s.save();
  return s;
}

/** Sustained CPU or memory above the rule over its window; any disk above a threshold. */
async function checkUsage(s: ServerDoc, r: AgentReport) {
  const where = { applicationId: s.applicationId, environmentId: s.environmentId, source: 'infrastructure' };
  for (const [signal, field, label] of [['cpu_high', 'cpu', 'CPU'], ['memory_high', 'memory', 'Memory']] as const) {
    const rule = await pickRule({ signal, key: '', ...where, title: '', message: '', value: 100 });
    const key = `srv:${field}:${s.id}`;
    if (!rule?.threshold) continue;
    const windowMin = rule.durationMin ?? 10;
    const samples = await ServerSample.find({ serverId: s._id, at: { $gte: new Date(Date.now() - windowMin * MIN) } }, { [field]: 1 }).lean();
    const expected = (windowMin * 60) / Math.max(r.intervalSec, 10);
    const avg = samples.reduce((n, x) => n + ((x as unknown as Record<string, number>)[field] ?? 0), 0) / Math.max(samples.length, 1);
    if (samples.length >= expected * 0.8 && avg >= rule.threshold) {
      await raiseAlert({ key, signal, value: avg, ...where, title: `${label} at ${Math.round(avg)}% on ${s.hostname}`, message: `Average ${Math.round(avg)}% over the last ${windowMin} minutes (alert above ${rule.threshold}%).` });
    } else if (avg < rule.threshold - 5) await autoResolve(key);
  }
  for (const d of r.disks) {
    if (!d.totalGb) continue;
    const pct = Math.round((d.usedGb / d.totalGb) * 1000) / 10;
    const key = `srv:disk:${s.id}:${d.mount}`;
    const rule = await pickRule({ signal: 'disk_high', key, ...where, title: '', message: '', value: pct });
    if (rule) await raiseAlert({ key, signal: 'disk_high', value: pct, ...where, title: `Disk ${d.mount} is ${pct}% full on ${s.hostname}`, message: `${d.usedGb} of ${d.totalGb} GB used. Clear old logs, images or backups, or grow the disk.` });
    else await autoResolve(key);
  }
}

/** Servers that missed the rule's number of reports go offline, with an event and an alert. Run by the scheduler. */
export async function checkOfflineServers() {
  const online = await Server.find({ status: 'online' });
  for (const s of online) {
    const rule = await pickRule({ signal: 'agent_offline', key: '', applicationId: s.applicationId, environmentId: s.environmentId, source: 'infrastructure', title: '', message: '' });
    const missed = rule?.threshold ?? 3;
    if (!s.lastSeenAt || Date.now() - s.lastSeenAt.getTime() < missed * s.intervalSec * 1000 + 15_000) continue;
    s.status = 'offline';
    event(s, 'Stopped reporting', 'high');
    await s.save();
    if (rule) await raiseAlert({ key: `srv:offline:${s.id}`, signal: 'agent_offline', applicationId: s.applicationId, environmentId: s.environmentId, source: 'infrastructure', title: `${s.hostname} stopped reporting`, message: `No report since ${s.lastSeenAt.toISOString()}. The server may be down, or the agent stopped (check: systemctl status shieldops-agent).` });
  }
}

/** Revoking a token takes its servers offline at once. */
export async function markTokenServersOffline(tokenId: Types.ObjectId) {
  const servers = await Server.find({ agentTokenId: tokenId, status: { $ne: 'offline' } });
  for (const s of servers) {
    s.status = 'offline';
    event(s, 'Agent token revoked', 'medium');
    await s.save();
  }
}

export function serverView(s: ServerDoc) {
  return {
    id: s.id, hostname: s.hostname, applicationId: String(s.applicationId), environmentId: String(s.environmentId), agentTokenId: String(s.agentTokenId),
    os: s.os, cpuCores: s.cpuCores, memoryGb: s.memoryGb, ips: s.ips, agentVersion: s.agentVersion, status: s.status, lastSeenAt: s.lastSeenAt,
    uptimeSec: s.uptimeSec, intervalSec: s.intervalSec, usage: s.usage ?? null, services: s.services, containers: s.containers,
  };
}

const RANGES = { '1h': { points: 60, step: MIN }, '24h': { points: 96, step: 15 * MIN }, '7d': { points: 84, step: 120 * MIN } } as const;

/** Averages per chart step; a step with no reports is null, so the chart shows a gap while the server was offline. */
export async function serverMetrics(serverId: Types.ObjectId, range: keyof typeof RANGES) {
  const { points, step } = RANGES[range];
  const end = Math.ceil(Date.now() / step) * step;
  const start = end - points * step;
  const rows = await ServerSample.find({ serverId, at: { $gte: new Date(start) } }).lean();
  const fields = ['cpu', 'memory', 'disk', 'load1', 'netInKbps', 'netOutKbps'] as const;
  const sums = Array.from({ length: points }, () => ({ n: 0, v: Object.fromEntries(fields.map((f) => [f, 0])) as Record<(typeof fields)[number], number> }));
  for (const r of rows) {
    const i = Math.floor((r.at.getTime() - start) / step);
    if (i < 0 || i >= points) continue;
    sums[i].n++;
    for (const f of fields) sums[i].v[f] += (r as unknown as Record<string, number>)[f] ?? 0;
  }
  return sums.map((b, i) => ({
    at: new Date(start + (i + 1) * step).toISOString(),
    ...Object.fromEntries(fields.map((f) => [f, b.n ? Math.round((b.v[f] / b.n) * 10) / 10 : null])),
  }));
}