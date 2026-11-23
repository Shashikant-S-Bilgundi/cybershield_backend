import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import mongoose from 'mongoose';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BUCKETS } from '../src/lib/histogram.js';
import { Anomaly, Release } from '../src/models/Advanced.js';
import { Alert } from '../src/models/Alert.js';
import { ensureDefaultRules } from '../src/models/AlertRule.js';
import { Monitor } from '../src/models/Monitor.js';
import { Notification } from '../src/models/Notification.js';
import { ErrorGroup, PerfMinute } from '../src/models/Telemetry.js';
import { detectAnomalies } from '../src/services/anomalies.js';
import { drainBackground } from '../src/services/background.js';
import { runEscalations } from '../src/services/escalation.js';
import { runMonitor } from '../src/services/monitors.js';
import { app as api, del, freshDb, get, post, put, setupFirstUser } from './helpers.js';

const BINARY = `${process.cwd()}/agent/dist/shieldops-agent-linux-${process.arch === 'arm64' ? 'arm64' : 'amd64'}`;
let admin: Awaited<ReturnType<typeof setupFirstUser>>;
let appId = '';
let envId = '';
let serverKey = '';
let browserKey = '';
let site: Server;
let apiServer: Server;
let probeProc: ChildProcess | null = null;

const ingest = (path: string, key: string, body: object) => request(api).post(`/ingest/v1${path}`).set('Authorization', `Bearer ${key}`).send(body);

beforeAll(async () => {
  await freshDb();
  await ensureDefaultRules();
  admin = await setupFirstUser();
  await (await import('./helpers.js')).patch(admin.agent, '/settings', { internalAllowlist: [{ cidr: '127.0.0.0/8', note: 'Test servers' }] });
  const a = await post(admin.agent, '/applications', { name: 'Shop', ownerId: admin.user.id, criticality: 'high', environments: [{ name: 'Production', type: 'production' }] });
  appId = a.body.id;
  envId = a.body.environments[0].id;
  serverKey = (await post(admin.agent, '/ingestion-keys', { name: 'Shop server', kind: 'server', applicationId: appId, environmentId: envId })).body.secret;
  browserKey = (await post(admin.agent, '/ingestion-keys', { name: 'Shop web', kind: 'browser', applicationId: appId, environmentId: envId })).body.secret;
  // Answers the remote probe but not ShieldOps' own check: a network problem near the ShieldOps server.
  site = createServer((req, res) => (String(req.headers['user-agent']).includes('ShieldOps-Probe') ? res.writeHead(200).end('ok') : res.writeHead(503).end('down')));
  await new Promise<void>((r) => site.listen(0, '127.0.0.1', () => r()));
  apiServer = api.listen(0, '127.0.0.1');
  await new Promise((r) => apiServer.once('listening', r));
});

afterAll(async () => {
  probeProc?.kill('SIGTERM');
  site?.close();
  apiServer?.close();
  await drainBackground();
  await mongoose.disconnect();
});

describe('releases', () => {
  it('records deploys from CI with a server key only', async () => {
    expect((await ingest('/releases', browserKey, { version: '1.4.0' })).status).toBe(403);
    const r = await ingest('/releases', serverKey, { version: '1.4.0', commit: 'a1b2c3d', deployedBy: 'github-actions' });
    expect(r.status).toBe(201);
    expect((await ingest('/releases', serverKey, { version: '1.4.0' })).body.id).toBe(r.body.id);
  });

  it('learns a release from errors, and calls it a possible regression when it brings new errors', async () => {
    const err = { type: 'TypeError', message: 'cart.items is undefined', platform: 'node', release: '1.5.0', stack: [{ file: 'src/cart.js', fn: 'total', line: 12, column: 3, inApp: true }] };
    expect((await ingest('/errors', serverKey, { events: [err] })).status).toBe(202);
    const rels = (await get(admin.agent, '/releases')).body as { version: string; verdict: string; newErrorGroups: number; deployedBy: string }[];
    const v15 = rels.find((x) => x.version === '1.5.0')!;
    expect(v15).toMatchObject({ verdict: 'regression', newErrorGroups: 1, deployedBy: 'SDK' });
    expect(rels.find((x) => x.version === '1.4.0')).toMatchObject({ deployedBy: 'github-actions' });
    expect(await Release.countDocuments()).toBe(2);
    expect(await ErrorGroup.countDocuments()).toBe(1);
  });
});

describe('logs', () => {
  it('stores logs with secrets removed and finds them by words, fields and level', async () => {
    const r = await ingest('/logs', serverKey, { logs: [
      { level: 'error', message: 'Disk full: ENOSPC writing /var/log/app.log for ravi@example.com', host: 'web-1', fields: { orderId: '981', password: 'hunter2hunter2' } },
      { level: 'info', message: 'Order paid', host: 'web-1', fields: { orderId: '982' } },
      { level: 'debug', message: 'cache warm', host: 'web-2' },
    ] });
    expect(r.status).toBe(202);
    expect((await ingest('/logs', browserKey, { logs: [{ level: 'info', message: 'x' }] })).status).toBe(403);
    const found = (await get(admin.agent, '/logs?search=ENOSPC&range=1h')).body;
    expect(found.total).toBe(1);
    expect(found.items[0].message).toContain('r***@example.com');
    expect(found.items[0].fields.password).toBe('[redacted]');
    expect((await get(admin.agent, '/logs?search=orderId%3D982')).body.items.map((l: { message: string }) => l.message)).toEqual(['Order paid']);
    expect((await get(admin.agent, '/logs?levels=error,warn')).body.total).toBe(1);
    const all = (await get(admin.agent, '/logs?range=15m')).body;
    expect(all.histogram).toHaveLength(30);
    expect(all.histogram.reduce((n: number, h: { count: number }) => n + h.count, 0)).toBe(3);
  });
});

describe('second probe location', () => {
  let probeId = '';
  let secret = '';
  let monitorId = '';

  it('adds a probe location and shows its token once', async () => {
    const r = await post(admin.agent, '/probes', { name: 'Mumbai VPS', region: 'ap-south-1' });
    expect(r.status).toBe(201);
    expect(r.body.secret).toMatch(/^so_probe_/);
    probeId = r.body.probe.id;
    secret = r.body.secret;
    const list = (await get(admin.agent, '/probes')).body as { id: string; status: string; kind: string }[];
    expect(list.map((p) => [p.id, p.kind, p.status])).toEqual([['local', 'built_in', 'online'], [probeId, 'remote', 'offline']]);
    expect(JSON.stringify(list)).not.toContain(secret);
  });

  it('hands remote probes only internet-facing monitors', async () => {
    const port = (site.address() as AddressInfo).port;
    const pub = await post(admin.agent, '/assets', { type: 'website', identifier: `http://localhost:${port}/`, label: '', applicationId: appId, environmentId: envId, exposure: 'internet', authorizationMethod: 'approval', justification: 'Public shop front for monitoring.' });
    const internal = await post(admin.agent, '/assets', { type: 'website', identifier: `http://127.0.0.1:${port}/`, label: '', applicationId: appId, environmentId: envId, exposure: 'internal', authorizationMethod: 'approval', justification: 'Internal admin for monitoring.' });
    const m = await post(admin.agent, '/monitors', { name: 'Shop front', type: 'http', assetId: pub.body.id, target: `http://localhost:${port}/`, intervalSec: 30, timeoutMs: 3000, expectedStatus: '200', keyword: '', recordType: 'A', downAfterFailures: 1 });
    expect(m.status).toBe(201);
    monitorId = m.body.id;
    await post(admin.agent, '/monitors', { name: 'Admin', type: 'http', assetId: internal.body.id, target: `http://127.0.0.1:${port}/`, intervalSec: 30, timeoutMs: 3000, expectedStatus: '200', keyword: '', recordType: 'A', downAfterFailures: 1 });
    const work = await request(api).get('/ingest/v1/probe/work').set('Authorization', `Bearer ${secret}`);
    expect(work.body.checks.map((c: { id: string }) => c.id)).toEqual([monitorId]);
    expect((await request(api).get('/ingest/v1/probe/work').set('Authorization', 'Bearer so_probe_wrongwrongwrongwrongwrong')).status).toBe(401);
  });

  it('runs the real agent in probe mode, and does not count a one-sided failure as down', async () => {
    if (!existsSync(BINARY)) return;
    const port = (apiServer.address() as AddressInfo).port;
    probeProc = spawn(BINARY, ['probe'], { env: { SHIELDOPS_PROBE_TOKEN: secret, SHIELDOPS_ENDPOINT: `http://127.0.0.1:${port}/ingest`, PATH: process.env.PATH ?? '' }, stdio: 'ignore' });
    let results: { probeId: string; status: string }[] = [];
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 250));
      results = (await get(admin.agent, `/monitors/${monitorId}/probe-results`)).body;
      if (results.find((x) => x.probeId === probeId)?.status === 'up') break;
    }
    expect(results.find((x) => x.probeId === probeId)).toMatchObject({ status: 'up' });
    expect((await get(admin.agent, '/probes')).body.find((p: { id: string }) => p.id === probeId).status).toBe('online');

    // ShieldOps' own check gets 503, but the remote probe got 200: degraded, not down, and no outage alert.
    const m = await Monitor.findById(monitorId);
    await runMonitor(m!);
    const after = await Monitor.findById(monitorId);
    expect(after!.status).toBe('degraded');
    expect(after!.events[0].reason).toMatch(/reachable from Mumbai VPS: not counted as down/);
    expect(await Alert.countDocuments({ key: `uptime:${monitorId}` })).toBe(0);
    probeProc.kill('SIGTERM');
    probeProc = null;
  }, 20_000);

  it('removes a probe, and its token stops working', async () => {
    expect((await del(admin.agent, '/probes/local')).body.error.code).toBe('BUILT_IN');
    expect((await del(admin.agent, `/probes/${probeId}`)).status).toBe(204);
    expect((await request(api).get('/ingest/v1/probe/work').set('Authorization', `Bearer ${secret}`)).status).toBe(401);
  });
});

describe('escalation policies', () => {
  const step = (afterMinutes: number, channels = ['in_app']) => ({ afterMinutes, targets: ['all'], channels });

  it('validates policies like the frontend', async () => {
    expect((await post(admin.agent, '/escalation-policies', { name: 'x', severities: ['critical'], steps: [step(5)], repeat: false, enabled: true })).body.error.code).toBe('FIRST_STEP');
    expect((await post(admin.agent, '/escalation-policies', { name: 'x', severities: ['critical'], steps: [step(0), step(0)], repeat: false, enabled: true })).body.error.code).toBe('STEP_ORDER');
    const ok = await post(admin.agent, '/escalation-policies', { name: 'Critical: on-call', severities: ['critical'], steps: [step(0), step(10, ['in_app', 'email']), step(30)], repeat: false, enabled: true });
    expect(ok.status).toBe(201);
    expect((await post(admin.agent, '/escalation-policies', { name: 'Clash', severities: ['critical', 'high'], steps: [step(0)], repeat: false, enabled: true })).body.error.code).toBe('SEVERITY_TAKEN');
    const edited = await put(admin.agent, `/escalation-policies/${ok.body.id}`, { ...ok.body, name: 'Critical: on-call team' });
    expect(edited.body.name).toBe('Critical: on-call team');
  });

  it('notifies the next step when nobody acknowledges, and stops when someone does', async () => {
    const a = await Alert.create({ key: 'esc:test', title: 'Payments API is down', message: 'HTTP 503', severity: 'critical', source: 'uptime', applicationId: appId, environmentId: envId, firstAt: new Date(Date.now() - 15 * 60_000) });
    const notes = await Notification.countDocuments();
    await runEscalations();
    const after = await Alert.findById(a.id);
    const esc = after!.deliveries.filter((d) => /escalation step 2/.test(d.recipient ?? ''));
    expect(esc.map((d) => d.channel)).toEqual(['in_app', 'email']);
    expect(await Notification.countDocuments()).toBe(notes + 1);
    const view = (await get(admin.agent, '/alerts/escalations')).body.find((e: { alertId: string }) => e.alertId === a.id);
    expect(view).toMatchObject({ step: 2, totalSteps: 3, policyName: 'Critical: on-call team' });
    expect(new Date(view.nextAt).getTime()).toBe(a.firstAt.getTime() + 30 * 60_000);
    await runEscalations();
    expect((await Alert.findById(a.id))!.deliveries.length).toBe(after!.deliveries.length);
    await post(admin.agent, `/alerts/${a.id}/acknowledge`);
    await Alert.updateOne({ _id: a.id }, { firstAt: new Date(Date.now() - 60 * 60_000) });
    await runEscalations();
    expect((await Alert.findById(a.id))!.deliveries.length).toBe(after!.deliveries.length);
  });
});

describe('anomaly detection', () => {
  const STEP = 600_000;
  const row = (minute: number, count: number, route = '/api/orders') => ({ applicationId: appId, environmentId: envId, method: 'GET', route, minute: new Date(minute), count, serverErrors: 0, buckets: Object.assign(Array(BUCKETS).fill(0), { 3: count }) });

  it('flags traffic that drops far below the usual level for this time of day, and closes it when it returns', async () => {
    const current = Math.floor(Date.now() / STEP) * STEP - STEP;
    const rows = [];
    for (let d = 1; d <= 7; d++) for (const off of [-STEP, 0, STEP]) rows.push(row(current - d * 86_400_000 + off, 1000 + d * 10));
    rows.push(row(current, 40));
    await PerfMinute.insertMany(rows);
    await detectAnomalies();
    const an = await Anomaly.findOne({ metric: 'requests' });
    expect(an).toMatchObject({ direction: 'down', actual: 4, title: 'Traffic dropped on Shop' });
    expect(an!.expectedLow).toBeGreaterThan(4);
    expect(await Alert.countDocuments({ key: `anomaly:${envId}:requests`, status: 'open' })).toBe(1);
    const view = (await get(admin.agent, '/anomalies')).body[0];
    expect(view.series).toHaveLength(48);
    expect(view.series.find((p: { at: string }) => Date.parse(p.at) === current)).toMatchObject({ actual: 4 });

    await PerfMinute.updateOne({ minute: new Date(current) }, { count: 1030 });
    await detectAnomalies();
    expect((await Anomaly.findById(an!.id))!.endedAt).not.toBeNull();
    expect(await Alert.countDocuments({ key: `anomaly:${envId}:requests`, status: 'resolved' })).toBe(1);
  });
});