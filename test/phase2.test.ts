import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createTcpServer, type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import mongoose from 'mongoose';
import { drainBackground } from '../src/services/background.js';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { parseRdap } from '../src/lib/rdap.js';
import { Alert } from '../src/models/Alert.js';
import { AlertRule } from '../src/models/AlertRule.js';
import { Heartbeat } from '../src/models/Heartbeat.js';
import { Monitor } from '../src/models/Monitor.js';
import { evaluateHeaders } from '../src/services/assetChecks.js';
import { evaluateHeartbeats } from '../src/services/heartbeats.js';
import { runDueMonitors } from '../src/services/monitors.js';
import { ensureDefaultRules } from '../src/models/AlertRule.js';
import { app, del, freshDb, get, patch, post, setupFirstUser } from './helpers.js';
import request from 'supertest';

let admin: Awaited<ReturnType<typeof setupFirstUser>>;
let appId = '';
let envId = '';
const servers: { close: () => void }[] = [];

/* A local site whose answer the tests control. */
const site = { status: 200, body: 'Welcome to the shop', headers: {} as Record<string, string> };
let sitePort = 0;
let tcpPort = 0;

const listen = (s: Server | ReturnType<typeof createTcpServer>) => new Promise<number>((r) => s.listen(0, '127.0.0.1', () => r((s.address() as AddressInfo).port)));

async function asset(type: string, identifier: string, extra: object = {}) {
  const r = await post(admin.agent, '/assets', { type, identifier, label: '', applicationId: appId, environmentId: envId, exposure: 'internet', authorizationMethod: 'approval', justification: 'Our own test server for monitoring.', ...extra });
  if (r.status !== 201) throw new Error(JSON.stringify(r.body));
  return r.body.id as string;
}

beforeAll(async () => {
  await freshDb();
  await ensureDefaultRules();
  admin = await setupFirstUser();
  const s = createServer((_req, res) => {
    res.writeHead(site.status, { 'content-type': 'text/html', ...site.headers });
    res.end(site.body);
  });
  sitePort = await listen(s);
  servers.push(s);
  const t = createTcpServer((sock) => sock.end());
  tcpPort = await listen(t);
  servers.push(t);
  await patch(admin.agent, '/settings', { internalAllowlist: [{ cidr: '127.0.0.0/8', note: 'Test servers' }] });
  const a = await post(admin.agent, '/applications', { name: 'Shop', ownerId: admin.user.id, criticality: 'critical', environments: [{ name: 'Production', type: 'production' }] });
  appId = a.body.id;
  envId = a.body.environments[0].id;
});

beforeEach(() => {
  site.status = 200;
});

afterAll(async () => {
  servers.forEach((s) => s.close());
  await drainBackground();
  await mongoose.disconnect();
});

describe('uptime monitors', () => {
  let monitorId = '';
  let assetId = '';

  it('has the 21 built-in alert rules (phases 2 and 3)', async () => {
    const rules = (await get(admin.agent, '/alert-rules')).body as { builtIn: boolean }[];
    expect(rules.filter((r) => r.builtIn)).toHaveLength(21);
  });

  it('only monitors the asset whose ownership was proved', async () => {
    assetId = await asset('website', `http://127.0.0.1:${sitePort}/`);
    const base = { name: 'Shop home', type: 'http', assetId, target: `http://127.0.0.1:${sitePort}/`, intervalSec: 60, timeoutMs: 5000, downAfterFailures: 3 };
    expect((await post(admin.agent, '/monitors', { ...base, target: 'https://example.org/' })).body.error.code).toBe('TARGET_NOT_ASSET');
    expect((await post(admin.agent, '/monitors', { ...base, type: 'tcp', target: `127.0.0.1:${sitePort}` })).body.error.code).toBe('TYPE_MISMATCH');
    expect((await post(admin.agent, '/monitors', { ...base, intervalSec: 10 })).status).toBe(422);
    const ok = await post(admin.agent, '/monitors', base);
    expect(ok.status).toBe(201);
    monitorId = ok.body.id;
    expect((await post(admin.agent, '/monitors', base)).body.error.code).toBe('DUPLICATE_MONITOR');
  });

  it('checks a working site as up', async () => {
    const r = await post(admin.agent, `/monitors/${monitorId}/run`);
    expect(r.body.status).toBe('up');
    expect(r.body.results.at(-1)).toMatchObject({ status: 'up', statusCode: 200 });
    expect(r.body.uptime.d1).toBe(100);
  });

  it('goes down after the set failures, opens a critical alert, and recovers', async () => {
    site.status = 500;
    await post(admin.agent, `/monitors/${monitorId}/run`);
    await post(admin.agent, `/monitors/${monitorId}/run`);
    const second = await post(admin.agent, `/monitors/${monitorId}/run`);
    expect(second.body.status).toBe('down');
    expect(second.body.results.at(-1)).toMatchObject({ status: 'down', statusCode: 500, error: 'UNEXPECTED_STATUS' });
    const alerts = (await get(admin.agent, '/alerts?status=active')).body as { title: string; severity: string; deliveries: { channel: string; status: string }[] }[];
    const down = alerts.find((a) => a.title === 'Shop home is down')!;
    expect(down.severity).toBe('critical');
    expect(down.deliveries.find((d) => d.channel === 'email')?.status).toBe('failed');
    expect((await get(admin.agent, '/dashboard')).body.health.down).toBe(1);

    site.status = 200;
    const back = await post(admin.agent, `/monitors/${monitorId}/run`);
    expect(back.body.status).toBe('up');
    expect(back.body.events[0]).toMatchObject({ from: 'down', to: 'up', reason: 'Recovered' });
    const resolved = await Alert.findOne({ title: 'Shop home is down' });
    expect(resolved).toMatchObject({ status: 'resolved', autoResolved: true });
  });

  it('flags a missing keyword', async () => {
    await patch(admin.agent, `/monitors/${monitorId}`, { keyword: 'Checkout' });
    const r = await post(admin.agent, `/monitors/${monitorId}/run`);
    expect(r.body.results.at(-1).error).toBe('KEYWORD_MISSING');
    await patch(admin.agent, `/monitors/${monitorId}`, { keyword: 'Welcome' });
  });

  it('runs a due monitor exactly once through the scheduler', async () => {
    await Monitor.updateOne({ _id: monitorId }, { nextCheckAt: new Date(0) });
    const before = (await get(admin.agent, `/monitors/${monitorId}`)).body.results.length;
    await Promise.all([runDueMonitors(), runDueMonitors()]);
    const after = (await get(admin.agent, `/monitors/${monitorId}`)).body.results.length;
    expect(after - before).toBe(1);
  });

  it('checks TCP ports', async () => {
    const srv = await asset('server', '127.0.0.1');
    const open = await post(admin.agent, '/monitors', { name: 'DB port', type: 'tcp', assetId: srv, target: `127.0.0.1:${tcpPort}`, intervalSec: 60, timeoutMs: 3000, downAfterFailures: 1 });
    expect((await post(admin.agent, `/monitors/${open.body.id}/run`)).body.status).toBe('up');
    const closed = await post(admin.agent, '/monitors', { name: 'Closed port', type: 'tcp', assetId: srv, target: '127.0.0.1:1', intervalSec: 60, timeoutMs: 3000, downAfterFailures: 1 });
    const r = await post(admin.agent, `/monitors/${closed.body.id}/run`);
    expect(r.body.results.at(-1)).toMatchObject({ status: 'down', error: 'CONNECTION_REFUSED' });
  });

  it('never reaches cloud metadata, even when its range is allowlisted', async () => {
    await patch(admin.agent, '/settings', { internalAllowlist: [{ cidr: '127.0.0.0/8', note: '' }, { cidr: '169.254.0.0/16', note: 'mistake' }] });
    const meta = await asset('website', 'http://169.254.169.254/');
    const m = await post(admin.agent, '/monitors', { name: 'Metadata', type: 'http', assetId: meta, target: 'http://169.254.169.254/latest/meta-data/', intervalSec: 60, timeoutMs: 2000, downAfterFailures: 1 });
    const r = await post(admin.agent, `/monitors/${m.body.id}/run`);
    expect(r.body.results.at(-1)).toMatchObject({ status: 'down', error: 'WORKER_ERROR' });
  });

  it('holds back notifications during maintenance', async () => {
    await post(admin.agent, '/maintenance-windows', { title: 'Deploy', applicationId: appId, environmentId: null, startsAt: new Date(Date.now() - 60_000).toISOString(), endsAt: new Date(Date.now() + 3_600_000).toISOString() });
    site.status = 503;
    for (let i = 0; i < 3; i++) await post(admin.agent, `/monitors/${monitorId}/run`);
    const a = await Alert.findOne({ title: 'Shop home is down', status: 'open' });
    expect(a?.deliveries).toHaveLength(0);
    site.status = 200;
    await post(admin.agent, `/monitors/${monitorId}/run`);
  });

  it('removes monitors and closes alerts when the asset is deleted', async () => {
    site.status = 500;
    for (let i = 0; i < 3; i++) await post(admin.agent, `/monitors/${monitorId}/run`);
    expect(await Alert.countDocuments({ title: 'Shop home is down', status: { $ne: 'resolved' } })).toBe(1);
    expect((await del(admin.agent, `/assets/${assetId}`)).status).toBe(204);
    expect(((await get(admin.agent, '/monitors')).body as { id: string }[]).some((m) => m.id === monitorId)).toBe(false);
    expect(await Alert.countDocuments({ title: 'Shop home is down', status: { $ne: 'resolved' } })).toBe(0);
    site.status = 200;
  });
});

describe('heartbeats', () => {
  it('records pings, alerts when a job is missed, and recovers on the next ping', async () => {
    expect((await post(admin.agent, '/heartbeats', { name: 'Backup', applicationId: appId, environmentId: envId, schedule: { kind: 'cron', expression: 'every night' }, graceSec: 300 })).body.error.code).toBe('INVALID_CRON');
    const h = await post(admin.agent, '/heartbeats', { name: 'Nightly backup', applicationId: appId, environmentId: envId, schedule: { kind: 'interval', seconds: 3600 }, graceSec: 300 });
    expect(h.body.status).toBe('new');
    const path = new URL(h.body.pingUrl).pathname;
    expect(path).toMatch(/^\/api\/v1\/hb\/[\w-]{30,}$/);
    expect((await request(app).get(path)).text).toBe('OK\n');
    expect((await get(admin.agent, '/heartbeats')).body[0].status).toBe('up');

    await Heartbeat.updateOne({ _id: h.body.id }, { nextDueAt: new Date(Date.now() - 10 * 60_000) });
    await evaluateHeartbeats();
    expect((await get(admin.agent, '/heartbeats')).body[0].status).toBe('down');
    expect(await Alert.countDocuments({ title: "Nightly backup didn't run", status: 'open' })).toBe(1);

    await request(app).post(path).send('');
    expect((await get(admin.agent, '/heartbeats')).body[0].status).toBe('up');
    expect(await Alert.countDocuments({ title: "Nightly backup didn't run", status: 'open' })).toBe(0);

    await request(app).get(`${path}/fail`);
    expect(await Alert.countDocuments({ title: 'Nightly backup reported a failure', status: 'open' })).toBe(1);
    expect((await request(app).get('/api/v1/hb/not-a-real-token-at-all-000')).status).toBe(404);
  });
});

describe('asset checks and findings', () => {
  it('reports missing security headers, then verifies the fix on recheck', async () => {
    const id = await asset('website', `http://localhost:${sitePort}/`);
    site.headers = {};
    expect((await post(admin.agent, `/assets/${id}/recheck`)).status).toBe(204);
    const report = ((await get(admin.agent, '/checks/headers')).body as { assetId: string; headers: Record<string, { present: boolean }> }[]).find((r) => r.assetId === id)!;
    expect(report.headers['content-security-policy'].present).toBe(false);
    let findings = (await get(admin.agent, `/findings?assetId=${id}`)).body as { title: string; status: string; priority: string }[];
    expect(findings.map((f) => f.title)).toEqual(expect.arrayContaining(['Content-Security-Policy header missing', 'Strict-Transport-Security header missing']));
    expect(await Alert.countDocuments({ source: 'headers', status: 'open' })).toBe(1);

    site.headers = { 'strict-transport-security': 'max-age=31536000', 'content-security-policy': "default-src 'self'", 'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff' };
    await post(admin.agent, `/assets/${id}/recheck`);
    findings = (await get(admin.agent, `/findings?assetId=${id}`)).body;
    expect(findings.every((f) => f.status === 'verified')).toBe(true);
    expect(await Alert.countDocuments({ source: 'headers', status: 'open' })).toBe(0);
  });

  it('finds an untrusted certificate that expires soon', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'so-cert-'));
    try {
      execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '10', '-subj', '/CN=other.example', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem')], { stdio: 'ignore' });
    } catch {
      return; // openssl is not installed here; skip.
    }
    const https = createHttpsServer({ key: readFileSync(join(dir, 'k.pem')), cert: readFileSync(join(dir, 'c.pem')) }, (_q, s) => s.end('ok'));
    const port = await listen(https as unknown as Server);
    servers.push(https);
    const id = await asset('website', `https://127.0.0.1:${port}/`);
    await post(admin.agent, `/assets/${id}/recheck`);
    expect(((await get(admin.agent, '/checks/domain-expiry')).body as { assetId: string }[]).some((d) => d.assetId === id)).toBe(false);
    expect(((await get(admin.agent, '/checks/dns')).body as { assetId: string }[]).some((d) => d.assetId === id)).toBe(false);
    const cert = ((await get(admin.agent, '/checks/ssl')).body as { assetId: string; chainValid: boolean; hostnameMatch: boolean; validTo: string }[]).find((c) => c.assetId === id)!;
    expect(cert).toMatchObject({ chainValid: false, hostnameMatch: false });
    const titles = ((await get(admin.agent, `/findings?assetId=${id}`)).body as { title: string; severity: string }[]).map((f) => `${f.title}|${f.severity}`);
    expect(titles).toEqual(expect.arrayContaining(['SSL certificate is not trusted|high', 'SSL certificate does not match the host name|high', 'SSL certificate expires in 10 days|medium']));
    const alert = await Alert.findOne({ source: 'ssl', status: 'open' });
    expect(alert?.severity).toBe('medium');
  }, 40_000);

  it('enforces the finding workflow', async () => {
    const f = ((await get(admin.agent, '/findings?status=active')).body as { id: string }[])[0];
    expect((await patch(admin.agent, `/findings/${f.id}`, { status: 'verified' })).body.error.code).toBe('VERIFY_BY_RECHECK');
    expect((await patch(admin.agent, `/findings/${f.id}`, { status: 'accepted_risk', acceptedRisk: { justification: 'short', expiresAt: new Date(Date.now() + 86_400_000).toISOString() } })).body.error.code).toBe('JUSTIFICATION_REQUIRED');
    expect((await patch(admin.agent, `/findings/${f.id}`, { status: 'accepted_risk', acceptedRisk: { justification: 'Internal test server only.', expiresAt: new Date(Date.now() - 1000).toISOString() } })).body.error.code).toBe('EXPIRY_IN_PAST');
    const ok = await patch(admin.agent, `/findings/${f.id}`, { status: 'accepted_risk', acceptedRisk: { justification: 'Internal test server only.', expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString() }, assigneeId: admin.user.id, note: 'Reviewed with the team.' });
    expect(ok.body.status).toBe('accepted_risk');
    expect(ok.body.history.map((h: { text: string }) => h.text).join(' | ')).toMatch(/Note: Reviewed.*Assigned to First Admin.*Accepted the risk/);
  });
});

describe('alerts, rules and channels', () => {
  it('acknowledges, snoozes and resolves alerts', async () => {
    const a = ((await get(admin.agent, '/alerts?status=active')).body as { id: string }[])[0];
    expect((await post(admin.agent, `/alerts/${a.id}/acknowledge`)).body.status).toBe('acknowledged');
    expect((await post(admin.agent, `/alerts/${a.id}/snooze`, { minutes: 1 })).status).toBe(422);
    expect((await post(admin.agent, `/alerts/${a.id}/snooze`, { minutes: 60 })).body.status).toBe('snoozed');
    expect((await post(admin.agent, `/alerts/${a.id}/resolve`)).body.status).toBe('resolved');
    expect((await post(admin.agent, `/alerts/${a.id}/resolve`)).body.error.code).toBe('ALREADY_RESOLVED');
  });

  it('protects built-in rules and validates channels', async () => {
    const builtIn = await AlertRule.findOne({ builtIn: true });
    expect((await del(admin.agent, `/alert-rules/${builtIn!.id}`)).body.error.code).toBe('BUILT_IN_RULE');
    expect((await patch(admin.agent, `/alert-rules/${builtIn!.id}`, { enabled: false })).body.enabled).toBe(false);
    expect((await post(admin.agent, '/alert-rules', { name: 'Staging down', signal: 'uptime_down', threshold: 5, durationMin: null, severity: 'low', scope: { applicationId: null, environmentType: 'staging' }, channels: ['in_app'], enabled: true })).status).toBe(201);
    expect((await request(app).put('/api/v1/notification-channels').set('Origin', 'http://localhost:5173').send({})).status).toBe(401);
    const bad = await admin.agent.put('/api/v1/notification-channels').set('Origin', 'http://localhost:5173').send({ emailRecipients: ['not-an-email'], criticalRenotifyMin: 15, maxRenotify: 4 });
    expect(bad.body.error.code).toBe('INVALID_EMAIL');
    const ok = await admin.agent.put('/api/v1/notification-channels').set('Origin', 'http://localhost:5173').send({ emailRecipients: ['it@example.com'], criticalRenotifyMin: 15, maxRenotify: 4 });
    expect(ok.body.emailRecipients).toEqual(['it@example.com']);
  });
});

describe('parsers', () => {
  it('reads expiry and registrar from an RDAP answer', () => {
    const r = parseRdap({ events: [{ eventAction: 'registration', eventDate: '2015-01-01T00:00:00Z' }, { eventAction: 'expiration', eventDate: '2027-03-04T05:06:07Z' }], entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar Ltd']]] }] });
    expect(r).toEqual({ expiresAt: '2027-03-04T05:06:07.000Z', registrar: 'Example Registrar Ltd' });
  });

  it('judges security headers', () => {
    const h = evaluateHeaders(new Headers({ 'strict-transport-security': 'max-age=300', 'content-security-policy': "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'", 'x-content-type-options': 'nosniff' }), true);
    expect(h['strict-transport-security'].issue).toMatch(/180 days/);
    expect(h['content-security-policy'].issue).toMatch(/unsafe-inline/);
    expect(h['x-frame-options'].present).toBe(true);
    expect(h['permissions-policy'].present).toBe(false);
  });
});