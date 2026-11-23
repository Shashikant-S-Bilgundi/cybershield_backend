import { createRequire } from 'node:module';
import type { AddressInfo, Server } from 'node:net';
import express from 'express';
import mongoose from 'mongoose';
import { drainBackground } from '../src/services/background.js';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BOUNDS, percentile } from '../src/lib/histogram.js';
import { maskEmail, scrubText } from '../src/lib/scrub.js';
import { Alert } from '../src/models/Alert.js';
import { ensureDefaultRules } from '../src/models/AlertRule.js';
import { ErrorGroup, PerfMinute, SecurityEvent } from '../src/models/Telemetry.js';
import { app as api, freshDb, get, patch, post, setupFirstUser } from './helpers.js';

const require = createRequire(import.meta.url);
const { ShieldOpsClient } = require('../sdk/node/index.js');

let admin: Awaited<ReturnType<typeof setupFirstUser>>;
let appId = '';
let envId = '';
let apiServer: Server;
let endpoint = '';
let serverKey = '';
let keyId = '';
let sdk: InstanceType<typeof ShieldOpsClient>;
let shop: express.Express;

beforeAll(async () => {
  await freshDb();
  await ensureDefaultRules();
  admin = await setupFirstUser();
  const a = await post(admin.agent, '/applications', { name: 'Payments', ownerId: admin.user.id, criticality: 'critical', environments: [{ name: 'Production', type: 'production' }] });
  appId = a.body.id;
  envId = a.body.environments[0].id;
  apiServer = api.listen(0, '127.0.0.1');
  await new Promise((r) => apiServer.once('listening', r));
  endpoint = `http://127.0.0.1:${(apiServer.address() as AddressInfo).port}/ingest/v1`;

  const k = await post(admin.agent, '/ingestion-keys', { name: 'Payments server', kind: 'server', applicationId: appId, environmentId: envId });
  serverKey = k.body.secret;
  keyId = k.body.key.id;

  // A small app instrumented exactly as the setup screen says.
  sdk = new ShieldOpsClient({ key: serverKey, endpoint, release: 'payments@1.0.0', captureUnhandled: false });
  shop = express();
  shop.use(sdk.requestHandler());
  shop.get('/orders/:id', (req, res) => {
    if (req.params.id === '0') throw new TypeError(`Cannot read properties of undefined (reading 'total') for order ${Math.random()}`);
    res.json({ ok: true });
  });
  shop.get('/admin', (_req, res) => res.status(403).json({ error: 'no' }));
  shop.post('/login', express.json(), (req, res) => {
    sdk.security.loginFailed({ account: req.body.email, ip: req.body.ip });
    res.status(401).end();
  });
  shop.use(sdk.errorHandler());
  shop.use((_err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => res.status(500).json({ error: 'oops' }));
});

afterAll(async () => {
  await sdk?.close();
  apiServer?.close();
  await drainBackground();
  await mongoose.disconnect();
});

// A sample JWT, assembled at run time so the source contains no complete token.
const FAKE_JWT = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', 'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'].join('.');

describe('ingestion keys', () => {
  it('shows the key once, stores only a hash, and lists it without the secret', async () => {
    expect(serverKey).toMatch(/^so_live_[A-Za-z0-9]{32}$/);
    const list = (await get(admin.agent, '/ingestion-keys')).body;
    expect(list[0]).toMatchObject({ kind: 'server', scopes: ['errors', 'performance', 'security_events'], status: 'active' });
    expect(JSON.stringify(list)).not.toContain(serverKey);
  });

  it('refuses bad keys and keeps browser keys to errors', async () => {
    expect((await request(api).post('/ingest/v1/errors').send({ events: [] })).status).toBe(401);
    expect((await request(api).post('/ingest/v1/errors').set('authorization', 'Bearer so_live_notarealkeynotarealkeynotareal1').send({ events: [{ type: 'E', platform: 'node' }] })).status).toBe(401);
    const b = await post(admin.agent, '/ingestion-keys', { name: 'Payments web', kind: 'browser', applicationId: appId, environmentId: envId });
    expect(b.body.secret).toMatch(/^so_pub_/);
    const r = await request(api).post('/ingest/v1/metrics').set('authorization', `Bearer ${b.body.secret}`).send({ windowStart: new Date().toISOString(), windowSec: 60, routes: [] });
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('SCOPE_NOT_ALLOWED');
  });

  it('lets any website call the ingestion endpoint, but not the console API', async () => {
    const pre = await request(api).options('/ingest/v1/errors').set('Origin', 'https://shop.example.com').set('Access-Control-Request-Method', 'POST').set('Access-Control-Request-Headers', 'authorization,content-type');
    expect(pre.headers['access-control-allow-origin']).toBe('https://shop.example.com');
    expect(pre.headers['access-control-allow-credentials']).toBeUndefined();
    const consolePre = await request(api).options('/api/v1/applications').set('Origin', 'https://shop.example.com').set('Access-Control-Request-Method', 'POST');
    expect(consolePre.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('errors through the Node SDK', () => {
  it('groups the same bug together, keeps the request and scrubs secrets', async () => {
    for (let i = 0; i < 3; i++) await request(shop).get('/orders/0');
    sdk.captureException(new Error(`Payment failed for ravi@example.com with token ${FAKE_JWT}`), { userId: 'user-42' });
    sdk.captureException(new Error(`Payment failed for ravi@example.com with token ${FAKE_JWT}`), { userId: 'user-43' });
    await sdk.flush();
    const groups = (await get(admin.agent, '/error-groups')).body as { id: string; type: string; message: string; count: number; usersAffected: number; culprit: string; trend: number[] }[];
    const typeErr = groups.find((g) => g.type === 'TypeError')!;
    expect(typeErr.count).toBe(3);
    expect(typeErr.culprit).toMatch(/phase3\.test\.ts/);
    expect(typeErr.trend.at(-1)).toBe(3);
    const pay = groups.find((g) => g.message.startsWith('Payment failed'))!;
    expect(pay.message).toContain('r***@example.com');
    expect(pay.message).not.toMatch(/ravi@|eyJhbGci/);
    expect(pay.usersAffected).toBe(2);
    const detail = (await get(admin.agent, `/error-groups/${typeErr.id}`)).body;
    expect(detail.events[0].request).toEqual({ method: 'GET', route: '/orders/:id', status: 500 });
    expect(detail.releases).toEqual([{ release: 'payments@1.0.0', count: 3 }]);
    expect(detail.stack.find((f: { inApp: boolean }) => f.inApp).code).toBeTruthy();
    expect(await Alert.countDocuments({ source: 'errors', title: /^New error on Payments/ })).toBe(2);
  });

  it('marks a resolved error that comes back as regressed, with an alert', async () => {
    const g = await ErrorGroup.findOne({ type: 'TypeError' });
    expect((await patch(admin.agent, `/error-groups/${g!.id}`, { status: 'regressed' })).body.error.code).toBe('INVALID_STATUS');
    expect((await patch(admin.agent, `/error-groups/${g!.id}`, { status: 'resolved', assigneeId: admin.user.id })).body.status).toBe('resolved');
    await request(shop).get('/orders/0');
    await sdk.flush();
    const back = (await get(admin.agent, `/error-groups/${g!.id}`)).body;
    expect(back.status).toBe('regressed');
    expect(back.history[0].text).toMatch(/Happened again after being resolved/);
    expect(await Alert.countDocuments({ source: 'errors', title: /is back on Payments/, status: 'open' })).toBe(1);
  });
});

describe('performance', () => {
  it('reports per-route percentiles from the SDK', async () => {
    for (let i = 0; i < 25; i++) await request(shop).get(`/orders/${i + 1}`);
    await sdk.flush();
    const summary = ((await get(admin.agent, '/performance')).body as { environmentId: string; rpm: number }[]).find((s) => s.environmentId === envId)!;
    expect(summary.rpm).toBeGreaterThan(0);
    const r = (await get(admin.agent, `/performance/${appId}/${envId}?range=1h`)).body;
    expect(r.series).toHaveLength(60);
    const orders = r.routes.find((x: { route: string }) => x.route === '/orders/:id');
    expect(orders.requests).toBe(29); // 4 failing requests from the error tests + 25 here
    expect(orders.errorRate).toBeGreaterThan(0);
    expect(r.routes.some((x: { route: string }) => x.route === '/admin')).toBe(false);
  });

  it('alerts when the 5xx rate is high', async () => {
    await PerfMinute.create({ applicationId: appId, environmentId: envId, minute: new Date(Math.floor(Date.now() / 60_000) * 60_000 - 60_000), method: 'GET', route: '/pay', count: 40, serverErrors: 20, sumMs: 4000, buckets: Array(BOUNDS.length + 1).fill(0) });
    await request(api).post('/ingest/v1/metrics').set('authorization', `Bearer ${serverKey}`).send({ windowStart: new Date().toISOString(), windowSec: 60, routes: [{ method: 'GET', route: '/pay', count: 1, errors: 1, sumMs: 50, buckets: Array(BOUNDS.length + 1).fill(0) }] });
    expect(await Alert.countDocuments({ source: 'performance', title: /^5xx rate above 5%/, status: 'open' })).toBe(1);
  });

  it('computes percentiles from buckets', () => {
    const b = Array(BOUNDS.length + 1).fill(0);
    b[3] = 90; // 25-50 ms
    b[12] = 10; // 750-1000 ms
    expect(percentile(b, 0.5)).toBeGreaterThanOrEqual(25);
    expect(percentile(b, 0.5)).toBeLessThanOrEqual(50);
    expect(percentile(b, 0.95)).toBeGreaterThanOrEqual(750);
  });
});

describe('security events', () => {
  it('records 403s automatically and detects credential stuffing', async () => {
    await request(shop).get('/admin');
    for (let i = 0; i < 12; i++) await request(shop).post('/login').send({ email: `victim${i}@example.com`, ip: '203.0.113.77' });
    await sdk.flush();
    const page = (await get(admin.agent, '/security-events?types=login_failure&page=1&pageSize=50')).body;
    expect(page.total).toBe(12);
    expect(page.items[0].account).toMatch(/^v\*\*\*@example\.com$/);
    expect(JSON.stringify(page)).not.toMatch(/victim\d+@/);
    expect(await SecurityEvent.countDocuments({ type: 'authz_failure', route: '/admin', status: 403 })).toBe(1);
    // The login route returns 401 but already reported loginFailed, so it is not counted twice.
    expect(await SecurityEvent.countDocuments({ type: 'authz_failure', route: '/login' })).toBe(0);
    const detections = (await get(admin.agent, '/detections')).body as { rule: string; subject: string; distinctAccounts: number; alertId: string }[];
    const stuffing = detections.find((d) => d.rule === 'credential_stuffing')!;
    expect(stuffing).toMatchObject({ subject: '203.0.113.77', distinctAccounts: 12 });
    expect(stuffing.alertId).toBeTruthy();
    expect((await Alert.findById(stuffing.alertId))?.severity).toBe('critical');
    const stats = (await get(admin.agent, '/security-events/stats')).body;
    expect(stats.byType.login_failure).toBe(12);
    expect(stats.failuresHourly.at(-1)).toBeGreaterThanOrEqual(12);
  });

  it('lists ShieldOps sign-ins from the audit log', async () => {
    const r = (await get(admin.agent, '/auth/sign-ins?page=1&pageSize=10')).body;
    expect(r.items[0]).toMatchObject({ result: 'success', detail: 'First account created', name: 'First Admin' });
  });

  it('masks emails and tokens', () => {
    expect(maskEmail('Ravi.K@Example.com')).toBe('r***@example.com');
    expect(scrubText('key so_live_abcdefghijklmnopqrstuvwx and Bearer abc.def')).toBe('key [key] and Bearer [redacted]');
  });
});

describe('key rotation and revocation', () => {
  it('keeps the old key working for a day after rotation, and refuses everything after revocation', async () => {
    const send = (k: string) => request(api).post('/ingest/v1/errors').set('authorization', `Bearer ${k}`).send({ events: [{ type: 'Probe', platform: 'node', message: 'x' }] });
    const rotated = await post(admin.agent, `/ingestion-keys/${keyId}/rotate`);
    expect(rotated.body.secret).not.toBe(serverKey);
    expect((await send(serverKey)).status).toBe(202);
    expect((await send(rotated.body.secret)).status).toBe(202);
    expect((await get(admin.agent, '/ingestion-keys')).body.find((k: { id: string }) => k.id === keyId).eventsLast24h).toBeGreaterThan(0);
    await post(admin.agent, `/ingestion-keys/${keyId}/revoke`);
    expect((await send(rotated.body.secret)).status).toBe(401);
    expect((await send(serverKey)).status).toBe(401);
  });
});