import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import type { AddressInfo, Server as NetServer } from 'node:net';
import mongoose from 'mongoose';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Alert } from '../src/models/Alert.js';
import { ensureDefaultRules } from '../src/models/AlertRule.js';
import { DbCheck, Server } from '../src/models/Infra.js';
import { drainBackground } from '../src/services/background.js';
import { checkOfflineServers } from '../src/services/servers.js';
import { app as api, del, freshDb, get, patch, post, setupFirstUser } from './helpers.js';

const AGENT = 'agent/dist/shieldops-agent-linux-amd64';
let admin: Awaited<ReturnType<typeof setupFirstUser>>;
let appId = '';
let envId = '';
let token = '';
let tokenId = '';
let apiServer: NetServer;
let endpoint = '';
let agent: ChildProcess | null = null;

const report = (over: Record<string, unknown> = {}) => ({
  agentVersion: '1.0.0', machineId: 'test-machine-1', hostname: 'web-01', os: 'Ubuntu 24.04 LTS', kernel: '6.8.0', cpuCores: 4, memoryGb: 7.8,
  ips: ['10.0.1.5'], uptimeSec: 86_400, intervalSec: 30,
  usage: { cpu: 12, memory: 40, disk: 50, load1: 0.4, netInKbps: 120, netOutKbps: 80 },
  disks: [{ mount: '/', usedGb: 40, totalGb: 80 }],
  services: [{ name: 'nginx', manager: 'systemd', status: 'running', restarts10m: 0, cpu: 1, memoryMb: 30 }],
  containers: [{ id: 'abc123def456', name: 'api', image: 'shop/api:2.3.1', state: 'running', restarts10m: 0, cpu: 4, memoryMb: 210, startedAt: new Date().toISOString() }],
  ...over,
});
const send = (body: object, t = token) => request(api).post('/ingest/v1/agent/report').set('authorization', `Bearer ${t}`).send(body);

beforeAll(async () => {
  await freshDb();
  await ensureDefaultRules();
  admin = await setupFirstUser();
  const a = await post(admin.agent, '/applications', { name: 'Shop', ownerId: admin.user.id, criticality: 'high', environments: [{ name: 'Production', type: 'production' }] });
  appId = a.body.id;
  envId = a.body.environments[0].id;
  apiServer = api.listen(0, '127.0.0.1');
  await new Promise((r) => apiServer.once('listening', r));
  endpoint = `http://127.0.0.1:${(apiServer.address() as AddressInfo).port}/ingest/v1`;
});

afterAll(async () => {
  agent?.kill('SIGTERM');
  apiServer?.close();
  await drainBackground();
  await mongoose.disconnect();
});

describe('agent tokens and installation', () => {
  it('creates a token shown once, and serves the installer and checked downloads', async () => {
    const t = await post(admin.agent, '/agent-tokens', { name: 'Shop servers', applicationId: appId, environmentId: envId });
    token = t.body.secret;
    tokenId = t.body.token.id;
    expect(token).toMatch(/^so_agent_[A-Za-z0-9]{32}$/);
    expect(JSON.stringify((await get(admin.agent, '/agent-tokens')).body)).not.toContain(token);

    const sh = await request(api).get('/ingest/agent/install.sh');
    expect(sh.status).toBe(200);
    expect(sh.text).toContain('BASE="http://localhost:5173"');
    expect(sh.text).not.toContain('__SHIELDOPS_BASE__');
    expect(sh.text).toMatch(/sha256sum -c/);
    expect(sh.text).toMatch(/User=shieldops-agent/);
    const sums = await request(api).get('/ingest/agent/download/SHA256SUMS');
    expect(sums.text).toMatch(/shieldops-agent-linux-amd64/);
    expect((await request(api).get('/ingest/agent/download/..%2F..%2F.env')).status).toBe(404);
  });
});

describe('the real agent', () => {
  it('reports this machine within seconds of starting', async () => {
    if (!existsSync(AGENT)) return; // binaries not built here
    agent = spawn(AGENT, [], { env: { SHIELDOPS_AGENT_TOKEN: token, SHIELDOPS_ENDPOINT: endpoint, SHIELDOPS_INTERVAL_SEC: '10', SHIELDOPS_DOCKER: '0' }, stdio: 'ignore' });
    let servers: { hostname: string; status: string; usage: { memory: number } | null; os: string; cpuCores: number }[] = [];
    for (let i = 0; i < 30 && !servers.length; i++) {
      await new Promise((r) => setTimeout(r, 300));
      servers = (await get(admin.agent, '/servers')).body;
    }
    expect(servers).toHaveLength(1);
    expect(servers[0]).toMatchObject({ status: 'online' });
    expect(servers[0].usage!.memory).toBeGreaterThan(0);
    expect(servers[0].cpuCores).toBeGreaterThan(0);
    expect(servers[0].os.length).toBeGreaterThan(0);
    agent.kill('SIGTERM');
    agent = null;
    await Server.deleteMany({});
  }, 20_000);
});

describe('reports, events and alerts', () => {
  let serverId = '';

  it('stores the server and its usage', async () => {
    expect((await send(report())).status).toBe(202);
    const list = (await get(admin.agent, '/servers')).body;
    serverId = list[0].id;
    const detail = (await get(admin.agent, `/servers/${serverId}`)).body;
    expect(detail).toMatchObject({ hostname: 'web-01', status: 'online', kernel: '6.8.0' });
    expect(detail.events[0].text).toMatch(/connected/);
    const points = (await get(admin.agent, `/servers/${serverId}/metrics?range=1h`)).body;
    expect(points).toHaveLength(60);
    expect(points.at(-1).cpu).toBe(12);
    expect(points[0].cpu).toBeNull();
  });

  it('records a failed service and a crashing container, with alerts that clear on recovery', async () => {
    await send(report({ services: [{ name: 'nginx', manager: 'systemd', status: 'failed', restarts10m: 0, cpu: 0, memoryMb: 0 }], containers: [{ id: 'abc123def456', name: 'api', image: 'shop/api:2.3.1', state: 'restarting', restarts10m: 4, cpu: 0, memoryMb: 0, startedAt: '' }] }));
    const d = (await get(admin.agent, `/servers/${serverId}`)).body;
    expect(d.events.map((e: { text: string }) => e.text)).toEqual(expect.arrayContaining(['nginx (systemd) failed', 'Container api restarting']));
    expect(await Alert.countDocuments({ source: 'infrastructure', title: 'nginx is failed on web-01', status: 'open' })).toBe(1);
    expect(await Alert.countDocuments({ source: 'infrastructure', title: /Container api restarted 4 times/, status: 'open' })).toBe(1);
    await send(report());
    expect(await Alert.countDocuments({ source: 'infrastructure', title: /nginx|Container api/, status: 'open' })).toBe(0);
  });

  it('picks the most severe disk rule', async () => {
    await send(report({ disks: [{ mount: '/', usedGb: 77, totalGb: 80 }, { mount: '/data', usedGb: 90, totalGb: 100 }] }));
    const root = await Alert.findOne({ title: /Disk \/ is 96\.3% full/ });
    const data = await Alert.findOne({ title: /Disk \/data is 90% full/ });
    expect(root?.severity).toBe('critical');
    expect(data?.severity).toBe('medium');
  });

  it('goes offline after missed reports and comes back', async () => {
    await Server.updateOne({ _id: serverId }, { lastSeenAt: new Date(Date.now() - 10 * 60_000) });
    await checkOfflineServers();
    expect((await get(admin.agent, `/servers/${serverId}`)).body.status).toBe('offline');
    expect(await Alert.countDocuments({ title: 'web-01 stopped reporting', status: 'open' })).toBe(1);
    expect((await get(admin.agent, '/servers')).body[0].status).toBe('offline');
    await send(report());
    expect((await get(admin.agent, `/servers/${serverId}`)).body.events[0].text).toBe('Reporting again');
    expect(await Alert.countDocuments({ title: 'web-01 stopped reporting', status: 'open' })).toBe(0);
  });

  it('refuses reports after the token is revoked and marks its servers offline', async () => {
    const rotated = await post(admin.agent, `/agent-tokens/${tokenId}/rotate`);
    expect((await send(report())).status).toBe(202);
    expect((await send(report(), rotated.body.secret)).status).toBe(202);
    expect((await get(admin.agent, '/agent-tokens')).body[0]).toMatchObject({ servers: 1 });
    await post(admin.agent, `/agent-tokens/${tokenId}/revoke`);
    expect((await send(report(), rotated.body.secret)).status).toBe(401);
    expect((await get(admin.agent, `/servers/${serverId}`)).body.status).toBe('offline');
    expect((await del(admin.agent, `/servers/${serverId}`)).status).toBe(204);
  });
});

describe('database checks', () => {
  let dbAsset = '';

  beforeAll(async () => {
    const a = await post(admin.agent, '/assets', { type: 'database', identifier: 'postgres://127.0.0.1:55432', label: 'Shop DB', applicationId: appId, environmentId: envId, exposure: 'internal', authorizationMethod: 'approval', justification: 'Our own database for the test.' });
    dbAsset = a.body.id;
  });

  const create = (over: object) => post(admin.agent, '/db-checks', { name: 'Shop DB', engine: 'postgresql', assetId: dbAsset, host: '127.0.0.1', port: 55432, database: 'shop', username: 'shieldops_ro', password: 'ro-pass-123', intervalSec: 60, ...over });

  it('refuses private hosts outside the allowlist', async () => {
    const r = await create({});
    expect(r.status).toBe(201);
    expect(r.body.error).toMatch(/Internal Network Allowlist/);
    expect(r.body.credentialsSet).toBe(true);
    expect(JSON.stringify(r.body)).not.toContain('ro-pass-123');
    await del(admin.agent, `/db-checks/${r.body.id}`);
  });

  it('checks PostgreSQL, Redis and MongoDB with read-only accounts', async () => {
    await patch(admin.agent, '/settings', { internalAllowlist: [{ cidr: '127.0.0.0/8', note: 'Test databases' }] });
    const pgCheck = await create({});
    if (pgCheck.body.error?.match(/refused/)) return; // no PostgreSQL here
    expect(pgCheck.body).toMatchObject({ status: 'up', error: null });
    expect(pgCheck.body.stats).toMatchObject({ role: 'standalone', maxConnections: 100 });
    expect(pgCheck.body.stats.connections).toBeGreaterThan(0);

    const redis = await create({ name: 'Cache', engine: 'redis', port: 56379, database: '', username: '', password: 'redis-pass-123' });
    expect(redis.body).toMatchObject({ status: 'up' });
    expect(redis.body.stats.connections).toBeGreaterThan(0);

    const mongo = await create({ name: 'Mongo', engine: 'mongodb', port: 27017, database: 'admin', username: 'shieldops', password: 'mongo-pass-123' });
    expect(mongo.body).toMatchObject({ status: 'up' });
    expect(mongo.body.stats.connections).toBeGreaterThan(0);
  });

  it('explains a wrong password and alerts after repeated failures', async () => {
    const bad = await create({ name: 'Wrong password', engine: 'redis', port: 56379, password: 'nope-nope', username: '' });
    if (!bad.body.lastCheckAt) return;
    expect(bad.body.error).toBe('The username or password was rejected.');
    await post(admin.agent, `/db-checks/${bad.body.id}/run`);
    const third = await post(admin.agent, `/db-checks/${bad.body.id}/run`);
    expect(third.body.status).toBe('down');
    expect(third.body.latency.slice(-3)).toEqual([null, null, null]);
    expect(await Alert.countDocuments({ title: 'Wrong password is not responding', severity: 'critical', status: 'open' })).toBe(1);
    expect((await del(admin.agent, `/db-checks/${bad.body.id}`)).status).toBe(204);
    expect(await DbCheck.countDocuments({ _id: bad.body.id })).toBe(0);
    expect(await Alert.countDocuments({ title: 'Wrong password is not responding', status: 'open' })).toBe(0);
  });

  it('refuses non-database assets and duplicates', async () => {
    const web = await post(admin.agent, '/assets', { type: 'website', identifier: 'http://127.0.0.1:9/', label: '', applicationId: appId, environmentId: envId, exposure: 'internal', authorizationMethod: 'approval', justification: 'Test site for the check.' });
    expect((await create({ assetId: web.body.id, port: 5555 })).body.error.code).toBe('NOT_A_DATABASE');
    expect((await create({})).body.error.code).toBe('DUPLICATE_CHECK');
  });
});