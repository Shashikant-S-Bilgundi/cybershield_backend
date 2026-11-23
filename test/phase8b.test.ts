import { createHash, createVerify, generateKeyPairSync, type KeyObject } from 'node:crypto';
import type { Server } from 'node:http';
import express from 'express';
import mongoose from 'mongoose';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { signRs256 } from '../src/lib/jwt.js';
import { ensureDefaultRules } from '../src/models/AlertRule.js';
import { Application } from '../src/models/Application.js';
import { Finding } from '../src/models/Finding.js';
import { RemediationTask } from '../src/models/Ops.js';
import { drainBackground } from '../src/services/background.js';
import { runCloudChecks } from '../src/services/cloud.js';
import { syncJira } from '../src/services/jira.js';
import { app as api, freshDb, get, ORIGIN, patch, post, setupFirstUser } from './helpers.js';

const BASE = 'http://127.0.0.1:47330';
const idp = generateKeyPairSync('rsa', { modulusLength: 2048 });
const rogue = generateKeyPairSync('rsa', { modulusLength: 2048 });
const sa = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
const pem = (k: KeyObject) => k.export({ type: 'pkcs8', format: 'pem' }) as string;

let admin: Awaited<ReturnType<typeof setupFirstUser>>;
let appId = '';
let envId = '';
let fake: Server;
/** What the identity provider will say for each code: the claims, the key it signs with, and the PKCE challenge it expects. */
const codes = new Map<string, { claims: Record<string, unknown>; key?: KeyObject; challenge: string }>();
const zone = { always_use_https: 'off', ssl: 'flexible', min_tls_version: '1.0', dnssec: 'disabled' };
let jiraStatus = 'To Do';

function fakeServer() {
  const g = express();
  g.use(express.json(), express.urlencoded({ extended: false }));
  // OpenID Connect provider
  g.get('/oidc/jwks', (_q, s) => s.json({ keys: [{ ...idp.publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' }] }));
  g.post('/oidc/token', (q, s) => {
    const c = codes.get(q.body.code);
    if (!c || q.body.client_secret !== 'sso-secret' || createHash('sha256').update(q.body.code_verifier).digest('base64url') !== c.challenge) return s.status(400).json({ error: 'invalid_grant' });
    const now = Math.floor(Date.now() / 1000);
    s.json({ id_token: signRs256({ iss: `${BASE}/oidc`, aud: 'client-123', iat: now, exp: now + 300, ...c.claims }, pem(c.key ?? idp.privateKey), 'k1') });
  });
  // Cloudflare
  g.use('/cf', (q, s, n) => (q.get('authorization') === 'Bearer cf-token' ? n() : s.status(403).json({ success: false, errors: [{ message: 'Invalid API Token' }] })));
  g.get('/cf/user/tokens/verify', (_q, s) => s.json({ result: { status: 'active' } }));
  g.get('/cf/zones', (_q, s) => s.json({ result: [{ id: 'z1', name: 'skyup.example', status: 'active', plan: { name: 'Free' } }], result_info: { total_pages: 1 } }));
  g.get('/cf/zones/z1/dns_records', (_q, s) => s.json({ result: [{ id: 'r1', name: 'shop.skyup.example', type: 'A', proxied: true, content: '203.0.113.9' }, { id: 'r2', name: 'skyup.example', type: 'MX', proxied: false, content: 'mail' }] }));
  g.get('/cf/zones/z1/settings', (_q, s) => s.json({ result: [{ id: 'always_use_https', value: zone.always_use_https }, { id: 'ssl', value: zone.ssl }, { id: 'min_tls_version', value: zone.min_tls_version }] }));
  g.get('/cf/zones/z1/dnssec', (_q, s) => s.json({ result: { status: zone.dnssec } }));
  // Google Workspace: the token request must be signed by the service account's key.
  g.post('/google/token', (q, s) => {
    const [h, p, sig] = String(q.body.assertion).split('.');
    const ok = createVerify('RSA-SHA256').update(`${h}.${p}`).verify(sa.publicKey, Buffer.from(sig, 'base64url'));
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    return ok && claims.sub === 'admin@skyup.example' ? s.json({ access_token: 'g-token' }) : s.status(401).json({ error: 'unauthorized_client' });
  });
  g.get('/google/admin/directory/v1/users', (q, s) => (q.get('authorization') === 'Bearer g-token' ? s.json({ users: [{ primaryEmail: 'boss@skyup.example', isAdmin: true, isEnrolledIn2Sv: false, lastLoginTime: new Date().toISOString() }, { primaryEmail: 'dev@skyup.example', isAdmin: false, isEnrolledIn2Sv: true, lastLoginTime: new Date().toISOString() }] }) : s.status(401).end()));
  // Entra
  g.post('/entra/:tenant/oauth2/v2.0/token', (q, s) => (q.body.client_secret === 'entra-secret' ? s.json({ access_token: 'e-token' }) : s.status(401).json({ error: 'invalid_client', error_description: 'bad secret' })));
  g.get('/graph/v1.0/organization', (_q, s) => s.json({ value: [{ id: 't' }] }));
  g.get('/graph/v1.0/reports/authenticationMethods/userRegistrationDetails', (_q, s) => s.json({ value: [{ userPrincipalName: 'ops@skyup.example', isAdmin: true, isMfaRegistered: true }, { userPrincipalName: 'sales@skyup.example', isAdmin: false, isMfaRegistered: false }] }));
  // AWS STS
  g.post('/sts', (_q, s) => s.status(403).type('text/xml').send('<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>Not authorized to perform sts:AssumeRole</Message></Error><RequestId>1</RequestId></ErrorResponse>'));
  return g.listen(47330, '127.0.0.1');
}

function fakeJira() {
  const j = express();
  j.use(express.json());
  const auth = `Basic ${Buffer.from('bot@example.com:jira-token').toString('base64')}`;
  j.use((q, s, n) => (q.get('authorization') === auth ? n() : s.status(401).json({ errorMessages: ['Unauthorized'] })));
  j.get('/rest/api/3/project/SEC', (_q, s) => s.json({ key: 'SEC', name: 'Security' }));
  j.post('/rest/api/3/issue', (q, s) => (q.body.fields.project.key === 'SEC' && q.body.fields.labels.includes('shieldops') ? s.status(201).json({ key: 'SEC-1' }) : s.status(400).json({ errors: { project: 'bad' } })));
  j.get('/rest/api/3/issue/SEC-1', (_q, s) => s.json({ fields: { status: { name: jiraStatus } } }));
  return j.listen(47331, '127.0.0.1');
}
let jiraServer: Server;

beforeAll(async () => {
  await freshDb();
  await ensureDefaultRules();
  admin = await setupFirstUser();
  const a = await post(admin.agent, '/applications', { name: 'Shop', ownerId: admin.user.id, criticality: 'high', environments: [{ name: 'Production', type: 'production' }] });
  appId = a.body.id;
  envId = a.body.environments[0].id;
  fake = fakeServer();
  jiraServer = fakeJira();
  await new Promise((r) => fake.once('listening', r));
});

afterAll(async () => {
  fake?.close();
  jiraServer?.close();
  await drainBackground();
  await mongoose.disconnect();
});

/** Runs one SSO sign-in in a fresh browser, with the provider answering with these claims. */
async function ssoSignIn(claims: Record<string, unknown>, opts: { key?: KeyObject; tamperState?: boolean } = {}) {
  const browser = request.agent(api);
  const start = await browser.post('/api/v1/auth/sso/google/start').set('Origin', ORIGIN);
  const url = new URL(start.body.redirectUrl);
  const code = `code-${Math.random()}`;
  codes.set(code, { claims: { nonce: url.searchParams.get('nonce'), ...claims }, key: opts.key, challenge: url.searchParams.get('code_challenge')! });
  const state = opts.tamperState ? 'someone-elses-state' : url.searchParams.get('state');
  const cb = await browser.get(`/api/v1/auth/sso/callback?code=${encodeURIComponent(code)}&state=${state}`);
  return { browser, location: cb.headers.location as string, start };
}

describe('single sign-on', () => {
  const good = { email: 'admin@example.com', email_verified: true, hd: 'example.com' };

  it('is refused until it is set up, and sends you to the provider with PKCE', async () => {
    expect((await request(api).post('/api/v1/auth/sso/google/start').set('Origin', ORIGIN)).body.error.code).toBe('SSO_DISABLED');
    expect((await patch(admin.agent, '/settings', { sso: { enabled: true, provider: 'google', domain: 'example.com', clientId: 'client-123', clientSecret: 'sso-secret', allowPasswordFallback: true } })).status).toBe(200);
    const { start } = await ssoSignIn(good);
    const u = new URL(start.body.redirectUrl);
    expect(u.origin + u.pathname).toBe(`${BASE}/oidc/authorize`);
    expect(Object.fromEntries(u.searchParams)).toMatchObject({ client_id: 'client-123', response_type: 'code', code_challenge_method: 'S256', hd: 'example.com', redirect_uri: 'http://localhost:5173/api/v1/auth/sso/callback' });
    expect(String(start.headers['set-cookie'])).toMatch(/so_sso_state=.*HttpOnly/);
  });

  it('signs in an invited member with a verified token', async () => {
    const { browser, location } = await ssoSignIn(good);
    expect(location).toBe('http://localhost:5173/');
    expect((await browser.get('/api/v1/auth/me')).body.user.email).toBe('admin@example.com');
  });

  it('refuses everything else, and says why', async () => {
    expect((await ssoSignIn(good, { tamperState: true })).location).toMatch(/sso=expired$/);
    expect((await ssoSignIn({ ...good, email: 'stranger@example.com' })).location).toMatch(/sso=not_member$/);
    expect((await ssoSignIn({ email: 'admin@other.example', email_verified: true, hd: 'other.example' })).location).toMatch(/sso=domain$/);
    expect((await ssoSignIn(good, { key: rogue.privateKey })).location).toMatch(/sso=invalid$/);
    expect((await ssoSignIn({ ...good, nonce: 'replayed-nonce' })).location).toMatch(/sso=invalid$/);
    expect((await ssoSignIn({ ...good, email_verified: false })).location).toMatch(/sso=unverified$/);
  });

  it('only lets someone who signed in with SSO turn off password sign-in', async () => {
    expect((await patch(admin.agent, '/settings', { sso: { allowPasswordFallback: false } })).body.error.code).toBe('SSO_NOT_PROVEN');
    const { browser } = await ssoSignIn(good);
    expect((await browser.patch('/api/v1/settings').set('Origin', ORIGIN).send({ sso: { allowPasswordFallback: false } })).status).toBe(200);
    const pw = await request(api).post('/api/v1/auth/login').set('Origin', ORIGIN).send({ email: 'admin@example.com', password: admin.password });
    expect(pw.body.error.code).toBe('SSO_REQUIRED');
    expect((await request(api).get('/api/v1/auth/sso/config')).body).toEqual({ enabled: true, provider: 'google', allowPasswordFallback: false });
    await browser.patch('/api/v1/settings').set('Origin', ORIGIN).send({ sso: { allowPasswordFallback: true } });
  });
});

describe('Jira', () => {
  const jira = { siteUrl: 'http://127.0.0.1:47331', email: 'bot@example.com', apiToken: 'jira-token', projectKey: 'SEC' };

  it('checks the credentials and project before storing them', async () => {
    expect((await post(admin.agent, '/integrations/jira/connect', { ...jira, apiToken: 'wrong' })).body.error.code).toBe('INVALID_CREDENTIALS');
    expect((await post(admin.agent, '/integrations/jira/connect', { ...jira, siteUrl: 'http://evil.example' })).body.error.code).toBe('INVALID_URL');
    const ok = await post(admin.agent, '/integrations/jira/connect', jira);
    expect(ok.body).toMatchObject({ status: 'connected', account: '127.0.0.1:47331 · SEC (Security)' });
    expect(JSON.stringify((await get(admin.agent, '/integrations')).body)).not.toContain('jira-token');
  });

  it('creates one issue per task, links it, and syncs its status', async () => {
    const task = await RemediationTask.create({ title: 'Rotate the leaked AWS key', linkedType: 'finding', linkedId: new mongoose.Types.ObjectId(), linkedTitle: 'aws-access-token in config.js', applicationId: appId });
    const r = await post(admin.agent, '/integrations/jira/issues', { type: 'task', id: task.id });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ system: 'jira', key: 'SEC-1', url: 'http://127.0.0.1:47331/browse/SEC-1', status: 'To Do' });
    expect((await post(admin.agent, '/integrations/jira/issues', { type: 'task', id: task.id })).body.error.code).toBe('ALREADY_LINKED');
    jiraStatus = 'In Progress';
    await syncJira();
    expect((await RemediationTask.findById(task.id))!.externalRef).toMatchObject({ key: 'SEC-1', status: 'In Progress' });
  });
});

describe('Cloudflare', () => {
  it('checks zones, turns failures into findings, and verifies fixes', async () => {
    expect((await post(admin.agent, '/integrations/cloudflare/connect', { apiToken: 'nope' })).body.error.code).toBe('INVALID_CREDENTIALS');
    expect((await post(admin.agent, '/integrations/cloudflare/connect', { apiToken: 'cf-token' })).body).toMatchObject({ status: 'connected', account: '1 zone' });
    await drainBackground();
    const checks = (await get(admin.agent, '/cloud-checks')).body as { id: string; failed: number; passed: number; findingIds: string[] }[];
    expect(checks.map((c) => [c.id, c.failed])).toEqual([['cf-dnssec', 1], ['cf-https', 1], ['cf-tls', 1]]);
    const tls = await Finding.findById(checks.find((c) => c.id === 'cf-tls')!.findingIds[0]);
    expect(tls).toMatchObject({ source: 'cloud', severity: 'high', title: 'Weak TLS settings on skyup.example' });
    expect((await Application.findById(tls!.applicationId))!.name).toBe('Shared infrastructure');
    Object.assign(zone, { always_use_https: 'on', ssl: 'strict', min_tls_version: '1.2' });
    await runCloudChecks('cloudflare');
    const after = (await get(admin.agent, '/cloud-checks')).body as { id: string; failed: number }[];
    expect(after.map((c) => [c.id, c.failed])).toEqual([['cf-dnssec', 1], ['cf-https', 0], ['cf-tls', 0]]);
    expect((await Finding.findById(tls!.id))!.status).toBe('verified');
  });

  it('discovers zones and hostnames, and imports only what is really in the account', async () => {
    const found = (await get(admin.agent, '/asset-import/cloudflare')).body as { externalId: string; type: string; identifier: string; alreadyAdded: boolean }[];
    expect(found.map((f) => [f.type, f.identifier])).toEqual([['domain', 'skyup.example'], ['website', 'https://shop.skyup.example/']]);
    const r = await post(admin.agent, '/asset-import/cloudflare', { externalIds: ['zone:z1', 'dns:r1', 'dns:made-up'], applicationId: appId, environmentId: envId });
    expect(r.body).toEqual({ imported: 2 });
    expect(((await get(admin.agent, '/asset-import/cloudflare')).body as { alreadyAdded: boolean }[]).every((f) => f.alreadyAdded)).toBe(true);
  });
});

describe('Google Workspace and Microsoft Entra', () => {
  it('flags admins without 2-step verification, with a signed service-account request', async () => {
    const key = JSON.stringify({ client_email: 'shieldops@proj.iam.gserviceaccount.com', private_key: sa.privateKey, private_key_id: 'sa1' });
    const bad = await post(admin.agent, '/integrations/google/connect', { domain: 'skyup.example', adminEmail: 'someone@skyup.example', serviceAccountKey: key });
    expect(bad.body.error.code).toBe('INVALID_CREDENTIALS');
    const ok = await post(admin.agent, '/integrations/google/connect', { domain: 'skyup.example', adminEmail: 'admin@skyup.example', serviceAccountKey: key });
    expect(ok.body).toMatchObject({ status: 'connected', account: 'skyup.example (2 users)' });
    await drainBackground();
    const f = await Finding.findOne({ key: 'gws:admin-2sv:boss@skyup.example' });
    expect(f).toMatchObject({ severity: 'critical', source: 'cloud' });
    expect(JSON.stringify((await get(admin.agent, '/integrations')).body)).not.toContain('PRIVATE KEY');
  });

  it('flags Entra users without MFA', async () => {
    expect((await post(admin.agent, '/integrations/entra/connect', { tenantId: 't1', clientId: 'c1', clientSecret: 'wrong' })).body.error.code).toBe('INVALID_CREDENTIALS');
    expect((await post(admin.agent, '/integrations/entra/connect', { tenantId: 't1', clientId: 'c1', clientSecret: 'entra-secret' })).body.status).toBe('connected');
    await drainBackground();
    const checks = (await get(admin.agent, '/cloud-checks')).body as { id: string; failed: number }[];
    expect(checks.find((c) => c.id === 'entra-admin-mfa')!.failed).toBe(0);
    expect(checks.find((c) => c.id === 'entra-users-mfa')!.failed).toBe(1);
  });
});

describe('AWS', () => {
  it('needs ShieldOps keys that may assume the role, and explains AWS refusals', async () => {
    const roleArn = 'arn:aws:iam::123456789012:role/ShieldOpsReadOnly';
    expect((await post(admin.agent, '/integrations/aws/connect', { roleArn: 'not-an-arn', externalId: 'shieldops-abc' })).body.error.code).toBe('INVALID_ROLE');
    delete process.env.AWS_ACCESS_KEY_ID;
    expect((await post(admin.agent, '/integrations/aws/connect', { roleArn, externalId: 'shieldops-abc' })).body.error.code).toBe('AWS_NOT_CONFIGURED');
    Object.assign(process.env, { AWS_ACCESS_KEY_ID: ['AKIA', 'TESTTESTTEST1234'].join(''), AWS_SECRET_ACCESS_KEY: 'test-secret', AWS_ENDPOINT_URL_STS: `${BASE}/sts` });
    const r = await post(admin.agent, '/integrations/aws/connect', { roleArn, externalId: 'shieldops-abc' });
    expect(r.body.error.code).toBe('INVALID_CREDENTIALS');
    expect(r.body.error.message).toMatch(/Not authorized to perform sts:AssumeRole/);
    for (const k of ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_ENDPOINT_URL_STS']) delete process.env[k];
  });
});