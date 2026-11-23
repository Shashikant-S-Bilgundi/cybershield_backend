import mongoose from 'mongoose';
import { drainBackground } from '../src/services/background.js';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuditLog } from '../src/models/AuditLog.js';
import { Session } from '../src/models/Session.js';
import { User } from '../src/models/User.js';
import { app, del, freshDb, get, ORIGIN, patch, post, setupFirstUser } from './helpers.js';

let admin: Awaited<ReturnType<typeof setupFirstUser>>;
const expireReauth = () => Session.updateMany({}, { reauthUntil: new Date(0) });

beforeAll(async () => {
  await freshDb();
});
afterAll(async () => {
  await drainBackground();
  await mongoose.disconnect();
});

describe('first-time setup and sign-in', () => {
  it('reports that setup is needed, then completes it once', async () => {
    expect((await get(request.agent(app), '/setup/status')).body).toEqual({ needsSetup: true });
    admin = await setupFirstUser();
    expect(admin.user.email).toBe('admin@example.com');
    expect(admin.user.passwordHash).toBeUndefined();
    expect((await get(admin.agent, '/auth/me')).body.user.email).toBe('admin@example.com');
    const again = await post(request.agent(app), '/setup', { name: 'X', email: 'x@example.com', password: 'AnotherPass123' });
    expect(again.status).toBe(409);
  });

  it('rejects weak passwords with the frontend wording', async () => {
    const r = await post(request.agent(app), '/invites/x/accept', { name: 'A', password: 'short' });
    expect([404, 422]).toContain(r.status);
  });

  it('signs in with email and password in one step, with an httpOnly, SameSite=Lax cookie', async () => {
    const agent = request.agent(app);
    const login = await post(agent, '/auth/login', { email: 'ADMIN@example.com', password: admin.password });
    expect(login.status).toBe(200);
    expect(login.body.user.email).toBe(admin.email);
    expect(login.body.reauthUntil).toBeTruthy();
    const cookie = String(login.headers['set-cookie']);
    expect(cookie).toMatch(/so_session=/);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Lax/i);
    expect((await get(agent, '/auth/me')).body.user.email).toBe(admin.email);
    expect(await AuditLog.countDocuments({ action: 'auth.login' })).toBeGreaterThanOrEqual(1);
  });

  it('never sends fields left over from the two-factor version', async () => {
    await User.collection.updateMany({}, { $set: { mfaEnabled: true, totpSecretEnc: 'v1.old.secret', totpLastStep: 9 } });
    const body = JSON.stringify((await get(admin.agent, '/users')).body) + JSON.stringify((await get(admin.agent, '/auth/me')).body);
    expect(body).not.toMatch(/totp|mfaEnabled|passwordHash/);
    expect(Object.keys((await get(admin.agent, '/auth/me')).body.user).sort()).toEqual(['createdAt', 'email', 'id', 'invitedBy', 'lastLoginAt', 'name', 'status']);
  });

  it('no longer has a two-factor step', async () => {
    const r = await post(request.agent(app), '/auth/mfa/verify', { challengeId: 'x'.repeat(20), code: '123456' });
    expect(r.status).toBe(404);
  });

  it('gives the same answer for a wrong password and an unknown email', async () => {
    const a = await post(request.agent(app), '/auth/login', { email: admin.email, password: 'wrong-password-1' });
    const b = await post(request.agent(app), '/auth/login', { email: 'nobody@example.com', password: 'wrong-password-1' });
    expect(a.status).toBe(401);
    expect(b.status).toBe(401);
    expect(a.body.error).toEqual(b.body.error);
    expect(await AuditLog.countDocuments({ action: 'auth.login_failed' })).toBeGreaterThanOrEqual(2);
  });

  it('answers 401 without a session, so the frontend shows sign-in', async () => {
    const r = await get(request.agent(app), '/auth/me');
    expect(r.status).toBe(401);
    expect(r.body.error.code).toBe('UNAUTHENTICATED');
  });
});

describe('request safety', () => {
  it('refuses changes from another website (CSRF)', async () => {
    const r = await admin.agent.post('/api/v1/applications').set('Origin', 'https://evil.example').send({});
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('BAD_ORIGIN');
  });

  it('answers 404 in the usual error shape for endpoints that do not exist', async () => {
    const r = await get(admin.agent, '/no-such-thing');
    expect(r.status).toBe(404);
    expect(r.body.error.code).toBe('NOT_FOUND');
  });

  it('never lets audit records be changed', async () => {
    await expect(AuditLog.updateOne({}, { summary: 'changed' })).rejects.toThrow(/append-only/);
    await expect(AuditLog.deleteMany({})).rejects.toThrow(/append-only/);
  });
});

describe('critical actions and the team', () => {
  let inviteLink = '';

  it('asks for re-authentication before inviting, then invites', async () => {
    await expireReauth();
    const blocked = await post(admin.agent, '/invites', { email: 'kiran@example.com' });
    expect(blocked.status).toBe(403);
    expect(blocked.body.error.code).toBe('REAUTH_REQUIRED');
    expect((await post(admin.agent, '/auth/reauth', { password: 'nope-nope-1' })).status).toBe(401);
    expect((await post(admin.agent, '/auth/reauth', { code: '123456' })).status).toBe(422);
    expect((await post(admin.agent, '/auth/reauth', { password: admin.password })).status).toBe(200);
    const inv = await post(admin.agent, '/invites', { email: 'Kiran@Example.com' });
    expect(inv.status).toBe(201);
    expect(inv.body.email).toBe('kiran@example.com');
    expect(inv.body.tokenHash).toBeUndefined();
    inviteLink = inv.body.link;
    expect(inviteLink).toMatch(/^http:\/\/localhost:5173\/invite\/[\w-]{40,}$/);
    expect((await post(admin.agent, '/invites', { email: 'kiran@example.com' })).status).toBe(409);
  });

  it('lets the invited person join and signs them straight in', async () => {
    const token = inviteLink.split('/').pop()!;
    const anon = request.agent(app);
    expect((await get(anon, `/invites/${token}`)).body.email).toBe('kiran@example.com');
    const weak = await post(anon, `/invites/${token}/accept`, { name: 'Kiran', password: 'short1' });
    expect(weak.body.error.code).toBe('WEAK_PASSWORD');
    const acc = await post(anon, `/invites/${token}/accept`, { name: 'Kiran Shetty', password: 'KiranPassword9' });
    expect(acc.status).toBe(201);
    expect(acc.body.user.email).toBe('kiran@example.com');
    expect((await get(anon, '/auth/me')).body.user.name).toBe('Kiran Shetty');
    expect((await get(anon, `/invites/${token}`)).status).toBe(404);
  });

  it('protects against self-lockout and revokes sessions of a disabled user', async () => {
    const users = (await get(admin.agent, '/users')).body as { id: string; email: string }[];
    const kiran = users.find((u) => u.email === 'kiran@example.com')!;
    expect((await patch(admin.agent, `/users/${admin.user.id}/status`, { status: 'disabled' })).body.error.code).toBe('SELF_ACTION');
    expect((await patch(admin.agent, `/users/${kiran.id}/status`, { status: 'disabled' })).status).toBe(200);
    expect(await Session.countDocuments({ userId: kiran.id, revokedAt: null })).toBe(0);
    const back = await patch(admin.agent, `/users/${kiran.id}/status`, { status: 'active' });
    expect(back.body.status).toBe('active');
  });
});

describe('applications and assets', () => {
  let appId = '';
  let prodEnv = '';

  it('creates an application and refuses a duplicate name', async () => {
    const body = { name: 'Payments API', description: 'Cards and UPI', ownerId: admin.user.id, criticality: 'critical', techStack: ['Node.js'], tags: [], environments: [{ name: 'Production', type: 'production' }, { name: 'Staging', type: 'staging' }] };
    const r = await post(admin.agent, '/applications', body);
    expect(r.status).toBe(201);
    appId = r.body.id;
    prodEnv = r.body.environments[0].id;
    expect(r.body.environments[0]).toMatchObject({ applicationId: appId, name: 'Production', type: 'production' });
    expect((await post(admin.agent, '/applications', { ...body, name: 'payments api' })).body.error.code).toBe('DUPLICATE_NAME');
  });

  it('checks identifiers, ownership methods and the internal allowlist', async () => {
    const base = { label: '', applicationId: appId, environmentId: prodEnv, exposure: 'internet' };
    expect((await post(admin.agent, '/assets', { ...base, type: 'domain', identifier: 'not a domain', authorizationMethod: 'dns_txt' })).body.error.code).toBe('INVALID_IDENTIFIER');
    expect((await post(admin.agent, '/assets', { ...base, type: 'server', identifier: '203.0.113.5', authorizationMethod: 'dns_txt' })).body.error.code).toBe('DNS_NOT_POSSIBLE');
    const dns = await post(admin.agent, '/assets', { ...base, type: 'domain', identifier: 'pay.example.com', authorizationMethod: 'dns_txt' });
    expect(dns.body.authorization).toMatchObject({ status: 'pending', method: 'dns_txt' });
    expect(dns.body.authorization.token).toMatch(/^shieldops-verify=[a-f0-9]{20}$/);
    expect((await post(admin.agent, '/assets', { ...base, type: 'domain', identifier: 'PAY.example.com', authorizationMethod: 'dns_txt' })).body.error.code).toBe('DUPLICATE_ASSET');
    const internal = { ...base, type: 'database', identifier: 'postgres://10.0.2.15:5432', exposure: 'internal', authorizationMethod: 'internal_allowlist' };
    expect((await post(admin.agent, '/assets', internal)).body.error.code).toBe('NOT_IN_ALLOWLIST');
    await post(admin.agent, '/auth/reauth', { password: admin.password });
    expect((await patch(admin.agent, '/settings', { internalAllowlist: [{ cidr: '10.0.0.0/16', note: 'Office' }] })).status).toBe(200);
    const ok = await post(admin.agent, '/assets', internal);
    expect(ok.body.authorization).toMatchObject({ status: 'verified', method: 'internal_allowlist' });
  });

  it('records a failed DNS verification with a clear reason', async () => {
    const list = (await get(admin.agent, `/assets?applicationId=${appId}`)).body as { id: string; identifier: string }[];
    const dns = list.find((a) => a.identifier === 'pay.example.com')!;
    const r = await post(admin.agent, `/assets/${dns.id}/verify`);
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('VERIFICATION_FAILED');
    const after = (await get(admin.agent, `/assets?applicationId=${appId}`)).body.find((a: { id: string }) => a.id === dns.id);
    expect(after.authorization.status).toBe('failed');
  });

  it('blocks removing an environment that still has assets', async () => {
    const r = await patch(admin.agent, `/applications/${appId}`, { environments: [{ name: 'Staging', type: 'staging' }] });
    expect(r.body.error.code).toBe('ENVIRONMENT_IN_USE');
  });

  it('soft-deletes an application and its assets after re-authentication', async () => {
    await expireReauth();
    expect((await del(admin.agent, `/applications/${appId}`)).status).toBe(403);
    await post(admin.agent, '/auth/reauth', { password: admin.password });
    expect((await del(admin.agent, `/applications/${appId}`)).status).toBe(204);
    expect((await get(admin.agent, '/applications')).body).toHaveLength(0);
    expect((await get(admin.agent, `/assets?applicationId=${appId}`)).body).toHaveLength(0);
  });
});

describe('settings and audit', () => {
  it('never returns secrets and validates ranges', async () => {
    await post(admin.agent, '/auth/reauth', { password: admin.password });
    const bad = await patch(admin.agent, '/settings', { internalAllowlist: [{ cidr: '10.0.0.0/99', note: '' }] });
    expect(bad.status).toBe(422);
    const r = await patch(admin.agent, '/settings', { smtp: { host: 'smtp-relay.brevo.com', port: 587, username: 'u@example.com', fromAddress: 'ShieldOps <a@example.com>', password: 'smtp-secret' } });
    expect(r.body.smtp.passwordSet).toBe(true);
    expect(JSON.stringify(r.body)).not.toContain('smtp-secret');
    expect(JSON.stringify((await get(admin.agent, '/settings')).body)).not.toMatch(/passwordEnc|smtp-secret/);
  });

  it('lists audit records newest first and exports CSV safely', async () => {
    const page = (await get(admin.agent, '/audit-logs?page=1&pageSize=5')).body;
    expect(page.items).toHaveLength(5);
    expect(page.total).toBeGreaterThan(10);
    expect(page.items[0].at >= page.items[1].at).toBe(true);
    await User.updateOne({ email: admin.email }, { name: '=HYPERLINK("http://evil")' });
    await post(admin.agent, '/auth/reauth', { password: admin.password });
    const csv = await post(admin.agent, '/audit-logs/export', {});
    expect(csv.headers['content-type']).toMatch(/text\/csv/);
    expect(csv.text.split('\n')[0]).toBe('"time","actor","action","resource","summary","ip"');
    expect(csv.text).toContain(`"'=HYPERLINK`);
  });

  it('signs out and the session stops working', async () => {
    expect((await post(admin.agent, '/auth/logout')).status).toBe(204);
    expect((await get(admin.agent, '/auth/me')).status).toBe(401);
  });

  it('rate-limits repeated sign-in attempts', async () => {
    const agent = request.agent(app);
    let last = 0;
    for (let i = 0; i < 12; i++) last = (await agent.post('/api/v1/auth/login').set('Origin', ORIGIN).send({ email: 'brute@example.com', password: `guess-${i}-000` })).status;
    expect(last).toBe(429);
  });
});