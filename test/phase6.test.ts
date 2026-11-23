import { createHmac } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import mongoose from 'mongoose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Alert } from '../src/models/Alert.js';
import { AlertRule, ensureDefaultRules } from '../src/models/AlertRule.js';
import { Finding } from '../src/models/Finding.js';
import { RemediationTask } from '../src/models/Ops.js';
import { ErrorGroup } from '../src/models/Telemetry.js';
import { raiseAlert } from '../src/services/alerts.js';
import { drainBackground } from '../src/services/background.js';
import { settleWatchedErrors } from '../src/services/verification.js';
import { freshDb, get, patch, post, setupFirstUser } from './helpers.js';

let admin: Awaited<ReturnType<typeof setupFirstUser>>;
let appId = '';
let envId = '';
let assetId = '';
let site: Server;
const headers: Record<string, string> = {};
const received: { body: string; sig: string; event: string }[] = [];
let hook: Server | null = null;
let hookPort = 0;

beforeAll(async () => {
  await freshDb();
  await ensureDefaultRules();
  admin = await setupFirstUser();
  await patch(admin.agent, '/settings', { internalAllowlist: [{ cidr: '127.0.0.0/8', note: 'Test servers' }] });
  const a = await post(admin.agent, '/applications', { name: 'Shop', ownerId: admin.user.id, criticality: 'critical', environments: [{ name: 'Production', type: 'production' }] });
  appId = a.body.id;
  envId = a.body.environments[0].id;
  site = createServer((_q, s) => (s.writeHead(200, { 'content-type': 'text/html', ...headers }), s.end('ok')));
  await new Promise<void>((r) => site.listen(0, '127.0.0.1', () => r()));
  const asset = await post(admin.agent, '/assets', { type: 'website', identifier: `http://localhost:${(site.address() as AddressInfo).port}/`, label: '', applicationId: appId, environmentId: envId, exposure: 'internal', authorizationMethod: 'approval', justification: 'Our test shop for monitoring.' });
  assetId = asset.body.id;
  await post(admin.agent, `/assets/${assetId}/recheck`);

  if (existsSync('/tmp/so-test-ca/leaf.pem')) {
    hook = createHttpsServer({ key: readFileSync('/tmp/so-test-ca/leaf.key'), cert: readFileSync('/tmp/so-test-ca/leaf.pem') }, (req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        received.push({ body, sig: String(req.headers['shieldops-signature']), event: String(req.headers['shieldops-event']) });
        res.writeHead(200).end('thanks');
      });
    });
    await new Promise<void>((r) => hook!.listen(0, '127.0.0.1', () => r()));
    hookPort = (hook.address() as AddressInfo).port;
  }
});

afterAll(async () => {
  site?.close();
  hook?.close();
  await drainBackground();
  await mongoose.disconnect();
});

const headerFinding = async () => (await Finding.findOne({ assetId, key: /^headers:content-security-policy:/ }))!;

describe('incidents', () => {
  let incId = '';

  it('opens incidents with sequential references and linked evidence', async () => {
    const f = await headerFinding();
    expect((await post(admin.agent, '/incidents', { title: 'x', summary: '', severity: 'low', applicationIds: [], ownerId: null })).body.error.code).toBe('VALIDATION');
    const inc = await post(admin.agent, '/incidents', { title: 'Payment page tampering risk', summary: 'CSP missing on checkout.', severity: 'critical', applicationIds: [appId], ownerId: admin.user.id, links: [{ type: 'finding', id: f.id }] });
    expect(inc.status).toBe(201);
    expect(inc.body).toMatchObject({ ref: 'INC-0001', status: 'new', ownerId: admin.user.id });
    expect(inc.body.linked[0]).toMatchObject({ type: 'finding', title: 'Content-Security-Policy header missing', severity: 'medium' });
    expect(inc.body.timeline.at(-1).text).toBe('Opened INC-0001');
    incId = inc.body.id;
    const second = await post(admin.agent, '/incidents', { title: 'Second', summary: '', severity: 'low', applicationIds: [appId], ownerId: null });
    expect(second.body.ref).toBe('INC-0002');
    expect((await get(admin.agent, '/dashboard')).body.activeIncidents).toBe(2);
  });

  it('follows the status workflow and needs a summary to close a critical incident', async () => {
    expect((await patch(admin.agent, `/incidents/${incId}`, { status: 'closed' })).body.error.code).toBe('INVALID_TRANSITION');
    const ack = await patch(admin.agent, `/incidents/${incId}`, { status: 'acknowledged', note: 'Looking into it.' });
    expect(ack.body.acknowledgedAt).toBeTruthy();
    expect(ack.body.timeline[0]).toMatchObject({ kind: 'note', text: 'Looking into it.' });
    await patch(admin.agent, `/incidents/${incId}`, { status: 'resolved', rootCause: 'The CSP header was dropped in the last nginx change.' });
    expect((await patch(admin.agent, `/incidents/${incId}`, { status: 'closed' })).body.error.code).toBe('SUMMARY_REQUIRED');
    const closed = await patch(admin.agent, `/incidents/${incId}`, { postIncident: 'CSP was missing for two days after an nginx change; no tampering seen. Added a config test.', status: 'closed' });
    expect(closed.body).toMatchObject({ status: 'closed' });
    expect(closed.body.closedAt).toBeTruthy();
    const reopened = await patch(admin.agent, `/incidents/${incId}`, { status: 'reopened' });
    expect(reopened.body).toMatchObject({ status: 'reopened', resolvedAt: null, closedAt: null });
  });

  it('links and unlinks evidence', async () => {
    const alert = await Alert.create({ key: 'test', title: 'Checkout 5xx spike', severity: 'high', source: 'performance', applicationId: appId, environmentId: envId });
    const linked = await post(admin.agent, `/incidents/${incId}/links`, { type: 'alert', id: alert.id });
    expect(linked.body.linked).toHaveLength(2);
    expect((await post(admin.agent, `/incidents/${incId}/links`, { type: 'alert', id: alert.id })).body.error.code).toBe('ALREADY_LINKED');
    const un = await admin.agent.delete(`/api/v1/incidents/${incId}/links/alert/${alert.id}`).set('Origin', 'http://localhost:5173');
    expect(un.body.linked).toHaveLength(1);
    expect(un.body.timeline[0].text).toMatch(/^Unlinked alert/);
  });
});

describe('remediation tasks', () => {
  let taskId = '';

  it('takes priority and due date from the finding, and cannot be verified by hand', async () => {
    const f = await headerFinding();
    const t = await post(admin.agent, '/remediation-tasks', { title: 'Add a CSP header in nginx', details: '', linkedType: 'finding', linkedId: f.id, ownerId: admin.user.id });
    expect(t.status).toBe(201);
    expect(t.body).toMatchObject({ priority: f.priority, linkedTitle: f.title, status: 'todo', applicationId: appId });
    expect(new Date(t.body.dueAt).getTime()).toBe(f.dueAt!.getTime());
    expect((await Finding.findById(f.id))?.status).toBe('in_progress');
    taskId = t.body.id;
    expect((await patch(admin.agent, `/remediation-tasks/${taskId}`, { status: 'verified' })).body.error.code).toBe('VERIFY_BY_RECHECK');
    expect((await patch(admin.agent, `/remediation-tasks/${taskId}`, { status: 'wont_fix', wontFixReason: 'meh' })).body.error.code).toBe('REASON_REQUIRED');
  });

  it('fails verification while the problem is still there', async () => {
    const r = await patch(admin.agent, `/remediation-tasks/${taskId}`, { status: 'ready_for_verification' });
    expect(r.body).toMatchObject({ status: 'ready_for_verification', verification: { status: 'pending' } });
    expect(r.body.verification.method).toMatch(/^Security header recheck of http:\/\/localhost/);
    expect((await patch(admin.agent, `/remediation-tasks/${taskId}`, { status: 'todo' })).body.error.code).toBe('VERIFYING');
    await drainBackground();
    const t = await RemediationTask.findById(taskId);
    expect(t).toMatchObject({ status: 'in_progress', verification: { status: 'failed' } });
    expect(t!.verification!.detail).toMatch(/still finds it: Content-Security-Policy header missing/);
  });

  it('passes once the fix is live, and verifies the finding too', async () => {
    headers['content-security-policy'] = "default-src 'self'";
    await patch(admin.agent, `/remediation-tasks/${taskId}`, { status: 'ready_for_verification' });
    await drainBackground();
    const t = (await get(admin.agent, '/remediation-tasks?status=verified')).body.find((x: { id: string }) => x.id === taskId);
    expect(t).toMatchObject({ status: 'verified', verification: { status: 'passed', detail: 'The recheck no longer finds the problem.' } });
    expect(t.verificationHistory.map((v: { status: string }) => v.status)).toEqual(['passed', 'failed']);
    expect((await headerFinding()).status).toBe('verified');
  });

  it('watches an error group for 7 days, failing if it comes back', async () => {
    const g = await ErrorGroup.create({ applicationId: appId, environmentId: envId, fingerprint: 'fp1', type: 'TypeError', message: 'x is undefined', platform: 'node', firstSeen: new Date(Date.now() - 3_600_000), lastSeen: new Date(Date.now() - 60_000), count: 4 });
    const t = await post(admin.agent, '/remediation-tasks', { title: 'Guard against missing cart', details: '', linkedType: 'error_group', linkedId: g.id, ownerId: null });
    await patch(admin.agent, `/remediation-tasks/${t.body.id}`, { status: 'ready_for_verification' });
    expect((await ErrorGroup.findById(g.id))?.status).toBe('resolved');
    await ErrorGroup.updateOne({ _id: g.id }, { lastSeen: new Date(Date.now() + 1000) });
    await settleWatchedErrors();
    expect((await RemediationTask.findById(t.body.id))!.verification!.detail).toMatch(/happened again/);
    await ErrorGroup.updateOne({ _id: g.id }, { lastSeen: new Date(Date.now() - 60_000) });
    await patch(admin.agent, `/remediation-tasks/${t.body.id}`, { status: 'ready_for_verification' });
    await RemediationTask.updateOne({ _id: t.body.id }, { watchUntil: new Date(Date.now() - 1000) });
    await settleWatchedErrors();
    expect(await RemediationTask.findById(t.body.id)).toMatchObject({ status: 'verified', verification: { detail: 'No new events for 7 days.' } });
  });

  it("checks everything linked to an incident, and records won't fix with a reason", async () => {
    const f = await Finding.findOne({ assetId, key: /^headers:strict-transport-security:/ });
    const inc = await post(admin.agent, '/incidents', { title: 'HSTS missing', summary: '', severity: 'medium', applicationIds: [appId], ownerId: null, links: [{ type: 'finding', id: f!.id }] });
    const t = await post(admin.agent, '/remediation-tasks', { title: 'Close out HSTS', details: '', linkedType: 'incident', linkedId: inc.body.id, ownerId: null });
    expect(t.body).toMatchObject({ priority: 'P3', linkedTitle: 'INC-0003 HSTS missing' });
    const r = await patch(admin.agent, `/remediation-tasks/${t.body.id}`, { status: 'ready_for_verification' });
    expect(r.body).toMatchObject({ status: 'in_progress', verification: { status: 'failed' } });
    expect(r.body.verification.detail).toMatch(/Still open: finding "Strict-Transport-Security header missing"/);
    expect((await get(admin.agent, `/incidents/${inc.body.id}`)).body.timeline[0].text).toBe('Recheck failed: Close out HSTS');
    const w = await patch(admin.agent, `/remediation-tasks/${t.body.id}`, { status: 'wont_fix', wontFixReason: 'The site is internal-only behind the VPN.' });
    expect(w.body).toMatchObject({ status: 'wont_fix', wontFixReason: 'The site is internal-only behind the VPN.' });
  });

  it('summarises SLAs', async () => {
    const open = (await get(admin.agent, '/incidents?status=active')).body as { id: string; ref: string }[];
    await patch(admin.agent, `/incidents/${open.find((i) => i.ref === 'INC-0002')!.id}`, { status: 'resolved' });
    await RemediationTask.create({ title: 'Overdue one', linkedType: 'finding', linkedId: (await headerFinding())._id, applicationId: appId, priority: 'P1', dueAt: new Date(Date.now() - 86_400_000), status: 'todo' });
    const s = (await get(admin.agent, '/sla')).body;
    expect(s.overdue).toBe(1);
    expect(s.byPriority.find((p: { priority: string }) => p.priority === 'P1')).toMatchObject({ open: 1, overdue: 1 });
    expect(s.verifiedLast30d).toBe(2);
    expect(s.onTimeRate).toBe(100);
    expect(s.mttrHours).not.toBeNull();
  });
});

describe('Slack and webhook alerts', () => {
  it('only accepts Slack incoming-webhook URLs and https webhooks', async () => {
    expect((await post(admin.agent, '/integrations/slack/connect', { url: 'https://example.com/hook', channel: 'it' })).body.error.code).toBe('INVALID_URL');
    expect((await post(admin.agent, '/integrations/webhook/connect', { url: 'http://ops.example.com/hook' })).body.error.code).toBe('INVALID_URL');
    expect((await post(admin.agent, '/integrations/webhook/connect', { url: 'https://10.9.9.9/hook' })).body.error.code).toBe('NOT_IN_ALLOWLIST');
    const s = await post(admin.agent, '/integrations/slack/connect', { url: 'https://hooks.slack.com/services/T000/B000/XXXX', channel: 'it-alerts' });
    expect(s.body).toMatchObject({ status: 'connected', account: '#it-alerts' });
    expect(JSON.stringify((await get(admin.agent, '/integrations')).body)).not.toContain('hooks.slack.com/services/T000');
  });

  it('sends signed, verifiable webhook alerts and test messages', async () => {
    if (!hook) return;
    const c = await post(admin.agent, '/integrations/webhook/connect', { url: `https://127.0.0.1:${hookPort}/shieldops` });
    expect(c.body.secret).toMatch(/^whsec_[0-9a-f]{48}$/);
    const secret = c.body.secret as string;
    expect(JSON.stringify((await get(admin.agent, '/integrations')).body)).not.toContain(secret);

    const t = await post(admin.agent, '/integrations/webhook/test');
    expect(t.body).toMatchObject({ ok: true });
    expect(t.body.detail).toMatch(/answered 200.*signed with your secret/);

    await AlertRule.updateOne({ builtInKey: 'r1' }, { channels: ['in_app', 'webhook'] });
    await raiseAlert({ key: 'uptime:test', signal: 'uptime_down', value: 5, applicationId: appId, environmentId: envId, source: 'uptime', title: 'Shop is down', message: 'HTTP 503 three times.' });
    await drainBackground();
    const last = received.at(-1)!;
    expect(last.event).toBe('alert.opened');
    expect(last.sig).toBe(`sha256=${createHmac('sha256', secret).update(last.body).digest('hex')}`);
    expect(JSON.parse(last.body)).toMatchObject({ event: 'alert.opened', alert: { title: 'Shop is down', severity: 'critical', application: 'Shop', environment: 'Production' } });
    const a = await Alert.findOne({ key: 'uptime:test' });
    expect(a!.deliveries.find((d) => d.channel === 'webhook')).toMatchObject({ status: 'sent', attempts: 1 });
  });

  it('reports a failed delivery without hiding it', async () => {
    const r = await post(admin.agent, '/integrations/slack/test');
    // Slack cannot be reached from the test machine (or rejects the fake URL): the test says so.
    expect(r.body.ok).toBe(false);
    expect(r.body.detail.length).toBeGreaterThan(5);
  }, 30_000);
});