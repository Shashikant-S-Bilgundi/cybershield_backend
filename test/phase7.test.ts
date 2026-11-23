import type { Server } from 'node:http';
import express from 'express';
import mongoose from 'mongoose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ensureDefaultRules } from '../src/models/AlertRule.js';
import { Asset } from '../src/models/Asset.js';
import { Finding } from '../src/models/Finding.js';
import { ReportSchedule, Report } from '../src/models/Intel.js';
import { Incident } from '../src/models/Ops.js';
import { maskForAi, parseAnswer } from '../src/services/ai.js';
import { drainBackground } from '../src/services/background.js';
import { runDueSchedules } from '../src/services/reports.js';
import { freshDb, get, patch, post, setupFirstUser } from './helpers.js';

// Fake tokens, assembled at run time so the source never contains a complete one.
const FAKE_GH = ['ghp', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('_');
const FAKE_SLACK = ['xoxb', '123456789012', 'abcdefghij'].join('-');

let admin: Awaited<ReturnType<typeof setupFirstUser>>;
let appId = '';
let envId = '';
let assetId = '';
let fake: Server;
const seen: { path: string; body: Record<string, unknown>; headers: Record<string, string> }[] = [];
let reply = (_path: string) => ({ summary: 'Add the CSP header in nginx.', sections: [{ title: 'How to fix it', bullets: ['add_header Content-Security-Policy ...'] }], suggestedTasks: ['Add a CSP header'] });
let failNext = false;

const finding = (over: Record<string, unknown>) =>
  Finding.create({ category: 'security', applicationId: appId, environmentId: envId, assetId, severity: 'high', riskScore: 9, priority: 'P2', evidence: [], ...over });

beforeAll(async () => {
  await freshDb();
  await ensureDefaultRules();
  admin = await setupFirstUser();
  const a = await post(admin.agent, '/applications', { name: 'Shop', ownerId: admin.user.id, criticality: 'high', environments: [{ name: 'Production', type: 'production' }] });
  appId = a.body.id;
  envId = a.body.environments[0].id;
  assetId = (await Asset.create({ type: 'repository', identifier: 'acme/shop', identifierKey: 'acme/shop', label: 'acme/shop', applicationId: appId, environmentId: envId, exposure: 'internal', authorization: { status: 'approved', method: 'approval' } })).id;

  const g = express();
  g.use(express.json());
  g.post('/openai/v1/chat/completions', (req, res) => {
    seen.push({ path: req.path, body: req.body, headers: req.headers as Record<string, string> });
    if (failNext) return (failNext = false), res.status(401).json({ error: { message: 'Incorrect API key provided: sk-test-op***' } });
    res.json({ choices: [{ message: { content: JSON.stringify(reply(req.path)) } }] });
  });
  g.post('/anthropic/v1/messages', (req, res) => {
    seen.push({ path: req.path, body: req.body, headers: req.headers as Record<string, string> });
    res.json({ content: [{ type: 'text', text: '```json\n' + JSON.stringify(reply(req.path)) + '\n```' }] });
  });
  fake = g.listen(47324, '127.0.0.1');
  await new Promise((r) => fake.once('listening', r));
});

afterAll(async () => {
  fake?.close();
  await drainBackground();
  await mongoose.disconnect();
});

describe('AI analyst', () => {
  let findingId = '';

  it('stays off until enabled and approved, and says what is missing', async () => {
    findingId = (await finding({ key: 'headers:csp:1', title: 'Content-Security-Policy header missing', description: 'Reported by ravi@example.com from 203.0.113.77 with token ' + FAKE_GH, source: 'headers', evidence: [{ label: 'URL', value: 'https://shop.example.com/' }] })).id;
    const ask = () => post(admin.agent, '/ai/ask', { question: 'Explain this finding', context: { type: 'finding', id: findingId } });
    expect((await ask()).body.error.code).toBe('AI_DISABLED');
    await patch(admin.agent, '/settings', { ai: { enabled: true, shareApproved: false } });
    expect((await ask()).body.error.code).toBe('AI_NOT_APPROVED');
    await patch(admin.agent, '/settings', { ai: { shareApproved: true, provider: 'azure_openai', model: 'shieldops-gpt' } });
    const r = await ask();
    expect(r.body.error.code).toBe('AI_NOT_CONFIGURED');
    expect(r.body.error.message).toMatch(/AZURE_OPENAI_ENDPOINT/);
  });

  it('sends only masked evidence and shows exactly what it sent', async () => {
    await patch(admin.agent, '/settings', { ai: { provider: 'openai', model: 'gpt-4.1-mini' } });
    const r = await post(admin.agent, '/ai/ask', { question: 'Explain this finding', context: { type: 'finding', id: findingId } });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ summary: 'Add the CSP header in nginx.', suggestedTasks: ['Add a CSP header'], model: 'OpenAI gpt-4.1-mini', contextTitle: 'Content-Security-Policy header missing' });
    const outgoing = JSON.stringify(seen.at(-1)!.body);
    for (const raw of ['ravi@example.com', '203.0.113.77', FAKE_GH]) expect(outgoing).not.toContain(raw);
    expect(outgoing).toContain('r***@example.com');
    expect(outgoing).toContain('203.0.113.x');
    expect(seen.at(-1)!.headers.authorization).toBe('Bearer sk-test-openai-key-0000000000');
    // What the person sees as "sent" is what went out.
    const desc = r.body.sent.find((s: { label: string }) => s.label === 'Description').value;
    expect(outgoing).toContain(desc.replace(/"/g, '\\"'));
  });

  it("leaves people's names out of incident context", async () => {
    const inc = await Incident.create({ ref: 'INC-0001', title: 'Checkout errors', severity: 'high', applicationIds: [appId], timeline: [{ at: new Date(), actorName: 'First Admin', kind: 'note', text: 'Rolled back the release' }] });
    const r = await post(admin.agent, '/ai/ask', { question: 'Summarise this incident', context: { type: 'incident', id: inc.id } });
    expect(JSON.stringify(seen.at(-1)!.body)).not.toContain('First Admin');
    expect(JSON.stringify(r.body.sent)).toContain('Rolled back the release');
  });

  it('works with Anthropic, and copes with odd answers and provider errors', async () => {
    await patch(admin.agent, '/settings', { ai: { provider: 'anthropic', model: 'claude-sonnet-4-5' } });
    const r = await post(admin.agent, '/ai/ask', { question: 'What should we fix first?', context: null });
    expect(r.body).toMatchObject({ summary: 'Add the CSP header in nginx.', model: 'Anthropic claude-sonnet-4-5' });
    expect(seen.at(-1)!.headers['x-api-key']).toBe('sk-ant-test-key-0000000000');
    expect(parseAnswer('Not JSON at all').summary).toBe('Not JSON at all');
    await patch(admin.agent, '/settings', { ai: { provider: 'openai' } });
    failNext = true;
    const bad = await post(admin.agent, '/ai/ask', { question: 'Explain', context: { type: 'finding', id: findingId } });
    expect(bad.body.error.code).toBe('AI_PROVIDER_ERROR');
    expect(bad.body.error.message).not.toContain('sk-test-openai-key');
  });

  it('masks addresses and tokens', () => {
    expect(maskForAi(`from 10.1.2.3 and 2001:db8:85a3:0:0:8a2e:370:7334, key ${FAKE_SLACK}`)).toBe('from 10.1.2.x and 2001:db8:85a3:…, key [slack-token]');
  });
});

describe('recommendations', () => {
  it('groups findings into fixes that close the most', async () => {
    const vuln = (id: string, fixedIn: string, priority: string) => finding({ key: `vuln:${assetId}:${id}:lodash`, title: `${id} in lodash 4.17.15`, source: 'vulnerabilities', priority, code: { kind: 'vuln', vulnId: id, package: 'lodash', ecosystem: 'npm', installed: '4.17.15', fixedIn, targetType: 'repository', targetName: 'acme/shop' } });
    await vuln('CVE-2021-23337', '4.17.21', 'P1');
    await vuln('CVE-2020-8203', '4.17.19', 'P2');
    await finding({ key: `secret:${assetId}:abc`, title: 'aws-access-token in config.js', source: 'secrets', code: { kind: 'secret', rule: 'aws-access-token', masked: 'AKIA••LF', file: 'config.js', line: 1, inCurrentCode: true } });
    const recs = (await get(admin.agent, '/recommendations')).body as { id: string; title: string; closes: Record<string, number>; steps: string[] }[];
    const lodash = recs.find((r) => r.id === 'rec-npm:lodash')!;
    expect(lodash.title).toBe('Upgrade lodash to 4.17.21');
    expect(lodash.closes).toMatchObject({ P1: 1, P2: 1 });
    expect(lodash.steps[0]).toMatch(/npm install lodash@\^4\.17\.21/);
    expect(recs[0].id).toBe('rec-npm:lodash');
    expect(recs.map((r) => r.id)).toEqual(expect.arrayContaining(['rec-secrets', 'rec-headers']));
  });

  it('dismisses with a reason and restores', async () => {
    expect((await post(admin.agent, '/recommendations/rec-headers/dismiss', { reason: 'no' })).body.error.code).toBe('REASON_REQUIRED');
    expect((await post(admin.agent, '/recommendations/rec-headers/dismiss', { reason: 'Handled by the CDN team this quarter.' })).body.dismissed).toBe(true);
    expect(((await get(admin.agent, '/recommendations')).body as { id: string }[]).some((r) => r.id === 'rec-headers')).toBe(false);
    expect(((await get(admin.agent, '/recommendations?includeDismissed=true')).body as { id: string; dismissedReason: string }[]).find((r) => r.id === 'rec-headers')?.dismissedReason).toMatch(/CDN/);
    expect((await post(admin.agent, '/recommendations/rec-headers/restore')).body.dismissed).toBe(false);
  });
});

describe('reports', () => {
  const range = { from: new Date(Date.now() - 30 * 86_400_000).toISOString(), to: new Date().toISOString() };

  it('generates a report in the background and serves a real PDF', async () => {
    expect((await post(admin.agent, '/reports', { type: 'posture', from: range.to, to: range.from, applicationId: null })).body.error.code).toBe('INVALID_RANGE');
    const r = await post(admin.agent, '/reports', { type: 'posture', ...range, applicationId: null });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ status: 'generating', title: 'Security posture: All applications' });
    await drainBackground();
    const d = (await get(admin.agent, `/reports/${r.body.id}`)).body;
    expect(d.status).toBe('ready');
    expect(d.sections[0].title).toBe('At a glance');
    expect(d.sections[0].metrics.find((m: { label: string }) => m.label === 'Open P1 findings').value).toBe('1');
    expect(d.sections.find((s: { title: string }) => s.title === 'Recommended next steps').bullets[0]).toMatch(/Upgrade lodash to 4\.17\.21/);
    const pdf = await admin.agent.get(`/api/v1/reports/${r.body.id}/pdf`).buffer(true).parse((res, cb) => { const c: Buffer[] = []; res.on('data', (x: Buffer) => c.push(x)); res.on('end', () => cb(null, Buffer.concat(c))); });
    expect(pdf.headers['content-type']).toBe('application/pdf');
    expect((pdf.body as Buffer).subarray(0, 5).toString()).toBe('%PDF-');
    expect(d.sizeKb).toBeGreaterThan(0);
  });

  it('continues long tables onto more pages', async () => {
    for (let i = 0; i < 90; i++) await Finding.create({ key: `vuln:${assetId}:CVE-2024-${1000 + i}:pkg${i}`, title: `CVE-2024-${1000 + i} in pkg${i}`, category: 'security', source: 'vulnerabilities', applicationId: appId, environmentId: envId, assetId, severity: 'medium', riskScore: 4, priority: 'P3', code: { kind: 'vuln', vulnId: `CVE-2024-${1000 + i}`, package: `pkg${i}`, ecosystem: 'npm', installed: '1.0.0', fixedIn: '1.0.1', targetType: 'repository', targetName: 'acme/shop' } });
    const r = await post(admin.agent, '/reports', { type: 'vulnerabilities', ...range, applicationId: appId });
    await drainBackground();
    const doc = await Report.findById(r.body.id).select('+pdf');
    const pages = (doc!.pdf!.toString('latin1').match(/\/Type \/Page\b/g) ?? []).length;
    expect(pages).toBeGreaterThanOrEqual(3);
  });

  it('schedules reports, and runs a due one for the period just ended', async () => {
    expect((await post(admin.agent, '/report-schedules', { type: 'posture', frequency: 'weekly', recipients: ['not-email'], applicationId: null })).body.error.code).toBe('INVALID_RECIPIENTS');
    const s = await post(admin.agent, '/report-schedules', { type: 'posture', frequency: 'weekly', recipients: ['it@example.com'], applicationId: null });
    const next = new Date(s.body.nextRunAt);
    expect(next.getTime()).toBeGreaterThan(Date.now());
    // Monday 09:00 in Asia/Kolkata is 03:30 UTC on Monday.
    expect(next.getUTCDay()).toBe(1);
    expect(next.toISOString().slice(11, 16)).toBe('03:30');
    await ReportSchedule.updateOne({ _id: s.body.id }, { nextRunAt: new Date(Date.now() - 1000) });
    const before = await Report.countDocuments();
    await runDueSchedules();
    expect(await Report.countDocuments()).toBe(before + 1);
    expect((await ReportSchedule.findById(s.body.id))!.nextRunAt.getTime()).toBeGreaterThan(Date.now());
  });
});

describe('compliance readiness', () => {
  it('evaluates controls from live data and records your own evidence', async () => {
    const fws = (await get(admin.agent, '/compliance/frameworks')).body as { id: string; enabled: boolean }[];
    expect(fws.filter((f) => f.enabled).map((f) => f.id)).toEqual(['iso27001', 'certin']);
    const iso = (await get(admin.agent, '/compliance/frameworks/iso27001/controls')).body;
    expect(iso.controls).toHaveLength(12);
    expect(iso.controls.find((c: { id: string }) => c.id === '5.17')).toMatchObject({ status: 'not_met' });
    expect(iso.controls.find((c: { id: string }) => c.id === '5.17').gaps[0]).toMatch(/still in the current code/);
    const put = (body: object | null) => admin.agent.put('/api/v1/compliance/frameworks/iso27001/controls/8.32/attestation').set('Origin', 'http://localhost:5173').send(body as object);
    expect((await put({ status: 'met', note: 'short' })).body.error.code).toBe('NOTE_REQUIRED');
    const attested = await put({ status: 'met', note: 'Change approvals happen in pull request reviews; see the engineering handbook.' });
    expect(attested.body.score).toBeGreaterThan(iso.score);
    expect(attested.body.controls.find((c: { id: string }) => c.id === '8.32').attestation).toMatchObject({ status: 'met' });
    expect((await put(null)).body.score).toBe(iso.score);
    expect((await admin.agent.put('/api/v1/compliance/frameworks/iso27001/controls/nope/attestation').set('Origin', 'http://localhost:5173').send({ status: 'met', note: 'xxxxxxxxxxxx' })).status).toBe(404);
    expect((await patch(admin.agent, '/compliance/frameworks/soc2', { enabled: true })).body.enabled).toBe(true);
  });
});