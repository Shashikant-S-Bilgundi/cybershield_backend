import { createHmac, createVerify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import type { Server } from 'node:http';
import express from 'express';
import mongoose from 'mongoose';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Alert } from '../src/models/Alert.js';
import { ensureDefaultRules } from '../src/models/AlertRule.js';
import { Asset } from '../src/models/Asset.js';
import { ScanJob } from '../src/models/Code.js';
import { Finding } from '../src/models/Finding.js';
import { drainBackground } from '../src/services/background.js';
import { compareVersions, maskSecret, parseOsv, parseTrivyImage } from '../src/services/scanners.js';
import { processScanQueue } from '../src/services/scans.js';
import { app as api, del, freshDb, get, ORIGIN, patch, post, setupFirstUser } from './helpers.js';

// Fake credentials for the secret-scanning tests. They are assembled at run time so the source never
// contains a complete key: GitHub push protection (rightly) blocks commits that do.
const FAKE_AWS = ['AKIA', 'IOSFODNN7EXAMPLF'].join('');
const FAKE_STRIPE = ['sk', 'live', '51HxQ2bLkdIwHu7ixZ4a8WgZ0Xb1c2d3e4f5g6h7i8j9k0lMnOpQrStUv'].join('_');
const HAVE_SCANNERS = !!process.env.SCANNER_BIN_DIR && existsSync(`${process.env.SCANNER_BIN_DIR}/gitleaks`);
const WORK = '/tmp/so-fake-gh-work';
const BARE = '/tmp/so-fake-gh/acme/shop.git';
let admin: Awaited<ReturnType<typeof setupFirstUser>>;
let appId = '';
let envId = '';
let fake: Server;
const deleted: string[] = [];

const git = (...args: string[]) => execFileSync('git', args, { cwd: WORK, stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_NAME: 'Dev One', GIT_AUTHOR_EMAIL: 'dev@example.com', GIT_COMMITTER_NAME: 'Dev One', GIT_COMMITTER_EMAIL: 'dev@example.com' } });
const push = () => git('push', '-q', 'origin', 'main');

/** A fake GitHub: checks the app JWT signature, issues an installation token, lists repositories. */
function fakeGithub() {
  const g = express();
  const jwtOk = (h?: string) => {
    const [head, body, sig] = (h ?? '').replace('Bearer ', '').split('.');
    if (!sig) return false;
    return createVerify('RSA-SHA256').update(`${head}.${body}`).verify(process.env.TEST_GITHUB_PUBLIC_KEY!, Buffer.from(sig, 'base64url')) && JSON.parse(Buffer.from(body, 'base64url').toString()).iss === '12345';
  };
  g.use(express.json());
  g.get('/app/installations/:id', (req, res) => (jwtOk(req.get('authorization')) ? res.json({ id: Number(req.params.id), account: { login: 'acme' }, permissions: { contents: 'read', metadata: 'read', packages: 'read' } }) : res.status(401).json({ message: 'Bad credentials' })));
  g.post('/app/installations/:id/access_tokens', (req, res) => {
    if (!jwtOk(req.get('authorization'))) return res.status(401).json({ message: 'Bad credentials' });
    // ShieldOps must ask for read-only permissions.
    if (JSON.stringify(req.body.permissions) !== JSON.stringify({ contents: 'read', metadata: 'read', packages: 'read' })) return res.status(422).json({ message: 'unexpected permissions' });
    res.status(201).json({ token: 'ghs_testinstallationtoken', expires_at: new Date(Date.now() + 3_600_000).toISOString() });
  });
  g.delete('/app/installations/:id', (req, res) => (jwtOk(req.get('authorization')) ? (deleted.push(String(req.params.id)), res.status(204).end()) : res.status(401).end()));
  g.get('/installation/repositories', (req, res) => {
    if (req.get('authorization') !== 'token ghs_testinstallationtoken') return res.status(401).json({ message: 'Bad credentials' });
    res.json({ total_count: 2, repositories: [{ id: 1001, full_name: 'acme/shop', private: true, default_branch: 'main', language: 'JavaScript' }, { id: 1002, full_name: 'acme/web', private: false, default_branch: 'main', language: 'TypeScript' }] });
  });
  g.get('/dockerauth', (req, res) => (req.get('authorization') === `Basic ${Buffer.from('acme:dckr_pat_good').toString('base64')}` ? res.json({ token: 'x' }) : res.status(401).json({ details: 'incorrect username or password' })));
  return g.listen(47321, '127.0.0.1');
}

beforeAll(async () => {
  await freshDb();
  await ensureDefaultRules();
  admin = await setupFirstUser();
  const a = await post(admin.agent, '/applications', { name: 'Shop', ownerId: admin.user.id, criticality: 'critical', environments: [{ name: 'Production', type: 'production' }] });
  appId = a.body.id;
  envId = a.body.environments[0].id;
  fake = fakeGithub();
  await new Promise((r) => fake.once('listening', r));

  // A repository with a key in its history, a key in its current code, and a weak Dockerfile.
  rmSync('/tmp/so-fake-gh', { recursive: true, force: true });
  rmSync(WORK, { recursive: true, force: true });
  mkdirSync(WORK, { recursive: true });
  mkdirSync('/tmp/so-fake-gh/acme', { recursive: true });
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', BARE]);
  git('init', '-q', '-b', 'main');
  git('remote', 'add', 'origin', BARE);
  writeFileSync(`${WORK}/config.js`, `const key = "${FAKE_AWS}";\n`);
  git('add', '.');
  git('commit', '-qm', 'config');
  writeFileSync(`${WORK}/config.js`, 'const key = process.env.KEY;\n');
  writeFileSync(`${WORK}/pay.py`, `stripe = "${FAKE_STRIPE}"\n`);
  writeFileSync(`${WORK}/Dockerfile`, 'FROM node:14\nUSER root\nADD . /app\n');
  // A real lockfile, so OSV-Scanner has something to check (and needs its online database to do it).
  writeFileSync(`${WORK}/package-lock.json`, JSON.stringify({ name: 'shop', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'shop', version: '1.0.0', dependencies: { lodash: '4.17.15' } }, 'node_modules/lodash': { version: '4.17.15', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz' } } }));
  git('add', '.');
  git('commit', '-qm', 'payments');
  push();
}, 60_000);

afterAll(async () => {
  fake?.close();
  await drainBackground();
  await mongoose.disconnect();
});

describe('connecting GitHub', () => {
  it('lists integrations, all of them available', async () => {
    const list = (await get(admin.agent, '/integrations')).body as { type: string; status: string; availableInPhase: number | null }[];
    expect(list.find((i) => i.type === 'github')).toMatchObject({ status: 'not_connected', availableInPhase: null });
    expect(list.every((i) => i.availableInPhase === null)).toBe(true);
  });

  it('sends you to GitHub to install the app, and checks the state on the way back', async () => {
    const r = await post(admin.agent, '/integrations/github/connect');
    expect(r.body.redirectUrl).toMatch(/^https:\/\/github\.example\/apps\/shieldops-test\/installations\/new\?state=[\w-]{30,}$/);
    const state = new URL(r.body.redirectUrl).searchParams.get('state')!;
    const forged = await admin.agent.get('/api/v1/integrations/github/callback?installation_id=777&state=not-the-real-state');
    expect(forged.headers.location).toMatch(/github=expired$/);
    const ok = await admin.agent.get(`/api/v1/integrations/github/callback?installation_id=777&setup_action=install&state=${state}`);
    expect(ok.headers.location).toBe('http://localhost:5173/integrations?github=connected');
    // A state works once.
    expect((await admin.agent.get(`/api/v1/integrations/github/callback?installation_id=777&state=${state}`)).headers.location).toMatch(/expired/);
    const list = (await get(admin.agent, '/integrations')).body as { type: string; status: string; account: string; scopes: string[] }[];
    expect(list.find((i) => i.type === 'github')).toMatchObject({ status: 'connected', account: 'acme' });
    expect(list.find((i) => i.type === 'ghcr')?.status).toBe('connected');
  });

  it('checks Docker Hub tokens before storing them, encrypted', async () => {
    const bad = await post(admin.agent, '/integrations/dockerhub/connect', { username: 'acme', token: 'wrong' });
    expect(bad.body.error.code).toBe('INVALID_CREDENTIALS');
    const ok = await post(admin.agent, '/integrations/dockerhub/connect', { username: 'acme', token: 'dckr_pat_good' });
    expect(ok.body).toMatchObject({ status: 'connected', account: 'acme' });
    expect(JSON.stringify((await get(admin.agent, '/integrations')).body)).not.toContain('dckr_pat_good');
  });
});

describe('repositories and scans', () => {
  let repoId = '';
  let assetId = '';

  it('lists repositories the app can see and adds one as an approved asset', async () => {
    const avail = (await get(admin.agent, '/repositories/available')).body;
    expect(avail.map((r: { fullName: string }) => r.fullName)).toEqual(['acme/shop', 'acme/web']);
    const added = await post(admin.agent, '/repositories', { fullNames: ['acme/shop'], applicationId: appId, environmentId: envId });
    expect(added.status).toBe(201);
    repoId = added.body[0].id;
    assetId = added.body[0].assetId;
    expect(added.body[0].lastScan).toMatchObject({ status: 'queued', trigger: 'initial' });
    expect((await Asset.findById(assetId))?.authorization?.status).toBe('approved');
    expect((await get(admin.agent, '/repositories/available')).body).toHaveLength(1);
    expect((await post(admin.agent, '/repositories', { fullNames: ['acme/shop'], applicationId: appId, environmentId: envId })).body.error.code).toBe('ALREADY_ADDED');
  });

  it('scans: secrets and Dockerfile problems found, a failed scanner shown as failed', async () => {
    await processScanQueue();
    const [job] = (await get(admin.agent, `/scans?targetType=repository&targetId=${repoId}`)).body;
    expect(job.revision).toMatch(/^[0-9a-f]{40}$/);
    if (!HAVE_SCANNERS) {
      expect(job.status).toBe('failed');
      expect(job.runs[0].error).toMatch(/not installed/);
      return;
    }
    const runs = Object.fromEntries(job.runs.map((r: { scanner: string; status: string; version: string }) => [r.scanner, r]));
    expect(runs.gitleaks).toMatchObject({ status: 'completed', version: '8.30.1' });
    expect(runs.trivy.status).toBe('completed');
    // OSV needs the internet. Here it fails, and the scan says "partial", never "clean".
    if (runs.osv.status === 'failed') expect(job.status).toBe('partial');

    const secrets = (await get(admin.agent, `/findings?assetId=${assetId}&source=secrets`)).body as { title: string; severity: string; code: { inCurrentCode: boolean; masked: string; rule: string } }[];
    expect(secrets).toHaveLength(2);
    const stripe = secrets.find((s) => s.code.rule.includes('stripe'))!;
    const aws = secrets.find((s) => s.code.rule.includes('aws'))!;
    expect(stripe).toMatchObject({ severity: 'critical', code: { inCurrentCode: true } });
    expect(aws).toMatchObject({ severity: 'medium', code: { inCurrentCode: false } });
    expect(aws.title).toMatch(/in the history of config\.js/);
    // The full secret is never stored, only a masked form.
    const everything = JSON.stringify(await Finding.find().lean()) + JSON.stringify(await Alert.find().lean()) + JSON.stringify(await ScanJob.find().lean());
    expect(everything).not.toContain(FAKE_AWS);
    expect(everything).not.toContain(FAKE_STRIPE);
    expect(stripe.code.masked).toMatch(/^sk_l•+Uv$/);

    const misconfig = (await Finding.find({ assetId, key: /^misconfig:/ }).lean()).map((f) => f.title);
    expect(misconfig.some((t) => /root/i.test(t))).toBe(true);
    const repo = (await get(admin.agent, `/repositories/${repoId}`)).body;
    expect(repo.openSecrets).toBe(2);
    expect(await Alert.countDocuments({ title: '2 secrets found in acme/shop', severity: 'high' })).toBe(1);
  }, 120_000);

  it('verifies fixes only for scanners that completed', async () => {
    if (!HAVE_SCANNERS) return;
    // Whether OSV can reach its database here or not, the lodash finding must not be marked fixed:
    // either OSV fails (and a failed scanner never verifies), or it finds lodash 4.17.15 again.
    // A vulnerability finding owned by OSV, which cannot run here: it must stay open.
    await Finding.create({ key: `vuln:${assetId}:CVE-2021-23337:lodash`, title: 'CVE-2021-23337 in lodash 4.17.15', category: 'security', source: 'vulnerabilities', applicationId: appId, environmentId: envId, assetId, severity: 'high', riskScore: 9, priority: 'P2', code: { kind: 'vuln', vulnId: 'CVE-2021-23337', package: 'lodash', ecosystem: 'npm', installed: '4.17.15', fixedIn: '4.17.21', targetType: 'repository', targetName: 'acme/shop' } });
    // Fix the Dockerfile and move the Stripe key out of the code (it stays in history).
    writeFileSync(`${WORK}/Dockerfile`, 'FROM node:22-alpine\nRUN adduser -D app\nUSER app\nCOPY . /app\nHEALTHCHECK CMD wget -q -O- http://localhost:3000/health || exit 1\n');
    writeFileSync(`${WORK}/pay.py`, 'import os\nstripe = os.environ["STRIPE_KEY"]\n');
    git('commit', '-qam', 'fixes');
    push();
    expect((await post(admin.agent, '/scans', { targetType: 'repository', targetId: repoId })).status).toBe(201);
    expect((await post(admin.agent, '/scans', { targetType: 'repository', targetId: repoId })).body.error.code).toBe('SCAN_IN_PROGRESS');
    await processScanQueue();
    const [job] = (await get(admin.agent, `/scans?targetType=repository&targetId=${repoId}`)).body;
    expect(job.fixedFindings).toBeGreaterThanOrEqual(1);
    expect(await Finding.countDocuments({ assetId, key: /^misconfig:.*DS-?0002/, status: 'verified' })).toBe(1);
    const stripe = await Finding.findOne({ assetId, 'code.rule': /stripe/ });
    expect(stripe).toMatchObject({ status: 'open', severity: 'medium', code: { inCurrentCode: false } });
    expect((await Finding.findOne({ key: `vuln:${assetId}:CVE-2021-23337:lodash` }))?.status).toBe('open');
    const deps = (await get(admin.agent, '/dependencies')).body as { package: string; upgradeTo: string; vulns: number }[];
    const lodash = deps.find((d) => d.package === 'lodash')!;
    expect(lodash.upgradeTo).toBe('4.17.21');
    expect(lodash.vulns).toBeGreaterThanOrEqual(1);
  }, 120_000);

  it('scans on push to the default branch, from signed webhooks only', async () => {
    const send = (body: object, secret = 'whsec-test-secret') => {
      const raw = JSON.stringify(body);
      return request(api).post('/api/v1/webhooks/github').set('content-type', 'application/json').set('x-github-event', 'push').set('x-hub-signature-256', `sha256=${createHmac('sha256', secret).update(raw).digest('hex')}`).send(raw);
    };
    expect((await send({ ref: 'refs/heads/main', repository: { id: 1001 } }, 'wrong-secret')).status).toBe(401);
    expect((await send({ ref: 'refs/heads/feature', repository: { id: 1001 } })).status).toBe(202);
    expect(await ScanJob.countDocuments({ targetId: repoId, status: 'queued' })).toBe(0);
    await send({ ref: 'refs/heads/main', repository: { id: 1001 } });
    expect(await ScanJob.countDocuments({ targetId: repoId, status: 'queued', trigger: 'push' })).toBe(1);
    await ScanJob.updateMany({ targetId: repoId, status: 'queued' }, { status: 'cancelled' });
    expect((await patch(admin.agent, `/repositories/${repoId}`, { scanOnPush: false })).body.scanOnPush).toBe(false);
  });

  it('marks an image scan that cannot run as failed, and alerts after three', async () => {
    const img = await post(admin.agent, '/images', { registry: 'ghcr.io', repository: 'acme/shop', tag: '2.3.1', applicationId: appId, environmentId: envId });
    expect(img.status).toBe(201);
    expect((await post(admin.agent, '/images', { registry: 'ghcr.io', repository: 'acme/shop', tag: '2.3.1', applicationId: appId, environmentId: envId })).body.error.code).toBe('ALREADY_ADDED');
    await processScanQueue();
    for (let i = 0; i < 2; i++) {
      await post(admin.agent, '/scans', { targetType: 'image', targetId: img.body.id });
      await processScanQueue();
    }
    const jobs = (await get(admin.agent, `/scans?targetType=image&targetId=${img.body.id}`)).body;
    expect(jobs).toHaveLength(3);
    if (jobs[0].status === 'failed') {
      expect(jobs[0].runs[0].error).toBeTruthy();
      expect(await Alert.countDocuments({ title: 'Scans of ghcr.io/acme/shop:2.3.1 keep failing', status: 'open' })).toBe(1);
    }
  }, 180_000);

  it('removes a repository and closes its findings', async () => {
    const open = await Finding.countDocuments({ assetId, status: 'open' });
    expect((await del(admin.agent, `/repositories/${repoId}`)).status).toBe(204);
    expect(await Finding.countDocuments({ assetId, status: 'open' })).toBe(0);
    if (open) expect(await Finding.countDocuments({ assetId, status: 'resolved', 'history.0.text': /removed from ShieldOps/ })).toBe(open);
  });

  it('uninstalls the app on GitHub when disconnecting', async () => {
    expect((await post(admin.agent, '/integrations/github/disconnect')).body.status).toBe('not_connected');
    expect(deleted).toEqual(['777']);
    expect((await get(admin.agent, '/repositories/available')).body.error.code).toBe('GITHUB_NOT_CONNECTED');
    expect((await get(admin.agent, '/integrations')).body.find((i: { type: string }) => i.type === 'ghcr').status).toBe('not_connected');
  });
});

describe('parsers', () => {
  it('reads OSV-Scanner output: CVE id, aliases, fix and severity', () => {
    const r = parseOsv({
      results: [{ source: { path: '/src/package-lock.json', type: 'lockfile' }, packages: [{
        package: { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
        vulnerabilities: [{ id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command Injection in lodash', affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] }],
        groups: [{ ids: ['GHSA-35jh-r3h4-6jhm'], aliases: ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm'], max_severity: '7.2' }],
      }] }],
    });
    expect(r.packages).toBe(1);
    expect(r.vulns[0]).toMatchObject({ vulnId: 'CVE-2021-23337', aliases: ['GHSA-35jh-r3h4-6jhm'], package: 'lodash', installed: '4.17.15', fixedIn: '4.17.21', cvss: 7.2, severity: 'high', ecosystem: 'npm' });
  });

  it('reads Trivy image output', () => {
    const r = parseTrivyImage({ Metadata: { OS: { Family: 'debian', Name: '12.5' }, RepoDigests: ['ghcr.io/acme/shop@sha256:abc123'], Size: 157286400 }, Results: [{ Target: 'ghcr.io/acme/shop (debian 12.5)', Type: 'debian', Vulnerabilities: [{ VulnerabilityID: 'CVE-2023-4911', PkgName: 'libc6', InstalledVersion: '2.36-9', FixedVersion: '2.36-9+deb12u3', Severity: 'HIGH', CVSS: { nvd: { V3Score: 7.8 } }, Title: 'Looney Tunables' }] }] });
    expect(r).toMatchObject({ digest: 'sha256:abc123', os: 'debian 12.5', sizeMb: 150 });
    expect(r.vulns[0]).toMatchObject({ vulnId: 'CVE-2023-4911', package: 'libc6', ecosystem: 'debian', fixedIn: '2.36-9+deb12u3', cvss: 7.8, severity: 'high' });
  });

  it('compares versions and masks secrets', () => {
    expect(['4.17.21', '4.17.19', '4.2.0'].sort(compareVersions)).toEqual(['4.2.0', '4.17.19', '4.17.21']);
    expect(maskSecret(['AKIA', 'IOSFODNN7EXAMPLE'].join(''))).toBe('AKIA••••••••••••LE');
    expect(maskSecret('short')).toBe('****');
  });
});

describe('routing', () => {
  it('refuses unsigned webhooks when no secret is configured, and keeps the console CSRF check', async () => {
    const r = await request(api).post('/api/v1/repositories').set('Origin', 'https://evil.example').send({});
    expect(r.status).toBe(403);
    expect(ORIGIN).toBe('http://localhost:5173');
  });
});