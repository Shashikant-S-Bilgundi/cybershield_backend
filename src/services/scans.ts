import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Types } from 'mongoose';
import { config } from '../config.js';
import { ApiError } from '../lib/errors.js';
import { installationToken } from '../lib/github.js';
import { logger } from '../lib/logger.js';
import { decrypt } from '../lib/crypto.js';
import { Asset, type AssetDoc } from '../models/Asset.js';
import { ContainerImage, Integration, KevCache, Repository, ScanJob, type ImageDoc, type RepositoryDoc, type ScanJobDoc } from '../models/Code.js';
import { Finding } from '../models/Finding.js';
import { autoResolve, pickRule, raiseAlert } from './alerts.js';
import { problemGone, reportProblem } from './findings.js';
import { settleAfterScan } from './verification.js';
import { cacheDir, explainFailure, parseGitleaks, parseOsv, parseTrivyImage, parseTrivyMisconfig, readJson, run, ScannerError, secretSeverity, tail, versionOf, type VulnHit } from './scanners.js';

type Scanner = 'gitleaks' | 'osv' | 'trivy';
const SCANNERS: Record<'repository' | 'image', Scanner[]> = { repository: ['gitleaks', 'osv', 'trivy'], image: ['trivy'] };
const DAY = 86_400_000;

/* ───────────── queue ───────────── */

export async function queueScan(targetType: 'repository' | 'image', targetId: Types.ObjectId | string, trigger: 'initial' | 'manual' | 'schedule' | 'push') {
  if (await ScanJob.exists({ targetType, targetId, status: { $in: ['queued', 'running'] } })) throw new ApiError(409, 'SCAN_IN_PROGRESS', 'A scan is already running for this target.');
  return ScanJob.create({ targetType, targetId, trigger, runs: SCANNERS[targetType].map((scanner) => ({ scanner, status: 'queued' })) });
}

/** A restart in the middle of a scan leaves it "running"; mark those as failed so they can be retried. */
export async function recoverInterruptedScans() {
  await ScanJob.updateMany({ status: 'running' }, { status: 'failed', finishedAt: new Date(), $set: { 'runs.$[r].status': 'failed', 'runs.$[r].error': 'Interrupted by a ShieldOps restart' } }, { arrayFilters: [{ 'r.status': { $in: ['queued', 'running'] } }] });
}

/** Targets with a daily scan whose last scan started more than a day ago. */
export async function queueDailyScans() {
  for (const [targetType, Model] of [['repository', Repository], ['image', ContainerImage]] as const) {
    const targets = await (Model as typeof Repository).find({ dailyScan: true }, { _id: 1 }).lean();
    for (const t of targets) {
      const last = await ScanJob.findOne({ targetType, targetId: t._id }).sort({ queuedAt: -1 }).lean();
      if (!last || (last.status !== 'queued' && last.status !== 'running' && Date.now() - last.queuedAt.getTime() > DAY)) await queueScan(targetType, t._id, 'schedule').catch(() => {});
    }
  }
}

let busy = false;
/** Runs the oldest queued scan. One at a time: scans are heavy, and the server also serves the console. */
export async function processScanQueue() {
  if (busy) return;
  busy = true;
  try {
    const job = await ScanJob.findOneAndUpdate({ status: 'queued' }, { status: 'running', startedAt: new Date() }, { sort: { queuedAt: 1 }, new: true });
    if (job) await runScanJob(job);
  } catch (err) {
    logger.error({ err }, 'Scan queue failed');
  } finally {
    busy = false;
  }
}

/* ───────────── known exploited (CISA KEV) ───────────── */

let kev: Set<string> | null = null;
/** Daily copy of CISA's list. If it cannot be fetched, the last copy is used; never blocks a scan. */
export async function knownExploited(): Promise<Set<string>> {
  const doc = await KevCache.findById('kev');
  if (kev && doc?.fetchedAt && Date.now() - doc.fetchedAt.getTime() < DAY) return kev;
  try {
    const r = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { signal: AbortSignal.timeout(20_000) });
    const j = (await r.json()) as { vulnerabilities: { cveID: string }[] };
    const ids = j.vulnerabilities.map((v) => v.cveID);
    await KevCache.updateOne({ _id: 'kev' }, { ids, fetchedAt: new Date() }, { upsert: true });
    kev = new Set(ids);
  } catch {
    kev = new Set(doc?.ids ?? []);
  }
  return kev;
}

/* ───────────── running a scan ───────────── */

interface Outcome {
  seen: Set<string>;
  newCount: number;
  newSecrets: number;
  newHigh: number;
  newKev: string[];
}

async function setRun(job: ScanJobDoc, scanner: Scanner, patch: { status: string; durationMs?: number | null; error?: string | null; version?: string }) {
  const r = job.runs.find((x) => x.scanner === scanner)!;
  Object.assign(r, patch);
  await job.save();
}

/** Runs one scanner, timing it and recording failure without stopping the others. */
async function step(job: ScanJobDoc, scanner: Scanner, fn: () => Promise<void>): Promise<boolean> {
  const started = Date.now();
  await setRun(job, scanner, { status: 'running', version: await versionOf(scanner === 'osv' ? 'osv-scanner' : scanner) });
  try {
    await fn();
    await setRun(job, scanner, { status: 'completed', durationMs: Date.now() - started, error: null });
    return true;
  } catch (err) {
    const msg = err instanceof ScannerError || err instanceof ApiError ? err.message : (err as Error).message?.slice(0, 400) || 'The scanner failed.';
    await setRun(job, scanner, { status: 'failed', durationMs: Date.now() - started, error: msg });
    return false;
  }
}

async function vulnFinding(asset: AssetDoc, v: VulnHit, targetType: 'repository' | 'image', targetName: string, kevIds: Set<string>, out: Outcome) {
  const key = `vuln:${asset.id}:${v.vulnId}:${v.package}`;
  out.seen.add(key);
  const exploited = [v.vulnId, ...v.aliases].some((id) => kevIds.has(id));
  const r = await reportProblem(asset, {
    key,
    title: `${v.vulnId} in ${v.package} ${v.installed}`,
    description: `${v.summary || 'A known vulnerability affects this version.'}${v.fixedIn ? ` Upgrade to ${v.fixedIn} or later.` : ' No fixed version is available yet.'}`,
    category: 'security',
    source: 'vulnerabilities',
    severity: exploited && v.severity !== 'critical' ? 'high' : v.severity,
    knownExploited: exploited,
    evidence: [{ label: 'Package', value: `${v.package} ${v.installed} (${v.ecosystem})` }, { label: 'Found in', value: v.source || targetName }, ...(v.fixedIn ? [{ label: 'Fixed in', value: v.fixedIn }] : [])],
    code: { kind: 'vuln', vulnId: v.vulnId, aliases: v.aliases, package: v.package, ecosystem: v.ecosystem, installed: v.installed, fixedIn: v.fixedIn, cvss: v.cvss, sources: [targetType === 'image' ? 'trivy' : 'osv'], targetType, targetName },
  });
  if (r.isNew || r.reopened) {
    out.newCount++;
    if (exploited) out.newKev.push(v.vulnId);
    else if (v.severity === 'critical' || v.severity === 'high') out.newHigh++;
  }
}

async function scanRepository(job: ScanJobDoc, repo: RepositoryDoc, asset: AssetDoc, out: Outcome, completed: Set<Scanner>) {
  const gh = await Integration.findOne({ type: 'github', status: 'connected' });
  if (!gh?.installationId) throw new ApiError(409, 'GITHUB_NOT_CONNECTED', 'GitHub is disconnected, so the repository cannot be cloned. Reconnect it in Integrations.');
  const token = await installationToken(gh.installationId);
  const dir = await mkdtemp(join(tmpdir(), 'shieldops-scan-'));
  try {
    const src = join(dir, 'src');
    // The token goes to git through its environment, never on the command line or into .git/config.
    const cloneUrl = process.env.GITHUB_CLONE_BASE ? `${process.env.GITHUB_CLONE_BASE}/${repo.fullName}.git` : `${config.GITHUB_WEB_URL.replace(/\/$/, '')}/${repo.fullName}.git`;
    const auth = Buffer.from(`x-access-token:${token}`).toString('base64');
    const gitEnv = { GIT_TERMINAL_PROMPT: '0', GIT_LFS_SKIP_SMUDGE: '1', GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.extraHeader', GIT_CONFIG_VALUE_0: `Authorization: Basic ${auth}` };
    const clone = await run('git', ['clone', '--quiet', '--no-recurse-submodules', '--branch', repo.defaultBranch, cloneUrl, src], { env: gitEnv, timeoutMs: 10 * 60_000 }).catch((e: Error) => ({ code: 1, stdout: '', stderr: e.message }));
    if (clone.code !== 0) throw new ApiError(502, 'CLONE_FAILED', `Could not clone ${repo.fullName}: ${tail(clone.stderr)}`);
    job.revision = (await run('git', ['rev-parse', 'HEAD'], { cwd: src })).stdout.trim().slice(0, 40);
    await job.save();

    if (await step(job, 'gitleaks', async () => {
      const report = join(dir, 'gitleaks.json');
      const r = await run('gitleaks', ['git', src, '--report-format', 'json', '--report-path', report, '--no-banner', '--exit-code', '0', '--log-level', 'error']);
      if (r.code !== 0) throw new ScannerError(explainFailure('gitleaks', r.stderr, r.code));
      const raw = await readJson(report);
      const files = new Map<string, string>();
      for (const f of new Set((raw as { File: string }[]).map((x) => x.File))) files.set(f, await readFile(join(src, f), 'utf8').catch(() => ''));
      for (const h of parseGitleaks(raw, files)) {
        const key = `secret:${asset.id}:${h.hash}`;
        out.seen.add(key);
        const res = await reportProblem(asset, {
          key,
          title: `${h.rule} ${h.inCurrentCode ? 'in' : 'in the history of'} ${h.file}`,
          description: h.inCurrentCode
            ? 'This credential is in the current code. Revoke it at the provider first, then remove it and load it from the environment instead.'
            : 'This credential was removed from the code but is still in the git history, where anyone with access can read it. Revoke it at the provider; rewriting history is optional once it no longer works.',
          category: 'security',
          source: 'secrets',
          severity: secretSeverity(h),
          evidence: [{ label: 'File', value: `${h.file}:${h.line}` }, { label: 'Commit', value: `${h.commit.slice(0, 7)} by ${h.author}` }, { label: 'Value', value: h.masked }],
          code: { kind: 'secret', rule: h.rule, masked: h.masked, file: h.file, line: h.line, commit: h.commit, author: h.author, committedAt: h.committedAt, inCurrentCode: h.inCurrentCode },
        });
        if (res.isNew || res.reopened) {
          out.newCount++;
          out.newSecrets++;
        }
      }
    })) completed.add('gitleaks');

    const kevIds = await knownExploited();
    if (await step(job, 'osv', async () => {
      const r = await run('osv-scanner', ['scan', 'source', '-r', '--format', 'json', src]);
      // 0 = nothing found, 1 = vulnerabilities found, 128 = no package files. Anything else is a failure.
      if (![0, 1, 128].includes(r.code)) throw new ScannerError(explainFailure('osv-scanner', r.stderr, r.code));
      const { packages, vulns } = r.code === 128 ? { packages: 0, vulns: [] } : parseOsv(JSON.parse(r.stdout || '{}'));
      repo.dependencies = packages;
      for (const v of vulns) await vulnFinding(asset, v, 'repository', repo.fullName, kevIds, out);
    })) completed.add('osv');

    if (await step(job, 'trivy', async () => {
      const r = await run('trivy', ['fs', '--scanners', 'misconfig', '--format', 'json', '--quiet', '--cache-dir', cacheDir(), src]);
      if (r.code !== 0) throw new ScannerError(explainFailure('trivy', r.stderr, r.code));
      for (const m of parseTrivyMisconfig(JSON.parse(r.stdout || '{}'))) {
        const key = `misconfig:${asset.id}:${m.checkId}:${m.file}`;
        out.seen.add(key);
        const res = await reportProblem(asset, { key, title: `${m.title} (${m.file})`, description: `${m.description} ${m.resolution}`.trim(), category: 'configuration', source: 'vulnerabilities', severity: m.severity, evidence: [{ label: 'File', value: `${m.file}${m.line ? `:${m.line}` : ''}` }, { label: 'Check', value: m.checkId }] });
        if (res.isNew || res.reopened) out.newCount++;
      }
    })) completed.add('trivy');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function scanImage(job: ScanJobDoc, img: ImageDoc, asset: AssetDoc, out: Outcome, completed: Set<Scanner>) {
  const ref = `${img.registry}/${img.repository}:${img.tag}`;
  const env: Record<string, string> = {};
  if (img.registry === 'ghcr.io') {
    const gh = await Integration.findOne({ type: 'github', status: 'connected' });
    if (!gh?.installationId) throw new ApiError(409, 'GITHUB_NOT_CONNECTED', 'GitHub is disconnected, so ghcr.io images cannot be pulled. Reconnect it in Integrations.');
    Object.assign(env, { TRIVY_USERNAME: 'x-access-token', TRIVY_PASSWORD: await installationToken(gh.installationId) });
  } else {
    const hub = await Integration.findOne({ type: 'dockerhub', status: 'connected' });
    if (hub?.credentialsEnc) {
      const c = JSON.parse(decrypt(hub.credentialsEnc)) as { username: string; token: string };
      Object.assign(env, { TRIVY_USERNAME: c.username, TRIVY_PASSWORD: c.token });
    }
  }
  const kevIds = await knownExploited();
  if (await step(job, 'trivy', async () => {
    const r = await run('trivy', ['image', '--scanners', 'vuln', '--format', 'json', '--quiet', '--cache-dir', cacheDir(), ref], { env });
    if (r.code !== 0) throw new ScannerError(explainFailure('trivy', r.stderr, r.code));
    const parsed = parseTrivyImage(JSON.parse(r.stdout || '{}'));
    Object.assign(img, { digest: parsed.digest || img.digest, os: parsed.os || img.os, sizeMb: parsed.sizeMb || img.sizeMb });
    job.revision = parsed.digest || null;
    for (const v of parsed.vulns) await vulnFinding(asset, v, 'image', ref, kevIds, out);
  })) completed.add('trivy');
}

/** Which finding keys each scanner owns, so only a completed scanner can mark its findings fixed. */
const OWNS: Record<Scanner, RegExp> = { gitleaks: /^secret:/, osv: /^vuln:/, trivy: /^(misconfig|vuln):/ };

export async function runScanJob(job: ScanJobDoc) {
  const target = job.targetType === 'repository' ? await Repository.findById(job.targetId) : await ContainerImage.findById(job.targetId);
  const out: Outcome = { seen: new Set(), newCount: 0, newSecrets: 0, newHigh: 0, newKev: [] };
  const completed = new Set<Scanner>();
  const asset = target ? await Asset.findById(target.assetId) : null;
  try {
    if (!target || !asset) throw new ApiError(404, 'NOT_FOUND', 'The scan target no longer exists.');
    if (job.targetType === 'repository') await scanRepository(job, target as RepositoryDoc, asset, out, completed);
    else await scanImage(job, target as ImageDoc, asset, out, completed);
  } catch (err) {
    // Clone or credential problems fail every scanner that had not run yet.
    const msg = (err as Error).message?.slice(0, 400) ?? 'The scan failed.';
    for (const r of job.runs) if (r.status === 'queued' || r.status === 'running') Object.assign(r, { status: 'failed', error: msg });
  }

  // Findings this target had before, owned by a scanner that completed, and not seen now: fixed.
  let fixed = 0;
  if (asset) {
    const ownedKeys = (k: string) => [...completed].some((s) => OWNS[s].test(k)) && !(k.startsWith('vuln:') && job.targetType === 'repository' && !completed.has('osv'));
    const open = await Finding.find({ assetId: asset._id, status: { $in: ['open', 'acknowledged', 'in_progress', 'resolved', 'reopened'] } }, { key: 1 }).lean();
    for (const f of open) if (ownedKeys(f.key) && !out.seen.has(f.key) && (await problemGone(f.key, `Verified fixed: not found by the ${job.targetType} scan of ${job.revision?.slice(0, 12) ?? 'the latest version'}`))) fixed++;
  }

  const ok = job.runs.filter((r) => r.status === 'completed').length;
  job.status = ok === job.runs.length ? 'completed' : ok === 0 ? 'failed' : 'partial';
  job.finishedAt = new Date();
  job.newFindings = out.newCount;
  job.fixedFindings = fixed;
  await job.save();
  if (target && asset) {
    await refreshCounts(target, asset._id);
    await scanAlerts(job, target, out);
    await settleAfterScan(asset._id, job);
  }
  logger.info({ scan: job.id, status: job.status, new: out.newCount, fixed }, 'Scan finished');
  return job;
}

/** Cached counts on the repository or image, from its active findings. */
async function refreshCounts(target: RepositoryDoc | ImageDoc, assetId: Types.ObjectId) {
  const active = await Finding.find({ assetId, status: { $nin: ['resolved', 'verified', 'accepted_risk', 'false_positive'] } }, { key: 1, severity: 1 }).lean();
  const vulns = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of active) if (f.key.startsWith('vuln:')) vulns[f.severity as keyof typeof vulns]++;
  target.set({ vulns });
  if ('openSecrets' in target) target.set({ openSecrets: active.filter((f) => f.key.startsWith('secret:')).length });
  await target.save();
}

/** One alert per scan per kind (not one per finding), and an alert when scans keep failing. */
async function scanAlerts(job: ScanJobDoc, target: RepositoryDoc | ImageDoc, out: Outcome) {
  const name = 'fullName' in target ? target.fullName : `${target.registry}/${target.repository}:${target.tag}`;
  const where = { applicationId: target.applicationId, environmentId: target.environmentId, assetId: target.assetId };
  if (out.newSecrets) await raiseAlert({ ...where, key: `scan:secret:${job.id}`, signal: 'secret_found', source: 'secrets', title: `${out.newSecrets} secret${out.newSecrets > 1 ? 's' : ''} found in ${name}`, message: 'Revoke each credential at its provider first, then remove it from the code.' });
  if (out.newKev.length) await raiseAlert({ ...where, key: `scan:kev:${job.id}`, signal: 'vuln_exploited', source: 'vulnerabilities', title: `Known-exploited vulnerability in ${name}`, message: `${[...new Set(out.newKev)].join(', ')} ${out.newKev.length > 1 ? 'are' : 'is'} on CISA's list of vulnerabilities attackers are using now. Fix first.` });
  if (out.newHigh) await raiseAlert({ ...where, key: `scan:vuln:${job.id}`, signal: 'vuln_found', source: 'vulnerabilities', title: `${out.newHigh} new critical or high vulnerabilit${out.newHigh > 1 ? 'ies' : 'y'} in ${name}`, message: 'See Vulnerabilities for the packages and the versions that fix them.' });

  const key = `scan:failing:${target.id}`;
  const rule = await pickRule({ signal: 'scan_failed', key, ...where, source: 'vulnerabilities', title: '', message: '' });
  const recent = await ScanJob.find({ targetId: target._id, status: { $in: ['completed', 'partial', 'failed'] } }).sort({ queuedAt: -1 }).limit(rule?.threshold ?? 3).lean();
  if (rule && recent.length >= (rule.threshold ?? 3) && recent.every((s) => s.status !== 'completed')) {
    const why = job.runs.find((r) => r.error)?.error ?? 'see the scan history';
    await raiseAlert({ ...where, key, signal: 'scan_failed', value: recent.length, source: 'vulnerabilities', title: `Scans of ${name} keep failing`, message: `The last ${recent.length} scans did not finish: ${why}. Results may be out of date.` });
  } else if (job.status === 'completed') await autoResolve(key);
}