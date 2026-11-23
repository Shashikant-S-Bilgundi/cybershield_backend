import type { Types } from 'mongoose';
import { logger } from '../lib/logger.js';
import { Alert } from '../models/Alert.js';
import { Asset } from '../models/Asset.js';
import { ContainerImage, Repository, ScanJob } from '../models/Code.js';
import { Finding, type FindingDoc } from '../models/Finding.js';
import { Incident, RemediationTask, type TaskDoc } from '../models/Ops.js';
import { ErrorGroup } from '../models/Telemetry.js';
import { runAssetChecks } from './assetChecks.js';
import { inBackground } from './background.js';
import { queueScan } from './scans.js';

const DAY = 86_400_000;
const CLOSED_FINDING = ['resolved', 'verified', 'accepted_risk', 'false_positive'];

function describeTarget(f: FindingDoc) {
  return f.evidence.find((e) => ['Host', 'URL', 'Domain', 'Found in', 'File'].includes(e.label ?? ''))?.value ?? f.title;
}

export function methodFor(task: TaskDoc, f?: FindingDoc | null): string {
  if (task.linkedType === 'incident') return 'Recheck of every item linked to the incident';
  if (task.linkedType === 'error_group') return 'Watching the error group for 7 days';
  switch (f?.source) {
    case 'ssl': return `SSL recheck of ${describeTarget(f)}`;
    case 'headers': return `Security header recheck of ${describeTarget(f)}`;
    case 'dns': return `DNS recheck of ${describeTarget(f)}`;
    case 'domain': return `Domain expiry recheck of ${describeTarget(f)}`;
    case 'secrets': return 'Repository scan with Gitleaks';
    case 'vulnerabilities': return f.key.startsWith('misconfig:') ? 'Repository scan with Trivy' : 'Dependency scan';
    default: return 'Recheck by the check that found it';
  }
}

/** Records the outcome. Passing verifies the task; failing sends it back to in progress with the reason. */
export async function settle(task: TaskDoc, passed: boolean, detail: string) {
  const result = { status: passed ? 'passed' : 'failed', at: new Date(), method: task.verification?.method ?? 'Recheck', detail };
  task.verification = result as never;
  task.verificationHistory.unshift(result as never);
  task.verificationHistory.splice(20);
  task.watchUntil = null;
  if (passed) {
    task.status = 'verified';
    task.completedAt = new Date();
  } else task.status = 'in_progress';
  await task.save();
  const incidentId = task.linkedType === 'incident' ? task.linkedId : null;
  if (incidentId) await Incident.updateOne({ _id: incidentId }, { $push: { timeline: { $each: [{ at: new Date(), actorName: 'ShieldOps', kind: 'task', text: `${passed ? 'Task verified' : 'Recheck failed'}: ${task.title}` }], $position: 0 } } });
}

/** Checks everything linked to an incident: findings closed, alerts resolved, error groups no longer open. */
async function checkIncident(task: TaskDoc) {
  const inc = await Incident.findById(task.linkedId);
  if (!inc) return settle(task, false, 'The incident no longer exists.');
  const open: string[] = [];
  for (const l of inc.linked) {
    if (l.type === 'finding') {
      const f = await Finding.findById(l.id).lean();
      if (f && !CLOSED_FINDING.includes(f.status)) open.push(`finding "${f.title}" is ${f.status.replace('_', ' ')}`);
    } else if (l.type === 'alert') {
      const a = await Alert.findById(l.id).lean();
      if (a && a.status !== 'resolved') open.push(`alert "${a.title}" is ${a.status}`);
    } else if (l.type === 'error_group') {
      const g = await ErrorGroup.findById(l.id).lean();
      if (g && (g.status === 'unresolved' || g.status === 'regressed')) open.push(`error "${g.type}" is ${g.status}`);
    }
  }
  return open.length ? settle(task, false, `Still open: ${open.slice(0, 5).join('; ')}.`) : settle(task, true, inc.linked.length ? 'Everything linked to the incident is fixed or closed.' : 'The incident has nothing linked to recheck.');
}

const findingResult = async (findingId: Types.ObjectId | string) => {
  const f = await Finding.findById(findingId);
  return { f, fixed: !!f && f.status === 'verified' };
};

/**
 * Starts the recheck that fits what the task is about. Asset checks run now in the background;
 * scans are queued and settle when they finish; error groups are watched for 7 days.
 */
export async function startVerification(task: TaskDoc) {
  const f = task.linkedType === 'finding' ? await Finding.findById(task.linkedId) : null;
  task.status = 'ready_for_verification';
  task.verification = { status: 'pending', at: new Date(), method: methodFor(task, f), detail: 'The recheck is running now.' } as never;

  if (task.linkedType === 'error_group') {
    const g = await ErrorGroup.findById(task.linkedId);
    if (g && g.status !== 'resolved') {
      g.status = 'resolved';
      g.resolvedAt = new Date();
      g.history.unshift({ at: new Date(), actorName: 'ShieldOps', text: `Marked resolved for verification of "${task.title}"` } as never);
      await g.save();
    }
    task.watchUntil = new Date(Date.now() + 7 * DAY);
    task.set('verification.detail', 'Passes if no new events arrive for 7 days after the fix is released.');
    await task.save();
    return;
  }
  await task.save();

  if (task.linkedType === 'incident') return void (await checkIncident(task));
  if (!f) return void (await settle(task, false, 'The finding no longer exists.'));

  if (['ssl', 'dns', 'domain', 'headers'].includes(f.source)) {
    const asset = await Asset.findById(f.assetId);
    if (!asset || asset.deletedAt) return void (await settle(task, false, 'The asset was removed, so it cannot be rechecked.'));
    inBackground(
      (async () => {
        await runAssetChecks(asset, true);
        const r = await findingResult(f._id);
        await settle(task, r.fixed, r.fixed ? 'The recheck no longer finds the problem.' : `The recheck still finds it: ${r.f?.title ?? f.title}.`);
      })(),
      `verification of task ${task.id}`,
    );
    return;
  }

  if (f.source === 'secrets' || f.source === 'vulnerabilities') {
    const repo = await Repository.findOne({ assetId: f.assetId });
    const img = repo ? null : await ContainerImage.findOne({ assetId: f.assetId });
    const target = repo ?? img;
    if (!target) return void (await settle(task, false, 'The repository or image is no longer scanned, so the fix cannot be confirmed.'));
    const type = repo ? 'repository' : 'image';
    await queueScan(type, target._id, 'manual').catch(() => {}); // a scan already queued or running will settle it
    task.set('verification.detail', `Waiting for the ${type} scan to finish.`);
    await task.save();
    return;
  }

  await settle(task, false, 'There is no automatic recheck for this kind of finding yet.');
}

/** Which scanner decides whether a finding is still there. */
const ownerScanner = (key: string, targetType: 'repository' | 'image') => (key.startsWith('secret:') ? 'gitleaks' : key.startsWith('misconfig:') || targetType === 'image' ? 'trivy' : 'osv');

/** Called when a scan finishes: settles tasks waiting on findings of that repository or image. */
export async function settleAfterScan(assetId: Types.ObjectId, job: { targetType: string; runs: { scanner?: string | null; status?: string | null; error?: string | null }[] }) {
  const findings = await Finding.find({ assetId }, { _id: 1 }).lean();
  const tasks = await RemediationTask.find({ status: 'ready_for_verification', linkedType: 'finding', linkedId: { $in: findings.map((x) => x._id) } });
  for (const t of tasks) {
    const { f, fixed } = await findingResult(t.linkedId);
    if (!f) {
      await settle(t, false, 'The finding no longer exists.');
      continue;
    }
    if (fixed) {
      await settle(t, true, f.source === 'secrets' ? 'The secret is no longer found. Make sure it was also rotated at the provider.' : `${(f.code as { package?: string } | undefined)?.package ?? 'The problem'} is no longer found.`);
      continue;
    }
    // A scanner that failed cannot say whether the problem is gone, so the fix is unconfirmed, not "still there".
    const run = job.runs.find((r) => r.scanner === ownerScanner(f.key, job.targetType as 'repository' | 'image'));
    if (run?.status !== 'completed') await settle(t, false, `The ${run?.scanner ?? ''} scan did not finish (${run?.error ?? 'failed'}), so the fix could not be confirmed.`.replace('The  scan', 'The scan'));
    else await settle(t, false, `The scan still finds it: ${f.title}.`);
  }
}

/** Run by the scheduler: error-group tasks fail if the error came back, pass when the 7 days are up. */
export async function settleWatchedErrors() {
  const tasks = await RemediationTask.find({ status: 'ready_for_verification', linkedType: 'error_group' });
  for (const t of tasks) {
    try {
      const g = await ErrorGroup.findById(t.linkedId);
      const since = t.verification?.at ?? t.createdAt;
      if (!g) await settle(t, false, 'The error group no longer exists.');
      else if (g.lastSeen > since || g.status === 'regressed') await settle(t, false, `The error happened again on ${g.lastSeen.toISOString().slice(0, 16).replace('T', ' ')}.`);
      else if (t.watchUntil && t.watchUntil.getTime() <= Date.now()) await settle(t, true, 'No new events for 7 days.');
    } catch (err) {
      logger.error({ err, task: t.id }, 'Error-group verification failed');
    }
  }
}

export const scanInProgress = (targetId: Types.ObjectId) => ScanJob.exists({ targetId, status: { $in: ['queued', 'running'] } });