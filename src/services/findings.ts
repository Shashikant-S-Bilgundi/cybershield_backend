import type { Types } from 'mongoose';
import { priorityFor, riskScore, SLA_DAYS, type Severity } from '../lib/risk.js';
import { Application } from '../models/Application.js';
import type { AssetDoc } from '../models/Asset.js';
import { Finding } from '../models/Finding.js';

const DAY = 86_400_000;
const CLOSED = ['resolved', 'verified', 'accepted_risk', 'false_positive'];
/** Statuses where a passing check proves the fix. */
const VERIFIABLE = ['open', 'acknowledged', 'in_progress', 'resolved', 'reopened'];

export interface Problem {
  key: string;
  title: string;
  description: string;
  category: 'security' | 'availability' | 'performance' | 'configuration';
  source: string;
  severity: Severity;
  evidence: { label: string; value: string }[];
}

/** Records that a check found a problem: creates the finding, refreshes it, or reopens it if it was thought fixed. */
export async function reportProblem(asset: AssetDoc, p: Problem) {
  const app = await Application.findById(asset.applicationId);
  const score = riskScore({ severity: p.severity, criticality: (app?.criticality ?? 'medium') as never, exposure: asset.exposure as 'internet' | 'internal', confidence: 'confirmed', knownExploited: false });
  const priority = priorityFor(score);
  const now = new Date();
  const existing = await Finding.findOne({ key: p.key });
  if (!existing) {
    return Finding.create({
      ...p,
      applicationId: asset.applicationId,
      environmentId: asset.environmentId,
      assetId: asset._id as Types.ObjectId,
      riskScore: score,
      priority,
      dueAt: new Date(now.getTime() + SLA_DAYS[priority] * DAY),
      firstSeen: now,
      lastSeen: now,
      history: [{ at: now, actorName: 'ShieldOps', text: 'Detected by a scheduled check' }],
    });
  }
  existing.set({ title: p.title, description: p.description, severity: p.severity, evidence: p.evidence, riskScore: score, priority, lastSeen: now });
  if (existing.status === 'verified' || existing.status === 'resolved') {
    existing.history.unshift({ at: now, actorName: 'ShieldOps', text: existing.status === 'verified' ? 'Reopened: the problem came back' : 'Reopened: the recheck still finds the problem' });
    existing.status = 'reopened';
    existing.dueAt = new Date(now.getTime() + SLA_DAYS[priority] * DAY);
  }
  await existing.save();
  return existing;
}

/** Records that a check passed: an open finding with this key is verified fixed. */
export async function problemGone(key: string) {
  const f = await Finding.findOne({ key, status: { $in: VERIFIABLE } });
  if (!f) return;
  f.status = 'verified';
  f.history.unshift({ at: new Date(), actorName: 'ShieldOps', text: 'Verified fixed by a recheck' });
  await f.save();
}

/** Accepted risks come back for review when their date passes. */
export async function expireAcceptedRisks() {
  const due = await Finding.find({ status: 'accepted_risk', 'acceptedRisk.expiresAt': { $lte: new Date() } });
  for (const f of due) {
    f.status = 'reopened';
    f.history.unshift({ at: new Date(), actorName: 'ShieldOps', text: 'Reopened: the accepted risk is due for review' });
    await f.save();
  }
}

export const activeFindingFilter = { status: { $nin: CLOSED } };