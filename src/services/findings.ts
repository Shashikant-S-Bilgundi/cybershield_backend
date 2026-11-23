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
  /** On CISA's Known Exploited Vulnerabilities list: raises the risk score and priority. */
  knownExploited?: boolean;
  /** Secret or vulnerability detail from a code or image scan. */
  code?: Record<string, unknown>;
}

/**
 * Records that a check found a problem: creates the finding, refreshes it, or reopens it if it was thought fixed.
 * Returns whether it is new or came back, so scans can count them.
 */
export async function reportProblem(asset: AssetDoc, p: Problem): Promise<{ isNew: boolean; reopened: boolean }> {
  const app = await Application.findById(asset.applicationId);
  const knownExploited = !!p.knownExploited;
  const score = riskScore({ severity: p.severity, criticality: (app?.criticality ?? 'medium') as never, exposure: asset.exposure as 'internet' | 'internal', confidence: 'confirmed', knownExploited });
  const priority = priorityFor(score);
  const now = new Date();
  const existing = await Finding.findOne({ key: p.key });
  if (!existing) {
    await Finding.create({
      ...p,
      knownExploited,
      applicationId: asset.applicationId,
      environmentId: asset.environmentId,
      assetId: asset._id as Types.ObjectId,
      riskScore: score,
      priority,
      dueAt: new Date(now.getTime() + SLA_DAYS[priority] * DAY),
      firstSeen: now,
      lastSeen: now,
      history: [{ at: now, actorName: 'ShieldOps', text: p.code ? 'Found by a scan' : 'Detected by a scheduled check' }],
    });
    return { isNew: true, reopened: false };
  }
  existing.set({ title: p.title, description: p.description, severity: p.severity, evidence: p.evidence, riskScore: score, priority, lastSeen: now, knownExploited, ...(p.code ? { code: p.code } : {}) });
  const reopened = existing.status === 'verified' || existing.status === 'resolved';
  if (reopened) {
    existing.history.unshift({ at: now, actorName: 'ShieldOps', text: existing.status === 'verified' ? 'Reopened: the problem came back' : 'Reopened: the recheck still finds the problem' });
    existing.status = 'reopened';
    existing.dueAt = new Date(now.getTime() + SLA_DAYS[priority] * DAY);
  }
  await existing.save();
  return { isNew: false, reopened };
}

/** Records that a check passed: an open finding with this key is verified fixed. Returns whether one was. */
export async function problemGone(key: string, why = 'Verified fixed by a recheck'): Promise<boolean> {
  const f = await Finding.findOne({ key, status: { $in: VERIFIABLE } });
  if (!f) return false;
  f.status = 'verified';
  f.history.unshift({ at: new Date(), actorName: 'ShieldOps', text: why });
  await f.save();
  return true;
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