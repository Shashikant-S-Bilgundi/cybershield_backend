import { Router } from 'express';
import { ApiError, notFound } from '../lib/errors.js';
import { objectId, parse, z } from '../lib/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { FINDING_STATUSES, Finding } from '../models/Finding.js';
import { User } from '../models/User.js';
import { audit } from '../services/audit.js';
import { activeFindingFilter } from '../services/findings.js';

export const findingsRouter = Router();
findingsRouter.use('/findings', requireAuth);

const STATUS_TEXT: Record<string, string> = {
  open: 'open', acknowledged: 'acknowledged', in_progress: 'in progress', resolved: 'resolved (waiting for a recheck)',
  reopened: 'reopened', accepted_risk: 'accepted risk', false_positive: 'false positive', verified: 'verified',
};

findingsRouter.get('/findings', async (req, res) => {
  const f = parse(
    z.object({
      assetId: objectId.optional(),
      status: z.enum([...FINDING_STATUSES, 'active']).optional(),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
      source: z.string().max(40).optional(),
      applicationId: objectId.optional(),
      environmentId: objectId.optional(),
    }),
    req.query,
  );
  const { status, ...rest } = f;
  const q = { ...rest, ...(status === 'active' ? activeFindingFilter : status ? { status } : {}) };
  const rows = await Finding.find(q).sort({ riskScore: -1, firstSeen: 1 }).limit(1000);
  res.json(rows.map((r) => r.toJSON()));
});

const findFinding = async (id: unknown) => {
  const f = await Finding.findById(parse(objectId, id));
  if (!f) throw notFound('Finding');
  return f;
};

findingsRouter.get('/findings/:id', async (req, res) => {
  res.json((await findFinding(req.params.id)).toJSON());
});

findingsRouter.patch('/findings/:id', async (req, res) => {
  const f = await findFinding(req.params.id);
  const input = parse(
    z.object({
      status: z.enum(FINDING_STATUSES).optional(),
      assigneeId: objectId.nullable().optional(),
      note: z.string().trim().max(2000).optional(),
      acceptedRisk: z.object({ justification: z.string().trim(), expiresAt: z.iso.datetime({ offset: true }) }).optional(),
    }),
    req.body,
  );
  const me = req.user!;
  const now = new Date();
  const log = (text: string) => f.history.unshift({ at: now, actorName: me.name, text });

  if (input.status && input.status !== f.status) {
    if (input.status === 'verified') throw new ApiError(422, 'VERIFY_BY_RECHECK', 'Only a passing recheck can mark a finding as verified.');
    if (input.status === 'accepted_risk') {
      const ar = input.acceptedRisk;
      if (!ar || ar.justification.length < 10) throw new ApiError(422, 'JUSTIFICATION_REQUIRED', 'Explain why this risk is acceptable (at least 10 characters).');
      if (new Date(ar.expiresAt).getTime() <= Date.now()) throw new ApiError(422, 'EXPIRY_IN_PAST', 'Choose a review date in the future.');
      f.acceptedRisk = { justification: ar.justification, expiresAt: new Date(ar.expiresAt), by: me._id, at: now } as never;
      log(`Accepted the risk until ${ar.expiresAt.slice(0, 10)}: ${ar.justification}`);
    } else {
      if (f.status === 'accepted_risk') f.acceptedRisk = null;
      log(`Changed status to ${STATUS_TEXT[input.status]}`);
    }
    f.status = input.status;
    await audit(req, `finding.${input.status}`, 'finding', f.id, `${f.title}: ${STATUS_TEXT[input.status]}`);
  }
  if (input.assigneeId !== undefined && String(input.assigneeId) !== String(f.assigneeId)) {
    const who = input.assigneeId ? await User.findOne({ _id: input.assigneeId, status: 'active' }) : null;
    if (input.assigneeId && !who) throw new ApiError(422, 'INVALID_ASSIGNEE', 'Choose an active team member.');
    f.assigneeId = (who?._id ?? null) as never;
    log(`Assigned to ${who?.name ?? 'nobody'}`);
  }
  if (input.note) log(`Note: ${input.note}`);
  await f.save();
  res.json(f.toJSON());
});