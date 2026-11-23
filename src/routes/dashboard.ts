import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { Alert } from '../models/Alert.js';
import { Application } from '../models/Application.js';
import { Asset } from '../models/Asset.js';
import { Certificate, DomainExpiry } from '../models/AssetChecks.js';
import { Finding } from '../models/Finding.js';
import { ErrorGroup } from '../models/Telemetry.js';
import { Incident } from '../models/Ops.js';
import { activeFindingFilter } from '../services/findings.js';
import { appHealth } from '../services/health.js';

export const dashboardRouter = Router();

const DAY = 86_400_000;

dashboardRouter.get('/dashboard', requireAuth, async (_req, res) => {
  const apps = await Application.find({ deletedAt: null, status: 'active' });
  const healthByApp = await Promise.all(apps.map(appHealth));
  const health = { up: 0, degraded: 0, down: 0, unknown: 0, paused: 0 };
  healthByApp.forEach((h) => (health[h.state as keyof typeof health] += 1));

  const findingsBySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const grouped = await Finding.aggregate<{ _id: keyof typeof findingsBySeverity; n: number }>([{ $match: activeFindingFilter }, { $group: { _id: '$severity', n: { $sum: 1 } } }]);
  grouped.forEach((g) => (findingsBySeverity[g._id] = g.n));

  // Certificates within 30 days and domains within 60 days, soonest first.
  const live = new Set((await Asset.find({ deletedAt: null }, { _id: 1 }).lean()).map((a) => String(a._id)));
  const certs = await Certificate.find({ validTo: { $ne: null, $lte: new Date(Date.now() + 30 * DAY) } }).lean();
  const domains = await DomainExpiry.find({ $or: [{ expiresAt: { $lte: new Date(Date.now() + 60 * DAY) } }, { source: 'unavailable' }] }).lean();
  const expiries = [
    ...certs.map((c) => ({ assetId: String(c.assetId), applicationId: String(c.applicationId), kind: 'ssl' as const, identifier: c.host ?? '', expiresAt: c.validTo?.toISOString() ?? null })),
    ...domains.map((d) => ({ assetId: String(d.assetId), applicationId: String(d.applicationId), kind: 'domain' as const, identifier: d.domain ?? '', expiresAt: d.expiresAt?.toISOString() ?? null })),
  ]
    .filter((e) => live.has(e.assetId))
    .sort((a, b) => (a.expiresAt ?? '9').localeCompare(b.expiresAt ?? '9'))
    .slice(0, 8);

  res.json({
    applications: apps.length,
    health,
    openAlerts: await Alert.countDocuments({ status: { $in: ['open', 'acknowledged'] } }),
    activeIncidents: await Incident.countDocuments({ status: { $in: ['new', 'acknowledged', 'investigating', 'remediating', 'reopened'] } }),
    findingsBySeverity,
    errorGroupsOpen: await ErrorGroup.countDocuments({ status: { $in: ['unresolved', 'regressed'] }, applicationId: { $in: apps.map((a) => a._id) } }),
    expiries,
    healthByApp,
  });
});