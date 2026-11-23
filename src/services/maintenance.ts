import { Application } from '../models/Application.js';
import { Asset } from '../models/Asset.js';
import { AuditLog } from '../models/AuditLog.js';
import { logger } from '../lib/logger.js';
import { getSettingsDoc } from './settings.js';
import { CheckResult } from '../models/CheckResult.js';
import { Heartbeat } from '../models/Heartbeat.js';
import { Monitor } from '../models/Monitor.js';
import { expireAcceptedRisks } from './findings.js';
import { ErrorEvent, ErrorGroup, ErrorUser, PerfMinute, SecurityEvent } from '../models/Telemetry.js';
import { ServerSample } from '../models/Infra.js';

const DAY = 86_400_000;

/** Daily: purge items soft-deleted over 30 days ago, and audit logs past their retention. */
export async function runMaintenance() {
  const cutoff = new Date(Date.now() - 30 * DAY);
  // Telemetry of applications deleted more than 30 days ago goes with them.
  const goneApps = (await Application.find({ deletedAt: { $lt: cutoff } }, { _id: 1 }).lean()).map((a) => a._id);
  if (goneApps.length) {
    const groups = (await ErrorGroup.find({ applicationId: { $in: goneApps } }, { _id: 1 }).lean()).map((g) => g._id);
    await Promise.all([ErrorEvent.deleteMany({ groupId: { $in: groups } }), ErrorUser.deleteMany({ groupId: { $in: groups } }), ErrorGroup.deleteMany({ _id: { $in: groups } })]);
  }
  const apps = await Application.deleteMany({ deletedAt: { $lt: cutoff } });
  const assets = await Asset.deleteMany({ deletedAt: { $lt: cutoff } });
  await Monitor.deleteMany({ deletedAt: { $lt: cutoff } });
  await Heartbeat.deleteMany({ deletedAt: { $lt: cutoff } });
  const { retention } = await getSettingsDoc();
  await CheckResult.deleteMany({ at: { $lt: new Date(Date.now() - retention!.checkResultsDays * DAY) } });
  await expireAcceptedRisks();
  const days = (n: number) => new Date(Date.now() - n * DAY);
  await ErrorEvent.deleteMany({ at: { $lt: days(retention!.errorEventsDays) } });
  await SecurityEvent.deleteMany({ at: { $lt: days(retention!.securityEventsDays) } });
  // The 7-day performance view needs at least 8 days of per-minute data.
  await PerfMinute.deleteMany({ minute: { $lt: days(Math.max(retention!.metricSamplesDays, 8)) } });
  await ServerSample.deleteMany({ at: { $lt: days(Math.max(retention!.metricSamplesDays, 8)) } });
  // Retention is the only path that removes audit records; it bypasses the append-only guard on purpose.
  const audit = await AuditLog.collection.deleteMany({ at: { $lt: new Date(Date.now() - retention!.auditLogsDays * DAY) } });
  if (apps.deletedCount || assets.deletedCount || audit.deletedCount) {
    logger.info({ apps: apps.deletedCount, assets: assets.deletedCount, auditLogs: audit.deletedCount }, 'Maintenance purge');
  }
}