import { Application } from '../models/Application.js';
import { Asset } from '../models/Asset.js';
import { AuditLog } from '../models/AuditLog.js';
import { logger } from '../lib/logger.js';
import { getSettingsDoc } from './settings.js';

const DAY = 86_400_000;

/** Daily: purge items soft-deleted over 30 days ago, and audit logs past their retention. */
export async function runMaintenance() {
  const cutoff = new Date(Date.now() - 30 * DAY);
  const apps = await Application.deleteMany({ deletedAt: { $lt: cutoff } });
  const assets = await Asset.deleteMany({ deletedAt: { $lt: cutoff } });
  const { retention } = await getSettingsDoc();
  // Retention is the only path that removes audit records; it bypasses the append-only guard on purpose.
  const audit = await AuditLog.collection.deleteMany({ at: { $lt: new Date(Date.now() - retention!.auditLogsDays * DAY) } });
  if (apps.deletedCount || assets.deletedCount || audit.deletedCount) {
    logger.info({ apps: apps.deletedCount, assets: assets.deletedCount, auditLogs: audit.deletedCount }, 'Maintenance purge');
  }
}