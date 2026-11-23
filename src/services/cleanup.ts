import type { Types } from 'mongoose';
import { Alert } from '../models/Alert.js';
import { Heartbeat } from '../models/Heartbeat.js';
import { Monitor } from '../models/Monitor.js';
import { IngestionKey } from '../models/IngestionKey.js';
import { AgentToken, DbCheck } from '../models/Infra.js';

/**
 * When an application or asset is deleted (or an asset paused), its checks stop and its open alerts close.
 * Deleting hides the monitors and heartbeats the same way as the asset, for the same 30 days.
 */
export async function stopMonitoringFor(scope: { applicationId?: Types.ObjectId; assetId?: Types.ObjectId }, remove = true) {
  const now = new Date();
  if (remove) {
    await Monitor.updateMany({ ...scope, deletedAt: null }, { deletedAt: now });
    if (scope.applicationId) await Heartbeat.updateMany({ applicationId: scope.applicationId, deletedAt: null }, { deletedAt: now });
    // A deleted application's apps must stop being able to send data.
    if (scope.applicationId) await IngestionKey.updateMany({ applicationId: scope.applicationId, status: 'active' }, { status: 'revoked', revokedAt: now, previousHash: null });
    if (scope.applicationId) await AgentToken.updateMany({ applicationId: scope.applicationId, status: 'active' }, { status: 'revoked', revokedAt: now, previousHash: null });
    // Database checks hold passwords: they are deleted outright, not kept for 30 days.
    await DbCheck.deleteMany(scope);
  } else {
    await Monitor.updateMany({ ...scope, deletedAt: null }, { paused: true });
    await DbCheck.updateMany({ ...scope, deletedAt: null }, { paused: true });
  }
  await Alert.updateMany({ ...scope, status: { $ne: 'resolved' } }, { status: 'resolved', resolvedAt: now, autoResolved: true });
}