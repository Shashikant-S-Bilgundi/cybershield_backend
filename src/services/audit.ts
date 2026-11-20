import type { Request } from 'express';
import { AuditLog } from '../models/AuditLog.js';
import { logger } from '../lib/logger.js';

/** Writes an audit record. Never throws: an audit failure is logged loudly instead of breaking the action. */
export async function audit(req: Request, action: string, resourceType: string, resourceId: string | null, summary: string, actor?: { id: unknown; name: string } | null) {
  const who = actor === undefined ? req.user : actor;
  try {
    await AuditLog.create({
      actorId: who?.id ?? null,
      actorName: who?.name ?? 'Unknown',
      action,
      resourceType,
      resourceId,
      summary: summary.slice(0, 1000),
      ip: req.ip ?? '',
      userAgent: (req.get('user-agent') ?? '').slice(0, 300),
    });
  } catch (err) {
    logger.error({ err, action }, 'AUDIT WRITE FAILED');
  }
}