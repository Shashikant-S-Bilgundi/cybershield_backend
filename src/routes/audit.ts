import { Router } from 'express';
import { parse, z } from '../lib/validate.js';
import { requireAuth, requireReauth } from '../middleware/auth.js';
import { AuditLog } from '../models/AuditLog.js';
import { audit } from '../services/audit.js';

export const auditRouter = Router();
auditRouter.use('/audit-logs', requireAuth);

const filterInput = z.object({
  search: z.string().trim().max(200).optional(),
  resourceType: z.string().trim().max(40).optional(),
  from: z.iso.datetime({ offset: true }).optional(),
  to: z.iso.datetime({ offset: true }).optional(),
});

function toQuery(f: z.infer<typeof filterInput>) {
  const q: Record<string, unknown> = {};
  if (f.resourceType) q.resourceType = f.resourceType;
  if (f.from || f.to) q.at = { ...(f.from && { $gte: new Date(f.from) }), ...(f.to && { $lte: new Date(f.to) }) };
  if (f.search) {
    const rx = { $regex: f.search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' };
    q.$or = [{ actorName: rx }, { action: rx }, { summary: rx }, { ip: rx }];
  }
  return q;
}

auditRouter.get('/audit-logs', async (req, res) => {
  const f = parse(filterInput.extend({ page: z.coerce.number().int().min(1).default(1), pageSize: z.coerce.number().int().min(1).max(100).default(25) }), req.query);
  const q = toQuery(f);
  const [items, total] = await Promise.all([
    AuditLog.find(q).sort({ at: -1 }).skip((f.page - 1) * f.pageSize).limit(f.pageSize),
    AuditLog.countDocuments(q),
  ]);
  res.json({ items: items.map((i) => i.toJSON()), total, page: f.page, pageSize: f.pageSize });
});

/** CSV cells that start with = + - @ are prefixed so spreadsheets do not run them as formulas. */
const cell = (v: unknown) => {
  let s = v instanceof Date ? v.toISOString() : String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
};

auditRouter.post('/audit-logs/export', requireReauth, async (req, res) => {
  const f = parse(filterInput, req.body ?? {});
  const rows = await AuditLog.find(toQuery(f)).sort({ at: -1 }).limit(50_000).lean();
  const csv = [['time', 'actor', 'action', 'resource', 'summary', 'ip'], ...rows.map((l) => [l.at, l.actorName, l.action, l.resourceType, l.summary, l.ip])]
    .map((r) => r.map(cell).join(','))
    .join('\n');
  await audit(req, 'audit.export', 'audit', null, `Exported ${rows.length} audit records`);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="shieldops-audit-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(csv);
});