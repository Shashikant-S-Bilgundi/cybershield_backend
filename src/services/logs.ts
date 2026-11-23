import { scrubTags, scrubText } from '../lib/scrub.js';
import type { IngestionKeyDoc } from '../models/IngestionKey.js';
import { LogEntry } from '../models/Advanced.js';

export interface IncomingLog {
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  timestamp?: string;
  host?: string;
  fields?: Record<string, string>;
}

/** Stores log lines with secrets removed: secret-looking field names are redacted, tokens and emails masked. */
export async function ingestLogs(key: IngestionKeyDoc, lines: IncomingLog[], source: 'sdk' | 'agent' = 'sdk') {
  const now = Date.now();
  await LogEntry.insertMany(
    lines.map((l) => ({
      applicationId: key.applicationId,
      environmentId: key.environmentId,
      at: l.timestamp && Math.abs(Date.parse(l.timestamp) - now) < 86_400_000 ? new Date(l.timestamp) : new Date(),
      level: l.level,
      source,
      host: (l.host ?? '').slice(0, 120),
      message: scrubText(l.message, 4000),
      fields: scrubTags(l.fields),
    })),
  );
}

const RANGE = { '15m': 15 * 60_000, '1h': 3_600_000, '24h': 86_400_000, '7d': 7 * 86_400_000 } as const;

/** Search: words match the message; key=value matches a field. Newest first, with a 30-bucket histogram. */
export async function searchLogs(q: { scope: Record<string, unknown>; search?: string; levels?: string[]; range: keyof typeof RANGE; page: number; pageSize: number }) {
  const to = Date.now();
  const from = to - RANGE[q.range];
  const filter: Record<string, unknown> = { ...q.scope, at: { $gte: new Date(from) } };
  if (q.levels?.length) filter.level = { $in: q.levels };
  const terms = (q.search ?? '').trim().split(/\s+/).filter(Boolean).slice(0, 5);
  const and: Record<string, unknown>[] = [];
  for (const t of terms) {
    const kv = t.match(/^([\w.-]{1,50})=(.+)$/);
    const rx = (s: string) => ({ $regex: s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' });
    if (kv) and.push({ $or: [{ [`fields.${kv[1]}`]: rx(kv[2]) }, { host: kv[1] === 'host' ? rx(kv[2]) : '\u0000' }] });
    else and.push({ $or: [{ message: rx(t) }, { host: rx(t) }] });
  }
  if (and.length) filter.$and = and;
  const [items, total, hist] = await Promise.all([
    LogEntry.find(filter).sort({ at: -1 }).skip((q.page - 1) * q.pageSize).limit(q.pageSize).lean(),
    LogEntry.countDocuments(filter),
    LogEntry.aggregate<{ _id: number; count: number; errors: number }>([
      { $match: filter },
      { $group: { _id: { $floor: { $divide: [{ $subtract: ['$at', new Date(from)] }, (to - from) / 30] } }, count: { $sum: 1 }, errors: { $sum: { $cond: [{ $eq: ['$level', 'error'] }, 1, 0] } } } },
    ]),
  ]);
  const size = (to - from) / 30;
  const histogram = Array.from({ length: 30 }, (_, i) => ({ at: new Date(from + (i + 1) * size).toISOString(), count: 0, errors: 0 }));
  for (const h of hist) if (h._id >= 0 && h._id < 30) Object.assign(histogram[h._id], { count: h.count, errors: h.errors });
  return {
    items: items.map((l) => ({ id: String(l._id), at: l.at, level: l.level, applicationId: String(l.applicationId), environmentId: String(l.environmentId), source: l.source, host: l.host, message: l.message, fields: l.fields ?? {} })),
    total, page: q.page, pageSize: q.pageSize, histogram,
  };
}