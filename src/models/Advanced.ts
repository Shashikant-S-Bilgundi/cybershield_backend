import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

/* ───────────── releases ───────────── */

const releaseSchema = new Schema({
  applicationId: { type: Schema.Types.ObjectId, required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  version: { type: String, required: true },
  commit: { type: String, default: '' },
  deployedAt: { type: Date, required: true, index: true },
  deployedBy: { type: String, default: '' },
});
releaseSchema.index({ environmentId: 1, version: 1 }, { unique: true });
export type ReleaseDoc = HydratedDocument<InferSchemaType<typeof releaseSchema>>;
export const Release = model('Release', releaseSchema);

/* ───────────── logs (kept 14 days) ───────────── */

const logSchema = new Schema({
  applicationId: { type: Schema.Types.ObjectId, required: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  at: { type: Date, required: true },
  level: { type: String, enum: ['debug', 'info', 'warn', 'error'], required: true },
  source: { type: String, enum: ['sdk', 'agent'], default: 'sdk' },
  host: { type: String, default: '' },
  message: { type: String, required: true },
  fields: { type: Schema.Types.Mixed, default: {} },
});
logSchema.index({ environmentId: 1, at: -1 });
logSchema.index({ applicationId: 1, at: -1 });
logSchema.index({ at: 1 }, { expireAfterSeconds: 14 * 86_400 });
export const LogEntry = model('LogEntry', logSchema);

/* ───────────── probe locations ───────────── */

const probeSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 80 },
    region: { type: String, default: '' },
    prefix: { type: String, required: true },
    hash: { type: String, required: true, unique: true },
    lastSeenAt: { type: Date, default: null },
    version: { type: String, default: '' },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
export type ProbeDoc = HydratedDocument<InferSchemaType<typeof probeSchema>>;
export const Probe = model('Probe', probeSchema);

/** The latest result from each remote probe for each monitor. */
const probeResultSchema = new Schema({
  probeId: { type: Schema.Types.ObjectId, required: true },
  monitorId: { type: Schema.Types.ObjectId, required: true },
  at: { type: Date, required: true },
  status: { type: String, enum: ['up', 'degraded', 'down', 'unknown'], required: true },
  latencyMs: { type: Number, default: null },
  error: { type: String, default: null },
});
probeResultSchema.index({ probeId: 1, monitorId: 1 }, { unique: true });
probeResultSchema.index({ monitorId: 1 });
export const ProbeResult = model('ProbeResult', probeResultSchema);

/* ───────────── escalation policies ───────────── */

const policySchema = new Schema({
  name: { type: String, required: true, trim: true, maxlength: 120 },
  severities: { type: [String], default: [] },
  steps: { type: [{ afterMinutes: Number, targets: [String], channels: [String], _id: false }], default: [] },
  repeat: { type: Boolean, default: false },
  enabled: { type: Boolean, default: true },
});
policySchema.set('toJSON', { versionKey: false, transform: (_d, ret: Record<string, unknown>) => ((ret.id = String(ret._id)), delete ret._id, ret) });
export type PolicyDoc = HydratedDocument<InferSchemaType<typeof policySchema>>;
export const EscalationPolicy = model('EscalationPolicy', policySchema);

/* ───────────── anomalies ───────────── */

const anomalySchema = new Schema({
  applicationId: { type: Schema.Types.ObjectId, required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  metric: { type: String, enum: ['requests', 'error_rate', 'p95', 'login_failures', 'error_events'], required: true },
  title: { type: String, required: true },
  direction: { type: String, enum: ['up', 'down'], required: true },
  actual: { type: Number, required: true },
  expectedLow: { type: Number, required: true },
  expectedHigh: { type: Number, required: true },
  unit: { type: String, required: true },
  startedAt: { type: Date, required: true },
  endedAt: { type: Date, default: null },
  alertId: { type: Schema.Types.ObjectId, default: null },
});
anomalySchema.index({ environmentId: 1, metric: 1, endedAt: 1 });
anomalySchema.index({ startedAt: 1 }, { expireAfterSeconds: 30 * 86_400 });
export type AnomalyDoc = HydratedDocument<InferSchemaType<typeof anomalySchema>>;
export const Anomaly = model('Anomaly', anomalySchema);