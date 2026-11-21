import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

const alertSchema = new Schema({
  /** Same key + rule while unresolved = the same alert (occurrences go up, no new notification). */
  key: { type: String, required: true },
  title: { type: String, required: true },
  message: { type: String, default: '' },
  severity: { type: String, enum: ['critical', 'high', 'medium', 'low', 'info'], required: true },
  status: { type: String, enum: ['open', 'acknowledged', 'snoozed', 'resolved'], default: 'open', index: true },
  source: { type: String, required: true },
  applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  assetId: { type: Schema.Types.ObjectId, default: null },
  ruleId: { type: Schema.Types.ObjectId, ref: 'AlertRule', default: null },
  firstAt: { type: Date, default: () => new Date() },
  lastAt: { type: Date, default: () => new Date() },
  occurrences: { type: Number, default: 1 },
  acknowledgedBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  acknowledgedAt: { type: Date, default: null },
  snoozedUntil: { type: Date, default: null },
  resolvedAt: { type: Date, default: null },
  autoResolved: { type: Boolean, default: false },
  renotified: { type: Number, default: 0 },
  lastNotifiedAt: { type: Date, default: null },
  deliveries: { type: [{ channel: String, recipient: String, status: String, at: Date, attempts: Number, _id: false }], default: [] },
});
alertSchema.index({ key: 1, ruleId: 1, status: 1 });
alertSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    for (const k of ['applicationId', 'environmentId', 'assetId', 'ruleId', 'acknowledgedBy']) ret[k] = ret[k] ? String(ret[k]) : null;
    delete ret.key;
    delete ret.renotified;
    delete ret.lastNotifiedAt;
    return ret;
  },
});

export type AlertDoc = HydratedDocument<InferSchemaType<typeof alertSchema>>;
export const Alert = model('Alert', alertSchema);