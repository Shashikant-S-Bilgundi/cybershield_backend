import { Schema, model } from 'mongoose';

/** One uptime check. Kept for the "check results" retention period in System settings. */
const resultSchema = new Schema({
  monitorId: { type: Schema.Types.ObjectId, ref: 'Monitor', required: true },
  at: { type: Date, required: true },
  status: { type: String, enum: ['up', 'degraded', 'down', 'unknown'], required: true },
  latencyMs: { type: Number, default: null },
  statusCode: { type: Number, default: undefined },
  error: { type: String, default: undefined },
});
resultSchema.index({ monitorId: 1, at: -1 });
resultSchema.index({ at: 1 });
resultSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    delete ret._id;
    delete ret.monitorId;
    return ret;
  },
});

export const CheckResult = model('CheckResult', resultSchema);