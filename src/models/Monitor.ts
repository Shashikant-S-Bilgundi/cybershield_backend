import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';
import { refsToJSON } from './plugins.js';

const HEALTH = ['up', 'degraded', 'down', 'unknown', 'paused'] as const;

const monitorSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    type: { type: String, enum: ['http', 'tcp', 'dns'], required: true },
    applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
    environmentId: { type: Schema.Types.ObjectId, required: true, index: true },
    assetId: { type: Schema.Types.ObjectId, ref: 'Asset', required: true, index: true },
    target: { type: String, required: true, maxlength: 2000 },
    intervalSec: { type: Number, required: true },
    timeoutMs: { type: Number, required: true },
    downAfterFailures: { type: Number, required: true },
    expectedStatus: { type: String, default: undefined },
    keyword: { type: String, default: undefined },
    recordType: { type: String, enum: ['A', 'AAAA', 'CNAME', 'MX'], default: undefined },
    paused: { type: Boolean, default: false },
    status: { type: String, enum: HEALTH, default: 'unknown' },
    consecutiveFailures: { type: Number, default: 0 },
    lastCheckAt: { type: Date, default: null },
    lastLatencyMs: { type: Number, default: null },
    /** When the scheduler should run it next; claimed atomically so two workers never run the same check. */
    nextCheckAt: { type: Date, default: () => new Date(), index: true },
    events: { type: [{ at: Date, from: String, to: String, reason: String, _id: false }], default: [] },
    deletedAt: { type: Date, default: null, index: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
refsToJSON(monitorSchema, ['applicationId', 'environmentId', 'assetId'], ['consecutiveFailures', 'nextCheckAt', 'events', 'deletedAt']);

export type MonitorDoc = HydratedDocument<InferSchemaType<typeof monitorSchema>>;
export const Monitor = model('Monitor', monitorSchema);