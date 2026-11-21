import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';
import { refsToJSON } from './plugins.js';

const heartbeatSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
    environmentId: { type: Schema.Types.ObjectId, required: true },
    schedule: {
      kind: { type: String, enum: ['interval', 'cron'], required: true },
      seconds: Number,
      expression: String,
    },
    graceSec: { type: Number, required: true },
    /** Secret part of the ping URL. Anyone with it can record pings for this job, nothing more. */
    token: { type: String, required: true, unique: true },
    status: { type: String, enum: ['new', 'up', 'late', 'down', 'paused'], default: 'new' },
    paused: { type: Boolean, default: false },
    lastPingAt: { type: Date, default: null },
    nextDueAt: { type: Date, default: null, index: true },
    recent: { type: [{ at: Date, kind: String, late: Boolean, _id: false }], default: [] },
    deletedAt: { type: Date, default: null, index: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
refsToJSON(heartbeatSchema, ['applicationId', 'environmentId'], ['token', 'paused', 'deletedAt']);

export type HeartbeatDoc = HydratedDocument<InferSchemaType<typeof heartbeatSchema>>;
export const Heartbeat = model('Heartbeat', heartbeatSchema);