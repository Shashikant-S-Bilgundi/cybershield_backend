import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

/* ───────────── agent tokens ───────────── */

const tokenSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
    environmentId: { type: Schema.Types.ObjectId, required: true },
    prefix: { type: String, required: true },
    hash: { type: String, required: true, unique: true },
    previousHash: { type: String, default: null, index: true },
    previousExpiresAt: { type: Date, default: null },
    status: { type: String, enum: ['active', 'revoked'], default: 'active' },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    revokedAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
export type AgentTokenDoc = HydratedDocument<InferSchemaType<typeof tokenSchema>>;
export const AgentToken = model('AgentToken', tokenSchema);

/* ───────────── servers ───────────── */

const usage = { cpu: Number, memory: Number, disk: Number, load1: Number, netInKbps: Number, netOutKbps: Number };

const serverSchema = new Schema({
  agentTokenId: { type: Schema.Types.ObjectId, ref: 'AgentToken', required: true, index: true },
  applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  /** /etc/machine-id: stays the same across hostname changes and reinstalls of the agent. */
  machineId: { type: String, required: true },
  hostname: { type: String, required: true },
  os: { type: String, default: '' },
  kernel: { type: String, default: '' },
  cpuCores: { type: Number, default: 0 },
  memoryGb: { type: Number, default: 0 },
  ips: { type: [String], default: [] },
  agentVersion: { type: String, default: '' },
  status: { type: String, enum: ['online', 'offline', 'new'], default: 'new', index: true },
  lastSeenAt: { type: Date, default: null },
  uptimeSec: { type: Number, default: 0 },
  intervalSec: { type: Number, default: 30 },
  usage: { type: usage, default: null, _id: false },
  disks: { type: [{ mount: String, usedGb: Number, totalGb: Number, _id: false }], default: [] },
  services: { type: [{ name: String, manager: String, status: String, restarts10m: Number, cpu: Number, memoryMb: Number, _id: false }], default: [] },
  containers: { type: [{ id: String, name: String, image: String, state: String, restarts10m: Number, cpu: Number, memoryMb: Number, startedAt: String, _id: false }], default: [] },
  events: { type: [{ at: Date, text: String, severity: String, _id: false }], default: [] },
  createdAt: { type: Date, default: () => new Date() },
});
serverSchema.index({ agentTokenId: 1, machineId: 1 }, { unique: true });
export type ServerDoc = HydratedDocument<InferSchemaType<typeof serverSchema>>;
export const Server = model('Server', serverSchema);

/** One report's usage numbers, for the charts. */
const sampleSchema = new Schema({ serverId: { type: Schema.Types.ObjectId, required: true }, at: { type: Date, required: true }, ...usage });
sampleSchema.index({ serverId: 1, at: -1 });
sampleSchema.index({ at: 1 });
export const ServerSample = model('ServerSample', sampleSchema);

/* ───────────── database checks ───────────── */

const dbCheckSchema = new Schema({
  name: { type: String, required: true, trim: true, maxlength: 120 },
  engine: { type: String, enum: ['postgresql', 'mysql', 'mongodb', 'redis'], required: true },
  applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  assetId: { type: Schema.Types.ObjectId, ref: 'Asset', required: true, index: true },
  host: { type: String, required: true },
  port: { type: Number, required: true },
  database: { type: String, default: '' },
  username: { type: String, default: '' },
  /** Encrypted with ENCRYPTION_KEY; never returned. */
  passwordEnc: { type: String, required: true },
  intervalSec: { type: Number, required: true },
  paused: { type: Boolean, default: false },
  status: { type: String, enum: ['up', 'degraded', 'down', 'unknown', 'paused'], default: 'unknown' },
  consecutiveFailures: { type: Number, default: 0 },
  lastCheckAt: { type: Date, default: null },
  lastLatencyMs: { type: Number, default: null },
  error: { type: String, default: null },
  latency: { type: [Schema.Types.Mixed], default: [] },
  stats: { type: { connections: Number, maxConnections: Number, sizeGb: Number, role: String, replicationLagSec: Number, _id: false }, default: null },
  nextCheckAt: { type: Date, default: () => new Date(), index: true },
  deletedAt: { type: Date, default: null, index: true },
});
dbCheckSchema.set('toJSON', {
  versionKey: false,
  transform: (doc, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    for (const k of ['_id', 'passwordEnc', 'consecutiveFailures', 'nextCheckAt', 'deletedAt']) delete ret[k];
    for (const k of ['applicationId', 'environmentId', 'assetId']) ret[k] = String(ret[k]);
    ret.credentialsSet = !!doc.passwordEnc;
    if (doc.paused) ret.status = 'paused';
    return ret;
  },
});
export type DbCheckDoc = HydratedDocument<InferSchemaType<typeof dbCheckSchema>>;
export const DbCheck = model('DbCheck', dbCheckSchema);