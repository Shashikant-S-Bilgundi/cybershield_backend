import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

/* ───────────── integrations ───────────── */

const integrationSchema = new Schema({
  type: { type: String, required: true, unique: true },
  status: { type: String, enum: ['connected', 'not_connected', 'error'], default: 'not_connected' },
  account: { type: String, default: null },
  scopes: { type: [String], default: [] },
  connectedAt: { type: Date, default: null },
  connectedBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  lastSyncAt: { type: Date, default: null },
  error: { type: String, default: null },
  /** GitHub App installation id. */
  installationId: { type: Number, default: null },
  /** Encrypted JSON, e.g. Docker Hub { username, token }. */
  credentialsEnc: { type: String, default: null },
});
export type IntegrationDoc = HydratedDocument<InferSchemaType<typeof integrationSchema>>;
export const Integration = model('Integration', integrationSchema);

/** The state parameter that ties a GitHub App installation back to the person who started it. */
const stateSchema = new Schema({ stateHash: { type: String, required: true, unique: true }, userId: { type: Schema.Types.ObjectId, required: true }, expiresAt: { type: Date, required: true } });
stateSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
export const GithubInstallState = model('GithubInstallState', stateSchema);

/* ───────────── scan targets ───────────── */

const counts = { critical: { type: Number, default: 0 }, high: { type: Number, default: 0 }, medium: { type: Number, default: 0 }, low: { type: Number, default: 0 }, info: { type: Number, default: 0 } };

const repoSchema = new Schema({
  githubId: { type: Number, required: true, unique: true },
  assetId: { type: Schema.Types.ObjectId, ref: 'Asset', required: true },
  fullName: { type: String, required: true },
  applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  private: { type: Boolean, default: true },
  defaultBranch: { type: String, default: 'main' },
  language: { type: String, default: '' },
  scanOnPush: { type: Boolean, default: true },
  dailyScan: { type: Boolean, default: true },
  dependencies: { type: Number, default: 0 },
  openSecrets: { type: Number, default: 0 },
  vulns: { type: counts, default: {}, _id: false },
  addedAt: { type: Date, default: () => new Date() },
});
export type RepositoryDoc = HydratedDocument<InferSchemaType<typeof repoSchema>>;
export const Repository = model('Repository', repoSchema);

const imageSchema = new Schema({
  assetId: { type: Schema.Types.ObjectId, ref: 'Asset', required: true },
  applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  registry: { type: String, enum: ['ghcr.io', 'docker.io'], required: true },
  repository: { type: String, required: true },
  tag: { type: String, required: true },
  digest: { type: String, default: '' },
  os: { type: String, default: '' },
  sizeMb: { type: Number, default: 0 },
  dailyScan: { type: Boolean, default: true },
  vulns: { type: counts, default: {}, _id: false },
  addedAt: { type: Date, default: () => new Date() },
});
imageSchema.index({ registry: 1, repository: 1, tag: 1 }, { unique: true });
export type ImageDoc = HydratedDocument<InferSchemaType<typeof imageSchema>>;
export const ContainerImage = model('ContainerImage', imageSchema);

/* ───────────── scans ───────────── */

const runSchema = new Schema({ scanner: String, version: { type: String, default: '' }, status: String, durationMs: { type: Number, default: null }, error: { type: String, default: null } }, { _id: false });

const scanSchema = new Schema({
  targetType: { type: String, enum: ['repository', 'image'], required: true },
  targetId: { type: Schema.Types.ObjectId, required: true },
  trigger: { type: String, enum: ['initial', 'manual', 'schedule', 'push'], required: true },
  status: { type: String, enum: ['queued', 'running', 'completed', 'partial', 'failed', 'cancelled'], default: 'queued', index: true },
  revision: { type: String, default: null },
  runs: { type: [runSchema], default: [] },
  queuedAt: { type: Date, default: () => new Date() },
  startedAt: { type: Date, default: null },
  finishedAt: { type: Date, default: null },
  newFindings: { type: Number, default: 0 },
  fixedFindings: { type: Number, default: 0 },
});
scanSchema.index({ targetType: 1, targetId: 1, queuedAt: -1 });
scanSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.startedAt;
    ret.targetId = String(ret.targetId);
    return ret;
  },
});
export type ScanJobDoc = HydratedDocument<InferSchemaType<typeof scanSchema>>;
export const ScanJob = model('ScanJob', scanSchema);

/** CISA's Known Exploited Vulnerabilities list, refreshed daily. */
export const KevCache = model('KevCache', new Schema({ _id: { type: String, default: 'kev' }, ids: { type: [String], default: [] }, fetchedAt: Date }));