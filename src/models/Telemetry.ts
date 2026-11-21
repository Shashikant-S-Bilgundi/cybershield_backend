import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

/* ───────────── errors ───────────── */

const frame = new Schema({ file: String, fn: String, line: Number, column: Number, inApp: Boolean, code: String }, { _id: false });

const groupSchema = new Schema({
  applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true, index: true },
  fingerprint: { type: String, required: true },
  type: { type: String, required: true },
  message: { type: String, required: true },
  culprit: { type: String, default: '' },
  platform: { type: String, enum: ['node', 'browser', 'react-native'], required: true },
  status: { type: String, enum: ['unresolved', 'resolved', 'ignored', 'regressed'], default: 'unresolved', index: true },
  firstSeen: { type: Date, required: true },
  lastSeen: { type: Date, required: true, index: true },
  count: { type: Number, default: 0 },
  usersAffected: { type: Number, default: 0 },
  assigneeId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  lastRelease: { type: String, default: '' },
  resolvedAt: { type: Date, default: null },
  stack: { type: [frame], default: [] },
  releases: { type: Map, of: Number, default: {} },
  history: { type: [{ at: Date, actorName: String, text: String, _id: false }], default: [] },
});
groupSchema.index({ environmentId: 1, fingerprint: 1 }, { unique: true });
export type ErrorGroupDoc = HydratedDocument<InferSchemaType<typeof groupSchema>>;
export const ErrorGroup = model('ErrorGroup', groupSchema);

const eventSchema = new Schema({
  groupId: { type: Schema.Types.ObjectId, ref: 'ErrorGroup', required: true },
  at: { type: Date, required: true },
  release: { type: String, default: '' },
  message: { type: String, default: '' },
  request: { type: { method: String, route: String, status: Number, _id: false }, default: null },
  userHash: { type: String, default: null },
  tags: { type: Schema.Types.Mixed, default: {} },
});
eventSchema.index({ groupId: 1, at: -1 });
eventSchema.index({ at: 1 });
export const ErrorEvent = model('ErrorEvent', eventSchema);

/** Events per group per hour, for trends and spike detection. */
const hourlySchema = new Schema({ groupId: { type: Schema.Types.ObjectId, required: true }, hour: { type: Date, required: true }, count: { type: Number, default: 0 } });
hourlySchema.index({ groupId: 1, hour: 1 }, { unique: true });
hourlySchema.index({ hour: 1 }, { expireAfterSeconds: 3 * 86_400 });
export const ErrorHourly = model('ErrorHourly', hourlySchema);

/** Which hashed users hit a group, so "users affected" counts each person once. */
const userSchema = new Schema({ groupId: { type: Schema.Types.ObjectId, required: true }, userHash: { type: String, required: true } });
userSchema.index({ groupId: 1, userHash: 1 }, { unique: true });
export const ErrorUser = model('ErrorUser', userSchema);

/* ───────────── performance ───────────── */

/** One minute of requests for one route, merged from every server sending for that environment. */
const perfSchema = new Schema({
  applicationId: { type: Schema.Types.ObjectId, required: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  minute: { type: Date, required: true },
  method: { type: String, required: true },
  route: { type: String, required: true },
  count: { type: Number, default: 0 },
  /** Requests answered with a 5xx status. ("errors" is a name Mongoose reserves.) */
  serverErrors: { type: Number, default: 0 },
  sumMs: { type: Number, default: 0 },
  buckets: { type: [Number], default: [] },
});
perfSchema.index({ environmentId: 1, minute: 1, method: 1, route: 1 }, { unique: true });
perfSchema.index({ minute: 1 });
export const PerfMinute = model('PerfMinute', perfSchema);

/* ───────────── security events ───────────── */

export const SECURITY_TYPES = ['login_success', 'login_failure', 'logout', 'mfa_failure', 'password_reset', 'authz_failure', 'rate_limited', 'admin_action', 'permission_change', 'input_rejected'] as const;

const secSchema = new Schema({
  at: { type: Date, required: true },
  applicationId: { type: Schema.Types.ObjectId, required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  type: { type: String, enum: SECURITY_TYPES, required: true },
  actorHash: { type: String, default: null },
  /** Masked for display; accountKey (a hash) is what detection counts. */
  account: { type: String, default: null },
  accountKey: { type: String, default: null },
  ip: { type: String, default: '' },
  country: { type: String, default: null },
  method: { type: String, default: null },
  route: { type: String, default: null },
  status: { type: Number, default: null },
  result: { type: String, enum: ['success', 'failure', 'blocked'], required: true },
});
secSchema.index({ environmentId: 1, at: -1 });
secSchema.index({ environmentId: 1, ip: 1, at: -1 });
secSchema.index({ at: 1 });
secSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.accountKey;
    ret.applicationId = String(ret.applicationId);
    ret.environmentId = String(ret.environmentId);
    return ret;
  },
});
export const SecurityEvent = model('SecurityEvent', secSchema);

const detectionSchema = new Schema({
  rule: { type: String, enum: ['failed_logins', 'credential_stuffing', 'auth_failure_spike', 'unusual_volume'], required: true },
  applicationId: { type: Schema.Types.ObjectId, required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  subject: { type: String, required: true },
  count: { type: Number, default: 0 },
  distinctAccounts: { type: Number, default: null },
  windowMin: { type: Number, required: true },
  firstAt: { type: Date, required: true },
  lastAt: { type: Date, required: true, index: true },
  alertId: { type: Schema.Types.ObjectId, default: null },
});
detectionSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    for (const k of ['applicationId', 'environmentId', 'alertId']) ret[k] = ret[k] ? String(ret[k]) : null;
    return ret;
  },
});
export const Detection = model('Detection', detectionSchema);