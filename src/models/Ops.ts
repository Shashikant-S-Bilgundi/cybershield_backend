import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

/** Sequence numbers, e.g. the 42 in INC-0042. Incremented atomically. */
export const Counter = model('Counter', new Schema({ _id: String, seq: { type: Number, default: 0 } }));

export async function nextSeq(name: string): Promise<number> {
  const c = await Counter.findOneAndUpdate({ _id: name }, { $inc: { seq: 1 } }, { upsert: true, new: true });
  return c!.seq;
}

const externalRef = { system: String, key: String, url: String, status: String, syncedAt: Date };

/* ───────────── incidents ───────────── */

export const INCIDENT_STATUSES = ['new', 'acknowledged', 'investigating', 'remediating', 'resolved', 'closed', 'reopened'] as const;

const incidentSchema = new Schema({
  ref: { type: String, required: true, unique: true },
  title: { type: String, required: true, trim: true, maxlength: 200 },
  summary: { type: String, default: '', maxlength: 5000 },
  severity: { type: String, enum: ['critical', 'high', 'medium', 'low', 'info'], required: true },
  status: { type: String, enum: INCIDENT_STATUSES, default: 'new', index: true },
  ownerId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  applicationIds: [{ type: Schema.Types.ObjectId, ref: 'Application' }],
  linked: { type: [{ type: { type: String }, id: String, title: String, severity: { type: String, default: null }, _id: false }], default: [] },
  openedAt: { type: Date, default: () => new Date() },
  acknowledgedAt: { type: Date, default: null },
  resolvedAt: { type: Date, default: null },
  closedAt: { type: Date, default: null },
  rootCause: { type: String, default: '', maxlength: 10000 },
  postIncident: { type: String, default: '', maxlength: 20000 },
  createdBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  timeline: { type: [{ at: Date, actorName: String, kind: String, text: String, _id: false }], default: [] },
  externalRef: { type: externalRef, default: undefined, _id: false },
});
incidentSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    ret.ownerId = ret.ownerId ? String(ret.ownerId) : null;
    ret.createdBy = ret.createdBy ? String(ret.createdBy) : null;
    ret.applicationIds = (ret.applicationIds as unknown[]).map(String);
    return ret;
  },
});
export type IncidentDoc = HydratedDocument<InferSchemaType<typeof incidentSchema>>;
export const Incident = model('Incident', incidentSchema);

/* ───────────── remediation tasks ───────────── */

const verification = { status: String, at: Date, method: String, detail: String };

const taskSchema = new Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  details: { type: String, default: '', maxlength: 5000 },
  linkedType: { type: String, enum: ['finding', 'incident', 'error_group'], required: true },
  linkedId: { type: Schema.Types.ObjectId, required: true, index: true },
  linkedTitle: { type: String, default: '' },
  applicationId: { type: Schema.Types.ObjectId, ref: 'Application', index: true },
  ownerId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  priority: { type: String, enum: ['P1', 'P2', 'P3', 'P4', null], default: null },
  dueAt: { type: Date, default: null },
  status: { type: String, enum: ['todo', 'in_progress', 'ready_for_verification', 'verified', 'wont_fix'], default: 'todo', index: true },
  createdAt: { type: Date, default: () => new Date() },
  createdBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  completedAt: { type: Date, default: null },
  verification: { type: verification, default: null, _id: false },
  verificationHistory: { type: [{ ...verification, _id: false }], default: [] },
  /** Error-group tasks pass when no new event arrives before this time. */
  watchUntil: { type: Date, default: null },
  wontFixReason: { type: String, default: null },
  notes: { type: [{ at: Date, actorName: String, text: String, _id: false }], default: [] },
  externalRef: { type: externalRef, default: undefined, _id: false },
});
taskSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.watchUntil;
    for (const k of ['linkedId', 'applicationId', 'ownerId', 'createdBy']) ret[k] = ret[k] ? String(ret[k]) : null;
    return ret;
  },
});
export type TaskDoc = HydratedDocument<InferSchemaType<typeof taskSchema>>;
export const RemediationTask = model('RemediationTask', taskSchema);