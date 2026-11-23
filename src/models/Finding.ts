import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

export const FINDING_STATUSES = ['open', 'acknowledged', 'in_progress', 'resolved', 'verified', 'reopened', 'accepted_risk', 'false_positive'] as const;

const findingSchema = new Schema({
  /** Identifies the problem, e.g. "ssl:expiry:<assetId>", so a recurring problem updates one finding. */
  key: { type: String, required: true, unique: true },
  title: { type: String, required: true },
  description: { type: String, default: '' },
  category: { type: String, enum: ['security', 'availability', 'performance', 'configuration'], required: true },
  source: { type: String, required: true, index: true },
  applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
  environmentId: { type: Schema.Types.ObjectId, required: true },
  assetId: { type: Schema.Types.ObjectId, ref: 'Asset', required: true, index: true },
  severity: { type: String, enum: ['critical', 'high', 'medium', 'low', 'info'], required: true },
  confidence: { type: String, enum: ['confirmed', 'likely', 'possible'], default: 'confirmed' },
  knownExploited: { type: Boolean, default: false },
  riskScore: { type: Number, required: true },
  priority: { type: String, enum: ['P1', 'P2', 'P3', 'P4'], required: true },
  status: { type: String, enum: FINDING_STATUSES, default: 'open', index: true },
  assigneeId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  dueAt: { type: Date, default: null },
  evidence: { type: [{ label: String, value: String, _id: false }], default: [] },
  firstSeen: { type: Date, default: () => new Date() },
  lastSeen: { type: Date, default: () => new Date() },
  acceptedRisk: { type: { justification: String, expiresAt: Date, by: Schema.Types.ObjectId, at: Date, _id: false }, default: null },
  history: { type: [{ at: Date, actorName: String, text: String, _id: false }], default: [] },
  /** Extra detail for findings from code and image scans (SecretDetail or VulnDetail). */
  code: { type: Schema.Types.Mixed, default: undefined },
});
findingSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.key;
    for (const k of ['applicationId', 'environmentId', 'assetId', 'assigneeId']) ret[k] = ret[k] ? String(ret[k]) : null;
    const ar = ret.acceptedRisk as { by?: unknown } | null;
    if (ar?.by) ar.by = String(ar.by);
    return ret;
  },
});

export type FindingDoc = HydratedDocument<InferSchemaType<typeof findingSchema>>;
export const Finding = model('Finding', findingSchema);