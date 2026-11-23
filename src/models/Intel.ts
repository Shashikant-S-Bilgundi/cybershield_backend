import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

/** A dismissed recommendation. Recommendations themselves are worked out live from open findings. */
export const RecDismissal = model('RecDismissal', new Schema({ recId: { type: String, required: true, unique: true }, reason: String, by: Schema.Types.ObjectId, at: { type: Date, default: () => new Date() } }));

const reportSchema = new Schema({
  type: { type: String, enum: ['posture', 'health', 'vulnerabilities', 'ssl_domains', 'incidents', 'compliance'], required: true },
  title: { type: String, required: true },
  from: { type: Date, required: true },
  to: { type: Date, required: true },
  applicationId: { type: Schema.Types.ObjectId, default: null },
  status: { type: String, enum: ['generating', 'ready', 'failed'], default: 'generating' },
  generatedAt: { type: Date, default: () => new Date() },
  generatedBy: { type: Schema.Types.ObjectId, default: null },
  sizeKb: { type: Number, default: null },
  sections: { type: Schema.Types.Mixed, default: [] },
  /** The rendered PDF (reports are small; well under MongoDB's document limit). */
  pdf: { type: Buffer, default: null, select: false },
  error: { type: String, default: null },
});
reportSchema.index({ generatedAt: -1 });
reportSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.pdf;
    delete ret.error;
    ret.applicationId = ret.applicationId ? String(ret.applicationId) : null;
    ret.generatedBy = ret.generatedBy ? String(ret.generatedBy) : null;
    return ret;
  },
});
export type ReportDoc = HydratedDocument<InferSchemaType<typeof reportSchema>>;
export const Report = model('Report', reportSchema);

const scheduleSchema = new Schema({
  type: { type: String, required: true },
  frequency: { type: String, enum: ['weekly', 'monthly'], required: true },
  recipients: { type: [String], default: [] },
  applicationId: { type: Schema.Types.ObjectId, default: null },
  nextRunAt: { type: Date, required: true, index: true },
  createdBy: { type: Schema.Types.ObjectId, required: true },
});
scheduleSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    ret.applicationId = ret.applicationId ? String(ret.applicationId) : null;
    ret.createdBy = String(ret.createdBy);
    return ret;
  },
});
export type ScheduleDoc = HydratedDocument<InferSchemaType<typeof scheduleSchema>>;
export const ReportSchedule = model('ReportSchedule', scheduleSchema);

/** Which frameworks are shown, and your own evidence for controls ShieldOps cannot check. */
export const FrameworkState = model('FrameworkState', new Schema({ _id: String, enabled: Boolean }));
export const Attestation = model(
  'Attestation',
  new Schema({ framework: { type: String, required: true }, controlId: { type: String, required: true }, status: { type: String, enum: ['met', 'not_met'] }, note: String, by: Schema.Types.ObjectId, at: Date }).index({ framework: 1, controlId: 1 }, { unique: true }),
);