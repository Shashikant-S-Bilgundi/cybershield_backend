import { Schema, model } from 'mongoose';

const auditSchema = new Schema({
  actorId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  actorName: { type: String, required: true },
  action: { type: String, required: true, index: true },
  resourceType: { type: String, required: true, index: true },
  resourceId: { type: String, default: null },
  summary: { type: String, required: true },
  ip: { type: String, default: '' },
  userAgent: { type: String, default: '' },
  at: { type: Date, default: () => new Date(), index: true },
});

/** Append-only: the application refuses to change or remove audit records. */
const refuse = () => {
  throw new Error('Audit logs are append-only.');
};
for (const op of ['updateOne', 'updateMany', 'findOneAndUpdate', 'replaceOne', 'deleteOne', 'deleteMany', 'findOneAndDelete', 'findOneAndReplace'] as const) {
  auditSchema.pre(op, refuse);
}

auditSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.userAgent;
    ret.actorId = ret.actorId ? String(ret.actorId) : null;
    return ret;
  },
});

export const AuditLog = model('AuditLog', auditSchema);