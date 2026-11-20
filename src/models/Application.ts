import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

const environmentSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 60 },
    type: { type: String, enum: ['production', 'staging', 'development', 'custom'], required: true },
  },
  { _id: true },
);
environmentSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    return ret;
  },
});

const applicationSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    description: { type: String, default: '', maxlength: 2000 },
    ownerId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    memberIds: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    criticality: { type: String, enum: ['critical', 'high', 'medium', 'low'], required: true },
    techStack: [{ type: String, maxlength: 60 }],
    tags: [{ type: String, maxlength: 60 }],
    status: { type: String, enum: ['active', 'archived'], default: 'active' },
    environments: { type: [environmentSchema], validate: [(v: unknown[]) => v.length > 0, 'At least one environment'] },
    /** Soft delete: restorable for 30 days, then purged. */
    deletedAt: { type: Date, default: null, index: true },
  },
  { timestamps: true },
);
applicationSchema.set('toJSON', {
  versionKey: false,
  transform: (doc, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.deletedAt;
    ret.ownerId = String(ret.ownerId);
    ret.memberIds = (ret.memberIds as unknown[]).map(String);
    ret.environments = (doc.environments ?? []).map((e) => ({ id: String(e._id), applicationId: String(doc._id), name: e.name, type: e.type }));
    return ret;
  },
});

export type ApplicationDoc = HydratedDocument<InferSchemaType<typeof applicationSchema>>;
export const Application = model('Application', applicationSchema);