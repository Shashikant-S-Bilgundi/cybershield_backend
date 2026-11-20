import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

export const ASSET_TYPES = ['domain', 'website', 'api', 'server', 'cloud', 'database', 'repository', 'image'] as const;
export const AUTH_METHODS = ['dns_txt', 'html_file', 'approval', 'internal_allowlist'] as const;

const assetSchema = new Schema(
  {
    type: { type: String, enum: ASSET_TYPES, required: true },
    identifier: { type: String, required: true, trim: true, maxlength: 500 },
    /** Lower-cased identifier for duplicate checks. */
    identifierKey: { type: String, required: true },
    label: { type: String, required: true, trim: true, maxlength: 120 },
    applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
    environmentId: { type: Schema.Types.ObjectId, required: true },
    exposure: { type: String, enum: ['internet', 'internal'], required: true },
    shared: { type: Boolean, default: false },
    status: { type: String, enum: ['active', 'paused', 'archived'], default: 'active' },
    authorization: {
      status: { type: String, enum: ['pending', 'verified', 'approved', 'failed'], required: true },
      method: { type: String, enum: AUTH_METHODS, required: true },
      token: String,
      justification: String,
      approvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      at: Date,
      lastError: String,
    },
    deletedAt: { type: Date, default: null, index: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
assetSchema.index({ type: 1, identifierKey: 1 }, { unique: true, partialFilterExpression: { deletedAt: null } });
assetSchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.identifierKey;
    delete ret.deletedAt;
    ret.applicationId = String(ret.applicationId);
    ret.environmentId = String(ret.environmentId);
    const a = ret.authorization as Record<string, unknown>;
    if (a?.approvedBy) a.approvedBy = String(a.approvedBy);
    delete a?.lastError;
    return ret;
  },
});

export type AssetDoc = HydratedDocument<InferSchemaType<typeof assetSchema>>;
export const Asset = model('Asset', assetSchema);