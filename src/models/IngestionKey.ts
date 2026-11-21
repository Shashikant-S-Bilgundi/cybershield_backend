import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

const keySchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    kind: { type: String, enum: ['server', 'browser'], required: true },
    applicationId: { type: Schema.Types.ObjectId, ref: 'Application', required: true, index: true },
    environmentId: { type: Schema.Types.ObjectId, required: true },
    /** First characters, shown so people can tell keys apart. */
    prefix: { type: String, required: true },
    /** SHA-256 of the full key; the key itself is never stored. */
    hash: { type: String, required: true, unique: true },
    /** After a rotation the old key keeps working until this time. */
    previousHash: { type: String, default: null, index: true },
    previousExpiresAt: { type: Date, default: null },
    scopes: { type: [String], default: [] },
    status: { type: String, enum: ['active', 'revoked'], default: 'active' },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    lastUsedAt: { type: Date, default: null },
    revokedAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
keySchema.set('toJSON', {
  versionKey: false,
  transform: (_d, ret: Record<string, unknown>) => {
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.hash;
    delete ret.previousHash;
    delete ret.previousExpiresAt;
    for (const k of ['applicationId', 'environmentId', 'createdBy']) ret[k] = String(ret[k]);
    return ret;
  },
});

export type IngestionKeyDoc = HydratedDocument<InferSchemaType<typeof keySchema>>;
export const IngestionKey = model('IngestionKey', keySchema);

/** Events received per key per hour, for "events in the last 24 hours". */
const usageSchema = new Schema({ keyId: { type: Schema.Types.ObjectId, required: true }, hour: { type: Date, required: true }, count: { type: Number, default: 0 } });
usageSchema.index({ keyId: 1, hour: 1 }, { unique: true });
usageSchema.index({ hour: 1 }, { expireAfterSeconds: 3 * 86_400 });
export const KeyUsage = model('KeyUsage', usageSchema);