import { Schema, model, type HydratedDocument, type InferSchemaType } from 'mongoose';

const sessionSchema = new Schema({
  tokenHash: { type: String, required: true, unique: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  /** Sliding idle expiry; MongoDB removes the document once it passes. */
  expiresAt: { type: Date, required: true },
  /** Hard limit regardless of activity. */
  absoluteExpiresAt: { type: Date, required: true },
  reauthUntil: { type: Date, default: null },
  revokedAt: { type: Date, default: null },
  /** How this session signed in: password or single sign-on. */
  method: { type: String, enum: ['password', 'sso'], default: 'password' },
  ip: String,
  userAgent: String,
  createdAt: { type: Date, default: () => new Date() },
});
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type SessionDoc = HydratedDocument<InferSchemaType<typeof sessionSchema>>;
export const Session = model('Session', sessionSchema);