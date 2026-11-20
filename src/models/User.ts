import { Schema, model, type InferSchemaType, type HydratedDocument } from 'mongoose';
import { toJSONPlugin } from './plugins.js';

const userSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    status: { type: String, enum: ['active', 'disabled'], default: 'active' },
    mfaEnabled: { type: Boolean, default: false },
    /** Encrypted TOTP secret (lib/crypto). */
    totpSecretEnc: { type: String, default: null },
    /** Last accepted TOTP time step, so a code cannot be used twice. */
    totpLastStep: { type: Number, default: 0 },
    lastLoginAt: { type: Date, default: null },
    invitedBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

toJSONPlugin(userSchema, { hidden: ['passwordHash', 'totpSecretEnc', 'totpLastStep'] });

export type UserDoc = HydratedDocument<InferSchemaType<typeof userSchema>>;
export const User = model('User', userSchema);