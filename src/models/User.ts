import { Schema, model, type InferSchemaType, type HydratedDocument } from 'mongoose';

const userSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    status: { type: String, enum: ['active', 'disabled'], default: 'active' },
    lastLoginAt: { type: Date, default: null },
    invitedBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

/** Only these fields ever leave the API, whatever else is stored on the document. */
userSchema.set('toJSON', {
  versionKey: false,
  transform: (_doc, ret: Record<string, unknown>) => ({
    id: String(ret._id),
    name: ret.name,
    email: ret.email,
    status: ret.status,
    lastLoginAt: ret.lastLoginAt ?? null,
    invitedBy: ret.invitedBy ? String(ret.invitedBy) : null,
    createdAt: ret.createdAt,
  }),
});

export type UserDoc = HydratedDocument<InferSchemaType<typeof userSchema>>;
export const User = model('User', userSchema);