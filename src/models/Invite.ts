import { Schema, model } from 'mongoose';
import { toJSONPlugin } from './plugins.js';

const inviteSchema = new Schema(
  {
    email: { type: String, required: true, lowercase: true, trim: true, unique: true },
    invitedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    tokenHash: { type: String, required: true, unique: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
inviteSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 7 * 86_400 });
toJSONPlugin(inviteSchema, { hidden: ['tokenHash'] });

export const Invite = model('Invite', inviteSchema);