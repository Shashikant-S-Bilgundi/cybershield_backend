import { Schema, model } from 'mongoose';

/** The step between password and two-factor code. Lives 10 minutes. */
const challengeSchema = new Schema({
  idHash: { type: String, required: true, unique: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  enroll: { type: Boolean, required: true },
  /** Encrypted secret being enrolled; saved on the user only once a code proves it works. */
  pendingSecretEnc: { type: String, default: null },
  attempts: { type: Number, default: 0 },
  expiresAt: { type: Date, required: true },
});
challengeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const LoginChallenge = model('LoginChallenge', challengeSchema);