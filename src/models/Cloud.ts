import { Schema, model } from 'mongoose';

/** One SSO sign-in in progress: ties the identity provider's answer to the browser that started it. */
const ssoStateSchema = new Schema({ stateHash: { type: String, required: true, unique: true }, nonce: String, verifier: String, provider: String, expiresAt: { type: Date, required: true } });
ssoStateSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
export const SsoState = model('SsoState', ssoStateSchema);

/** The latest result of each cloud or identity check, for the Cloud and identity page. */
export const CloudCheckResult = model(
  'CloudCheckResult',
  new Schema({ _id: String, provider: String, title: String, passed: Number, failed: Number, findingKeys: [String], checkedAt: Date, error: { type: String, default: null } }),
);