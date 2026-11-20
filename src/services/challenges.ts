import { encrypt } from '../lib/crypto.js';
import { randomToken, sha256 } from '../lib/crypto.js';
import { newTotpSecret, otpauthUrl } from '../lib/totp.js';
import { LoginChallenge } from '../models/LoginChallenge.js';
import type { UserDoc } from '../models/User.js';

/** Starts the two-factor step. New users get a secret to enrol; it is saved only after a valid code. */
export async function startChallenge(user: UserDoc) {
  const challengeId = randomToken(24);
  const enroll = !user.mfaEnabled || !user.totpSecretEnc;
  const secret = enroll ? newTotpSecret() : null;
  await LoginChallenge.create({
    idHash: sha256(challengeId),
    userId: user._id,
    enroll,
    pendingSecretEnc: secret ? encrypt(secret) : null,
    expiresAt: new Date(Date.now() + 10 * 60_000),
  });
  if (!enroll) return { status: 'mfa_required' as const, challengeId };
  return { status: 'mfa_enroll' as const, challengeId, enrollment: { secret: secret!, otpauthUrl: otpauthUrl(user.email, secret!) } };
}