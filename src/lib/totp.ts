import { authenticator } from 'otplib';

authenticator.options = { window: 1, step: 30, digits: 6 };

export const newTotpSecret = () => authenticator.generateSecret(20);
export const otpauthUrl = (email: string, secret: string) => authenticator.keyuri(email, 'ShieldOps', secret);

/**
 * Checks a 6-digit code against the secret, allowing one step of clock drift.
 * Returns the time step the code belongs to, or null. Callers reject steps already used.
 */
export function totpStep(secret: string, code: string): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const delta = authenticator.checkDelta(code, secret);
  if (delta === null) return null;
  return Math.floor(Date.now() / 30_000) + delta;
}