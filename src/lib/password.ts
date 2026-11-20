import argon2 from 'argon2';

/** argon2id with OWASP's recommended minimum (19 MiB, 2 passes). */
const OPTIONS = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

export const hashPassword = (plain: string) => argon2.hash(plain, OPTIONS);

/** A fixed hash to verify against when the email is unknown, so timing does not reveal which emails exist. */
let dummy: string | null = null;
export async function verifyPassword(hash: string | null | undefined, plain: string): Promise<boolean> {
  dummy ??= await argon2.hash('not-a-real-password-0000', OPTIONS);
  try {
    return await argon2.verify(hash ?? dummy, plain).then((ok) => ok && !!hash);
  } catch {
    return false;
  }
}

/** Same rules as the frontend (src/pages/auth/passwordRules.ts). */
export function passwordProblem(password: string): string | null {
  if (password.length < 12) return 'Use at least 12 characters.';
  if (password.length > 256) return 'Use at most 256 characters.';
  if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) return 'Use both letters and numbers.';
  return null;
}