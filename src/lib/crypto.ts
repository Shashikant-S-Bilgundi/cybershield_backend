import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { config } from '../config.js';

/** URL-safe random token, used for sessions and invites. */
export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');

export const randomHex = (chars: number) => randomBytes(Math.ceil(chars / 2)).toString('hex').slice(0, chars);

/** Tokens are stored hashed, so a database leak does not hand out live sessions or invites. */
export const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

export const safeEqual = (a: string, b: string) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

/** AES-256-GCM with the key from ENCRYPTION_KEY (SMTP and integration credentials). Output: v1.<iv>.<tag>.<ciphertext>, base64url. */
export function encrypt(plain: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', config.encryptionKey, iv);
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), data.toString('base64url')].join('.');
}

export function decrypt(sealed: string): string {
  const [v, iv, tag, data] = sealed.split('.');
  if (v !== 'v1' || !iv || !tag || !data) throw new Error('Unknown encrypted value format');
  const decipher = createDecipheriv('aes-256-gcm', config.encryptionKey, Buffer.from(iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(data, 'base64url')), decipher.final()]).toString('utf8');
}