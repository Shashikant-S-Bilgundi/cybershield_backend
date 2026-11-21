import { createHmac } from 'node:crypto';
import { config } from '../config.js';

/** "ravi@example.com" → "r***@example.com". Already-masked values pass through. */
export function maskEmail(value: string): string {
  const v = value.trim().toLowerCase();
  const at = v.indexOf('@');
  if (at < 1) return v.length > 2 ? `${v[0]}***` : '***';
  if (v.slice(1, at).startsWith('***')) return v;
  return `${v[0]}***${v.slice(at)}`;
}

/** A stable, non-reversible id for a user: HMAC with the server key, so a leaked database cannot be matched to user ids. */
export const hashUser = (id: string) => `usr_${createHmac('sha256', config.encryptionKey).update(`user:${id}`).digest('hex').slice(0, 12)}`;

const SECRET_KEY = /pass(word)?|secret|token|authori[sz]ation|cookie|api[-_]?key|session|bearer|credential/i;
const PATTERNS: [RegExp, string][] = [
  [/eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/g, '[jwt]'],
  [/\b(sk|pk|rk|so)_(live|test|pub)_[\w]{8,}/g, '[key]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[aws-key]'],
  [/\b[A-Fa-f0-9]{32,}\b/g, '[hex]'],
  [/\b(Bearer|Basic)\s+[\w.~+/-]+=*/gi, '$1 [redacted]'],
  [/[\w.+-]+@[\w-]+\.[\w.-]+/g, (m: string) => maskEmail(m)] as unknown as [RegExp, string],
];

/** Removes tokens, keys and emails from free text such as error messages. */
export function scrubText(text: string, max = 2000): string {
  let out = text.slice(0, max);
  for (const [rx, rep] of PATTERNS) out = out.replace(rx, rep as never);
  return out;
}

/** Tags whose name suggests a secret are replaced; the rest are scrubbed like text. */
export function scrubTags(tags: Record<string, string> = {}): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(tags).slice(0, 20)) out[k.slice(0, 50)] = SECRET_KEY.test(k) ? '[redacted]' : scrubText(String(v), 200);
  return out;
}

/** Collapses numbers, ids and hex so "User 123 not found" and "User 456 not found" group together. */
export function normalizeMessage(message: string): string {
  return message
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<uuid>')
    .replace(/\b[0-9a-f]{12,}\b/gi, '<hex>')
    .replace(/\d+/g, '<n>')
    .slice(0, 300);
}