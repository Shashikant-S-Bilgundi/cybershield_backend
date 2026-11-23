import nodemailer from 'nodemailer';
import { decrypt } from '../lib/crypto.js';
import { logger } from '../lib/logger.js';
import { getSettingsDoc } from './settings.js';

/** Sends through the SMTP server in System settings. Returns false (and logs) when SMTP is not set up or fails. */
export async function sendMail(to: string | string[], subject: string, text: string, attachments: { filename: string; content: Buffer; contentType?: string }[] = []): Promise<boolean> {
  const s = (await getSettingsDoc()).smtp!;
  if (!s.host || !s.fromAddress) return false;
  try {
    const transport = nodemailer.createTransport({
      host: s.host,
      port: s.port,
      secure: s.port === 465,
      requireTLS: s.port !== 465,
      auth: s.username ? { user: s.username, pass: s.passwordEnc ? decrypt(s.passwordEnc) : '' } : undefined,
      connectionTimeout: 10_000,
    });
    await transport.sendMail({ from: s.fromAddress, to, subject, text, attachments });
    return true;
  } catch (err) {
    logger.warn({ err: (err as Error).message, subject }, 'Email could not be sent');
    return false;
  }
}