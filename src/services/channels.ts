import { createHmac } from 'node:crypto';
import { config } from '../config.js';
import { decrypt } from '../lib/crypto.js';
import { ApiError } from '../lib/errors.js';
import { guardedPost } from '../lib/probe.js';
import { Application } from '../models/Application.js';
import { Integration } from '../models/Code.js';
import { getAllowlist } from './settings.js';

export interface AlertPayload {
  id: string;
  title: string;
  message: string;
  severity: string;
  applicationId: unknown;
  environmentId: unknown;
}

const EMOJI: Record<string, string> = { critical: ':red_circle:', high: ':large_orange_circle:', medium: ':large_yellow_circle:', low: ':large_blue_circle:', info: ':white_circle:' };

async function names(a: AlertPayload) {
  const app = await Application.findById(a.applicationId).lean();
  return { application: app?.name ?? 'Unknown application', environment: app?.environments.find((e) => String(e._id) === String(a.environmentId))?.name ?? '' };
}

/** HMAC-SHA256 of the exact body bytes, hex, as "sha256=<hex>". Receivers recompute it with their secret. */
export const signBody = (secret: string, body: string) => `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;

type Result = { ok: boolean; detail: string; recipient: string };

/** Posts to Slack or the webhook. Up to 3 attempts (1 s, then 5 s apart) for network errors and 5xx answers. */
export async function sendToChannel(type: 'slack' | 'webhook', a: AlertPayload, event = 'alert.opened'): Promise<Result & { attempts: number }> {
  const doc = await Integration.findOne({ type, status: 'connected' });
  if (!doc?.credentialsEnc) return { ok: false, detail: `${type === 'slack' ? 'Slack' : 'The webhook'} is not connected.`, recipient: 'Not set up', attempts: 0 };
  const creds = JSON.parse(decrypt(doc.credentialsEnc)) as { url: string; secret?: string };
  const n = await names(a);
  const link = `${config.appUrl}/alerts`;
  const body =
    type === 'slack'
      ? JSON.stringify({
          text: `${EMOJI[a.severity] ?? ''} ${a.title}`,
          blocks: [
            { type: 'section', text: { type: 'mrkdwn', text: `${EMOJI[a.severity] ?? ''} *${a.title.replace(/[<>&]/g, '')}*\n${a.message.replace(/[<>&]/g, '').slice(0, 1500)}` } },
            { type: 'context', elements: [{ type: 'mrkdwn', text: `${a.severity.toUpperCase()} · ${n.application}${n.environment ? `, ${n.environment}` : ''} · <${link}|Open in ShieldOps>` }] },
          ],
        })
      : JSON.stringify({ event, alert: { id: a.id, title: a.title, message: a.message, severity: a.severity, application: n.application, environment: n.environment, url: link }, sent_at: new Date().toISOString() });
  const headers: Record<string, string> = type === 'webhook' ? { 'ShieldOps-Signature': signBody(creds.secret!, body), 'ShieldOps-Event': event, 'ShieldOps-Delivery': a.id } : {};
  const allow = await getAllowlist();
  let last: Result = { ok: false, detail: '', recipient: doc.account ?? '' };
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const r = await guardedPost(creds.url, body, headers, allow);
      if (r.status >= 200 && r.status < 300) return { ok: true, detail: `${type === 'slack' ? 'Slack' : new URL(creds.url).host} answered ${r.status} in ${r.latencyMs} ms.`, recipient: doc.account ?? '', attempts: attempt };
      last = { ok: false, detail: `${type === 'slack' ? 'Slack' : new URL(creds.url).host} answered ${r.status}${r.text ? `: ${r.text.slice(0, 120)}` : ''}.`, recipient: doc.account ?? '' };
      if (r.status < 500 && r.status !== 429) return { ...last, attempts: attempt };
    } catch (err) {
      last = { ok: false, detail: err instanceof ApiError ? err.message : `Could not reach ${new URL(creds.url).host}: ${(err as Error).message}`, recipient: doc.account ?? '' };
    }
    if (attempt < 3) await new Promise((r) => setTimeout(r, attempt === 1 ? 1000 : 5000).unref());
  }
  return { ...last, attempts: 3 };
}