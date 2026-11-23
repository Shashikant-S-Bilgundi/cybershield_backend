import { decrypt } from '../lib/crypto.js';
import { ApiError } from '../lib/errors.js';
import { logger } from '../lib/logger.js';
import { Integration } from '../models/Code.js';
import { Incident, RemediationTask } from '../models/Ops.js';
import { config } from '../config.js';

type Jira = { siteUrl: string; email: string; apiToken: string; projectKey: string };

async function jira<T>(c: Jira, path: string, init: { method?: string; body?: object } = {}): Promise<T> {
  const res = await fetch(`${c.siteUrl.replace(/\/$/, '')}/rest/api/3${path}`, {
    method: init.method ?? 'GET',
    headers: { authorization: `Basic ${Buffer.from(`${c.email}:${c.apiToken}`).toString('base64')}`, accept: 'application/json', ...(init.body ? { 'content-type': 'application/json' } : {}) },
    body: init.body ? JSON.stringify(init.body) : undefined,
    signal: AbortSignal.timeout(15_000),
  }).catch((e: Error) => {
    throw new ApiError(502, 'JIRA_UNREACHABLE', `Could not reach Jira: ${e.message}`);
  });
  const data = (await res.json().catch(() => ({}))) as T & { errorMessages?: string[]; errors?: Record<string, string> };
  if (!res.ok) {
    const msg = [...(data.errorMessages ?? []), ...Object.values(data.errors ?? {})].join(' ') || `HTTP ${res.status}`;
    throw new ApiError(res.status === 401 || res.status === 403 ? 422 : 502, res.status === 401 || res.status === 403 ? 'INVALID_CREDENTIALS' : 'JIRA_ERROR', `Jira answered ${res.status}: ${msg}`);
  }
  return data;
}

/** Checks the site, account and project before anything is stored. */
export async function verifyJira(c: Jira) {
  if (!/^(https:\/\/[\w.-]+|http:\/\/(localhost|127\.0\.0\.1))(:\d+)?\/?$/.test(c.siteUrl ?? '')) throw new ApiError(422, 'INVALID_URL', 'Enter your Jira site, like https://your-team.atlassian.net.');
  if (!/^[A-Z][A-Z0-9_]{1,9}$/.test(c.projectKey ?? '')) throw new ApiError(422, 'INVALID_PROJECT', 'Enter the project key in capitals, like SEC.');
  if (!c.email || !c.apiToken) throw new ApiError(422, 'MISSING_FIELD', 'Fill in every field.');
  const p = await jira<{ key: string; name: string }>(c, `/project/${c.projectKey}`);
  return { account: `${new URL(c.siteUrl).host} · ${p.key} (${p.name})`, scopes: [`Create and read issues in ${p.key}`] };
}

async function creds(): Promise<Jira> {
  const d = await Integration.findOne({ type: 'jira', status: 'connected' });
  if (!d?.credentialsEnc) throw new ApiError(409, 'NOT_CONNECTED', 'Connect Jira in Integrations first.');
  return JSON.parse(decrypt(d.credentialsEnc));
}

/** Jira's document format, from plain paragraphs. */
const adf = (paras: string[]) => ({ type: 'doc', version: 1, content: paras.filter(Boolean).map((t) => ({ type: 'paragraph', content: [{ type: 'text', text: t.slice(0, 3000) }] })) });

/** Creates one Jira issue for an incident or task, and links it both ways. */
export async function createIssue(target: { type: 'incident' | 'task'; id: string }, actorName: string) {
  const c = await creds();
  const doc = target.type === 'incident' ? await Incident.findById(target.id) : await RemediationTask.findById(target.id);
  if (!doc) throw new ApiError(404, 'NOT_FOUND', target.type === 'incident' ? 'Incident not found.' : 'Task not found.');
  if (doc.externalRef?.key) throw new ApiError(409, 'ALREADY_LINKED', `Already linked to ${doc.externalRef.key}.`);
  const link = `${config.appUrl}/${target.type === 'incident' ? `incidents/${doc.id}` : 'remediation'}`;
  const summary = target.type === 'incident' ? `[${(doc as InstanceType<typeof Incident>).ref}] ${doc.title}` : doc.title;
  const body = target.type === 'incident'
    ? [`Severity: ${(doc as InstanceType<typeof Incident>).severity}.`, (doc as InstanceType<typeof Incident>).summary, `Open in ShieldOps: ${link}`]
    : [`For: ${(doc as InstanceType<typeof RemediationTask>).linkedTitle}.`, (doc as InstanceType<typeof RemediationTask>).details, `ShieldOps verifies the fix with a recheck; close the task there: ${link}`];
  const r = await jira<{ key: string }>(c, '/issue', { method: 'POST', body: { fields: { project: { key: c.projectKey }, summary: summary.slice(0, 250), description: adf(body), issuetype: { name: 'Task' }, labels: ['shieldops'] } } });
  const ref = { system: 'jira', key: r.key, url: `${c.siteUrl.replace(/\/$/, '')}/browse/${r.key}`, status: 'To Do', syncedAt: new Date() };
  doc.externalRef = ref as never;
  if (target.type === 'incident') (doc as InstanceType<typeof Incident>).timeline.unshift({ at: new Date(), actorName, kind: 'note', text: `Created Jira issue ${r.key}` } as never);
  else (doc as InstanceType<typeof RemediationTask>).notes.unshift({ at: new Date(), actorName, text: `Created Jira issue ${r.key}` } as never);
  await doc.save();
  return ref;
}

/** Run by the scheduler: copies each linked issue's status into ShieldOps. Read-only towards Jira. */
export async function syncJira() {
  const doc = await Integration.findOne({ type: 'jira', status: 'connected' });
  if (!doc?.credentialsEnc) return;
  const c = JSON.parse(decrypt(doc.credentialsEnc)) as Jira;
  for (const Model of [Incident, RemediationTask] as const) {
    for (const d of await (Model as typeof Incident).find({ 'externalRef.system': 'jira' })) {
      try {
        const i = await jira<{ fields: { status: { name: string } } }>(c, `/issue/${d.externalRef!.key}?fields=status`);
        d.set({ 'externalRef.status': i.fields.status.name, 'externalRef.syncedAt': new Date() });
        await d.save();
      } catch (err) {
        logger.warn({ key: d.externalRef?.key, err: (err as Error).message }, 'Jira sync failed');
      }
    }
  }
}