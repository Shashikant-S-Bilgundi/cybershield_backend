import { config } from '../config.js';
import { ApiError } from '../lib/errors.js';
import { scrubText } from '../lib/scrub.js';
import { z } from '../lib/validate.js';
import { Alert } from '../models/Alert.js';
import { Application } from '../models/Application.js';
import { Finding } from '../models/Finding.js';
import { Incident } from '../models/Ops.js';
import { ErrorGroup } from '../models/Telemetry.js';
import { getSettingsDoc } from './settings.js';

type Field = { label: string; value: string };

/**
 * Everything sent to the AI provider goes through this: emails, tokens, keys and long hex are removed
 * (scrubText), IPv4 addresses keep only their network, and IPv6 addresses only their first blocks.
 */
export function maskForAi(text: string, max = 1500): string {
  return scrubText(String(text ?? ''), max)
    .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b/g, '$1.x')
    .replace(/\b([0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}):[0-9a-f:]+\b/gi, '$1:…');
}

const appName = async (id: unknown) => (await Application.findById(id, { name: 1 }).lean())?.name ?? 'an application';

/** Builds the evidence for a question from ShieldOps' own data. People's names are never included. */
async function contextFields(context: { type: string; id: string } | null): Promise<{ title: string | null; fields: Field[] }> {
  if (!context) {
    const open = await Finding.find({ status: { $nin: ['resolved', 'verified', 'accepted_risk', 'false_positive'] } }).sort({ riskScore: -1 }).limit(8).lean();
    const byPri = ['P1', 'P2', 'P3', 'P4'].map((p) => `${p}: ${open.filter((f) => f.priority === p).length}`).join(', ');
    const incidents = await Incident.countDocuments({ status: { $in: ['new', 'acknowledged', 'investigating', 'remediating', 'reopened'] } });
    return {
      title: null,
      fields: [
        { label: 'Open findings (top by risk)', value: open.map((f) => `${f.priority} ${f.title}`).join('; ') || 'none' },
        { label: 'Open findings by priority (top 8 shown)', value: byPri },
        { label: 'Active incidents', value: String(incidents) },
      ],
    };
  }
  if (context.type === 'finding') {
    const f = await Finding.findById(context.id).lean();
    if (!f) throw new ApiError(404, 'NOT_FOUND', 'Finding not found.');
    const code = f.code as Record<string, unknown> | undefined;
    return {
      title: f.title,
      fields: [
        { label: 'Finding', value: f.title },
        { label: 'Severity and priority', value: `${f.severity}, ${f.priority} (risk score ${f.riskScore}${f.knownExploited ? ', known exploited' : ''})` },
        { label: 'Application', value: await appName(f.applicationId) },
        { label: 'Source', value: f.source },
        ...f.evidence.map((e) => ({ label: e.label ?? '', value: e.value ?? '' })),
        { label: 'Description', value: f.description },
        ...(code?.kind === 'vuln' ? [{ label: 'Package', value: `${code.package} ${code.installed} (${code.ecosystem}), fixed in ${code.fixedIn ?? 'no fixed version yet'}` }] : []),
        ...(code?.kind === 'secret' ? [{ label: 'Secret', value: `${code.rule} in ${code.file}:${code.line}, ${code.inCurrentCode ? 'still in the current code' : 'only in git history'} (value masked)` }] : []),
      ],
    };
  }
  if (context.type === 'incident') {
    const i = await Incident.findById(context.id).lean();
    if (!i) throw new ApiError(404, 'NOT_FOUND', 'Incident not found.');
    return {
      title: `${i.ref} ${i.title}`,
      fields: [
        { label: 'Incident', value: `${i.ref}: ${i.title}` },
        { label: 'Severity and status', value: `${i.severity}, ${i.status}` },
        { label: 'Summary', value: i.summary || '(none yet)' },
        { label: 'Root cause so far', value: i.rootCause || '(not recorded)' },
        { label: 'Linked evidence', value: i.linked.map((l) => `${l.type}: ${l.title}`).join('; ') || 'none' },
        // Timeline text without the names of the people who wrote it.
        { label: 'Recent timeline', value: i.timeline.slice(0, 12).map((t) => `${t.at?.toISOString().slice(0, 16)} ${t.text}`).join(' | ') },
      ],
    };
  }
  if (context.type === 'error_group') {
    const g = await ErrorGroup.findById(context.id).lean();
    if (!g) throw new ApiError(404, 'NOT_FOUND', 'Error group not found.');
    return {
      title: `${g.type}: ${g.message}`.slice(0, 120),
      fields: [
        { label: 'Error', value: `${g.type}: ${g.message}` },
        { label: 'Where', value: g.culprit },
        { label: 'Frequency', value: `${g.count} events, ${g.usersAffected} users affected, first seen ${g.firstSeen.toISOString().slice(0, 10)}, status ${g.status}` },
        { label: 'Release', value: g.lastRelease || 'not reported' },
        { label: 'Stack (your code first)', value: [...g.stack].sort((a, b) => Number(b.inApp) - Number(a.inApp)).slice(0, 8).map((s) => `${s.fn} (${s.file}:${s.line})${s.code ? ` → ${s.code}` : ''}`).join('\n') },
      ],
    };
  }
  const a = await Alert.findById(context.id).lean();
  if (!a) throw new ApiError(404, 'NOT_FOUND', 'Alert not found.');
  return {
    title: a.title,
    fields: [
      { label: 'Alert', value: a.title },
      { label: 'Severity and source', value: `${a.severity}, ${a.source}, ${a.occurrences} occurrence(s), ${a.status}` },
      { label: 'Application', value: await appName(a.applicationId) },
      { label: 'Detail', value: a.message },
    ],
  };
}

const SYSTEM = `You are the security analyst inside ShieldOps, an in-house monitoring console for a small IT team.
Answer only from the evidence provided. If the evidence is not enough, say what to check instead of guessing.
Be concrete: name files, settings, commands and versions from the evidence. Use plain English, short sentences.
Reply with JSON only, no markdown fences:
{"summary": "two or three sentences", "sections": [{"title": "short heading", "bullets": ["..."]}], "suggestedTasks": ["imperative task titles, at most 4"]}
Use 2 to 4 sections, such as "Why it matters", "How to fix it", "How to confirm the fix".`;

const answerShape = z.object({
  summary: z.string().max(4000),
  sections: z.array(z.object({ title: z.string().max(200), bullets: z.array(z.string().max(1500)).max(12) })).max(8).default([]),
  suggestedTasks: z.array(z.string().max(200)).max(6).default([]),
});

async function callProvider(provider: string, model: string, user: string): Promise<string> {
  const post = async (url: string, headers: Record<string, string>, body: object) => {
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(60_000) }).catch((e: Error) => {
      throw new ApiError(502, 'AI_PROVIDER_UNREACHABLE', `Could not reach the AI provider: ${e.name === 'TimeoutError' ? 'it took longer than 60 seconds' : e.message}`);
    });
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      const msg = ((data.error as { message?: string })?.message ?? JSON.stringify(data).slice(0, 200)).replace(/sk-[\w-]{10,}/g, '***');
      throw new ApiError(502, 'AI_PROVIDER_ERROR', `The AI provider answered ${res.status}: ${msg}`);
    }
    return data;
  };
  if (provider === 'anthropic') {
    if (!config.ANTHROPIC_API_KEY) throw new ApiError(409, 'AI_NOT_CONFIGURED', 'Set ANTHROPIC_API_KEY on the ShieldOps server, then restart it.');
    const d = await post(`${config.ANTHROPIC_BASE_URL.replace(/\/$/, '')}/v1/messages`, { 'x-api-key': config.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' }, { model, max_tokens: 1500, system: SYSTEM, messages: [{ role: 'user', content: user }] });
    return ((d.content as { type: string; text?: string }[]) ?? []).filter((c) => c.type === 'text').map((c) => c.text).join('');
  }
  const messages = [{ role: 'system', content: SYSTEM }, { role: 'user', content: user }];
  if (provider === 'azure_openai') {
    if (!config.AZURE_OPENAI_ENDPOINT || !config.AZURE_OPENAI_API_KEY) throw new ApiError(409, 'AI_NOT_CONFIGURED', 'Set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY on the ShieldOps server, then restart it. The model name in System settings is your deployment name.');
    const d = await post(`${config.AZURE_OPENAI_ENDPOINT.replace(/\/$/, '')}/openai/deployments/${encodeURIComponent(model)}/chat/completions?api-version=${config.AZURE_OPENAI_API_VERSION}`, { 'api-key': config.AZURE_OPENAI_API_KEY }, { messages, temperature: 0.2, max_tokens: 1500, response_format: { type: 'json_object' } });
    return (d.choices as { message: { content: string } }[])?.[0]?.message?.content ?? '';
  }
  if (!config.OPENAI_API_KEY) throw new ApiError(409, 'AI_NOT_CONFIGURED', 'Set OPENAI_API_KEY on the ShieldOps server, then restart it.');
  const d = await post(`${config.OPENAI_BASE_URL.replace(/\/$/, '')}/v1/chat/completions`, { authorization: `Bearer ${config.OPENAI_API_KEY}` }, { model, messages, temperature: 0.2, max_tokens: 1500, response_format: { type: 'json_object' } });
  return (d.choices as { message: { content: string } }[])?.[0]?.message?.content ?? '';
}

/** Reads the model's JSON; if it is not valid, the text becomes the summary rather than failing the request. */
export function parseAnswer(text: string) {
  const json = text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1);
  try {
    return answerShape.parse(JSON.parse(json));
  } catch {
    return { summary: text.trim().slice(0, 4000) || 'The AI provider returned an empty answer.', sections: [], suggestedTasks: [] };
  }
}

const PROVIDER_NAME: Record<string, string> = { openai: 'OpenAI', anthropic: 'Anthropic', azure_openai: 'Azure OpenAI' };

export async function askAi(question: string, context: { type: string; id: string } | null) {
  const { ai } = await getSettingsDoc();
  if (!ai?.enabled) throw new ApiError(503, 'AI_DISABLED', 'The AI assistant is turned off in System settings. Everything else keeps working.');
  if (!ai.shareApproved) throw new ApiError(409, 'AI_NOT_APPROVED', 'Approve sending masked evidence to the AI provider in System settings first.');
  const { title, fields } = await contextFields(context);
  const sent = fields.map((f) => ({ label: f.label, value: maskForAi(f.value) })).filter((f) => f.value);
  const q = maskForAi(question.trim() || (context ? 'Explain this and how to fix it.' : 'What should we fix first?'), 1000);
  const prompt = `Question: ${q}\n\nEvidence from ShieldOps:\n${sent.map((f) => `- ${f.label}: ${f.value}`).join('\n')}`;
  const answer = parseAnswer(await callProvider(ai.provider!, ai.model!, prompt));
  return { contextTitle: title, sent: [{ label: 'Question', value: q }, ...sent], ...answer, model: `${PROVIDER_NAME[ai.provider!] ?? ai.provider} ${ai.model}` };
}