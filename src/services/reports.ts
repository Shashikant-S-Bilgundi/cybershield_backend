import PDFDocument from 'pdfkit';
import type { Types } from 'mongoose';
import { config } from '../config.js';
import { nextCronRun } from '../lib/cron.js';
import { logger } from '../lib/logger.js';
import { Application } from '../models/Application.js';
import { Certificate, DomainExpiry } from '../models/AssetChecks.js';
import { Finding } from '../models/Finding.js';
import { Server } from '../models/Infra.js';
import { Report, ReportSchedule, type ReportDoc } from '../models/Intel.js';
import { Monitor } from '../models/Monitor.js';
import { Incident, RemediationTask } from '../models/Ops.js';
import { ErrorGroup } from '../models/Telemetry.js';
import { User } from '../models/User.js';
import { inBackground } from './background.js';
import { compliance, frameworks, type FrameworkId } from './compliance.js';
import { appHealth } from './health.js';
import { sendMail } from './mailer.js';
import { recommendations } from './recommendations.js';
import { getSettingsDoc } from './settings.js';

export type ReportType = 'posture' | 'health' | 'vulnerabilities' | 'ssl_domains' | 'incidents' | 'compliance';
interface Section {
  title: string;
  summary?: string;
  metrics?: { label: string; value: string; tone?: 'good' | 'warn' | 'bad' }[];
  table?: { columns: string[]; rows: string[][] };
  bullets?: string[];
}

export const TYPE_TITLE: Record<ReportType, string> = {
  posture: 'Security posture',
  health: 'Application health',
  vulnerabilities: 'Vulnerabilities and secrets',
  ssl_domains: 'Certificates and domains',
  incidents: 'Incidents and remediation',
  compliance: 'Compliance readiness',
};

const DAY = 86_400_000;
const d10 = (d: Date | string | null | undefined) => (d ? new Date(d).toISOString().slice(0, 10) : '-');
const tone = (bad: boolean) => (bad ? 'bad' : 'good') as 'bad' | 'good';

/** The report's content, from live data at generation time. Empty tables are left out. */
export async function buildSections(type: ReportType, from: Date, to: Date, applicationId: Types.ObjectId | null): Promise<Section[]> {
  const scope = applicationId ? { applicationId } : {};
  const apps = await Application.find({ deletedAt: null, status: 'active', ...(applicationId ? { _id: applicationId } : {}) });
  const name = new Map(apps.map((a) => [a.id, a.name]));
  const appName = (id: unknown) => name.get(String(id)) ?? 'another application';
  const active = await Finding.find({ ...scope, status: { $nin: ['resolved', 'verified', 'accepted_risk', 'false_positive'] } }).sort({ riskScore: -1 }).lean();
  const incidents = await Incident.find({ ...(applicationId ? { applicationIds: applicationId } : {}), openedAt: { $gte: from, $lte: to } }).sort({ openedAt: -1 }).lean();
  const openTasks = await RemediationTask.find({ ...scope, status: { $in: ['todo', 'in_progress', 'ready_for_verification'] } }).lean();
  const overdue = openTasks.filter((t) => t.dueAt && t.dueAt.getTime() < Date.now());
  const users = new Map((await User.find({}, { name: 1 }).lean()).map((u) => [String(u._id), u.name]));

  if (type === 'posture') {
    const health = await Promise.all(apps.map(appHealth));
    const recs = (await recommendations(applicationId ? { applicationId: String(applicationId) } : {})).filter((r) => !r.dismissed).slice(0, 5);
    return [
      {
        title: 'At a glance',
        summary: 'Current state when the report was generated.',
        metrics: [
          { label: 'Applications down', value: String(health.filter((h) => h.state === 'down').length), tone: tone(health.some((h) => h.state === 'down')) },
          { label: 'Open P1 findings', value: String(active.filter((f) => f.priority === 'P1').length), tone: tone(active.some((f) => f.priority === 'P1')) },
          { label: 'Open findings', value: String(active.length) },
          { label: 'Incidents in period', value: String(incidents.length) },
          { label: 'Tasks past SLA', value: String(overdue.length), tone: tone(overdue.length > 0) },
        ],
      },
      { title: 'Highest risks', table: { columns: ['Priority', 'Finding', 'Application', 'Due'], rows: active.slice(0, 10).map((f) => [f.priority, f.title, appName(f.applicationId), d10(f.dueAt)]) } },
      { title: 'Recommended next steps', bullets: recs.map((r) => `${r.title}: ${r.why}`) },
    ].filter(keep);
  }
  if (type === 'health') {
    const rows = await Promise.all(apps.map(async (a) => {
      const h = await appHealth(a);
      const monitors = await Monitor.countDocuments({ applicationId: a._id, deletedAt: null });
      const errors = await ErrorGroup.countDocuments({ applicationId: a._id, status: { $in: ['unresolved', 'regressed'] } });
      return [a.name, h.state, h.uptime30d === null ? '-' : `${h.uptime30d}%`, String(monitors), String(errors)];
    }));
    const downs = (await Monitor.find({ ...scope, deletedAt: null }).lean()).flatMap((m) => m.events.filter((e) => e.to === 'down' && e.at && e.at >= from && e.at <= to).map((e) => `${d10(e.at)} ${m.name}: ${e.reason}`)).slice(0, 25);
    const servers = await Server.find(scope).lean();
    return [
      { title: 'Production health', table: { columns: ['Application', 'Now', 'Uptime 30d', 'Monitors', 'Errors to fix'], rows } },
      { title: 'Downtime in the period', bullets: downs.length ? downs : ['No monitor went down in this period.'] },
      { title: 'Servers', table: { columns: ['Server', 'Application', 'Status', 'CPU', 'Memory', 'Disk'], rows: servers.map((s) => [s.hostname, appName(s.applicationId), s.status === 'online' ? 'online' : 'not reporting', s.usage ? `${s.usage.cpu}%` : '-', s.usage ? `${s.usage.memory}%` : '-', s.usage ? `${s.usage.disk}%` : '-']) } },
    ].filter(keep);
  }
  if (type === 'vulnerabilities') {
    const v = active.filter((f) => (f.code as { kind?: string } | undefined)?.kind === 'vuln');
    const sec = active.filter((f) => (f.code as { kind?: string } | undefined)?.kind === 'secret');
    return [
      { title: 'Summary', metrics: [{ label: 'Open vulnerabilities', value: String(v.length) }, { label: 'Known exploited', value: String(v.filter((x) => x.knownExploited).length), tone: tone(v.some((x) => x.knownExploited)) }, { label: 'Exposed secrets', value: String(sec.length), tone: tone(sec.length > 0) }] },
      { title: 'Vulnerabilities', table: { columns: ['Priority', 'ID', 'Package', 'Fixed in', 'Where'], rows: v.map((x) => { const c = x.code as Record<string, string>; return [x.priority, c.vulnId, `${c.package} ${c.installed}`, c.fixedIn ?? '-', c.targetName]; }) } },
      { title: 'Exposed secrets (values masked)', table: { columns: ['Priority', 'Type', 'Value', 'Where'], rows: sec.map((x) => { const c = x.code as Record<string, string>; return [x.priority, c.rule, c.masked, `${c.file}:${c.line}`]; }) } },
    ].filter(keep);
  }
  if (type === 'ssl_domains') {
    const certs = await Certificate.find(scope).lean();
    const domains = await DomainExpiry.find(scope).lean();
    return [
      { title: 'Certificates', table: { columns: ['Host', 'Expires', 'Days left', 'Issuer', 'Protocol'], rows: certs.map((c) => [c.host ?? '', d10(c.validTo), c.validTo ? String(Math.ceil((c.validTo.getTime() - Date.now()) / DAY)) : '-', c.issuer ?? '-', c.protocol ?? (c.error ? 'unreachable' : '-')]) } },
      { title: 'Domains', table: { columns: ['Domain', 'Expires', 'Registrar'], rows: domains.map((d) => [d.domain ?? '', d.expiresAt ? d10(d.expiresAt) : 'not published', d.registrar ?? '-']) } },
    ].filter(keep);
  }
  if (type === 'incidents') {
    return [
      { title: 'Summary', metrics: [{ label: 'Incidents', value: String(incidents.length) }, { label: 'Critical', value: String(incidents.filter((i) => i.severity === 'critical').length) }, { label: 'Open tasks', value: String(openTasks.length) }, { label: 'Tasks past SLA', value: String(overdue.length), tone: tone(overdue.length > 0) }] },
      { title: 'Incidents', table: { columns: ['Ref', 'Title', 'Severity', 'Status', 'Opened'], rows: incidents.map((i) => [i.ref, i.title, i.severity, i.status, d10(i.openedAt)]) } },
      { title: 'Tasks past their SLA', table: { columns: ['Task', 'Due', 'Owner'], rows: overdue.map((t) => [t.title, d10(t.dueAt), t.ownerId ? users.get(String(t.ownerId)) ?? '-' : 'nobody']) } },
    ].filter(keep);
  }
  const enabled = (await frameworks()).filter((f) => f.enabled);
  const out: Section[] = [];
  for (const fw of enabled) {
    const c = await compliance(fw.id as FrameworkId);
    out.push({ title: `${c.framework.name} (${c.framework.version}): ${c.score}% ready`, summary: 'Readiness signals from ShieldOps data, not a certification or audit opinion.', table: { columns: ['Control', 'Status', 'Gaps'], rows: c.controls.map((x) => [`${x.code} ${x.title}`, x.attestation ? `${x.attestation.status.replace('_', ' ')} (attested)` : x.status.replace('_', ' '), x.gaps.join(' ') || '-']) } });
  }
  return out.length ? out : [{ title: 'No frameworks turned on', bullets: ['Turn on a framework on the Compliance page to include it here.'] }];
}

const keep = (s: Section) => !s.table || s.table.rows.length > 0 || !!s.bullets?.length;

/* ───────────── PDF ───────────── */

// The built-in PDF fonts cover Western European characters only; anything else is replaced.
const latin = (s: string) => String(s ?? '').replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/[–—]/g, '-').replace(/•/g, '*').replace(/→/g, '->').replace(/…/g, '...').replace(/[^\x09\x0a\x0d\x20-\x7e\xa0-\xff]/g, '?');

const TEAL = '#0f766e';
const MUTED = '#64748b';
const TONE = { good: '#15803d', warn: '#b45309', bad: '#b91c1c' } as const;

/** A real, multi-page PDF: header, metric tiles, wrapped tables that continue on new pages, page numbers. */
export function renderPdf(r: { title: string; from: Date; to: Date; generatedAt: Date; sections: Section[] }, scopeLabel: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 48, bufferPages: true, info: { Title: latin(r.title), Creator: 'ShieldOps' } });
    const chunks: Buffer[] = [];
    doc.on('data', (c: Buffer) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    const left = doc.page.margins.left;
    const width = doc.page.width - left - doc.page.margins.right;
    const bottom = () => doc.page.height - doc.page.margins.bottom - 20;
    const ensure = (h: number) => {
      if (doc.y + h > bottom()) doc.addPage();
    };

    doc.font('Helvetica-Bold').fontSize(9).fillColor(TEAL).text('SHIELDOPS', left, 48);
    doc.font('Helvetica-Bold').fontSize(20).fillColor('#0f172a').text(latin(r.title), left, 64, { width });
    doc.font('Helvetica').fontSize(10).fillColor(MUTED).text(latin(`${scopeLabel} | ${d10(r.from)} to ${d10(r.to)} | generated ${r.generatedAt.toISOString().slice(0, 16).replace('T', ' ')} UTC`), { width });
    doc.moveDown(1.2);

    for (const s of r.sections) {
      ensure(60);
      doc.font('Helvetica-Bold').fontSize(13).fillColor('#0f172a').text(latin(s.title), left, doc.y, { width });
      if (s.summary) doc.font('Helvetica').fontSize(9).fillColor(MUTED).text(latin(s.summary), { width });
      doc.moveDown(0.5);
      if (s.metrics?.length) {
        const n = Math.min(s.metrics.length, 5);
        const w = (width - (n - 1) * 8) / n;
        let x = left;
        ensure(52);
        const y = doc.y;
        s.metrics.slice(0, 5).forEach((m) => {
          doc.roundedRect(x, y, w, 46, 4).lineWidth(0.6).strokeColor('#cbd5e1').stroke();
          doc.font('Helvetica').fontSize(8).fillColor(MUTED).text(latin(m.label), x + 8, y + 7, { width: w - 16, lineBreak: false, ellipsis: true });
          doc.font('Helvetica-Bold').fontSize(16).fillColor(m.tone ? TONE[m.tone] : '#0f172a').text(latin(m.value), x + 8, y + 20, { width: w - 16, lineBreak: false });
          x += w + 8;
        });
        doc.y = y + 56;
        doc.x = left;
      }
      if (s.table?.rows.length) {
        const cols = s.table.columns.length;
        // Short values (dates, statuses, numbers) get narrow columns; descriptive text gets the room.
        const NARROW = /^(priority|now|days left|status|severity|cpu|memory|disk|monitors|ref|due|expires|opened|uptime 30d|errors to fix|fixed in|protocol|value|type)$/i;
        const WIDE = /^(finding|title|task|gaps|control|where|package|issuer|registrar)$/i;
        const weights = s.table.columns.map((c) => (NARROW.test(c) ? 0.7 : WIDE.test(c) ? 2.4 : 1.2));
        void cols;
        const total = weights.reduce((a, b) => a + b, 0);
        const widths = weights.map((wt) => (wt / total) * width);
        const drawRow = (cells: string[], header: boolean) => {
          doc.font(header ? 'Helvetica-Bold' : 'Helvetica').fontSize(8.5);
          const h = Math.max(...cells.map((c, i) => doc.heightOfString(latin(c), { width: widths[i] - 8 }))) + 8;
          if (doc.y + h > bottom()) {
            doc.addPage();
            if (!header) drawRow(s.table!.columns, true);
          }
          const y = doc.y;
          if (header) doc.rect(left, y, width, h).fill('#f1f5f9');
          let x = left;
          cells.forEach((c, i) => {
            doc.fillColor(header ? '#334155' : '#0f172a').text(latin(c), x + 4, y + 4, { width: widths[i] - 8 });
            x += widths[i];
          });
          doc.moveTo(left, y + h).lineTo(left + width, y + h).lineWidth(0.4).strokeColor('#e2e8f0').stroke();
          doc.y = y + h;
        };
        drawRow(s.table.columns, true);
        s.table.rows.forEach((row) => drawRow(row, false));
        doc.x = left;
        doc.moveDown(0.8);
      }
      if (s.bullets?.length) {
        doc.font('Helvetica').fontSize(9.5).fillColor('#0f172a');
        s.bullets.forEach((b) => {
          ensure(18);
          doc.text(latin(`-  ${b}`), left + 4, doc.y, { width: width - 4 });
          doc.moveDown(0.25);
        });
        doc.moveDown(0.6);
      }
      doc.moveDown(0.4);
    }

    const range = doc.bufferedPageRange();
    for (let i = 0; i < range.count; i++) {
      doc.switchToPage(i);
      doc.font('Helvetica').fontSize(8).fillColor(MUTED).text(`ShieldOps | ${latin(r.title)} | page ${i + 1} of ${range.count}`, left, doc.page.height - 36, { width, align: 'center', lineBreak: false });
    }
    doc.end();
  });
}

/* ───────────── generating ───────────── */

async function scopeLabel(applicationId: Types.ObjectId | null | undefined) {
  return applicationId ? (await Application.findById(applicationId, { name: 1 }).lean())?.name ?? 'Application' : 'All applications';
}

/** Builds the sections and the PDF. Runs in the background; the report shows "generating" until then. */
export async function produce(r: ReportDoc) {
  try {
    r.sections = await buildSections(r.type as ReportType, r.from, r.to, r.applicationId as Types.ObjectId | null);
    r.generatedAt = new Date();
    const pdf = await renderPdf({ title: r.title, from: r.from, to: r.to, generatedAt: r.generatedAt, sections: r.sections as Section[] }, await scopeLabel(r.applicationId as Types.ObjectId | null));
    r.pdf = pdf;
    r.sizeKb = Math.max(1, Math.round(pdf.length / 1024));
    r.status = 'ready';
  } catch (err) {
    logger.error({ err, report: r.id }, 'Report generation failed');
    r.status = 'failed';
    r.error = (err as Error).message;
  }
  await r.save();
  return r;
}

export async function createReport(input: { type: ReportType; from: Date; to: Date; applicationId: Types.ObjectId | string | null }, by: Types.ObjectId | null, background = true) {
  const title = `${TYPE_TITLE[input.type]}: ${await scopeLabel(input.applicationId as Types.ObjectId | null)}`;
  const r = await Report.create({ ...input, title, generatedBy: by });
  if (background) inBackground(produce(r), `report ${r.id}`);
  else await produce(r);
  return r;
}

/* ───────────── schedules ───────────── */

/** Weekly: Mondays 09:00. Monthly: the 1st at 09:00. In the time zone from System settings. */
export async function nextRunAfter(frequency: 'weekly' | 'monthly', from = new Date()) {
  const tz = (await getSettingsDoc()).timezone ?? 'Asia/Kolkata';
  return nextCronRun(frequency === 'weekly' ? '0 9 * * 1' : '0 9 1 * *', from, tz);
}

/** Generates due scheduled reports for the period just ended and emails the PDF. Run by the scheduler. */
export async function runDueSchedules() {
  const due = await ReportSchedule.find({ nextRunAt: { $lte: new Date() } });
  for (const s of due) {
    const to = new Date();
    const from = new Date(to.getTime() - (s.frequency === 'weekly' ? 7 : 30) * DAY);
    // Move the schedule on first, so a failure does not send the same report every minute.
    s.nextRunAt = await nextRunAfter(s.frequency as 'weekly' | 'monthly', to);
    await s.save();
    const r = await createReport({ type: s.type as ReportType, from, to, applicationId: s.applicationId ?? null }, null, false);
    if (r.status !== 'ready') continue;
    const full = await Report.findById(r._id).select('+pdf');
    const sent = await sendMail(
      s.recipients,
      `[ShieldOps] ${r.title}, ${d10(from)} to ${d10(to)}`,
      `Your ${s.frequency} ShieldOps report is attached.\n\nOpen it in ShieldOps: ${config.appUrl}/reports/${r.id}\n\nThis report was scheduled in ShieldOps; change or stop it on the Reports page.`,
      [{ filename: `shieldops-${r.type}-${d10(to)}.pdf`, content: full!.pdf!, contentType: 'application/pdf' }],
    );
    logger.info({ schedule: s.id, report: r.id, sent }, 'Scheduled report');
  }
}