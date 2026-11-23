import { Alert } from '../models/Alert.js';
import { Application } from '../models/Application.js';
import { Repository, ScanJob, ContainerImage } from '../models/Code.js';
import { Finding } from '../models/Finding.js';
import { Server } from '../models/Infra.js';
import { Attestation, FrameworkState } from '../models/Intel.js';
import { Monitor } from '../models/Monitor.js';
import { Incident, RemediationTask } from '../models/Ops.js';
import { Detection } from '../models/Telemetry.js';
import { User } from '../models/User.js';
import { getSettingsDoc } from './settings.js';

export type FrameworkId = 'iso27001' | 'soc2' | 'certin' | 'dpdp';
type Status = 'met' | 'partial' | 'not_met' | 'manual';
interface Eval {
  status: Status;
  evidence: string[];
  gaps: string[];
  links: { label: string; to: string }[];
}

export const FRAMEWORKS = [
  { id: 'iso27001', name: 'ISO/IEC 27001', version: '2022, Annex A', description: 'International standard for information security management. Shows the Annex A controls ShieldOps has evidence for.' },
  { id: 'soc2', name: 'SOC 2', version: 'Trust Services Criteria (Security)', description: 'US audit framework. Shows the common criteria for monitoring, incidents and access.' },
  { id: 'certin', name: 'CERT-In Directions', version: '28 April 2022', description: 'Indian Computer Emergency Response Team directions on incident reporting, logs and time sync.' },
  { id: 'dpdp', name: 'DPDP Act', version: '2023', description: 'India’s Digital Personal Data Protection Act: security safeguards and breach notification.' },
] as const;
const DEFAULT_ON: Record<FrameworkId, boolean> = { iso27001: true, soc2: false, certin: true, dpdp: false };

export async function frameworks() {
  const states = new Map((await FrameworkState.find().lean()).map((s) => [s._id, s.enabled]));
  return FRAMEWORKS.map((f) => ({ ...f, enabled: states.get(f.id) ?? DEFAULT_ON[f.id] }));
}

const DAY = 86_400_000;
const ev = (status: Status, evidence: string[], gaps: string[], links: Eval['links'] = []): Eval => ({ status, evidence: evidence.filter(Boolean), gaps, links });
const manual = (evidence: string[]): Eval => ({ status: 'manual', evidence, gaps: [], links: [] });

/** Gathers the live facts every control reads, once per request. */
async function facts() {
  const s = await getSettingsDoc();
  const active = await Finding.find({ status: { $nin: ['resolved', 'verified', 'accepted_risk', 'false_positive'] } }).lean();
  const apps = await Application.find({ deletedAt: null, status: 'active' }).lean();
  const monitored = new Set((await Monitor.find({ deletedAt: null }, { applicationId: 1 }).lean()).map((m) => String(m.applicationId)));
  const repos = await Repository.find({}, { _id: 1, fullName: 1 }).lean();
  const recentScans = new Set((await ScanJob.find({ targetType: 'repository', status: 'completed', queuedAt: { $gte: new Date(Date.now() - 7 * DAY) } }, { targetId: 1 }).lean()).map((j) => String(j.targetId)));
  const acked = await Alert.find({ acknowledgedAt: { $ne: null } }, { firstAt: 1, acknowledgedAt: 1 }).lean();
  const incidents = await Incident.find({}, { ref: 1, status: 1, severity: 1, ownerId: 1, postIncident: 1 }).lean();
  const overdueTasks = await RemediationTask.find({ status: { $in: ['todo', 'in_progress', 'ready_for_verification'] }, dueAt: { $lt: new Date() } }, { linkedId: 1, linkedType: 1 }).lean();
  const vulnIds = new Set(active.filter((f) => f.source === 'vulnerabilities').map((f) => String(f._id)));
  return {
    retention: s.retention!,
    users: await User.countDocuments({ status: 'active' }),
    vulns: active.filter((f) => f.source === 'vulnerabilities' && f.key.startsWith('vuln:')),
    kev: active.filter((f) => f.knownExploited),
    secretsLive: active.filter((f) => (f.code as { kind?: string; inCurrentCode?: boolean } | undefined)?.inCurrentCode),
    secretsAll: active.filter((f) => f.source === 'secrets'),
    headerGaps: active.filter((f) => f.source === 'headers' || f.source === 'dns'),
    weakTls: active.filter((f) => f.source === 'ssl'),
    p1: active.filter((f) => f.priority === 'P1'),
    unmonitored: apps.filter((a) => !monitored.has(String(a._id))),
    offline: await Server.find({ status: 'offline' }, { hostname: 1 }).lean(),
    monitors: await Monitor.countDocuments({ deletedAt: null }),
    servers: await Server.countDocuments(),
    detections: await Detection.countDocuments({ lastAt: { $gte: new Date(Date.now() - DAY) } }),
    repos,
    images: await ContainerImage.countDocuments(),
    recentlyScanned: repos.filter((r) => recentScans.has(String(r._id))).length,
    alerts: await Alert.countDocuments(),
    mtta: acked.length ? Math.round(acked.reduce((n, a) => n + (a.acknowledgedAt!.getTime() - a.firstAt.getTime()), 0) / acked.length / 60_000) : null,
    incidents,
    noOwner: incidents.filter((i) => ['new', 'acknowledged', 'investigating', 'remediating', 'reopened'].includes(i.status) && !i.ownerId),
    closedCritical: incidents.filter((i) => i.status === 'closed' && i.severity === 'critical'),
    overdueVulnTasks: overdueTasks.filter((t) => vulnIds.has(String(t.linkedId))),
  };
}

type Facts = Awaited<ReturnType<typeof facts>>;
interface ControlDef {
  id: string;
  code: string;
  title: string;
  check: (f: Facts) => Eval;
}

const vulnMgmt = (f: Facts) =>
  ev(f.kev.length || f.overdueVulnTasks.length ? 'partial' : f.repos.length || f.images ? 'met' : 'partial',
    [`${f.repos.length} repositories and ${f.images} images scanned with OSV-Scanner and Trivy; ${f.recentlyScanned} repositories completed a scan in the last 7 days.`, `${f.vulns.length} open vulnerability findings, each with an SLA due date.`],
    [...(f.repos.length || f.images ? [] : ['No repositories or images are being scanned yet.']), ...(f.kev.length ? [`${f.kev.length} known-exploited vulnerabilit${f.kev.length > 1 ? 'ies' : 'y'} still open.`] : []), ...(f.overdueVulnTasks.length ? [`${f.overdueVulnTasks.length} vulnerability task(s) past their SLA.`] : [])],
    [{ label: 'Vulnerabilities', to: '/vulnerabilities' }]);
const monitoring = (f: Facts) =>
  ev(f.unmonitored.length || f.offline.length || !f.monitors ? 'partial' : 'met',
    [`${f.monitors} uptime monitors, ${f.servers} servers with the agent, ${f.detections} security detections in the last 24 hours.`],
    [...f.unmonitored.map((a) => `${a.name} has no uptime monitor.`), ...f.offline.map((s) => `${s.hostname} has stopped reporting.`)],
    [{ label: 'Servers', to: '/servers' }]);
const incidentResponse = (f: Facts) =>
  ev(f.noOwner.length ? 'partial' : 'met',
    [`${f.incidents.length} incident(s) recorded with owners, timelines and linked evidence.`, f.mtta !== null ? `Mean time to acknowledge alerts: ${f.mtta} minutes.` : 'No acknowledged alerts yet.'],
    f.noOwner.map((i) => `${i.ref} has no owner.`), [{ label: 'Incidents', to: '/incidents' }]);
const logging = (f: Facts, needDays: number) => {
  const short = [f.retention.auditLogsDays < needDays && `Audit logs kept ${f.retention.auditLogsDays} days`, f.retention.securityEventsDays < needDays && `Security events kept ${f.retention.securityEventsDays} days`].filter(Boolean) as string[];
  return ev(short.length === 0 ? 'met' : short.length === 2 ? 'not_met' : 'partial', [`Audit logs: ${f.retention.auditLogsDays} days, append-only. Security events: ${f.retention.securityEventsDays} days.`], short.map((x) => `${x}; needs ${needDays}.`), [{ label: 'Retention settings', to: '/settings' }]);
};

const CONTROLS: Record<FrameworkId, ControlDef[]> = {
  iso27001: [
    { id: '5.7', code: 'A.5.7', title: 'Threat intelligence', check: (f) => ev(f.recentlyScanned ? 'met' : 'partial', ['Vulnerability data from OSV and Trivy, with the CISA known-exploited list used in risk scoring.'], f.recentlyScanned ? [] : ['No repository completed a scan in the last 7 days.']) },
    { id: '5.17', code: 'A.5.17', title: 'Authentication information', check: (f) => ev(f.secretsLive.length ? 'not_met' : f.secretsAll.length ? 'partial' : 'met', ['Gitleaks scans every repository and its history for committed credentials.'], [...f.secretsLive.map((x) => `${x.title} is still in the current code.`), ...(f.secretsAll.length > f.secretsLive.length ? [`${f.secretsAll.length - f.secretsLive.length} secret(s) only in history, not yet rotated.`] : [])], [{ label: 'Secrets', to: '/secrets' }]) },
    { id: '5.24', code: 'A.5.24 / 5.26', title: 'Incident management and response', check: incidentResponse },
    { id: '5.27', code: 'A.5.27', title: 'Learning from incidents', check: (f) => ev(f.closedCritical.every((i) => i.postIncident) ? 'met' : 'partial', [`${f.closedCritical.length} closed critical incident(s); ShieldOps requires a post-incident summary before closing them.`], f.closedCritical.filter((i) => !i.postIncident).map((i) => `${i.ref} has no summary.`)) },
    { id: '8.5', code: 'A.8.5', title: 'Secure authentication', check: (f) => ev('partial', [`${f.users} ShieldOps members sign in with a password of at least 12 characters; critical actions ask for the password again.`, 'Brute-force and credential-stuffing detection on applications that send security events.'], ['ShieldOps sign-in uses passwords only. Turn on single sign-on with two-step verification to meet this fully.']) },
    { id: '8.8', code: 'A.8.8', title: 'Management of technical vulnerabilities', check: vulnMgmt },
    { id: '8.9', code: 'A.8.9', title: 'Configuration management', check: (f) => ev(f.headerGaps.length ? 'partial' : 'met', ['Daily checks of security headers and DNS records with change history.'], f.headerGaps.length ? [`${f.headerGaps.length} open header or DNS finding(s).`] : [], [{ label: 'Security headers', to: '/security-headers' }]) },
    // ISO 27001 leaves the period to your own policy, so only a short audit trail is flagged.
    { id: '8.15', code: 'A.8.15', title: 'Logging', check: (f) => ev(f.retention.auditLogsDays >= 365 ? 'met' : 'partial', [`Audit logs: ${f.retention.auditLogsDays} days, append-only. Security events: ${f.retention.securityEventsDays} days.`, 'ISO 27001 does not set a period; your retention policy should state one.'], f.retention.auditLogsDays >= 365 ? [] : [`Audit logs are kept ${f.retention.auditLogsDays} days; auditors usually expect at least a year.`], [{ label: 'Retention settings', to: '/settings' }]) },
    { id: '8.16', code: 'A.8.16', title: 'Monitoring activities', check: monitoring },
    { id: '8.24', code: 'A.8.24', title: 'Use of cryptography', check: (f) => ev(f.weakTls.length ? 'partial' : 'met', ['Certificates, protocols and ciphers checked daily on every site.'], f.weakTls.map((x) => `${x.title}.`), [{ label: 'SSL and DNS', to: '/ssl-dns' }]) },
    { id: '8.32', code: 'A.8.32', title: 'Change management', check: () => manual(['ShieldOps scans on push, but approval of changes happens in your own process.']) },
    { id: '5.30', code: 'A.5.30', title: 'ICT readiness for business continuity', check: () => manual(['Backups, failover and recovery tests are outside what ShieldOps can see.']) },
  ],
  soc2: [
    { id: 'cc6.1', code: 'CC6.1', title: 'Logical access security', check: (f) => ev('partial', ['Invitation-only accounts; re-authentication with the password for critical actions.'], ['ShieldOps sign-in uses passwords only, without a second factor.', ...(f.secretsLive.length ? [`${f.secretsLive.length} credential(s) exposed in code.`] : [])]) },
    { id: 'cc7.1', code: 'CC7.1', title: 'Detect vulnerabilities and configuration changes', check: vulnMgmt },
    { id: 'cc7.2', code: 'CC7.2', title: 'Monitor system components for anomalies', check: monitoring },
    { id: 'cc7.3', code: 'CC7.3', title: 'Evaluate security events', check: (f) => ev(f.mtta !== null && f.mtta <= 60 ? 'met' : 'partial', [`${f.alerts} alerts with acknowledgement tracking.`, f.mtta !== null ? `Mean time to acknowledge: ${f.mtta} minutes.` : ''], f.mtta === null ? ['No alert has been acknowledged yet.'] : f.mtta > 60 ? ['Alerts take more than an hour on average to acknowledge.'] : []) },
    { id: 'cc7.4', code: 'CC7.4', title: 'Respond to security incidents', check: incidentResponse },
    { id: 'cc7.5', code: 'CC7.5', title: 'Recover from incidents', check: () => manual(['Restore tests and recovery plans are outside what ShieldOps can see.']) },
    { id: 'cc8.1', code: 'CC8.1', title: 'Change management', check: () => manual(['Change approval and testing happen in your own process.']) },
  ],
  certin: [
    { id: 'report6h', code: 'Direction (ii)', title: 'Report cyber incidents to CERT-In within 6 hours of noticing them', check: (f) => ev('partial', [`Incidents are timestamped when opened and acknowledged${f.mtta !== null ? `; mean time to acknowledge alerts is ${f.mtta} minutes` : ''}.`], ['Reporting to CERT-In itself is manual. Add the 6-hour deadline to your incident checklist.'], [{ label: 'Incidents', to: '/incidents' }]) },
    { id: 'logs180', code: 'Direction (iv)', title: 'Keep logs of ICT systems for 180 days, within India', check: (f) => { const r = logging(f, 180); return { ...r, gaps: [...r.gaps, 'Confirm the ShieldOps database and its backups are hosted in India.'] }; } },
    { id: 'ntp', code: 'Direction (i)', title: 'Synchronise system clocks with NTP servers of NIC or NPL', check: () => manual(['ShieldOps cannot see server NTP settings.']) },
    { id: 'poc', code: 'Direction (iii)', title: 'Name a point of contact for CERT-In', check: () => manual(['Record who the point of contact is and when CERT-In was told.']) },
  ],
  dpdp: [
    { id: 'safeguards', code: 'Section 8(5)', title: 'Reasonable security safeguards to prevent personal data breaches', check: (f) => ev(f.p1.length ? 'partial' : 'met', ['Monitoring, scanning, incident handling and remediation tracking are in place.'], f.p1.length ? [`${f.p1.length} P1 finding(s) open, including ${f.p1.slice(0, 2).map((x) => x.title).join(' and ')}.`] : [], [{ label: 'Findings', to: '/findings' }]) },
    { id: 'breach', code: 'Section 8(6)', title: 'Tell the Data Protection Board and each affected person about a personal data breach', check: () => ev('partial', ['Incidents record what happened, when, and the impact.'], ['Notifying the Board and affected people is manual. Add it to the incident checklist for any incident involving personal data.']) },
    { id: 'erasure', code: 'Section 8(7)', title: 'Erase personal data when its purpose is served', check: () => manual(['Data retention in your applications is outside what ShieldOps can see.']) },
  ],
};

export const controlIds = (fw: FrameworkId) => CONTROLS[fw].map((c) => c.id);

/** Readiness from live data. Score: met = 1, partial = 0.5, a manual control you attested as met = 1. */
export async function compliance(fw: FrameworkId) {
  const f = await facts();
  const meta = (await frameworks()).find((x) => x.id === fw)!;
  const att = new Map((await Attestation.find({ framework: fw }).lean()).map((a) => [a.controlId, { status: a.status as 'met' | 'not_met', note: a.note ?? '', by: String(a.by), at: a.at }]));
  const controls = CONTROLS[fw].map((c) => ({ id: c.id, code: c.code, title: c.title, ...c.check(f), attestation: att.get(c.id) ?? null }));
  const points = controls.reduce((n, c) => n + (c.status === 'met' ? 1 : c.status === 'partial' ? 0.5 : c.status === 'manual' && c.attestation?.status === 'met' ? 1 : 0), 0);
  return { framework: meta, controls, score: Math.round((points / controls.length) * 100), checkedAt: new Date().toISOString() };
}