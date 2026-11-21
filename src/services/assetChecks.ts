import { isIP } from 'node:net';
import { classify, guardedGet, lookupRecords, tlsHandshake, type DnsType } from '../lib/probe.js';
import { logger } from '../lib/logger.js';
import { hostOf } from '../lib/net.js';
import { lookupDomain } from '../lib/rdap.js';
import { Application } from '../models/Application.js';
import { Asset, type AssetDoc } from '../models/Asset.js';
import { AssetCheckSchedule, Certificate, DnsSnapshot, DomainExpiry, HeaderReport } from '../models/AssetChecks.js';
import { autoResolve, raiseAlert } from './alerts.js';
import { problemGone, reportProblem } from './findings.js';
import { getAllowlist, getSettingsDoc } from './settings.js';

const DAY = 86_400_000;
const CHECKABLE = ['domain', 'website', 'api'];

/** Assets ShieldOps may check: proved ownership, not paused, not deleted. */
export const checkableQuery = {
  deletedAt: null,
  status: 'active',
  type: { $in: CHECKABLE },
  'authorization.status': { $in: ['verified', 'approved'] },
};

const daysUntil = (d: Date) => Math.ceil((d.getTime() - Date.now()) / DAY);
const httpsPort = (a: AssetDoc) => {
  try {
    const u = new URL(a.identifier);
    return u.protocol === 'https:' && u.port ? Number(u.port) : 443;
  } catch {
    return 443;
  }
};
const base = (a: AssetDoc) => ({ applicationId: a.applicationId, environmentId: a.environmentId, assetId: a._id, checkedAt: new Date() });

/* ───────────── SSL ───────────── */

export async function checkSsl(a: AssetDoc) {
  const host = hostOf(a.identifier);
  const allow = await getAllowlist();
  const k = (p: string) => `ssl:${p}:${a.id}`;
  try {
    const t = await tlsHandshake(host, httpsPort(a), allow, 10_000);
    // Does the server still accept TLS 1.0 or 1.1? A successful handshake capped at 1.1 means yes.
    const oldProtocol = await tlsHandshake(host, httpsPort(a), allow, 8_000, 'TLSv1.1').then((r) => r.protocol, () => null);
    const weakCipher = /RC4|3DES|DES-CBC|NULL|EXPORT|MD5/i.test(t.cipher ?? '');
    await Certificate.updateOne({ assetId: a._id }, { $set: { ...base(a), host, issuer: t.issuer, validFrom: t.validFrom, validTo: t.validTo, chainValid: t.chainValid, hostnameMatch: t.hostnameMatch, protocol: t.protocol, weakCiphers: !!oldProtocol || weakCipher }, $unset: { error: 1 } }, { upsert: true });

    const evidence = [{ label: 'Host', value: host }, { label: 'Issuer', value: t.issuer ?? 'unknown' }, { label: 'Expires', value: t.validTo ?? 'unknown' }];
    if (t.validTo) {
      const days = daysUntil(new Date(t.validTo));
      if (days <= 30) {
        await reportProblem(a, { key: k('expiry'), title: days <= 0 ? 'SSL certificate has expired' : `SSL certificate expires in ${days} ${days === 1 ? 'day' : 'days'}`, description: 'Visitors will see a security warning once it expires. Renew it, or check why automatic renewal did not run.', category: 'availability', source: 'ssl', severity: days <= 1 ? 'critical' : days <= 7 ? 'high' : days <= 14 ? 'medium' : 'low', evidence });
        await raiseAlert({ key: k('expiry'), signal: 'ssl_expiry', value: days, applicationId: a.applicationId, environmentId: a.environmentId, assetId: a._id, source: 'ssl', title: days <= 0 ? `SSL certificate for ${host} has expired` : `SSL certificate for ${host} expires in ${days} ${days === 1 ? 'day' : 'days'}`, message: `Issued by ${t.issuer ?? 'unknown'}, valid until ${t.validTo}.` });
      } else {
        await problemGone(k('expiry'));
        await autoResolve(k('expiry'));
      }
    }
    if (!t.chainValid) await reportProblem(a, { key: k('chain'), title: 'SSL certificate is not trusted', description: 'Browsers reject this certificate: it may be self-signed, issued for another name, or missing its intermediate certificate.', category: 'security', source: 'ssl', severity: 'high', evidence });
    else await problemGone(k('chain'));
    if (!t.hostnameMatch) await reportProblem(a, { key: k('hostname'), title: 'SSL certificate does not match the host name', description: `The certificate is not valid for ${host}.`, category: 'security', source: 'ssl', severity: 'high', evidence });
    else await problemGone(k('hostname'));
    if (oldProtocol) await reportProblem(a, { key: k('protocol'), title: `${oldProtocol === 'TLSv1' ? 'TLS 1.0' : 'TLS 1.1'} still enabled`, description: 'TLS 1.0 and 1.1 have known weaknesses and are rejected by modern browsers. Allow only TLS 1.2 and 1.3.', category: 'security', source: 'ssl', severity: 'high', evidence: [...evidence, { label: 'Accepted protocol', value: oldProtocol }] });
    else await problemGone(k('protocol'));
  } catch (err) {
    await Certificate.updateOne({ assetId: a._id }, { $set: { ...base(a), host, error: classify(err) } }, { upsert: true });
  }
}

/* ───────────── DNS ───────────── */

const DNS_TYPES: DnsType[] = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA'];

export async function checkDns(a: AssetDoc) {
  const host = hostOf(a.identifier);
  // An IP address has no DNS records of its own to watch.
  if (isIP(host)) return void (await DnsSnapshot.deleteOne({ assetId: a._id }));
  const records = (await Promise.all(DNS_TYPES.map(async (type) => (await lookupRecords(host, type).catch(() => [])).map((r) => ({ type, ...r }))))).flat();
  const prev = await DnsSnapshot.findOne({ assetId: a._id });
  const now = new Date();
  const changes: { at: Date; type: DnsType; before: string[]; after: string[] }[] = [];
  if (prev?.records.length) {
    for (const type of DNS_TYPES) {
      const before = prev.records.filter((r) => r.type === type).map((r) => r.value!).sort();
      const after = records.filter((r) => r.type === type).map((r) => r.value).sort();
      if (JSON.stringify(before) !== JSON.stringify(after)) changes.push({ at: now, type, before, after });
    }
  }
  await DnsSnapshot.updateOne({ assetId: a._id }, { $set: { ...base(a), host, records }, $push: { changes: { $each: changes, $position: 0, $slice: 50 } } }, { upsert: true });
  for (const c of changes) {
    await raiseAlert({ key: `dns:${a.id}:${c.type}:${now.getTime()}`, signal: 'dns_change', applicationId: a.applicationId, environmentId: a.environmentId, assetId: a._id, source: 'dns', title: `${c.type} record changed on ${host}`, message: `Before: ${c.before.join(', ') || 'none'}. After: ${c.after.join(', ') || 'none'}. Check this was planned.` });
  }
}

/* ───────────── domain expiry ───────────── */

export async function checkDomain(a: AssetDoc) {
  // An IP address has no domain registration that could expire.
  if (isIP(hostOf(a.identifier))) return void (await DomainExpiry.deleteOne({ assetId: a._id }));
  const info = await lookupDomain(hostOf(a.identifier));
  await DomainExpiry.updateOne({ assetId: a._id }, { $set: { ...base(a), domain: info.domain, registrar: info.registrar, expiresAt: info.expiresAt, source: info.source } }, { upsert: true });
  const key = `domain:expiry:${a.id}`;
  if (!info.expiresAt) return;
  const days = daysUntil(new Date(info.expiresAt));
  if (days <= 60) {
    const evidence = [{ label: 'Domain', value: info.domain }, { label: 'Registrar', value: info.registrar ?? 'unknown' }, { label: 'Expires', value: info.expiresAt }];
    await reportProblem(a, { key, title: days <= 0 ? `Domain ${info.domain} has expired` : `Domain ${info.domain} expires in ${days} days`, description: 'If the registration lapses, the site and email on it stop working and someone else can register it. Renew it and turn on auto-renew.', category: 'availability', source: 'domain', severity: days <= 7 ? 'critical' : days <= 30 ? 'medium' : 'low', evidence });
    await raiseAlert({ key, signal: 'domain_expiry', value: days, applicationId: a.applicationId, environmentId: a.environmentId, assetId: a._id, source: 'domain', title: `Domain ${info.domain} expires in ${days} days`, message: `Registrar: ${info.registrar ?? 'unknown'}. Expiry: ${info.expiresAt}.` });
  } else {
    await problemGone(key);
    await autoResolve(key);
  }
}

/* ───────────── security headers ───────────── */

type HeaderName = 'strict-transport-security' | 'content-security-policy' | 'x-frame-options' | 'x-content-type-options' | 'referrer-policy' | 'permissions-policy';

/** Checks the six headers; exported for tests. */
export function evaluateHeaders(h: Headers, https: boolean) {
  const get = (n: string) => h.get(n) ?? undefined;
  const out = {} as Record<HeaderName, { present: boolean; value?: string; issue?: string }>;
  const hsts = get('strict-transport-security');
  const maxAge = Number(hsts?.match(/max-age=(\d+)/i)?.[1] ?? 0);
  out['strict-transport-security'] = { present: !!hsts, value: hsts, issue: !https ? 'The site is not served over HTTPS' : hsts && maxAge < 15_552_000 ? 'max-age is under 180 days' : undefined };
  const csp = get('content-security-policy');
  out['content-security-policy'] = { present: !!csp, value: csp, issue: csp && /script-src[^;]*'unsafe-inline'/i.test(csp) ? "script-src allows 'unsafe-inline'" : undefined };
  const xfo = get('x-frame-options');
  const frameAncestors = /frame-ancestors/i.test(csp ?? '');
  out['x-frame-options'] = { present: !!xfo || frameAncestors, value: xfo ?? (frameAncestors ? 'covered by CSP frame-ancestors' : undefined) };
  const xcto = get('x-content-type-options');
  out['x-content-type-options'] = { present: !!xcto, value: xcto, issue: xcto && xcto.toLowerCase() !== 'nosniff' ? 'Should be nosniff' : undefined };
  const rp = get('referrer-policy');
  out['referrer-policy'] = { present: !!rp, value: rp, issue: rp && /unsafe-url/i.test(rp) ? 'unsafe-url sends full URLs to other sites' : undefined };
  const pp = get('permissions-policy');
  out['permissions-policy'] = { present: !!pp, value: pp };
  return out;
}

const HEADER_FINDINGS: { name: HeaderName; title: string; severity: 'medium' | 'low'; why: string }[] = [
  { name: 'strict-transport-security', title: 'Strict-Transport-Security header missing', severity: 'medium', why: 'Without HSTS, a visitor on a hostile network can be downgraded to plain HTTP.' },
  { name: 'content-security-policy', title: 'Content-Security-Policy header missing', severity: 'medium', why: 'A CSP limits which scripts can run and reduces the impact of injected code.' },
  { name: 'x-frame-options', title: 'Clickjacking protection missing', severity: 'low', why: 'Without X-Frame-Options or CSP frame-ancestors, other sites can frame this page to trick users into clicks.' },
  { name: 'x-content-type-options', title: 'X-Content-Type-Options header missing', severity: 'low', why: 'Without nosniff, browsers may treat uploaded files as scripts.' },
];

export async function checkHeaders(a: AssetDoc) {
  const url = a.type === 'domain' ? `https://${hostOf(a.identifier)}/` : a.identifier;
  try {
    const r = await guardedGet(url, await getAllowlist(), { timeoutMs: 10_000 });
    const headers = evaluateHeaders(r.headers, r.finalUrl.startsWith('https:'));
    await HeaderReport.updateOne({ assetId: a._id }, { $set: { ...base(a), url: r.finalUrl, headers } }, { upsert: true });
    for (const hf of HEADER_FINDINGS) {
      const key = `headers:${hf.name}:${a.id}`;
      if (!headers[hf.name].present) await reportProblem(a, { key, title: hf.title, description: hf.why, category: 'configuration', source: 'headers', severity: hf.severity, evidence: [{ label: 'URL', value: r.finalUrl }] });
      else await problemGone(key);
    }
    const app = await Application.findById(a.applicationId);
    const isProd = app?.environments.find((e) => String(e._id) === String(a.environmentId))?.type === 'production';
    const missing = (['strict-transport-security', 'content-security-policy'] as const).filter((n) => !headers[n].present);
    const key = `headers:${a.id}`;
    if (isProd && missing.length) {
      await raiseAlert({ key, signal: 'headers_missing', applicationId: a.applicationId, environmentId: a.environmentId, assetId: a._id, source: 'headers', title: `${missing.map((n) => (n === 'strict-transport-security' ? 'HSTS' : 'CSP')).join(' and ')} missing on ${hostOf(a.identifier)}`, message: `${r.finalUrl} does not send ${missing.join(' or ')}.` });
    } else await autoResolve(key);
  } catch (err) {
    logger.debug({ err: (err as Error).message, asset: a.id }, 'Header check failed');
  }
}

/* ───────────── scheduling ───────────── */

/** Runs the checks that are due for one asset (or all of them when forced). */
export async function runAssetChecks(a: AssetDoc, force = false) {
  const { monitoring } = await getSettingsDoc();
  const sched = (await AssetCheckSchedule.findOne({ assetId: a._id })) ?? new AssetCheckSchedule({ assetId: a._id });
  const due = (last: Date | null | undefined, hours: number) => force || !last || Date.now() - last.getTime() >= hours * 3_600_000;
  const jobs: [keyof typeof sched & ('sslAt' | 'dnsAt' | 'domainAt' | 'headersAt'), number, (x: AssetDoc) => Promise<void>][] = [
    ['sslAt', monitoring?.sslCheckHours ?? 24, checkSsl],
    ['dnsAt', monitoring?.dnsCheckHours ?? 6, checkDns],
    ['domainAt', 24, checkDomain],
    ['headersAt', 24, checkHeaders],
  ];
  for (const [field, hours, fn] of jobs) {
    if (!due(sched[field] as Date | null, hours)) continue;
    await fn(a).catch((err) => logger.warn({ err: (err as Error).message, asset: a.id, field }, 'Asset check failed'));
    (sched as unknown as Record<string, Date>)[field] = new Date();
  }
  sched.claimedUntil = null;
  await sched.save();
}

/** Claims assets one at a time (so two workers never check the same one) and runs what is due. */
export async function runDueAssetChecks(limit = 5) {
  const assets = await Asset.find(checkableQuery, { _id: 1 }).lean();
  let ran = 0;
  for (const { _id } of assets) {
    if (ran >= limit) break;
    const now = new Date();
    const claim = await AssetCheckSchedule.findOneAndUpdate(
      { assetId: _id, $or: [{ claimedUntil: null }, { claimedUntil: { $lt: now } }] },
      { $set: { claimedUntil: new Date(now.getTime() + 5 * 60_000) }, $setOnInsert: { assetId: _id } },
      { upsert: true, new: false },
    ).catch(() => 'busy' as const);
    if (claim === 'busy') continue;
    const asset = await Asset.findById(_id);
    if (!asset) continue;
    const { monitoring } = await getSettingsDoc();
    const s = claim ?? { sslAt: null, dnsAt: null, domainAt: null, headersAt: null };
    const stale = (d: Date | null | undefined, h: number) => !d || Date.now() - d.getTime() >= h * 3_600_000;
    if (stale(s.sslAt, monitoring?.sslCheckHours ?? 24) || stale(s.dnsAt, monitoring?.dnsCheckHours ?? 6) || stale(s.domainAt, 24) || stale(s.headersAt, 24)) {
      await runAssetChecks(asset);
      ran++;
    } else await AssetCheckSchedule.updateOne({ assetId: _id }, { claimedUntil: null });
  }
}