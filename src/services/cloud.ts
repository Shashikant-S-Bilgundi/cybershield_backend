import { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } from '@aws-sdk/client-cloudtrail';
import { DescribeInstancesCommand, DescribeSecurityGroupsCommand, EC2Client } from '@aws-sdk/client-ec2';
import { GetAccountSummaryCommand, IAMClient, ListAccessKeysCommand, ListUsersCommand } from '@aws-sdk/client-iam';
import { DescribeDBInstancesCommand, RDSClient } from '@aws-sdk/client-rds';
import { GetPublicAccessBlockCommand, ListBucketsCommand, S3Client } from '@aws-sdk/client-s3';
import { AssumeRoleCommand, STSClient } from '@aws-sdk/client-sts';
import type { Types } from 'mongoose';
import { decrypt, encrypt } from '../lib/crypto.js';
import { ApiError } from '../lib/errors.js';
import { signRs256 } from '../lib/jwt.js';
import { logger } from '../lib/logger.js';
import { Application } from '../models/Application.js';
import { Asset, type AssetDoc } from '../models/Asset.js';
import { CloudCheckResult } from '../models/Cloud.js';
import { Integration } from '../models/Code.js';
import { Finding } from '../models/Finding.js';
import { problemGone, reportProblem } from './findings.js';

export type CloudProvider = 'cloudflare' | 'aws' | 'google' | 'entra';
type Creds = Record<string, string>;
const DAY = 86_400_000;

/* ───────────── HTTP helper ───────────── */

async function call<T>(url: string, init: RequestInit & { what: string }): Promise<T> {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(20_000) }).catch((e: Error) => {
    throw new ApiError(502, 'PROVIDER_UNREACHABLE', `Could not reach ${init.what}: ${e.message}`);
  });
  const data = (await res.json().catch(() => ({}))) as T & { errors?: { message: string }[]; error?: { message?: string } | string; error_description?: string };
  if (!res.ok) {
    const msg = data.errors?.[0]?.message ?? (typeof data.error === 'string' ? data.error_description ?? data.error : data.error?.message) ?? `HTTP ${res.status}`;
    throw new ApiError(res.status === 401 || res.status === 403 ? 422 : 502, res.status === 401 || res.status === 403 ? 'INVALID_CREDENTIALS' : 'PROVIDER_ERROR', `${init.what} answered ${res.status}: ${msg}`);
  }
  return data;
}

/* ───────────── Cloudflare ───────────── */

const CF = () => process.env.CLOUDFLARE_API_BASE ?? 'https://api.cloudflare.com/client/v4';
const cf = <T>(token: string, path: string) => call<{ result: T; result_info?: { total_pages: number } }>(`${CF()}${path}`, { headers: { authorization: `Bearer ${token}` }, what: 'Cloudflare' });

async function cfZones(token: string) {
  const zones: { id: string; name: string; status: string; plan?: { name: string } }[] = [];
  for (let page = 1; page <= 10; page++) {
    const r = await cf<typeof zones>(token, `/zones?per_page=50&page=${page}`);
    zones.push(...r.result);
    if (page >= (r.result_info?.total_pages ?? 1)) break;
  }
  return zones;
}

/* ───────────── AWS ───────────── */

const awsRegions = () => (process.env.AWS_REGIONS ?? 'ap-south-1').split(',').map((r) => r.trim()).filter(Boolean);

/**
 * Temporary credentials for your read-only role. ShieldOps' own keys (AWS_ACCESS_KEY_ID and
 * AWS_SECRET_ACCESS_KEY in .env) can do nothing but assume roles that trust them with your external ID.
 */
async function awsSession(c: Creds) {
  if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) throw new ApiError(409, 'AWS_NOT_CONFIGURED', 'Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY on the ShieldOps server first (see the README), then restart it.');
  const sts = new STSClient({ region: awsRegions()[0] });
  const r = await sts.send(new AssumeRoleCommand({ RoleArn: c.roleArn, RoleSessionName: 'shieldops', ExternalId: c.externalId, DurationSeconds: 3600 })).catch((e: Error) => {
    throw new ApiError(422, 'INVALID_CREDENTIALS', `AWS would not let ShieldOps assume the role: ${e.message}`);
  });
  const k = r.Credentials!;
  return { accessKeyId: k.AccessKeyId!, secretAccessKey: k.SecretAccessKey!, sessionToken: k.SessionToken! };
}

/* ───────────── Google Workspace ───────────── */

async function googleToken(c: Creds, scope: string) {
  let key: { client_email: string; private_key: string; private_key_id?: string; token_uri?: string };
  try {
    key = JSON.parse(c.serviceAccountKey);
  } catch {
    throw new ApiError(422, 'INVALID_CREDENTIALS', 'Paste the whole service account key file (JSON).');
  }
  const tokenUri = process.env.GOOGLE_TOKEN_URL ?? 'https://oauth2.googleapis.com/token';
  const now = Math.floor(Date.now() / 1000);
  const assertion = signRs256({ iss: key.client_email, sub: c.adminEmail, scope, aud: tokenUri, iat: now, exp: now + 3600 }, key.private_key, key.private_key_id);
  const r = await call<{ access_token: string }>(tokenUri, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }), what: 'Google' });
  return r.access_token;
}

type GUser = { primaryEmail: string; isAdmin?: boolean; isEnrolledIn2Sv?: boolean; suspended?: boolean; lastLoginTime?: string; creationTime?: string };
async function googleUsers(c: Creds) {
  const token = await googleToken(c, 'https://www.googleapis.com/auth/admin.directory.user.readonly');
  const base = process.env.GOOGLE_ADMIN_API ?? 'https://admin.googleapis.com';
  const users: GUser[] = [];
  let pageToken = '';
  for (let i = 0; i < 20; i++) {
    const r = await call<{ users?: GUser[]; nextPageToken?: string }>(`${base}/admin/directory/v1/users?domain=${encodeURIComponent(c.domain)}&maxResults=500${pageToken ? `&pageToken=${pageToken}` : ''}`, { headers: { authorization: `Bearer ${token}` }, what: 'Google Workspace' });
    users.push(...(r.users ?? []));
    if (!r.nextPageToken) break;
    pageToken = r.nextPageToken;
  }
  return users;
}

/* ───────────── Microsoft Entra ───────────── */

async function graph<T>(c: Creds, path: string): Promise<T[]> {
  const login = process.env.ENTRA_LOGIN_BASE ?? 'https://login.microsoftonline.com';
  const graphBase = process.env.GRAPH_API_BASE ?? 'https://graph.microsoft.com';
  const t = await call<{ access_token: string }>(`${login}/${encodeURIComponent(c.tenantId)}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: c.clientId, client_secret: c.clientSecret, scope: 'https://graph.microsoft.com/.default' }),
    what: 'Microsoft Entra',
  });
  const out: T[] = [];
  let url: string | undefined = `${graphBase}/v1.0${path}`;
  for (let i = 0; url && i < 50; i++) {
    const r: { value: T[]; '@odata.nextLink'?: string } = await call(url, { headers: { authorization: `Bearer ${t.access_token}` }, what: 'Microsoft Graph' });
    out.push(...r.value);
    url = r['@odata.nextLink'];
  }
  return out;
}

/* ───────────── connecting ───────────── */

const REQUIRED: Record<CloudProvider, string[]> = { cloudflare: ['apiToken'], aws: ['roleArn', 'externalId'], google: ['domain', 'adminEmail', 'serviceAccountKey'], entra: ['tenantId', 'clientId', 'clientSecret'] };

/** Checks the credentials work (read-only calls), and returns the account name to show. */
export async function verifyCloud(provider: CloudProvider, c: Creds): Promise<{ account: string; scopes: string[] }> {
  for (const k of REQUIRED[provider]) if (!c[k]?.trim()) throw new ApiError(422, 'MISSING_FIELD', 'Fill in every field.');
  if (provider === 'cloudflare') {
    const v = await cf<{ status: string }>(c.apiToken, '/user/tokens/verify');
    if (v.result.status !== 'active') throw new ApiError(422, 'INVALID_CREDENTIALS', 'Cloudflare says this token is not active.');
    const zones = await cfZones(c.apiToken);
    return { account: `${zones.length} zone${zones.length === 1 ? '' : 's'}`, scopes: ['Zone: Read', 'DNS: Read'] };
  }
  if (provider === 'aws') {
    if (!/^arn:aws:iam::\d{12}:role\/[\w+=,.@/-]+$/.test(c.roleArn)) throw new ApiError(422, 'INVALID_ROLE', 'Enter a role ARN like arn:aws:iam::123456789012:role/ShieldOpsReadOnly.');
    await awsSession(c);
    return { account: `AWS account ${c.roleArn.split(':')[4]}`, scopes: ['SecurityAudit (read-only)'] };
  }
  if (provider === 'google') {
    const users = await googleUsers(c);
    return { account: `${c.domain} (${users.length} users)`, scopes: ['admin.directory.user.readonly'] };
  }
  await graph(c, '/organization?$select=id');
  return { account: `Tenant ${c.tenantId.slice(0, 8)}…`, scopes: ['Directory.Read.All', 'AuditLog.Read.All'] };
}

/** Account-wide findings belong to a "Shared infrastructure" application, created on first use. */
async function sharedScope(ownerId: Types.ObjectId | null) {
  let app = await Application.findOne({ name: 'Shared infrastructure', deletedAt: null });
  if (!app) {
    const owner = ownerId ?? (await Application.findOne({ deletedAt: null }))?.ownerId;
    app = await Application.create({ name: 'Shared infrastructure', description: 'Company-wide accounts every application relies on: cloud, DNS and identity.', ownerId: owner, criticality: 'high', environments: [{ name: 'All', type: 'production' }] });
  }
  return { applicationId: app._id, environmentId: app.environments[0]._id };
}

/** The asset that stands for a connected account, so its findings have a home. */
export async function accountAsset(provider: CloudProvider, account: string, ownerId: Types.ObjectId | null): Promise<AssetDoc> {
  const identifier = `${provider}:${account}`;
  const existing = await Asset.findOne({ identifierKey: identifier, deletedAt: null });
  if (existing) return existing;
  const scope = await sharedScope(ownerId);
  return Asset.create({ type: 'cloud', identifier, identifierKey: identifier, label: { cloudflare: 'Cloudflare', aws: 'AWS', google: 'Google Workspace', entra: 'Microsoft Entra' }[provider], ...scope, exposure: 'internet', shared: true, authorization: { status: 'approved', method: 'approval', justification: `Read-only access granted by connecting ${provider} in Integrations.`, approvedBy: ownerId, at: new Date() } });
}

export async function credsOf(provider: CloudProvider): Promise<Creds> {
  const doc = await Integration.findOne({ type: provider, status: 'connected' });
  if (!doc?.credentialsEnc) throw new ApiError(409, 'NOT_CONNECTED', 'Connect it in Integrations first.');
  return JSON.parse(decrypt(doc.credentialsEnc));
}

export const encryptCreds = (c: Creds) => encrypt(JSON.stringify(c));

/* ───────────── discovering assets ───────────── */

export interface Discovered {
  externalId: string;
  source: 'cloudflare' | 'aws';
  type: 'domain' | 'website' | 'server' | 'database';
  identifier: string;
  label: string;
  exposure: 'internet' | 'internal';
  details: string;
}

export async function discover(source: 'cloudflare' | 'aws'): Promise<Discovered[]> {
  const c = await credsOf(source);
  const out: Discovered[] = [];
  if (source === 'cloudflare') {
    for (const z of await cfZones(c.apiToken)) {
      out.push({ externalId: `zone:${z.id}`, source, type: 'domain', identifier: z.name, label: z.name, exposure: 'internet', details: `Zone, ${z.plan?.name ?? ''} plan, ${z.status}`.replace(', ,', ',') });
      const recs = await cf<{ id: string; name: string; type: string; proxied: boolean; content: string }[]>(c.apiToken, `/zones/${z.id}/dns_records?per_page=200`);
      for (const r of recs.result.filter((x) => ['A', 'AAAA', 'CNAME'].includes(x.type)).slice(0, 100)) {
        out.push({ externalId: `dns:${r.id}`, source, type: 'website', identifier: `https://${r.name}/`, label: r.name, exposure: 'internet', details: `${r.type} → ${r.content}${r.proxied ? ' (proxied by Cloudflare)' : ''}` });
      }
    }
    return out;
  }
  const credentials = await awsSession(c);
  for (const region of awsRegions()) {
    const ec2 = new EC2Client({ region, credentials });
    const res = await ec2.send(new DescribeInstancesCommand({ MaxResults: 1000 }));
    for (const i of (res.Reservations ?? []).flatMap((r) => r.Instances ?? [])) {
      if (i.State?.Name === 'terminated') continue;
      const name = i.Tags?.find((t) => t.Key === 'Name')?.Value ?? i.InstanceId!;
      out.push({ externalId: `ec2:${i.InstanceId}`, source, type: 'server', identifier: i.PublicIpAddress ?? i.PrivateIpAddress ?? i.InstanceId!, label: name, exposure: i.PublicIpAddress ? 'internet' : 'internal', details: `EC2 ${i.InstanceType}, ${region}, ${i.State?.Name}` });
    }
    const rds = new RDSClient({ region, credentials });
    for (const d of (await rds.send(new DescribeDBInstancesCommand({}))).DBInstances ?? []) {
      out.push({ externalId: `rds:${d.DBInstanceArn}`, source, type: 'database', identifier: `${d.Endpoint?.Address}:${d.Endpoint?.Port}`, label: d.DBInstanceIdentifier!, exposure: d.PubliclyAccessible ? 'internet' : 'internal', details: `RDS ${d.Engine} ${d.EngineVersion}, ${d.DBInstanceClass}, ${region}` });
    }
  }
  return out;
}

/* ───────────── checks ───────────── */

interface Problem {
  key: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  evidence: { label: string; value: string }[];
}
interface CheckOutcome {
  id: string;
  title: string;
  total: number;
  problems: Problem[];
}

async function cloudflareChecks(c: Creds): Promise<CheckOutcome[]> {
  const zones = await cfZones(c.apiToken);
  const https: Problem[] = [];
  const tls: Problem[] = [];
  const dnssec: Problem[] = [];
  for (const z of zones) {
    const settings = new Map((await cf<{ id: string; value: unknown }[]>(c.apiToken, `/zones/${z.id}/settings`)).result.map((s) => [s.id, s.value]));
    if (settings.get('always_use_https') !== 'on') https.push({ key: `cf:https:${z.id}`, title: `Always Use HTTPS is off for ${z.name}`, description: 'Visitors can still reach the site over plain HTTP. Turn on SSL/TLS → Edge Certificates → Always Use HTTPS.', severity: 'medium', evidence: [{ label: 'Zone', value: z.name }] });
    const ssl = String(settings.get('ssl') ?? '');
    const minTls = String(settings.get('min_tls_version') ?? '1.0');
    if (ssl === 'off' || ssl === 'flexible' || Number(minTls) < 1.2) tls.push({ key: `cf:tls:${z.id}`, title: `Weak TLS settings on ${z.name}`, description: 'Use SSL mode "Full (strict)" so Cloudflare checks your server certificate, and set the minimum TLS version to 1.2.', severity: ssl === 'off' || ssl === 'flexible' ? 'high' : 'medium', evidence: [{ label: 'SSL mode', value: ssl || 'unknown' }, { label: 'Minimum TLS', value: minTls }] });
    const d = await cf<{ status: string }>(c.apiToken, `/zones/${z.id}/dnssec`);
    if (d.result.status !== 'active') dnssec.push({ key: `cf:dnssec:${z.id}`, title: `DNSSEC is off for ${z.name}`, description: 'Without DNSSEC, DNS answers for the domain can be forged. Turn it on in DNS → Settings, then add the DS record at your registrar.', severity: 'low', evidence: [{ label: 'Zone', value: z.name }, { label: 'DNSSEC', value: d.result.status }] });
  }
  return [
    { id: 'cf-https', title: 'Always Use HTTPS is on for every zone', total: zones.length, problems: https },
    { id: 'cf-tls', title: 'Full (strict) SSL and TLS 1.2 or newer on every zone', total: zones.length, problems: tls },
    { id: 'cf-dnssec', title: 'DNSSEC is on for every zone', total: zones.length, problems: dnssec },
  ];
}

async function awsChecks(c: Creds): Promise<CheckOutcome[]> {
  const credentials = await awsSession(c);
  const region = awsRegions()[0];
  const account = c.roleArn.split(':')[4];
  const iam = new IAMClient({ region, credentials });
  const summary = (await iam.send(new GetAccountSummaryCommand({}))).SummaryMap ?? {};
  const rootMfa: Problem[] = summary.AccountMFAEnabled === 1 ? [] : [{ key: `aws:root-mfa:${account}`, title: 'AWS root account has no MFA', description: 'The root user can do anything in the account, including closing it. Add an MFA device to it and stop using it day to day.', severity: 'critical', evidence: [{ label: 'Account', value: account }, { label: 'Check', value: 'AccountMFAEnabled = 0' }] }];

  const keys: Problem[] = [];
  let keyCount = 0;
  for (const u of (await iam.send(new ListUsersCommand({ MaxItems: 1000 }))).Users ?? []) {
    for (const k of (await iam.send(new ListAccessKeysCommand({ UserName: u.UserName }))).AccessKeyMetadata ?? []) {
      if (k.Status !== 'Active') continue;
      keyCount++;
      const age = Math.floor((Date.now() - (k.CreateDate?.getTime() ?? Date.now())) / DAY);
      if (age > 90) keys.push({ key: `aws:key-age:${k.AccessKeyId}`, title: `IAM access key for ${u.UserName} is ${age} days old`, description: 'Long-lived keys are the most common way AWS accounts are breached. Rotate it, or switch to roles (for CI, GitHub OIDC) so no key is needed.', severity: 'medium', evidence: [{ label: 'User', value: u.UserName! }, { label: 'Key', value: `${k.AccessKeyId?.slice(0, 4)}…${k.AccessKeyId?.slice(-4)}` }] });
    }
  }

  const s3 = new S3Client({ region, credentials });
  const buckets = (await s3.send(new ListBucketsCommand({}))).Buckets ?? [];
  const publicBuckets: Problem[] = [];
  for (const b of buckets) {
    const block = await s3.send(new GetPublicAccessBlockCommand({ Bucket: b.Name })).then((r) => r.PublicAccessBlockConfiguration).catch(() => null);
    const on = !!block && !!block.BlockPublicAcls && !!block.BlockPublicPolicy && !!block.IgnorePublicAcls && !!block.RestrictPublicBuckets;
    if (!on) publicBuckets.push({ key: `aws:s3-public:${b.Name}`, title: `S3 bucket ${b.Name} does not block public access`, description: 'Without Block Public Access, one wrong bucket policy or ACL makes the data public. Turn on all four Block Public Access settings for the bucket and the account.', severity: 'high', evidence: [{ label: 'Bucket', value: b.Name! }] });
  }

  const sg: Problem[] = [];
  let sgCount = 0;
  const dbs: Problem[] = [];
  let dbCount = 0;
  for (const r of awsRegions()) {
    const groups = (await new EC2Client({ region: r, credentials }).send(new DescribeSecurityGroupsCommand({ MaxResults: 1000 }))).SecurityGroups ?? [];
    sgCount += groups.length;
    for (const g of groups) {
      const open = (g.IpPermissions ?? []).filter((p) => (p.IpRanges ?? []).some((x) => x.CidrIp === '0.0.0.0/0') || (p.Ipv6Ranges ?? []).some((x) => x.CidrIpv6 === '::/0'));
      const ports = open.filter((p) => p.IpProtocol === '-1' || [22, 3389].some((port) => (p.FromPort ?? 0) <= port && port <= (p.ToPort ?? 65535)));
      if (ports.length) sg.push({ key: `aws:sg-admin:${g.GroupId}`, title: `Security group ${g.GroupName} opens SSH or RDP to the internet`, description: 'Remote login ports open to everyone are scanned constantly. Allow them only from your office or VPN addresses, or use Session Manager.', severity: 'high', evidence: [{ label: 'Group', value: `${g.GroupName} (${g.GroupId}, ${r})` }] });
    }
    const instances = (await new RDSClient({ region: r, credentials }).send(new DescribeDBInstancesCommand({}))).DBInstances ?? [];
    dbCount += instances.length;
    for (const d of instances) if (d.PubliclyAccessible) dbs.push({ key: `aws:rds-public:${d.DBInstanceIdentifier}`, title: `RDS instance ${d.DBInstanceIdentifier} is publicly accessible`, description: 'The database has a public endpoint. Even with a password it is exposed to brute force. Turn off public access and reach it through the private network.', severity: 'medium', evidence: [{ label: 'Instance', value: `${d.DBInstanceIdentifier} (${d.Engine}, ${r})` }, { label: 'Setting', value: 'PubliclyAccessible = true' }] });
  }

  const ct = new CloudTrailClient({ region, credentials });
  let logging = false;
  for (const t of (await ct.send(new DescribeTrailsCommand({}))).trailList ?? []) {
    if (!t.IsMultiRegionTrail) continue;
    if ((await ct.send(new GetTrailStatusCommand({ Name: t.TrailARN }))).IsLogging) logging = true;
  }
  const trail: Problem[] = logging ? [] : [{ key: `aws:cloudtrail:${account}`, title: 'CloudTrail is not logging every region', description: 'Without a multi-region trail there is no record of who did what in the account. Create one trail for all regions, logging to a bucket in a separate account if possible.', severity: 'high', evidence: [{ label: 'Account', value: account }] }];

  return [
    { id: 'aws-root-mfa', title: 'Root account has MFA', total: 1, problems: rootMfa },
    { id: 'aws-s3-public', title: 'S3 buckets block public access', total: buckets.length, problems: publicBuckets },
    { id: 'aws-sg-ssh', title: 'No security group opens SSH or RDP to the internet', total: sgCount, problems: sg },
    { id: 'aws-rds-public', title: 'Databases are not publicly accessible', total: dbCount, problems: dbs },
    { id: 'aws-key-age', title: 'Access keys are younger than 90 days', total: keyCount, problems: keys },
    { id: 'aws-cloudtrail', title: 'CloudTrail logs every region', total: 1, problems: trail },
  ];
}

async function googleChecks(c: Creds): Promise<CheckOutcome[]> {
  const users = (await googleUsers(c)).filter((u) => !u.suspended);
  const admins = users.filter((u) => u.isAdmin);
  const no2sv = (list: GUser[], admin: boolean): Problem[] => list.filter((u) => !u.isEnrolledIn2Sv).map((u) => ({ key: `gws:${admin ? 'admin-' : ''}2sv:${u.primaryEmail}`, title: `${admin ? 'Admin' : 'User'} ${u.primaryEmail} has no 2-step verification`, description: admin ? 'An admin account without 2-step verification can be taken over with just a password, and controls every account. Enforce 2SV for admins in the Admin console.' : 'Enforce 2-step verification for everyone in Security → Authentication.', severity: admin ? 'critical' : 'medium', evidence: [{ label: 'Account', value: u.primaryEmail }] }));
  const stale = users.filter((u) => {
    const last = Date.parse(u.lastLoginTime ?? '') || 0;
    const created = Date.parse(u.creationTime ?? '') || 0;
    return Date.now() - Math.max(last, created) > 90 * DAY;
  });
  return [
    { id: 'gws-admin-2sv', title: 'Admins use 2-step verification', total: admins.length, problems: no2sv(admins, true) },
    { id: 'gws-users-2sv', title: 'Everyone uses 2-step verification', total: users.length - admins.length, problems: no2sv(users.filter((u) => !u.isAdmin), false) },
    { id: 'gws-inactive', title: 'Accounts unused for 90 days are suspended', total: users.length, problems: stale.map((u) => ({ key: `gws:inactive:${u.primaryEmail}`, title: `${u.primaryEmail} has not signed in for 90 days`, description: 'Unused accounts are easy targets because nobody notices them being used. Suspend it, or delete it after transferring its data.', severity: 'low', evidence: [{ label: 'Account', value: u.primaryEmail }, { label: 'Last sign-in', value: u.lastLoginTime?.slice(0, 10) ?? 'never' }] })) },
  ];
}

async function entraChecks(c: Creds): Promise<CheckOutcome[]> {
  const reg = await graph<{ userPrincipalName: string; isAdmin?: boolean; isMfaRegistered?: boolean; userType?: string }>(c, '/reports/authenticationMethods/userRegistrationDetails');
  const members = reg.filter((r) => r.userType !== 'guest');
  const admins = members.filter((r) => r.isAdmin);
  const noMfa = (list: typeof members, admin: boolean): Problem[] => list.filter((u) => !u.isMfaRegistered).map((u) => ({ key: `entra:${admin ? 'admin-' : ''}mfa:${u.userPrincipalName}`, title: `${admin ? 'Admin' : 'User'} ${u.userPrincipalName} has no MFA registered`, description: admin ? 'An admin without MFA can be taken over with one phished password. Require MFA for admin roles with a Conditional Access policy.' : 'Require MFA for everyone with security defaults or a Conditional Access policy.', severity: admin ? 'critical' : 'medium', evidence: [{ label: 'Account', value: u.userPrincipalName }] }));
  return [
    { id: 'entra-admin-mfa', title: 'Admins have MFA registered', total: admins.length, problems: noMfa(admins, true) },
    { id: 'entra-users-mfa', title: 'Everyone has MFA registered', total: members.length - admins.length, problems: noMfa(members.filter((m) => !m.isAdmin), false) },
  ];
}

const TITLES: Record<CloudProvider, (c: Creds) => Promise<CheckOutcome[]>> = { cloudflare: cloudflareChecks, aws: awsChecks, google: googleChecks, entra: entraChecks };

/**
 * Runs one provider's checks: failures become findings on the account's asset (source "cloud"), and
 * findings no longer seen are verified fixed. A provider that cannot be reached changes nothing.
 */
export async function runCloudChecks(provider: CloudProvider) {
  const doc = await Integration.findOne({ type: provider, status: 'connected' });
  if (!doc?.credentialsEnc) return;
  const c = JSON.parse(decrypt(doc.credentialsEnc)) as Creds;
  const asset = await accountAsset(provider, c.roleArn?.split(':')[4] ?? c.domain ?? c.tenantId ?? 'account', doc.connectedBy as Types.ObjectId | null);
  let outcomes: CheckOutcome[];
  try {
    outcomes = await TITLES[provider](c);
  } catch (err) {
    logger.warn({ provider, err: (err as Error).message }, 'Cloud checks failed');
    await Integration.updateOne({ _id: doc._id }, { error: (err as Error).message.slice(0, 300) });
    await CloudCheckResult.updateMany({ provider }, { error: (err as Error).message.slice(0, 300) });
    return;
  }
  const seen = new Set<string>();
  for (const o of outcomes) {
    for (const p of o.problems) {
      seen.add(p.key);
      await reportProblem(asset, { key: p.key, title: p.title, description: p.description, category: 'security', source: 'cloud', severity: p.severity, evidence: p.evidence });
    }
    await CloudCheckResult.updateOne({ _id: o.id }, { provider, title: o.title, passed: Math.max(0, o.total - o.problems.length), failed: o.problems.length, findingKeys: o.problems.map((p) => p.key), checkedAt: new Date(), error: null }, { upsert: true });
  }
  for (const f of await Finding.find({ assetId: asset._id, source: 'cloud', status: { $nin: ['verified', 'accepted_risk', 'false_positive'] } }, { key: 1 }).lean()) if (!seen.has(f.key)) await problemGone(f.key, 'Verified fixed: the cloud check passes now');
  await Integration.updateOne({ _id: doc._id }, { lastSyncAt: new Date(), error: null });
}

export async function cloudCheckViews() {
  const connected = new Set((await Integration.find({ type: { $in: ['cloudflare', 'aws', 'google', 'entra'] }, status: 'connected' }, { type: 1 }).lean()).map((d) => d.type));
  const rows = await CloudCheckResult.find({ provider: { $in: [...connected] } }).sort({ provider: 1, _id: 1 }).lean();
  const out = [];
  for (const r of rows) {
    const findings = await Finding.find({ key: { $in: r.findingKeys ?? [] }, status: { $nin: ['resolved', 'verified', 'accepted_risk', 'false_positive'] } }, { _id: 1 }).lean();
    out.push({ id: r._id, provider: r.provider, title: r.title, passed: r.passed, failed: findings.length, findingIds: findings.map((f) => String(f._id)) });
  }
  return out;
}