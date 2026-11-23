import { compareVersions } from './scanners.js';
import { Finding, type FindingDoc } from '../models/Finding.js';
import { RecDismissal } from '../models/Intel.js';

type Priority = 'P1' | 'P2' | 'P3' | 'P4';
const PRI: Priority[] = ['P1', 'P2', 'P3', 'P4'];
const ACTIVE = { status: { $nin: ['resolved', 'verified', 'accepted_risk', 'false_positive'] } };

export interface Recommendation {
  id: string;
  title: string;
  why: string;
  source: 'rule' | 'ai';
  effort: 'small' | 'medium' | 'large';
  findingIds: string[];
  applicationIds: string[];
  closes: Record<Priority, number>;
  steps: string[];
  dismissed: boolean;
  dismissedReason: string | null;
}

const INSTALL: Record<string, (pkg: string, v: string) => string> = {
  npm: (p, v) => `npm install ${p}@^${v} in each repository (or upgrade the package that depends on it).`,
  pypi: (p, v) => `pip install "${p}>=${v}" and update requirements or the lockfile.`,
  go: (p, v) => `go get ${p}@v${v.replace(/^v/, '')} && go mod tidy`,
};

/**
 * Turns open findings into a short list of fixes, each closing as many findings as possible:
 * one package upgrade, one image rebuild, one nginx snippet. Same rules as the frontend's.
 */
export async function recommendations(filter: { applicationId?: string } = {}): Promise<Recommendation[]> {
  const active = (await Finding.find({ ...ACTIVE, ...(filter.applicationId ? { applicationId: filter.applicationId } : {}) })) as FindingDoc[];
  const dismissed = new Map((await RecDismissal.find().lean()).map((d) => [d.recId, d.reason ?? '']));
  const make = (id: string, title: string, why: string, effort: Recommendation['effort'], fs: FindingDoc[], steps: string[]): Recommendation => ({
    id, title, why, source: 'rule', effort, findingIds: fs.map((f) => f.id), applicationIds: [...new Set(fs.map((f) => String(f.applicationId)))],
    closes: Object.fromEntries(PRI.map((p) => [p, fs.filter((f) => f.priority === p).length])) as Record<Priority, number>, steps,
    dismissed: dismissed.has(id), dismissedReason: dismissed.get(id) ?? null,
  });
  const recs: Recommendation[] = [];

  const byPkg = new Map<string, FindingDoc[]>();
  for (const f of active) {
    const c = f.code as { kind?: string; targetType?: string; targetName?: string; ecosystem?: string; package?: string } | undefined;
    if (c?.kind !== 'vuln') continue;
    const key = c.targetType === 'image' ? `image:${c.targetName}` : `${c.ecosystem}:${c.package}`;
    byPkg.set(key, [...(byPkg.get(key) ?? []), f]);
  }
  for (const [key, fs] of byPkg) {
    const c = fs[0].code as { package: string; ecosystem: string; targetName: string; fixedIn: string | null; vulnId: string };
    const ids = [...new Set(fs.map((f) => (f.code as { vulnId: string }).vulnId))];
    if (key.startsWith('image:')) {
      recs.push(make(`rec-${key}`, `Rebuild ${c.targetName} on a patched base image`, `${fs.length} vulnerable package(s) in this image, including ${ids.slice(0, 3).join(', ')}.`, 'small', fs, ['Update the FROM line to the latest patch release of the same base image.', 'Rebuild, push and redeploy.', 'Rescan the image in ShieldOps to confirm.']));
      continue;
    }
    const fixes = fs.map((f) => (f.code as { fixedIn: string | null }).fixedIn).filter((v): v is string => !!v);
    const noFix = fixes.length < fs.length;
    const target = fixes.sort(compareVersions).at(-1);
    const repos = [...new Set(fs.map((f) => (f.code as { targetName: string }).targetName))];
    if (!target) {
      recs.push(make(`rec-${key}`, `Replace or isolate ${c.package}`, `${ids.join(', ')} ${ids.length > 1 ? 'have' : 'has'} no fixed version yet, in ${repos.join(', ')}.`, 'medium', fs, ['Check whether the vulnerable code path is used at all.', 'Look for a maintained alternative package.', 'If you keep it, accept the risk on the finding with a review date.']));
      continue;
    }
    recs.push(make(`rec-${key}`, `Upgrade ${c.package} to ${target}`, `Closes ${fs.length} finding(s) in ${repos.join(', ')}${noFix ? '; some vulnerabilities have no fix yet' : ''}.`, repos.length > 2 ? 'medium' : 'small', fs, [(INSTALL[c.ecosystem] ?? INSTALL.npm)(c.package, target), 'Run the tests and deploy.', 'The scan on push confirms the fix.']));
  }

  const secrets = active.filter((f) => f.source === 'secrets');
  if (secrets.length) recs.push(make('rec-secrets', `Rotate ${secrets.length} exposed secret(s)`, 'Every committed secret should be treated as already copied, whether or not it is still in the code.', 'medium', secrets, ['Deactivate or regenerate each one with its provider.', 'Move them into a secrets manager or environment variables.', 'Add a pre-commit Gitleaks hook to every repository.']));

  const misconfig = active.filter((f) => f.key.startsWith('misconfig:'));
  if (misconfig.length) recs.push(make('rec-misconfig', 'Harden Dockerfiles and deployment files', `${misconfig.length} configuration finding(s) from Trivy, such as ${misconfig[0].title}.`, 'small', misconfig, ['Run containers as a non-root user (USER app).', 'Use COPY instead of ADD, and add a HEALTHCHECK.', 'Pin base images to a specific version.']));

  const headers = active.filter((f) => f.source === 'headers');
  if (headers.length) recs.push(make('rec-headers', 'Add the missing security headers', `${headers.length} header finding(s) across ${new Set(headers.map((f) => String(f.assetId))).size} site(s). One shared nginx snippet fixes most of them.`, 'small', headers, ['add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;', 'add_header X-Frame-Options "DENY" always;  add_header X-Content-Type-Options "nosniff" always;', 'add_header Content-Security-Policy "default-src \'self\'" always;  (try Content-Security-Policy-Report-Only first)', 'Reload nginx; the daily header check verifies it.']));

  const tls = active.filter((f) => f.source === 'ssl' && !/expire/.test(f.title));
  if (tls.length) recs.push(make('rec-tls', 'Fix TLS settings', `${tls.length} finding(s) about certificates, old protocols or weak ciphers.`, 'small', tls, ['ssl_protocols TLSv1.2 TLSv1.3;', 'Use the Mozilla "intermediate" cipher list and a certificate from a trusted CA for the right host name.', 'Reload and recheck SSL in ShieldOps.']));

  const expiring = active.filter((f) => f.source === 'ssl' && /expire/.test(f.title));
  if (expiring.length) recs.push(make('rec-renew', 'Fix certificate auto-renewal', `${expiring.length} certificate(s) close to expiry suggests renewal is not automated.`, 'small', expiring, ['Check the certbot timer (systemctl list-timers) or your host’s auto-renew setting.', 'Renew now with certbot renew, then reload the web server.']));

  const domains = active.filter((f) => f.source === 'domain');
  if (domains.length) recs.push(make('rec-domains', 'Renew domains and turn on auto-renew', `${domains.length} domain(s) expire within 60 days.`, 'small', domains, ['Renew at the registrar now.', 'Turn on auto-renew and check the payment card on file.']));

  const weight = (r: Recommendation) => r.closes.P1 * 8 + r.closes.P2 * 4 + r.closes.P3 * 2 + r.closes.P4;
  return recs.sort((a, b) => weight(b) - weight(a));
}