import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { config } from '../config.js';

/* ───────────── running ───────────── */

/** SCANNER_BIN_DIR applies to the three scanners only; git and everything else come from PATH. */
const SCANNER_BINARIES = new Set(['gitleaks', 'osv-scanner', 'trivy']);
const bin = (name: string) => (config.SCANNER_BIN_DIR && SCANNER_BINARIES.has(name) ? join(config.SCANNER_BIN_DIR, name) : name);
export const cacheDir = () => config.SCAN_CACHE_DIR || join(homedir(), '.cache', 'shieldops-scanners');

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Runs a scanner with a time limit and a minimal environment: only PATH, HOME and proxy settings
 * plus what the caller adds. ShieldOps' own secrets (database, encryption key) are never passed on.
 */
export function run(name: string, args: string[], opts: { cwd?: string; env?: Record<string, string>; timeoutMs?: number } = {}): Promise<RunResult> {
  const env: Record<string, string> = { PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin', HOME: process.env.HOME ?? homedir() };
  for (const k of ['HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy', 'SYSTEMROOT', 'TEMP', 'TMP']) if (process.env[k]) env[k] = process.env[k]!;
  return new Promise((resolve, reject) => {
    execFile(bin(name), args, { cwd: opts.cwd, env: { ...env, ...opts.env }, timeout: opts.timeoutMs ?? config.SCAN_TIMEOUT_SEC * 1000, maxBuffer: 256 * 1024 * 1024, killSignal: 'SIGKILL' }, (err, stdout, stderr) => {
      const e = err as (NodeJS.ErrnoException & { killed?: boolean; code?: number | string }) | null;
      if (e?.code === 'ENOENT') return reject(new ScannerError(SCANNER_BINARIES.has(name) ? `${name} is not installed on the ShieldOps server. Run scripts/install-scanners.sh.` : `${name} is not installed on the ShieldOps server (apt install ${name}).`));
      if (e?.killed) return reject(new ScannerError(`Timed out after ${Math.round((opts.timeoutMs ?? config.SCAN_TIMEOUT_SEC * 1000) / 1000)} s.`));
      resolve({ code: typeof e?.code === 'number' ? e.code : 0, stdout, stderr });
    });
  });
}

export class ScannerError extends Error {}

/** The line that says what went wrong (not progress chatter), without anything that looks like a token. */
export const tail = (s: string) => {
  const lines = s.split('\n').map((l) => l.trim()).filter(Boolean);
  const errorLine = [...lines].reverse().find((l) => /error|fatal|fail|denied|unauthori[sz]ed|forbidden|not found|timeout|refused/i.test(l));
  return (errorLine ?? lines.slice(-2).join(' ')).replace(/(x-access-token:|token[=: ]+|password[=: ]+)\S+/gi, '$1***').slice(0, 400);
};

/** Turns the usual scanner failures into a sentence that says what to do. */
export function explainFailure(scanner: 'gitleaks' | 'osv-scanner' | 'trivy', stderr: string, code: number): string {
  const t = tail(stderr);
  if (/max retries|dial tcp|no such host|i\/o timeout|connection refused|network is unreachable|TLS handshake timeout/i.test(stderr)) {
    if (scanner === 'osv-scanner') return 'Could not reach the OSV vulnerability database (api.osv.dev). Check that the ShieldOps server can make outbound HTTPS requests.';
    if (scanner === 'trivy') return 'Trivy could not download its vulnerability database or the image (mirror.gcr.io, ghcr.io or the registry). Check the server\'s outbound HTTPS access.';
  }
  if (scanner === 'trivy' && /unauthorized|denied|authentication required/i.test(stderr)) return 'The registry refused access to this image. Check the image name and that the registry connection can read it.';
  if (scanner === 'trivy' && /MANIFEST_UNKNOWN|manifest unknown|not found/i.test(stderr)) return 'The image or tag was not found in the registry.';
  return t || `${scanner} exited with code ${code}`;
}

const versions = new Map<string, string>();
export async function versionOf(name: 'gitleaks' | 'osv-scanner' | 'trivy'): Promise<string> {
  if (versions.has(name)) return versions.get(name)!;
  const r = await run(name, name === 'gitleaks' ? ['version'] : ['--version'], { timeoutMs: 15_000 }).catch(() => null);
  const v = r?.stdout.match(/(\d+\.\d+\.\d+)/)?.[1] ?? '';
  if (v) versions.set(name, v);
  return v;
}

/* ───────────── severity helpers ───────────── */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export const fromCvss = (score: number | null): Severity => (score === null ? 'medium' : score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'info');

/* ───────────── gitleaks ───────────── */

export interface SecretHit {
  hash: string;
  rule: string;
  description: string;
  masked: string;
  file: string;
  line: number;
  commit: string;
  author: string;
  committedAt: string;
  inCurrentCode: boolean;
}

/** First 4 and last 2 characters only. The full value is dropped here and never stored. */
export const maskSecret = (s: string) => (s.length <= 8 ? '****' : `${s.slice(0, 4)}${'•'.repeat(Math.min(12, s.length - 6))}${s.slice(-2)}`);

/**
 * One entry per distinct secret: the same key committed several times is one problem.
 * The newest sighting decides where it is shown; it is "in current code" if HEAD still contains it.
 */
export function parseGitleaks(json: unknown, currentFiles: Map<string, string>): SecretHit[] {
  const rows = Array.isArray(json) ? (json as Record<string, unknown>[]) : [];
  const byHash = new Map<string, SecretHit>();
  for (const r of rows) {
    const secret = String(r.Secret ?? r.Match ?? '');
    if (!secret) continue;
    const hash = createHash('sha256').update(secret).digest('hex').slice(0, 16);
    const file = String(r.File ?? '');
    const hit: SecretHit = {
      hash, rule: String(r.RuleID ?? 'secret'), description: String(r.Description ?? '').slice(0, 300), masked: maskSecret(secret), file, line: Number(r.StartLine ?? 0),
      commit: String(r.Commit ?? '').slice(0, 40), author: String(r.Author ?? ''), committedAt: String(r.Date ?? ''), inCurrentCode: currentFiles.get(file)?.includes(secret) ?? false,
    };
    const prev = byHash.get(hash);
    if (!prev || hit.inCurrentCode || (!prev.inCurrentCode && hit.committedAt > prev.committedAt)) byHash.set(hash, { ...hit, inCurrentCode: hit.inCurrentCode || (prev?.inCurrentCode ?? false) });
  }
  return [...byHash.values()];
}

/** Keys that open cloud accounts or payments are critical while still in the code. */
const HIGH_IMPACT = /aws|gcp|google|azure|private-key|stripe|github|gitlab|slack|twilio|sendgrid|mailgun|digitalocean|heroku|npm|pypi|square|paypal|razorpay/i;
export const secretSeverity = (h: SecretHit): Severity => (h.inCurrentCode ? (HIGH_IMPACT.test(h.rule) ? 'critical' : 'high') : 'medium');

/* ───────────── OSV-Scanner ───────────── */

export interface VulnHit {
  vulnId: string;
  aliases: string[];
  package: string;
  ecosystem: 'npm' | 'alpine' | 'debian' | 'pypi' | 'go';
  installed: string;
  fixedIn: string | null;
  cvss: number | null;
  severity: Severity;
  summary: string;
  source: string;
}

const ECOSYSTEMS: Record<string, VulnHit['ecosystem']> = { npm: 'npm', PyPI: 'pypi', Go: 'go', Alpine: 'alpine', Debian: 'debian', pypi: 'pypi', golang: 'go', gomod: 'go', alpine: 'alpine', debian: 'debian', ubuntu: 'debian', 'node-pkg': 'npm', yarn: 'npm', pnpm: 'npm', pip: 'pypi', pipenv: 'pypi', poetry: 'pypi' };

const numberOr = (v: unknown) => {
  const n = Number.parseFloat(String(v ?? ''));
  return Number.isFinite(n) ? n : null;
};

/** osv-scanner --format json: results[].packages[] with vulnerabilities and groups (aliases, max severity). */
export function parseOsv(json: unknown): { packages: number; vulns: VulnHit[] } {
  const results = ((json as { results?: unknown[] })?.results ?? []) as { source?: { path?: string }; packages?: Record<string, unknown>[] }[];
  const vulns: VulnHit[] = [];
  let packages = 0;
  for (const res of results) {
    for (const p of res.packages ?? []) {
      packages++;
      const pkg = p.package as { name: string; version: string; ecosystem: string };
      const eco = ECOSYSTEMS[pkg?.ecosystem];
      if (!eco) continue;
      const groups = (p.groups ?? []) as { ids: string[]; aliases?: string[]; max_severity?: string }[];
      const records = (p.vulnerabilities ?? []) as { id: string; aliases?: string[]; summary?: string; affected?: { package?: { name: string }; ranges?: { events?: { fixed?: string }[] }[] }[] }[];
      for (const g of groups) {
        const rec = records.find((r) => g.ids.includes(r.id));
        const ids = [...new Set([...g.ids, ...(g.aliases ?? [])])];
        const cve = ids.find((i) => i.startsWith('CVE-'));
        const fixes = (rec?.affected ?? []).filter((a) => !a.package || a.package.name === pkg.name).flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed).filter(Boolean))) as string[];
        const cvss = numberOr(g.max_severity);
        vulns.push({ vulnId: cve ?? g.ids[0], aliases: ids.filter((i) => i !== (cve ?? g.ids[0])), package: pkg.name, ecosystem: eco, installed: pkg.version, fixedIn: fixes.sort(compareVersions).at(-1) ?? null, cvss, severity: fromCvss(cvss), summary: rec?.summary ?? '', source: res.source?.path ?? '' });
      }
    }
  }
  return { packages, vulns };
}

/** Rough semantic-version comparison, good enough to pick the highest "fixed in" version. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  const pb = b.split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    return String(x).localeCompare(String(y));
  }
  return 0;
}

/* ───────────── Trivy ───────────── */

const TRIVY_SEV: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', UNKNOWN: 'info' };

export interface MisconfigHit {
  checkId: string;
  title: string;
  description: string;
  resolution: string;
  severity: Severity;
  file: string;
  line: number | null;
}

/** trivy fs --scanners misconfig: failing checks only. */
export function parseTrivyMisconfig(json: unknown): MisconfigHit[] {
  const out: MisconfigHit[] = [];
  for (const r of ((json as { Results?: unknown[] })?.Results ?? []) as { Target: string; Misconfigurations?: Record<string, unknown>[] }[]) {
    for (const m of r.Misconfigurations ?? []) {
      if (m.Status !== 'FAIL') continue;
      out.push({ checkId: String(m.ID ?? m.AVDID ?? 'check'), title: String(m.Title ?? ''), description: String(m.Description ?? '').slice(0, 600), resolution: String(m.Resolution ?? '').slice(0, 300), severity: TRIVY_SEV[String(m.Severity)] ?? 'medium', file: r.Target, line: ((m.CauseMetadata as { StartLine?: number })?.StartLine ?? null) || null });
    }
  }
  return out;
}

/** trivy image --scanners vuln: OS and language packages in the image. */
export function parseTrivyImage(json: unknown): { digest: string; os: string; sizeMb: number; vulns: VulnHit[] } {
  const d = (json ?? {}) as { Metadata?: { OS?: { Family?: string; Name?: string }; RepoDigests?: string[]; ImageID?: string; Size?: number }; Results?: { Target: string; Type?: string; Vulnerabilities?: Record<string, unknown>[] }[] };
  const vulns: VulnHit[] = [];
  for (const r of d.Results ?? []) {
    for (const v of r.Vulnerabilities ?? []) {
      const eco = ECOSYSTEMS[String(r.Type ?? '')] ?? (['alpine', 'wolfi', 'chainguard'].includes(String(r.Type)) ? 'alpine' : ['debian', 'ubuntu'].includes(String(r.Type)) ? 'debian' : undefined);
      if (!eco) continue;
      const cvssScores = Object.values((v.CVSS ?? {}) as Record<string, { V3Score?: number; V2Score?: number }>).map((c) => c.V3Score ?? c.V2Score ?? null).filter((n): n is number => n !== null);
      const sev = TRIVY_SEV[String(v.Severity)] ?? 'medium';
      vulns.push({ vulnId: String(v.VulnerabilityID), aliases: [], package: String(v.PkgName), ecosystem: eco, installed: String(v.InstalledVersion ?? ''), fixedIn: (String(v.FixedVersion ?? '').split(',')[0].trim() || null), cvss: cvssScores.length ? Math.max(...cvssScores) : null, severity: sev, summary: String(v.Title ?? '').slice(0, 300), source: r.Target });
    }
  }
  const os = d.Metadata?.OS ? `${d.Metadata.OS.Family ?? ''} ${d.Metadata.OS.Name ?? ''}`.trim() : '';
  const digest = d.Metadata?.RepoDigests?.[0]?.split('@')[1] ?? d.Metadata?.ImageID ?? '';
  return { digest, os, sizeMb: d.Metadata?.Size ? Math.round(d.Metadata.Size / 1024 / 1024) : 0, vulns };
}

export const readJson = async (path: string) => JSON.parse(await readFile(path, 'utf8'));