import { getDomain } from 'tldts';
import { guardedGet } from './probe.js';

/** RDAP is the registries' official replacement for WHOIS. The IANA bootstrap file says which server serves each TLD. */
let bootstrap: { at: number; services: [string[], string[]][] } | null = null;

async function rdapBase(tld: string): Promise<string | null> {
  if (!bootstrap || Date.now() - bootstrap.at > 24 * 3_600_000) {
    const r = await guardedGet('https://data.iana.org/rdap/dns.json', [], { timeoutMs: 10_000, readBody: true, maxBytes: 2 * 1024 * 1024 });
    bootstrap = { at: Date.now(), services: (JSON.parse(r.body) as { services: [string[], string[]][] }).services };
  }
  const svc = bootstrap.services.find(([tlds]) => tlds.includes(tld));
  return svc?.[1].find((u) => u.startsWith('https://')) ?? null;
}

export interface DomainInfo {
  domain: string;
  registrar: string | null;
  expiresAt: string | null;
  source: 'rdap' | 'unavailable';
}

/** Reads the expiry date from an RDAP answer; exported for tests. */
export function parseRdap(json: unknown): { registrar: string | null; expiresAt: string | null } {
  const j = json as { events?: { eventAction: string; eventDate: string }[]; entities?: { roles?: string[]; vcardArray?: [string, [string, unknown, string, string][]] }[] };
  const exp = j.events?.find((e) => e.eventAction === 'expiration')?.eventDate ?? null;
  const reg = j.entities?.find((e) => e.roles?.includes('registrar'));
  const fn = reg?.vcardArray?.[1]?.find((f) => f[0] === 'fn')?.[3] ?? null;
  return { registrar: fn, expiresAt: exp ? new Date(exp).toISOString() : null };
}

export async function lookupDomain(host: string): Promise<DomainInfo> {
  const domain = getDomain(host) ?? host;
  try {
    const base = await rdapBase(domain.split('.').pop()!);
    if (!base) return { domain, registrar: null, expiresAt: null, source: 'unavailable' };
    const r = await guardedGet(`${base.replace(/\/$/, '')}/domain/${domain}`, [], { timeoutMs: 10_000, readBody: true, maxBytes: 512 * 1024 });
    if (r.status !== 200) return { domain, registrar: null, expiresAt: null, source: 'unavailable' };
    const info = parseRdap(JSON.parse(r.body));
    return { domain, ...info, source: info.expiresAt ? 'rdap' : 'unavailable' };
  } catch {
    return { domain, registrar: null, expiresAt: null, source: 'unavailable' };
  }
}