import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { Agent } from 'undici';
import { ApiError } from './errors.js';

const ipv4ToInt = (ip: string) => ip.split('.').reduce((acc, p) => (acc << 8) + Number(p), 0) >>> 0;

export function ipv4InCidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split('/');
  if (isIP(ip) !== 4 || isIP(range) !== 4) return false;
  const bits = Number(bitsStr);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(range) & mask);
}

export function isValidCidr(value: string): boolean {
  const [ip, bits] = value.trim().split('/');
  if (!ip || bits === undefined || !/^\d+$/.test(bits)) return false;
  if (isIP(ip) === 4) return Number(bits) >= 8 && Number(bits) <= 32;
  return isIP(ip) === 6 && Number(bits) >= 16 && Number(bits) <= 128;
}

const PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10', '0.0.0.0/8'];
/** Cloud metadata endpoints: never reachable, even if someone allowlists their range. */
const ALWAYS_BLOCKED = ['169.254.169.254', '169.254.170.2', 'fd00:ec2::254', '100.100.100.200'];

export function isPrivate(ip: string): boolean {
  if (isIP(ip) === 4) return PRIVATE_V4.some((c) => ipv4InCidr(ip, c));
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivate(v.slice(7));
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
}

/** Pulls a bare host out of a URL, connection string or plain host. */
export function hostOf(identifier: string): string {
  const v = identifier.trim();
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return new URL(v.replace(/^[a-z0-9+.-]+:\/\//i, 'http://')).hostname.replace(/^\[|\]$/g, '');
  } catch {
    /* fall through */
  }
  return v.split('/')[0].split(':')[0];
}

/**
 * Resolves a host and checks every address: private and internal addresses are allowed
 * only inside the Internal Network Allowlist, and metadata addresses never.
 * Every outbound check must go through this (section 15 of the requirements).
 */
export async function resolveSafe(host: string, allowlist: { cidr: string }[]): Promise<string[]> {
  const addrs = isIP(host) ? [host] : (await lookup(host, { all: true, verbatim: true }).catch(() => [])).map((a) => a.address);
  if (!addrs.length) throw new ApiError(422, 'DNS_FAILED', `${host} does not resolve to an address.`);
  for (const ip of addrs) {
    if (ALWAYS_BLOCKED.includes(ip.toLowerCase())) throw new ApiError(422, 'BLOCKED_TARGET', `${host} points at a blocked address.`);
    if (isPrivate(ip) && !allowlist.some((r) => ipv4InCidr(ip, r.cidr))) {
      throw new ApiError(422, 'NOT_IN_ALLOWLIST', `${host} resolves to ${ip}, a private address outside the Internal Network Allowlist.`);
    }
  }
  return addrs;
}

/**
 * GET a URL with the SSRF guard, a timeout, no redirects and a body size cap.
 * The connection is pinned to the addresses that passed the check, so a DNS answer
 * that changes between the check and the request (DNS rebinding) cannot reach a private host.
 */
export async function safeGet(url: string, allowlist: { cidr: string }[], opts: { timeoutMs?: number; maxBytes?: number } = {}): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new ApiError(422, 'BAD_URL', 'Only http and https are allowed.');
  const addrs = await resolveSafe(u.hostname, allowlist);
  const dispatcher = new Agent({
    connect: {
      lookup: (_host, _opts, cb) => cb(null, [{ address: addrs[0], family: isIP(addrs[0]) === 6 ? 6 : 4 }]),
    },
  });
  try {
    const res = await fetch(u, {
      redirect: 'manual',
      signal: AbortSignal.timeout(opts.timeoutMs ?? 5000),
      headers: { 'user-agent': 'ShieldOps-Verifier/1.0' },
      // @ts-expect-error: Node's fetch accepts an undici dispatcher.
      dispatcher,
    }).catch((e: Error) => {
      throw new ApiError(422, 'FETCH_FAILED', `Could not reach ${u.host}: ${e.name === 'TimeoutError' ? 'timed out' : e.message}`);
    });
    const reader = res.body?.getReader();
    const max = opts.maxBytes ?? 64 * 1024;
    let size = 0;
    const chunks: Uint8Array[] = [];
    while (reader) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) {
        await reader.cancel();
        break;
      }
      chunks.push(value);
    }
    return { status: res.status, body: Buffer.concat(chunks).toString('utf8') };
  } finally {
    await dispatcher.close();
  }
}