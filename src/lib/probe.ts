import { resolve4, resolve6, resolveCname, resolveMx, resolveNs, resolveTxt, resolveCaa } from 'node:dns/promises';
import { connect as netConnect, isIP } from 'node:net';
import { readFileSync } from 'node:fs';
import { checkServerIdentity, connect as tlsConnect, rootCertificates, type PeerCertificate } from 'node:tls';
import { config } from '../config.js';
import { Agent } from 'undici';
import { ApiError } from './errors.js';
import { resolveSafe } from './net.js';

export type CheckError = 'TIMEOUT' | 'DNS_ERROR' | 'TLS_ERROR' | 'CONNECTION_REFUSED' | 'UNEXPECTED_STATUS' | 'KEYWORD_MISSING' | 'WORKER_ERROR';
type Allow = { cidr: string }[];

/** Turns a network failure into one of the check error codes the frontend knows. */
export function classify(err: unknown): CheckError {
  const e = err as { code?: string; name?: string; cause?: { code?: string }; message?: string };
  const code = e.code ?? e.cause?.code ?? '';
  if (e instanceof ApiError) return e.code === 'DNS_FAILED' ? 'DNS_ERROR' : 'WORKER_ERROR';
  if (e.name === 'TimeoutError' || e.name === 'AbortError' || code === 'ETIMEDOUT' || code === 'UND_ERR_CONNECT_TIMEOUT') return 'TIMEOUT';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'ENODATA' || code === 'ESERVFAIL') return 'DNS_ERROR';
  if (code === 'ECONNREFUSED' || code === 'ECONNRESET' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') return 'CONNECTION_REFUSED';
  if (/CERT|SSL|TLS|self.signed|unable to verify/i.test(`${code} ${e.message ?? ''}`)) return 'TLS_ERROR';
  return 'WORKER_ERROR';
}

/** Public CAs plus WEBHOOK_CA_FILE, for internal endpoints signed by your own certificate authority. */
let extraCa: string[] | null = null;
const trustedCas = () => {
  if (!config.WEBHOOK_CA_FILE) return undefined;
  extraCa ??= [...rootCertificates, readFileSync(config.WEBHOOK_CA_FILE, 'utf8')];
  return extraCa;
};

/** An undici agent whose connections can only go to the addresses that passed the guard. */
function pinnedAgent(addr: string, timeoutMs: number) {
  return new Agent({
    connect: { timeout: timeoutMs, ca: trustedCas(), lookup: (_h, _o, cb) => cb(null, [{ address: addr, family: isIP(addr) === 6 ? 6 : 4 }]) },
    headersTimeout: timeoutMs,
    bodyTimeout: timeoutMs,
  });
}

export interface HttpResult {
  status: number;
  latencyMs: number;
  headers: Headers;
  body: string;
  finalUrl: string;
}

/**
 * GET with the SSRF guard. Redirects are followed by hand (at most 5) so every hop is
 * checked against the allowlist again. The body is capped.
 */
export async function guardedGet(url: string, allow: Allow, opts: { timeoutMs: number; maxBytes?: number; readBody?: boolean }): Promise<HttpResult> {
  const started = performance.now();
  let current = new URL(url);
  for (let hop = 0; hop <= 5; hop++) {
    if (current.protocol !== 'http:' && current.protocol !== 'https:') throw new ApiError(422, 'BAD_URL', 'Only http and https are allowed.');
    const [addr] = await resolveSafe(current.hostname, allow);
    const agent = pinnedAgent(addr, opts.timeoutMs);
    try {
      const res = await fetch(current, {
        redirect: 'manual',
        signal: AbortSignal.timeout(opts.timeoutMs),
        headers: { 'user-agent': 'ShieldOps-Monitor/1.0', accept: 'text/html,application/json;q=0.9,*/*;q=0.8' },
        // @ts-expect-error: Node's fetch accepts an undici dispatcher.
        dispatcher: agent,
      });
      const location = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && location && hop < 5) {
        await res.body?.cancel();
        current = new URL(location, current);
        continue;
      }
      let body = '';
      if (opts.readBody && res.body) {
        const reader = res.body.getReader();
        const max = opts.maxBytes ?? 1024 * 1024;
        const chunks: Uint8Array[] = [];
        let size = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          chunks.push(value);
          if (size >= max) {
            await reader.cancel();
            break;
          }
        }
        body = Buffer.concat(chunks).toString('utf8');
      } else await res.body?.cancel();
      return { status: res.status, latencyMs: Math.round(performance.now() - started), headers: res.headers, body, finalUrl: current.toString() };
    } finally {
      await agent.close();
    }
  }
  throw new ApiError(422, 'TOO_MANY_REDIRECTS', 'More than 5 redirects.');
}

/**
 * POST JSON with the guard and a pinned connection. Redirects are not followed: a webhook that
 * redirects is treated as a failure, so a URL cannot bounce the request somewhere private.
 */
export async function guardedPost(url: string, body: string, headers: Record<string, string>, allow: Allow, timeoutMs = 10_000): Promise<{ status: number; latencyMs: number; text: string }> {
  const u = new URL(url);
  if (u.protocol !== 'https:') throw new ApiError(422, 'BAD_URL', 'Only https:// URLs are allowed.');
  const [addr] = await resolveSafe(u.hostname, allow);
  const agent = pinnedAgent(addr, timeoutMs);
  const started = performance.now();
  try {
    const res = await fetch(u, {
      method: 'POST',
      redirect: 'manual',
      body,
      headers: { 'content-type': 'application/json', 'user-agent': 'ShieldOps-Alerts/1.0', ...headers },
      signal: AbortSignal.timeout(timeoutMs),
      // @ts-expect-error: Node's fetch accepts an undici dispatcher.
      dispatcher: agent,
    });
    const text = (await res.text()).slice(0, 500);
    return { status: res.status, latencyMs: Math.round(performance.now() - started), text };
  } finally {
    await agent.close();
  }
}

/** Opens a TCP connection with the guard; resolves with the connect time. */
export async function guardedTcp(host: string, port: number, allow: Allow, timeoutMs: number): Promise<number> {
  const [addr] = await resolveSafe(host, allow);
  const started = performance.now();
  await new Promise<void>((resolve, reject) => {
    const sock = netConnect({ host: addr, port, timeout: timeoutMs });
    sock.once('connect', () => {
      sock.destroy();
      resolve();
    });
    sock.once('timeout', () => {
      sock.destroy();
      reject(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }));
    });
    sock.once('error', reject);
  });
  return Math.round(performance.now() - started);
}

export type DnsType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'TXT' | 'CAA';

/** Looks up one record type; an empty list means "no records", not an error. */
export async function lookupRecords(host: string, type: DnsType): Promise<{ value: string; ttl: number }[]> {
  const none = (e: { code?: string }) => {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') return [];
    throw e;
  };
  switch (type) {
    case 'A':
      return (await resolve4(host, { ttl: true }).catch(none)).map((r) => ({ value: r.address, ttl: r.ttl }));
    case 'AAAA':
      return (await resolve6(host, { ttl: true }).catch(none)).map((r) => ({ value: r.address, ttl: r.ttl }));
    case 'CNAME':
      return (await resolveCname(host).catch(none)).map((v) => ({ value: v, ttl: 0 }));
    case 'MX':
      return (await resolveMx(host).catch(none)).map((r) => ({ value: `${r.priority} ${r.exchange}`, ttl: 0 }));
    case 'NS':
      return (await resolveNs(host).catch(none)).map((v) => ({ value: v, ttl: 0 }));
    case 'TXT':
      return (await resolveTxt(host).catch(none)).map((r) => ({ value: r.join(''), ttl: 0 }));
    case 'CAA':
      return (await resolveCaa(host).catch(none)).map((r) => ({ value: `${r.critical} ${r.issue ? 'issue' : r.issuewild ? 'issuewild' : 'iodef'} "${r.issue ?? r.issuewild ?? r.iodef ?? ''}"`, ttl: 0 }));
  }
}

export interface TlsInfo {
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  chainValid: boolean;
  hostnameMatch: boolean;
  protocol: string | null;
  cipher: string | null;
}

/** TLS handshake with the guard. `maxVersion` lets us ask whether an old protocol is still accepted. */
export async function tlsHandshake(host: string, port: number, allow: Allow, timeoutMs: number, maxVersion?: 'TLSv1.1'): Promise<TlsInfo> {
  const [addr] = await resolveSafe(host, allow);
  return new Promise((resolve, reject) => {
    const sock = tlsConnect({
      host: addr,
      port,
      servername: isIP(host) ? undefined : host,
      rejectUnauthorized: false,
      timeout: timeoutMs,
      ...(maxVersion ? { maxVersion, minVersion: 'TLSv1' as const, ciphers: 'DEFAULT@SECLEVEL=0' } : {}),
    });
    sock.once('secureConnect', () => {
      const cert = sock.getPeerCertificate(false) as PeerCertificate;
      const has = cert && Object.keys(cert).length > 0;
      const info: TlsInfo = {
        issuer: has ? ([cert.issuer?.O ?? cert.issuer?.CN ?? null].flat()[0] ?? null) : null,
        validFrom: has && cert.valid_from ? new Date(cert.valid_from).toISOString() : null,
        validTo: has && cert.valid_to ? new Date(cert.valid_to).toISOString() : null,
        chainValid: sock.authorized,
        hostnameMatch: has ? checkServerIdentity(host, cert) === undefined : false,
        protocol: sock.getProtocol(),
        cipher: sock.getCipher()?.name ?? null,
      };
      sock.end();
      resolve(info);
    });
    sock.once('timeout', () => {
      sock.destroy();
      reject(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }));
    });
    sock.once('error', reject);
  });
}