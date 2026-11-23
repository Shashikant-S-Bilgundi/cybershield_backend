import { resolveSrv } from 'node:dns/promises';
import { connect as netConnect, isIP, type Socket } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { MongoClient } from 'mongodb';
import mysql from 'mysql2/promise';
import pg from 'pg';
import { decrypt } from '../lib/crypto.js';
import { ApiError } from '../lib/errors.js';
import { logger } from '../lib/logger.js';
import { resolveSafe } from '../lib/net.js';
import { DbCheck, type DbCheckDoc } from '../models/Infra.js';
import { autoResolve, raiseAlert } from './alerts.js';
import { getAllowlist } from './settings.js';

const TIMEOUT = 8000;

export interface DbStats {
  connections: number;
  maxConnections: number;
  sizeGb: number;
  role: 'primary' | 'replica' | 'standalone';
  replicationLagSec: number | null;
}

interface Target {
  engine: string;
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
}

const gb = (bytes: number) => Math.round((bytes / 1024 ** 3) * 100) / 100;

/** Maps driver errors to a sentence a person can act on; never echoes the password. */
function explain(err: unknown, t: Target): string {
  const e = err as { code?: string; message?: string };
  const m = (e.message ?? '').replaceAll(t.password, '***');
  if (err instanceof ApiError) return err.message;
  if (e.code === 'ECONNREFUSED') return `Connection refused on ${t.host}:${t.port}. Is the database running and listening there?`;
  if (e.code === 'ETIMEDOUT' || /timeout|timed out/i.test(m)) return `No answer from ${t.host}:${t.port} within ${TIMEOUT / 1000} seconds. Check the firewall allows ShieldOps.`;
  if (e.code === 'ENOTFOUND') return `${t.host} does not resolve.`;
  if (/password|auth|denied|28P01|ER_ACCESS_DENIED|WRONGPASS|NOAUTH/i.test(`${e.code} ${m}`)) return 'The username or password was rejected.';
  if (/does not exist|unknown database|3D000|ER_BAD_DB/i.test(`${e.code} ${m}`)) return `The database "${t.database}" does not exist or the account cannot connect to it.`;
  return m.slice(0, 300) || 'The check failed.';
}

async function postgres(t: Target, addr: string): Promise<DbStats | null> {
  // Encrypted if the server supports it, plain otherwise (sslmode=prefer).
  const attempt = async (ssl: boolean) => {
    const c = new pg.Client({ host: addr, port: t.port, user: t.username, password: t.password, database: t.database || 'postgres', connectionTimeoutMillis: TIMEOUT, query_timeout: TIMEOUT, ssl: ssl ? { servername: isIP(t.host) ? undefined : t.host, rejectUnauthorized: false } : false });
    await c.connect();
    return c;
  };
  const client = await attempt(true).catch((e: Error) => (/does not support SSL|SSL off/i.test(e.message) ? attempt(false) : Promise.reject(e)));
  try {
    await client.query('SELECT 1');
    // One query at a time: a pg connection runs queries in order anyway.
    const stats = await (async () => {
      const q = (sql: string) => client.query(sql);
      return [
        await q('SELECT count(*)::int AS n FROM pg_stat_activity'),
        await q('SHOW max_connections'),
        await q('SELECT pg_database_size(current_database())::bigint AS b'),
        await q("SELECT pg_is_in_recovery() AS r, CASE WHEN pg_is_in_recovery() THEN EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp()) END AS lag"),
      ];
    })().catch(() => null);
    if (!stats) return null;
    const replica = stats[3].rows[0].r as boolean;
    return { connections: stats[0].rows[0].n, maxConnections: Number(stats[1].rows[0].max_connections), sizeGb: gb(Number(stats[2].rows[0].b)), role: replica ? 'replica' : 'standalone', replicationLagSec: replica && stats[3].rows[0].lag != null ? Math.round(Number(stats[3].rows[0].lag)) : null };
  } finally {
    await client.end().catch(() => {});
  }
}

async function mysqlCheck(t: Target, addr: string): Promise<DbStats | null> {
  const attempt = (ssl: boolean) => mysql.createConnection({ host: addr, port: t.port, user: t.username, password: t.password, database: t.database || undefined, connectTimeout: TIMEOUT, ssl: ssl ? { rejectUnauthorized: false } : undefined });
  const conn = await attempt(true).catch((e: Error) => (/secure connection|SSL/i.test(e.message) ? attempt(false) : Promise.reject(e)));
  try {
    await conn.query('SELECT 1');
    const [threads] = (await conn.query("SHOW GLOBAL STATUS LIKE 'Threads_connected'").catch(() => [[]])) as [{ Value: string }[]];
    const [vars] = (await conn.query('SELECT @@max_connections AS m, @@read_only AS ro').catch(() => [[]])) as [{ m: number; ro: number }[]];
    const [size] = (await conn.query('SELECT COALESCE(SUM(data_length + index_length), 0) AS b FROM information_schema.tables WHERE table_schema = DATABASE()').catch(() => [[]])) as [{ b: number }[]];
    if (!threads[0] || !vars[0]) return null;
    return { connections: Number(threads[0].Value), maxConnections: Number(vars[0].m), sizeGb: gb(Number(size[0]?.b ?? 0)), role: vars[0].ro ? 'replica' : 'standalone', replicationLagSec: null };
  } finally {
    await conn.end().catch(() => {});
  }
}

async function mongo(t: Target, addr: string | null): Promise<DbStats | null> {
  const cred = `${encodeURIComponent(t.username)}:${encodeURIComponent(t.password)}@`;
  // Atlas-style hosts use DNS SRV records and always TLS; everything else connects directly to the checked address.
  const uri = addr === null ? `mongodb+srv://${cred}${t.host}/${t.database || 'admin'}?serverSelectionTimeoutMS=${TIMEOUT}` : `mongodb://${cred}${isIP(addr) === 6 ? `[${addr}]` : addr}:${t.port}/${t.database || 'admin'}?directConnection=true&serverSelectionTimeoutMS=${TIMEOUT}&connectTimeoutMS=${TIMEOUT}`;
  const client = new MongoClient(uri);
  try {
    await client.connect();
    const admin = client.db('admin');
    await admin.command({ ping: 1 });
    const status = await admin.command({ serverStatus: 1 }).catch(() => null);
    const hello = await admin.command({ hello: 1 }).catch(() => null);
    const dbs = await client.db(t.database || 'admin').command({ dbStats: 1 }).catch(() => null);
    if (!status) return null;
    const role = hello?.setName ? (hello.isWritablePrimary ? 'primary' : 'replica') : 'standalone';
    return { connections: status.connections?.current ?? 0, maxConnections: (status.connections?.current ?? 0) + (status.connections?.available ?? 0), sizeGb: gb((dbs?.dataSize ?? 0) + (dbs?.indexSize ?? 0)), role, replicationLagSec: null };
  } finally {
    await client.close().catch(() => {});
  }
}

/** A tiny Redis client: AUTH, PING and INFO are all a health check needs. Tries plain, then TLS (e.g. Upstash). */
async function redis(t: Target, addr: string): Promise<DbStats | null> {
  const talk = (useTls: boolean) =>
    new Promise<Record<string, string>>((resolve, reject) => {
      const sock: Socket = useTls ? tlsConnect({ host: addr, port: t.port, servername: isIP(t.host) ? undefined : t.host, rejectUnauthorized: false }) : netConnect({ host: addr, port: t.port });
      const timer = setTimeout(() => (sock.destroy(), reject(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }))), TIMEOUT);
      let buf = '';
      const cmd = (...args: string[]) => `*${args.length}\r\n${args.map((a) => `$${Buffer.byteLength(a)}\r\n${a}\r\n`).join('')}`;
      sock.once(useTls ? 'secureConnect' : 'connect', () => {
        const auth = t.password ? (t.username && t.username !== 'default' ? cmd('AUTH', t.username, t.password) : cmd('AUTH', t.password)) : '';
        sock.write(auth + cmd('PING') + cmd('INFO'));
      });
      sock.on('data', (d) => {
        buf += d.toString('utf8');
        if (/^-/m.test(buf) && !buf.includes('+PONG')) {
          clearTimeout(timer);
          sock.destroy();
          return reject(new Error(buf.match(/^-(.*)$/m)?.[1] ?? 'Redis error'));
        }
        const m = buf.match(/\$(\d+)\r\n/);
        if (buf.includes('+PONG') && m && buf.length >= buf.indexOf(m[0]) + m[0].length + Number(m[1])) {
          clearTimeout(timer);
          sock.end();
          const info = Object.fromEntries(buf.split('\r\n').filter((l) => l.includes(':')).map((l) => [l.slice(0, l.indexOf(':')), l.slice(l.indexOf(':') + 1)]));
          resolve(info);
        }
      });
      sock.once('error', (e) => (clearTimeout(timer), reject(e)));
      sock.once('close', () => (clearTimeout(timer), reject(Object.assign(new Error('Connection closed'), { code: 'ECONNRESET' }))));
    });
  const info = await talk(false).catch((e: { code?: string }) => (e.code === 'ECONNRESET' ? talk(true) : Promise.reject(e)));
  const role = info.role === 'slave' ? 'replica' : info.connected_slaves && info.connected_slaves !== '0' ? 'primary' : 'standalone';
  return { connections: Number(info.connected_clients ?? 0), maxConnections: Number(info.maxclients ?? 0), sizeGb: gb(Number(info.used_memory ?? 0)), role, replicationLagSec: info.master_last_io_seconds_ago ? Number(info.master_last_io_seconds_ago) : null };
}

/**
 * Connects with the read-only account, pings, reads basic stats, disconnects.
 * The host must pass the network guard (private addresses only inside the allowlist), and the
 * connection goes to the checked address. SRV hosts (MongoDB Atlas) have each target checked.
 */
export async function probeDb(t: Target): Promise<{ ok: true; latencyMs: number; stats: DbStats | null } | { ok: false; latencyMs: null; error: string }> {
  const allow = await getAllowlist();
  const started = performance.now();
  try {
    if (t.engine === 'mongodb' && /\.mongodb\.net$/i.test(t.host)) {
      const targets = await resolveSrv(`_mongodb._tcp.${t.host}`);
      for (const s of targets) await resolveSafe(s.name, allow);
      const stats = await mongo(t, null);
      return { ok: true, latencyMs: Math.round(performance.now() - started), stats };
    }
    const [addr] = await resolveSafe(t.host, allow);
    const stats = t.engine === 'postgresql' ? await postgres(t, addr) : t.engine === 'mysql' ? await mysqlCheck(t, addr) : t.engine === 'mongodb' ? await mongo(t, addr) : await redis(t, addr);
    return { ok: true, latencyMs: Math.round(performance.now() - started), stats };
  } catch (err) {
    return { ok: false, latencyMs: null, error: explain(err, t) };
  }
}

export async function runDbCheck(d: DbCheckDoc) {
  const out = await probeDb({ engine: d.engine, host: d.host, port: d.port, database: d.database ?? '', username: d.username ?? '', password: decrypt(d.passwordEnc) });
  d.lastCheckAt = new Date();
  d.latency.push(out.latencyMs);
  d.latency.splice(0, Math.max(0, d.latency.length - 30));
  const key = `db:${d.id}`;
  if (out.ok) {
    d.consecutiveFailures = 0;
    d.status = out.latencyMs > 1000 ? 'degraded' : 'up';
    d.lastLatencyMs = out.latencyMs;
    d.error = null;
    if (out.stats) d.stats = out.stats as never;
    await d.save();
    await autoResolve(key);
  } else {
    d.consecutiveFailures += 1;
    d.lastLatencyMs = null;
    d.error = out.error;
    d.status = d.consecutiveFailures >= 2 ? 'down' : 'degraded';
    await d.save();
    await raiseAlert({ key, signal: 'db_down', value: d.consecutiveFailures, applicationId: d.applicationId, environmentId: d.environmentId, assetId: d.assetId, source: 'database', title: `${d.name} is not responding`, message: `${d.engine} at ${d.host}:${d.port}: ${out.error}` });
  }
  return d;
}

export async function runDueDbChecks(limit = 10) {
  const jobs: Promise<unknown>[] = [];
  for (let i = 0; i < limit; i++) {
    const now = new Date();
    const d = await DbCheck.findOneAndUpdate({ paused: false, deletedAt: null, nextCheckAt: { $lte: now } }, [{ $set: { nextCheckAt: { $add: [now, { $multiply: ['$intervalSec', 1000] }] } } }], { new: true });
    if (!d) break;
    jobs.push(runDbCheck(d).catch((err) => logger.error({ err, check: d.id }, 'Database check failed')));
  }
  await Promise.all(jobs);
}