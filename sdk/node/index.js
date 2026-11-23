'use strict';
/**
 * @shieldops/node: errors, API performance and security events for ShieldOps.
 * No dependencies. It never throws into your app: if ShieldOps is unreachable, data is dropped, not queued forever.
 */
const { AsyncLocalStorage } = require('node:async_hooks');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const VERSION = '0.2.0';
const LOG_LEVELS = ['debug', 'info', 'warn', 'error'];
const MAX_LOGS_PER_MINUTE = 1000;
/** Must match the ShieldOps server (src/lib/histogram.ts). */
const BOUNDS = [5, 10, 25, 50, 75, 100, 150, 200, 300, 400, 500, 750, 1000, 1500, 2000, 3000, 5000, 7500, 10000];
const MAX_ERRORS_PER_MINUTE = 100;
/** Per-request context: lets the SDK skip its automatic 401/403 report when your code already reported the event. */
const requestContext = new AsyncLocalStorage();

/* ───────────── helpers ───────────── */

function bucketOf(ms) {
  const i = BOUNDS.findIndex((b) => ms <= b);
  return i === -1 ? BOUNDS.length : i;
}

/** "ravi@example.com" → "r***@example.com" */
function maskAccount(v) {
  const s = String(v).trim().toLowerCase();
  const at = s.indexOf('@');
  return at < 1 ? (s.length > 2 ? `${s[0]}***` : '***') : `${s[0]}***${s.slice(at)}`;
}

const hashAccount = (v) => createHash('sha256').update(String(v).trim().toLowerCase()).digest('hex').slice(0, 32);

const sourceCache = new Map();
function sourceLine(abs, line) {
  try {
    let lines = sourceCache.get(abs);
    if (!lines) {
      if (sourceCache.size > 200) sourceCache.clear();
      lines = fs.readFileSync(abs, 'utf8').split('\n');
      sourceCache.set(abs, lines);
    }
    const l = lines[line - 1];
    return l ? l.trim().slice(0, 300) : undefined;
  } catch {
    return undefined;
  }
}

/** V8 stack lines like "    at fn (/app/src/x.js:10:5)" → frames; your own files (not node_modules) are "in app". */
function parseStack(stack) {
  const frames = [];
  for (const line of String(stack || '').split('\n').slice(1)) {
    const m = line.match(/^\s*at (?:(?:async )?(.+?) \()?(.+?):(\d+):(\d+)\)?$/);
    if (!m) continue;
    let file = m[2];
    if (file.startsWith('file://')) file = decodeURIComponent(file.slice(7));
    const absolute = path.isAbsolute(file);
    const inApp = absolute && !file.includes(`${path.sep}node_modules${path.sep}`) && !file.includes('/node_modules/');
    // Paths relative to the app folder read best; files outside it keep their full path.
    const relative = absolute ? path.relative(process.cwd(), file) : file;
    const shown = absolute && relative.startsWith('..') ? file : relative;
    const frame = { file: shown.split(path.sep).join('/').slice(0, 500), fn: (m[1] || '<anonymous>').slice(0, 200), line: Number(m[3]), column: Number(m[4]), inApp };
    if (inApp && frames.filter((f) => f.code).length < 5) frame.code = sourceLine(file, frame.line);
    frames.push(frame);
    if (frames.length >= 50) break;
  }
  return frames;
}

/** The route pattern, like "/users/:id", so one route is one row however many ids it serves. */
function routeOf(req, res) {
  if (req.route && typeof req.route.path === 'string') return `${req.baseUrl || ''}${req.route.path}` || '/';
  if (res && res.statusCode === 404) return '(unmatched)';
  return String(req.path || req.url || '/')
    .split('?')[0]
    .split('/')
    .map((seg) => (/^\d+$|^[0-9a-f]{8}-[0-9a-f-]{27,}$|^[0-9a-f]{16,}$/i.test(seg) ? ':id' : seg))
    .join('/')
    .slice(0, 300);
}

const clientIp = (req) => String(req.ip || (req.socket && req.socket.remoteAddress) || '').replace(/^::ffff:/, '');

/* ───────────── client ───────────── */

class ShieldOpsClient {
  constructor(options) {
    const o = options || {};
    this.key = o.key || '';
    this.endpoint = String(o.endpoint || '').replace(/\/$/, '');
    this.release = o.release ? String(o.release) : '';
    this.environment = o.environment || '';
    this.debug = !!o.debug;
    this.enabled = o.enabled !== false && !!this.key && !!this.endpoint;
    this.errors = [];
    this.securityQueue = [];
    this.logQueue = [];
    this.logsThisMinute = 0;
    this.logMinuteStart = Date.now();
    this.minLogLevel = LOG_LEVELS.includes(o.logLevel) ? o.logLevel : 'info';
    this.routes = new Map();
    this.windowStart = Date.now();
    this.sentThisMinute = 0;
    this.minuteStart = Date.now();
    if (!this.enabled) {
      if (this.debug || (o.key === undefined && process.env.NODE_ENV === 'production')) console.warn('[shieldops] Not sending data: key or endpoint missing.');
      return;
    }
    this.fastTimer = setInterval(() => void this.flushEvents(), o.flushIntervalMs || 5000);
    this.metricsTimer = setInterval(() => void this.flushMetrics(), 60000);
    this.fastTimer.unref();
    this.metricsTimer.unref();
    if (o.captureUnhandled !== false) {
      process.on('unhandledRejection', (reason) => this.captureException(reason, { tags: { handled: 'no' } }));
      // Monitor only: records the crash without changing how your app exits.
      process.on('uncaughtExceptionMonitor', (err) => {
        this.captureException(err, { tags: { handled: 'no', fatal: 'yes' } });
        void this.flushEvents();
      });
    }
    const send = (type) => (d) => this.securityEvent(type, d);
    /** Security events for your login and access code. Pass `account` (email or username) and it is masked and hashed before sending. */
    this.security = {
      loginSucceeded: send('login_success'),
      loginFailed: send('login_failure'),
      logout: send('logout'),
      mfaFailed: send('mfa_failure'),
      passwordReset: send('password_reset'),
      accessDenied: send('authz_failure'),
      rateLimited: send('rate_limited'),
      adminAction: send('admin_action'),
      permissionChanged: send('permission_change'),
      inputRejected: send('input_rejected'),
    };
  }

  log(...args) {
    if (this.debug) console.log('[shieldops]', ...args);
  }

  async post(pathname, body) {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const res = await fetch(`${this.endpoint}${pathname}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${this.key}`, 'user-agent': `shieldops-node/${VERSION}` },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(5000),
        });
        if (res.ok) return true;
        this.log(`POST ${pathname} answered ${res.status}`, await res.text().catch(() => ''));
        if (res.status < 500 && res.status !== 429) return false; // a bad key or bad data will not get better with a retry
      } catch (err) {
        this.log(`POST ${pathname} failed:`, err && err.message);
      }
      await new Promise((r) => setTimeout(r, 1500).unref());
    }
    return false;
  }

  /** Reports an error. `context.request`, `context.userId` and `context.tags` add detail. Returns nothing and never throws. */
  captureException(error, context) {
    try {
      if (!this.enabled) return;
      const now = Date.now();
      if (now - this.minuteStart > 60000) {
        this.minuteStart = now;
        this.sentThisMinute = 0;
      }
      if (++this.sentThisMinute > MAX_ERRORS_PER_MINUTE) return;
      const err = error instanceof Error ? error : new Error(typeof error === 'string' ? error : JSON.stringify(error));
      const c = context || {};
      this.errors.push({
        type: (err.name || 'Error').slice(0, 200),
        message: String(err.message || '').slice(0, 5000),
        platform: 'node',
        release: this.release || undefined,
        timestamp: new Date(now).toISOString(),
        stack: parseStack(err.stack),
        request: c.request,
        userId: c.userId != null ? String(c.userId) : undefined,
        tags: { runtime: `node ${process.versions.node}`, os: os.platform(), ...(this.environment ? { environment: this.environment } : {}), ...(c.tags || {}) },
      });
      if (this.errors.length >= 50) void this.flushEvents();
    } catch {
      /* never break the app */
    }
  }

  securityEvent(type, details, automatic) {
    try {
      if (!this.enabled) return;
      const store = requestContext.getStore();
      if (store) {
        if (automatic && store.reported) return;
        if (!automatic) store.reported = true;
      }
      const d = details || {};
      this.securityQueue.push({
        type,
        timestamp: new Date().toISOString(),
        account: d.account ? maskAccount(d.account) : undefined,
        accountHash: d.account ? hashAccount(d.account) : undefined,
        userId: d.userId != null ? String(d.userId) : undefined,
        ip: d.ip ? String(d.ip).replace(/^::ffff:/, '') : undefined,
        method: d.method,
        route: d.route,
        status: d.status,
        result: d.result,
      });
      if (this.securityQueue.length >= 100) void this.flushEvents();
    } catch {
      /* never break the app */
    }
  }

  recordRequest(method, route, status, ms) {
    const k = `${method} ${route}`;
    let r = this.routes.get(k);
    if (!r) {
      if (this.routes.size >= 500) return;
      r = { method, route, count: 0, errors: 0, sumMs: 0, buckets: new Array(BOUNDS.length + 1).fill(0) };
      this.routes.set(k, r);
    }
    r.count += 1;
    if (status >= 500) r.errors += 1;
    r.sumMs += ms;
    r.buckets[bucketOf(ms)] += 1;
  }

  /** Express middleware: put it before your routes. Times every request and records its route. */
  requestHandler() {
    return (req, res, next) => {
      if (!this.enabled) return next();
      const start = process.hrtime.bigint();
      const store = { reported: false };
      res.on('finish', () => {
        try {
          const ms = Number(process.hrtime.bigint() - start) / 1e6;
          const route = routeOf(req, res);
          this.recordRequest(req.method, route, res.statusCode, ms);
          // Skipped when your code already reported this request (e.g. loginFailed on a login route that returns 401).
          if (!store.reported && (res.statusCode === 401 || res.statusCode === 403)) this.securityEvent('authz_failure', { ip: clientIp(req), method: req.method, route, status: res.statusCode }, true);
          else if (!store.reported && res.statusCode === 429) this.securityEvent('rate_limited', { ip: clientIp(req), method: req.method, route, status: 429 }, true);
        } catch {
          /* never break the app */
        }
      });
      requestContext.run(store, next);
    };
  }

  /** Express error middleware: put it after your routes. Reports server errors, then passes them on unchanged. */
  errorHandler() {
    return (err, req, res, next) => {
      const status = Number((err && (err.status || err.statusCode)) || 500);
      if (status >= 500) {
        this.captureException(err, { request: { method: req.method, route: routeOf(req, res), status }, userId: req.user && (req.user.id || req.user._id) });
      }
      next(err);
    };
  }

  /**
   * Queues a log line. Fields are flat strings (values are converted). Lines below logLevel (default
   * "info") are dropped, as are lines beyond 1000 a minute, so a loop cannot flood ShieldOps.
   */
  log(level, message, fields) {
    try {
      if (!this.enabled || LOG_LEVELS.indexOf(level) < LOG_LEVELS.indexOf(this.minLogLevel)) return;
      const now = Date.now();
      if (now - this.logMinuteStart > 60000) {
        this.logMinuteStart = now;
        this.logsThisMinute = 0;
      }
      if (++this.logsThisMinute > MAX_LOGS_PER_MINUTE) return;
      const flat = {};
      for (const [k, v] of Object.entries(fields || {}).slice(0, 30)) flat[String(k).slice(0, 100)] = typeof v === 'string' ? v.slice(0, 1000) : JSON.stringify(v === undefined ? null : v).slice(0, 1000);
      if (this.environment && !flat.env) flat.env = String(this.environment);
      this.logQueue.push({ level, message: String(message).slice(0, 8000), timestamp: new Date(now).toISOString(), host: os.hostname(), fields: flat });
      if (this.logQueue.length >= 500) void this.flushEvents();
    } catch {
      /* never throw into the app */
    }
  }

  async flushEvents() {
    const errors = this.errors.splice(0, 50);
    const security = this.securityQueue.splice(0, 100);
    const logs = this.logQueue.splice(0, 500);
    await Promise.all([
      errors.length ? this.post('/errors', { events: errors }) : null,
      security.length ? this.post('/security', { events: security }) : null,
      logs.length ? this.post('/logs', { logs }) : null,
    ]);
  }

  async flushMetrics() {
    if (!this.routes.size) {
      this.windowStart = Date.now();
      return;
    }
    const routes = [...this.routes.values()];
    const windowStart = new Date(this.windowStart).toISOString();
    const windowSec = Math.max(1, Math.round((Date.now() - this.windowStart) / 1000));
    this.routes = new Map();
    this.windowStart = Date.now();
    await this.post('/metrics', { windowStart, windowSec: Math.min(windowSec, 600), routes });
  }

  /** Sends everything waiting now. Call before your process exits on purpose. */
  async flush() {
    if (!this.enabled) return;
    await Promise.all([this.flushEvents(), this.flushMetrics()]);
  }

  async close() {
    clearInterval(this.fastTimer);
    clearInterval(this.metricsTimer);
    await this.flush();
  }
}

const ShieldOps = {
  instance: null,
  /** Creates the client once; later calls return the same one. */
  init(options) {
    if (!this.instance) this.instance = new ShieldOpsClient(options);
    return this.instance;
  },
  captureException(error, context) {
    if (this.instance) this.instance.captureException(error, context);
  },
  /** Structured logs, searchable on the Logs page for 14 days: ShieldOps.logger.info('Order paid', { orderId }). */
  logger: Object.fromEntries(LOG_LEVELS.map((level) => [level, (message, fields) => ShieldOps.instance && ShieldOps.instance.log(level, message, fields)])),
};

module.exports = { ShieldOps, ShieldOpsClient, parseStack, routeOf };