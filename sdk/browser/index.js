/**
 * @shieldops/browser: front-end errors for ShieldOps. Uses a browser key (so_pub_…), which can only send errors.
 * No dependencies; never throws into your app.
 */
const VERSION = '0.1.0';
let config = null;
let queue = [];
let timer = null;
let userId;
let sentThisMinute = 0;
let minuteStart = Date.now();

function browserTags() {
  const ua = navigator.userAgent;
  const pick = (rx) => (ua.match(rx) || [])[1];
  const browser = /Edg\//.test(ua) ? `Edge ${pick(/Edg\/(\d+)/)}` : /Firefox\//.test(ua) ? `Firefox ${pick(/Firefox\/(\d+)/)}` : /Chrome\//.test(ua) ? `Chrome ${pick(/Chrome\/(\d+)/)}` : /Safari\//.test(ua) ? `Safari ${pick(/Version\/(\d+(\.\d+)?)/)}` : 'Other';
  const os = /Windows NT 10/.test(ua) ? 'Windows' : /Android (\d+)/.test(ua) ? `Android ${pick(/Android (\d+)/)}` : /iPhone|iPad/.test(ua) ? `iOS ${(pick(/OS (\d+)_/) || '')}` : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Other';
  return { browser, os };
}

/** Chrome/Edge ("at fn (url:1:2)") and Firefox/Safari ("fn@url:1:2") stack lines. */
export function parseStack(stack) {
  const frames = [];
  for (const line of String(stack || '').split('\n')) {
    const m = line.match(/^\s*at (?:(.+?) \()?(.+?):(\d+):(\d+)\)?$/) || line.match(/^(.*?)@(.+?):(\d+):(\d+)$/);
    if (!m) continue;
    let file = m[2];
    let inApp = false;
    try {
      const u = new URL(file, location.href);
      inApp = u.origin === location.origin && !u.pathname.includes('/node_modules/');
      file = u.origin === location.origin ? u.pathname : u.href;
    } catch {
      /* keep as is */
    }
    frames.push({ file: file.slice(0, 500), fn: (m[1] || '<anonymous>').slice(0, 200), line: Number(m[3]), column: Number(m[4]), inApp });
    if (frames.length >= 50) break;
  }
  return frames;
}

function send(useBeacon) {
  if (!config || !queue.length) return;
  const body = JSON.stringify({ events: queue.splice(0, 50) });
  const url = `${config.endpoint}/errors`;
  // The key goes in a header with fetch; sendBeacon cannot set headers, so page-exit sends use keepalive fetch instead.
  try {
    fetch(url, { method: 'POST', keepalive: useBeacon || body.length < 60000, headers: { 'content-type': 'application/json', authorization: `Bearer ${config.key}`, 'x-shieldops-sdk': `browser/${VERSION}` }, body }).catch(() => {});
  } catch {
    /* never break the page */
  }
}

/** Reports an error. Safe to call before init (it is ignored). */
export function captureException(error, context) {
  try {
    if (!config) return;
    const now = Date.now();
    if (now - minuteStart > 60000) {
      minuteStart = now;
      sentThisMinute = 0;
    }
    if (++sentThisMinute > config.maxPerMinute) return;
    const err = error instanceof Error ? error : new Error(typeof error === 'string' ? error : (() => { try { return JSON.stringify(error); } catch { return String(error); } })());
    queue.push({
      type: (err.name || 'Error').slice(0, 200),
      message: String(err.message || '').slice(0, 5000),
      platform: 'browser',
      release: config.release || undefined,
      timestamp: new Date(now).toISOString(),
      stack: parseStack(err.stack),
      request: { method: 'GET', route: location.pathname.slice(0, 300), status: 0 },
      userId: userId != null ? String(userId) : undefined,
      tags: { ...browserTags(), ...(config.environment ? { environment: config.environment } : {}), ...((context && context.tags) || {}) },
    });
    if (queue.length >= 20) send(false);
  } catch {
    /* never break the page */
  }
}

/** Ties later errors to a user. Pass your internal id; ShieldOps stores only a hash. */
export function setUser(id) {
  userId = id;
}

export function init(options) {
  if (config || typeof window === 'undefined') return;
  const o = options || {};
  if (!o.key || !o.endpoint) return;
  config = { key: o.key, endpoint: String(o.endpoint).replace(/\/$/, ''), release: o.release, environment: o.environment, maxPerMinute: o.maxPerMinute || 30 };
  window.addEventListener('error', (e) => {
    if (e.error) captureException(e.error);
    else if (e.message) captureException(new Error(e.message));
  });
  window.addEventListener('unhandledrejection', (e) => captureException(e.reason, { tags: { handled: 'no' } }));
  timer = setInterval(() => send(false), 3000);
  addEventListener('pagehide', () => send(true));
  return { captureException, setUser };
}

export function close() {
  if (timer) clearInterval(timer);
  send(true);
}

export const ShieldOps = { init, captureException, setUser, close };