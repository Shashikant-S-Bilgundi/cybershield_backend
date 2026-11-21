# ShieldOps API

The backend for ShieldOps: Express 5, TypeScript and MongoDB. It implements `src/api/contract.ts` from the frontend; the frontend's mock (`src/api/mock`) is the reference for how each endpoint behaves.

## What is built (backend phases 1 to 3)

| Area | Endpoints |
| --- | --- |
| First-time setup | `GET /setup/status`, `POST /setup` |
| Sign-in | `POST /auth/login`, `GET /auth/me`, `POST /auth/logout`, `POST /auth/reauth`, `GET /auth/sso/config` |
| Invites and team | `GET/POST /invites`, `DELETE /invites/:id`, `GET /invites/:token`, `POST /invites/:token/accept`, `GET /users`, `PATCH /users/:id/status`, `DELETE /users/:id` |
| Applications | `GET/POST /applications`, `GET/PATCH/DELETE /applications/:id`, `PATCH /applications/:id/status` |
| Assets | `GET/POST /assets`, `POST /assets/:id/verify`, `POST /assets/:id/approve`, `PATCH /assets/:id/status`, `DELETE /assets/:id` |
| Audit log | `GET /audit-logs`, `POST /audit-logs/export` |
| Settings | `GET/PATCH /settings` |
| Dashboard | `GET /dashboard`: real health, alerts, findings and expiry dates |
| Uptime monitors | `GET/POST /monitors`, `GET/PATCH/DELETE /monitors/:id`, `PATCH /monitors/:id/paused`, `POST /monitors/:id/run` |
| Heartbeats | `GET/POST /heartbeats`, `PATCH /heartbeats/:id/paused`, `DELETE /heartbeats/:id`, and the public ping URL `GET or POST /hb/:token` (plus `/start` and `/fail`) |
| Asset checks | `GET /checks/ssl`, `/checks/dns`, `/checks/domain-expiry`, `/checks/headers`, `POST /assets/:id/recheck` |
| Alerts | `GET /alerts`, `POST /alerts/:id/acknowledge`, `/snooze`, `/resolve` |
| Findings | `GET /findings`, `GET/PATCH /findings/:id` |
| Alert rules | `GET/POST /alert-rules`, `PATCH/DELETE /alert-rules/:id`, `GET/PUT /notification-channels`, `GET/POST /maintenance-windows`, `DELETE /maintenance-windows/:id` |
| Errors | `GET /error-groups`, `GET/PATCH /error-groups/:id` |
| Performance | `GET /performance`, `GET /performance/:applicationId/:environmentId?range=1h\|24h\|7d` |
| Security events | `GET /security-events`, `GET /security-events/stats`, `GET /detections`, `GET /auth/sign-ins` |
| Ingestion keys | `GET/POST /ingestion-keys`, `POST /ingestion-keys/:id/rotate`, `POST /ingestion-keys/:id/revoke` |
| **Ingestion (for your apps)** | `POST /ingest/v1/errors`, `/ingest/v1/metrics`, `/ingest/v1/security`: not under `/api/v1`, authenticated by an ingestion key |

Every path is under `/api/v1`. Endpoints from later phases answer `501 NOT_IMPLEMENTED` with the phase they arrive in.

## How it keeps accounts safe

Sign-in is email and password, in one step. Setup and invite acceptance sign the new person straight in.

- **Passwords:** at least 12 characters, with letters and numbers. They are hashed with argon2id (19 MiB, 2 passes), and unknown emails take the same time as wrong passwords.
- **Sessions:** a random token in an `HttpOnly`, `SameSite=Lax` cookie; only its SHA-256 hash is stored. Sessions end after 12 idle hours or 7 days, and on sign-out or when the user is disabled.
- **Critical actions:** inviting, disabling or removing users, settings, deleting applications or assets, and audit export all need the password entered in the last 10 minutes (`403 REAUTH_REQUIRED` otherwise). Each one also sends a notice to every active user.
- **CSRF:** every request that changes something must come from the frontend's origin (`APP_URL`).
- **Rate limits:** 10 sign-in attempts per IP and email, and 20 password confirmations per IP, per 15 minutes.
- **Audit log:** append-only; the app refuses updates and deletes. Only the retention job removes records older than the configured period.
- **Outbound checks:** asset verification goes through one guarded client. Private addresses are reachable only inside the Internal Network Allowlist, cloud metadata addresses never, and the connection is pinned to the checked address so DNS rebinding cannot slip past.
- **No lock-out:** you cannot disable or remove yourself or the last active user.
- **Soft deletes:** applications and assets are hidden at once and purged after 30 days.

With passwords as the only factor, a leaked password is enough to get in. Single sign-on (phase 8) with the identity provider's two-step verification is the simplest way to add a second factor later.

## How monitoring works

A scheduler runs inside the API process:

- **Every 5 seconds:** it runs uptime checks that are due and marks heartbeats late or missed.
- **Every minute:** it runs SSL, DNS, domain and header checks that are due, wakes snoozed alerts, and re-sends unacknowledged critical alerts.
- **Each check is claimed atomically before it runs,** so a check never runs twice, even with more than one process.

What each check does:

- **Uptime:** HTTP, TCP or DNS. A monitor's target must be on the asset whose ownership was proved. Requests go through the network guard, and each HTTP redirect is checked again. A response slower than 2 seconds counts as degraded. A monitor is down after its "mark down after" number of failures in a row, and up again on the first success.
- **Heartbeats:** each job gets a secret ping URL under `/api/v1/hb/`. It is late once due, and missed once the grace period also passes. Cron schedules use the time zone in System settings.
- **SSL:** expiry, trusted chain, host name, and whether TLS 1.0 or 1.1 is still accepted. Runs every *SSL check* hours (System settings).
- **DNS:** A, AAAA, CNAME, MX, NS, TXT and CAA records, with any change recorded and alerted. Runs every *DNS check* hours. Skipped for IP addresses.
- **Domain expiry:** the registry's RDAP service, daily. When a registry has no RDAP service, the result shows as "Unavailable". Skipped for IP addresses.
- **Security headers:** HSTS, CSP, frame protection, nosniff, Referrer-Policy and Permissions-Policy, daily.

**Findings** are created from these problems with the section 13 risk score, priority and SLA due date. A finding moves to *verified* only when a later check passes. If the problem comes back, it is *reopened*.

**Alerts** follow the 13 built-in rules and any rules you add.

- The rule that applies is the most urgent threshold first, then the most specific scope.
- The same problem stays one alert; repeats add occurrences.
- Alerts close themselves when the condition clears.
- Email goes to the recipients set under Alert rules, through the SMTP server in System settings.
- During a maintenance window, alerts are recorded but no one is notified.

Check results are kept for the *check results* retention period in System settings.

## Telemetry from your apps

Your apps send data to `/ingest/v1` with an ingestion key, never with cookies, so any website may call it. Keys are created on the Ingestion page.

- **Server keys (`so_live_…`)** can send errors, performance and security events.
- **Browser keys (`so_pub_…`)** are public by nature, so they can send errors only.
- **Storage and rotation:** only a hash of each key is stored. Rotating keeps the old key working for 24 hours, and revoking stops it at once.
- **Limits:** each key may send 600 requests a minute, with at most 50 errors or 100 security events per request.

What ShieldOps does with the data:

- **Errors** are grouped by type, by message with numbers and ids removed, and by the first stack frame in your own code.
  - Each new group, each resolved group that comes back (*regressed*), and each hour with many times the usual count raises an alert.
  - Emails, JWTs, API keys and long hex strings in messages and tags are masked on arrival.
  - User ids are stored only as a keyed hash.
- **Performance** arrives once a minute per route, as counts and a latency histogram. Histograms add up correctly across servers and time, so p50, p95 and p99 are accurate for any range. Alerts fire for a 5xx rate above the rule's threshold, and for traffic stopping in production.
- **Security events** are stored with the account masked, and they drive three detections:
  - *brute force:* many failed logins from one IP
  - *credential stuffing:* one IP failing across many accounts, counted through account hashes the SDK computes
  - *401/403 spikes*

### SDKs

`sdk/node` (`@shieldops/node`) and `sdk/browser` (`@shieldops/browser`) are in this repository and have no dependencies. Install them by path until you publish them to a private registry:

```bash
npm install /path/to/shieldops-api/sdk/node      # in a Node/Express app
npm install /path/to/shieldops-api/sdk/browser   # in a web front end
```

The Ingestion page shows the setup code with your key and URL filled in. Each folder has a README saying exactly what leaves your server.

## Run it locally

```bash
cp .env.example .env          # then set ENCRYPTION_KEY (command is in the file)
npm install
npm run dev                   # http://localhost:4000/health
```

In the frontend, set `VITE_USE_MOCKS=false` and `VITE_API_URL=/api/v1` in `.env`, then `npm run dev`. Vite forwards `/api` to port 4000. Open http://localhost:5173 and you land on first-time setup.

## Tests

The tests need a MongoDB (any 6+ server; they use and drop the `shieldops_test` database):

```bash
TEST_MONGODB_URI=mongodb://127.0.0.1:27017/shieldops_test npm test
```

## Deploy (Hetzner VPS, PM2, MongoDB Atlas)

1. **Database:** create an Atlas cluster and a database user, then add the server's IP to Atlas network access. Put the connection string in `MONGODB_URI`.
2. **Configure:** on the server, set `NODE_ENV=production`, `APP_URL=https://shieldops.example.com`, `COOKIE_SECURE=true`, `TRUST_PROXY=1` and a fresh `ENCRYPTION_KEY`. Store a copy of the key in your password manager: without it, the stored SMTP and integration credentials are unreadable.
3. **Build and start:** `npm ci && npm run build`, then `pm2 start ecosystem.config.cjs && pm2 save`.
4. **Serve:** use `deploy/nginx.conf` so the frontend, `/api` and `/ingest` share one domain, then get a certificate with certbot.
5. **Set up:** open the site once and complete first-time setup straight away. Setup is open only until the first account exists.
6. **Email:** in System settings, add SMTP (for Brevo: `smtp-relay.brevo.com`, port 587, your Brevo SMTP login and key).

**Backups:** turn on Atlas scheduled backups (the requirements ask for daily, kept 14 days) and test a restore each quarter.

## Layout

```
src/
  config.ts            environment, validated at start
  app.ts, server.ts    Express setup and start-up
  db.ts                MongoDB connection and indexes
  lib/                 crypto, passwords, network guard, probes, RDAP, cron, risk, validation, errors, logger
  middleware/          sessions and re-auth, origin check, rate limits, error format
  models/              User, Session, Invite, Application, Asset, AuditLog, Settings, Notification,
                       Monitor, CheckResult, Heartbeat, AssetChecks, Alert, AlertRule, MaintenanceWindow, Finding
  routes/              one file per area; notBuilt.ts answers for later phases
  services/            audit, email, notices, settings, maintenance, scheduler, monitors,
                       heartbeats, asset checks, alerts, findings, health
sdk/node, sdk/browser  the SDKs your apps install
test/                  API tests (Vitest + Supertest), including an Express app using the Node SDK
deploy/nginx.conf      single-domain reverse proxy for the frontend, /api and /ingest
```