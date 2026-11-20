# ShieldOps API

The backend for ShieldOps: Express 5, TypeScript and MongoDB. It implements `src/api/contract.ts` from the frontend; the frontend's mock (`src/api/mock`) is the reference for how each endpoint behaves.

## What this phase includes (backend phase 1)

| Area | Endpoints |
| --- | --- |
| First-time setup | `GET /setup/status`, `POST /setup` |
| Sign-in | `POST /auth/login`, `POST /auth/mfa/verify`, `GET /auth/me`, `POST /auth/logout`, `POST /auth/reauth`, `GET /auth/sso/config` |
| Invites and team | `GET/POST /invites`, `DELETE /invites/:id`, `GET /invites/:token`, `POST /invites/:token/accept`, `GET /users`, `PATCH /users/:id/status`, `DELETE /users/:id` |
| Applications | `GET/POST /applications`, `GET/PATCH/DELETE /applications/:id`, `PATCH /applications/:id/status` |
| Assets | `GET/POST /assets`, `POST /assets/:id/verify`, `POST /assets/:id/approve`, `PATCH /assets/:id/status`, `DELETE /assets/:id` |
| Audit log | `GET /audit-logs`, `POST /audit-logs/export` |
| Settings | `GET/PATCH /settings` |
| Dashboard | `GET /dashboard` (applications are real; health and alerts stay empty until phase 2) |

Every path is under `/api/v1`. Endpoints from later phases answer `501 NOT_IMPLEMENTED` with the phase they arrive in.

## How it keeps accounts safe

- **Passwords:** argon2id (19 MiB, 2 passes). Unknown emails take the same time as wrong passwords.
- **Two-factor:** TOTP is required for everyone. The secret is saved only after the first valid code, stored encrypted (AES-256-GCM), and each code works once.
- **Sessions:** a random token in an `HttpOnly`, `SameSite=Lax` cookie; only its SHA-256 hash is stored. Sessions end after 12 idle hours or 7 days, and on sign-out or when the user is disabled.
- **Critical actions:** inviting, disabling or removing users, settings, deleting applications or assets, and audit export all need a password or code from the last 10 minutes (`403 REAUTH_REQUIRED` otherwise). Each one also sends a notice to every active user.
- **CSRF:** every request that changes something must come from the frontend's origin (`APP_URL`).
- **Rate limits:** 10 sign-in attempts and 20 code attempts per 15 minutes.
- **Audit log:** append-only; the app refuses updates and deletes. Only the retention job removes records older than the configured period.
- **Outbound checks:** asset verification goes through one guarded client. Private addresses are reachable only inside the Internal Network Allowlist, cloud metadata addresses never, and the connection is pinned to the checked address so DNS rebinding cannot slip past.
- **No lock-out:** you cannot disable or remove yourself or the last active user.
- **Soft deletes:** applications and assets are hidden at once and purged after 30 days.

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
2. **Configure:** on the server, set `NODE_ENV=production`, `APP_URL=https://shieldops.example.com`, `COOKIE_SECURE=true`, `TRUST_PROXY=1` and a fresh `ENCRYPTION_KEY`. Store a copy of the key in your password manager: without it, every two-factor secret and SMTP password is unreadable.
3. **Build and start:** `npm ci && npm run build`, then `pm2 start ecosystem.config.cjs && pm2 save`.
4. **Serve:** use `deploy/nginx.conf` so the frontend and `/api` share one domain, then get a certificate with certbot.
5. **Set up:** open the site once and complete first-time setup straight away. Setup is open only until the first account exists.
6. **Email:** in System settings, add SMTP (for Brevo: `smtp-relay.brevo.com`, port 587, your Brevo SMTP login and key).

**Backups:** turn on Atlas scheduled backups (the requirements ask for daily, kept 14 days) and test a restore each quarter.

## Layout

```
src/
  config.ts            environment, validated at start
  app.ts, server.ts    Express setup and start-up
  db.ts                MongoDB connection and indexes
  lib/                 crypto, passwords, TOTP, network guard, validation, errors, logger
  middleware/          sessions and re-auth, origin check, rate limits, error format
  models/              User, Session, LoginChallenge, Invite, Application, Asset, AuditLog, Settings, Notification
  routes/              one file per area; notBuilt.ts answers for later phases
  services/            audit, email, notices to all users, settings, daily maintenance
test/                  API tests (Vitest + Supertest)
deploy/nginx.conf      single-domain reverse proxy
```