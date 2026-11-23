# ShieldOps API

The backend for ShieldOps: Express 5, TypeScript and MongoDB. It implements `src/api/contract.ts` from the frontend; the frontend's mock (`src/api/mock`) is the reference for how each endpoint behaves.

## What is built (all backend phases, 1 to 8)

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
| Servers | `GET /servers`, `GET/DELETE /servers/:id`, `GET /servers/:id/metrics?range=` |
| Agent tokens | `GET/POST /agent-tokens`, `POST /agent-tokens/:id/rotate`, `POST /agent-tokens/:id/revoke` |
| Database checks | `GET/POST /db-checks`, `POST /db-checks/:id/run`, `PATCH /db-checks/:id/paused`, `DELETE /db-checks/:id` |
| Integrations | `GET /integrations`, `POST /integrations/:type/connect`, `POST /integrations/:type/disconnect`, `GET /integrations/github/callback` |
| Repositories | `GET/POST /repositories`, `GET /repositories/available`, `GET/PATCH/DELETE /repositories/:id` |
| Images | `GET/POST /images`, `DELETE /images/:id` |
| Scans | `GET /scans?targetType&targetId`, `POST /scans`, `GET /dependencies` |
| Incidents | `GET/POST /incidents`, `GET/PATCH /incidents/:id`, `POST /incidents/:id/links`, `DELETE /incidents/:id/links/:type/:itemId` |
| Remediation tasks | `GET/POST /remediation-tasks`, `PATCH /remediation-tasks/:id`, `GET /sla` |
| Alert channels | Slack and webhook through `/integrations/:type/connect`, and `POST /integrations/:type/test` |
| AI analyst | `POST /ai/ask` |
| Recommendations | `GET /recommendations`, `POST /recommendations/:id/dismiss`, `/restore` |
| Reports | `GET/POST /reports`, `GET /reports/:id`, `GET /reports/:id/pdf`, `GET/POST /report-schedules`, `DELETE /report-schedules/:id` |
| Compliance | `GET /compliance/frameworks`, `PATCH /compliance/frameworks/:id`, `GET /compliance/frameworks/:id/controls`, `PUT …/controls/:controlId/attestation` |
| Releases | `GET /releases`; CI sends `POST /ingest/v1/releases` |
| Logs | `GET /logs`; the Node SDK sends `POST /ingest/v1/logs` |
| Probe locations | `GET/POST /probes`, `DELETE /probes/:id`, `GET /monitors/:id/probe-results`; probes use `/ingest/v1/probe/work` and `/results` |
| Escalation | `GET/POST /escalation-policies`, `PUT/DELETE /escalation-policies/:id`, `GET /alerts/escalations` |
| Anomalies | `GET /anomalies` |
| Single sign-on | `POST /auth/sso/:provider/start`, `GET /auth/sso/callback` |
| Cloud and identity | `GET /asset-import/:source`, `POST /asset-import/:source`, `GET /cloud-checks` |
| Jira | `POST /integrations/jira/issues` |
| **GitHub webhook** | `POST /api/v1/webhooks/github` (signed with GITHUB_WEBHOOK_SECRET) |
| **Agent (for your servers)** | `GET /ingest/agent/install.sh`, `GET /ingest/agent/download/:file`, `POST /ingest/v1/agent/report` (agent token) |
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

## Servers and databases

**Servers:**

- **The agent** (`agent/`, see its README) reports every 30 seconds. ShieldOps records each change as an event: a service failed, a container exited, the server came back or rebooted.
- **Alerts:**
  - CPU or memory above the rule's threshold for its whole window (90% for 10 minutes by default)
  - any disk over 85% (medium) or 95% (critical), per mount
  - a service or container that fails, or restarts 3 times in 10 minutes
  - a server that misses 3 reports
- **Tokens:** revoking a token stops its servers reporting at once, and rotating one keeps the old token working for 24 hours.

**Database checks** connect to PostgreSQL, MySQL, MongoDB or Redis with a read-only account, ping, read connections, size and role, then disconnect.

- **Network guard:** the host must pass it, so internal databases need their range in the Internal Network Allowlist. MongoDB Atlas (`*.mongodb.net`) is reached through its DNS SRV record, with each target checked.
- **Encryption:** connections use TLS when the server offers it.
- **Password:** stored encrypted and deleted with the check.
- **Alert:** three failures in a row (production) opens a critical alert.

## Code security

ShieldOps scans the repositories you add, and the container images you list.

**Repositories** are cloned through the GitHub App and scanned with three tools:

- **Gitleaks** looks for secrets in the code and its whole history.
  - One finding per distinct secret. It is critical or high while in the current code, medium once it is only in history.
  - Only a masked form (`sk_l••••Uv`) is stored; the full value never leaves the scan folder.
- **OSV-Scanner** checks dependencies against the OSV database. Vulnerabilities on CISA's known-exploited list raise the priority.
- **Trivy** checks Dockerfiles, Kubernetes and Terraform files for misconfiguration.

**Images** on ghcr.io (through the GitHub App) or Docker Hub (with a read-only token) are scanned by Trivy for vulnerable packages.

**When scans run:**

- once when a target is added
- daily
- on each push to the default branch, through the webhook
- on demand

They run one at a time, on the ShieldOps server, in a temporary folder that is always deleted afterwards. The installation token reaches git through its environment, never on the command line.

**A scanner that fails never marks anything as fixed.** The scan shows as *partial* or *failed* with the reason, and the screens show *Unknown* rather than *none*. A finding becomes *verified* only when a completed scan no longer finds it.

### Install the scanners (on the server)

```bash
sudo apt install -y git
sudo sh scripts/install-scanners.sh   # gitleaks 8.30.1, osv-scanner 2.7.0, trivy 0.76.1, checksums verified
```

The server needs outbound HTTPS to:

- **api.osv.dev:** OSV-Scanner's database
- **mirror.gcr.io and ghcr.io:** Trivy's database, about 100 MB, cached
- **www.cisa.gov:** the known-exploited list, fetched daily

### Connect GitHub

1. **Create the app.** On GitHub, open your organisation's **Settings → Developer settings → GitHub Apps → New GitHub App** and fill in:
   - **Homepage URL:** `https://shieldops.example.com`
   - **Setup URL:** `https://shieldops.example.com/api/v1/integrations/github/callback`, and tick *Redirect on update*.
   - **Webhook:** active. URL `https://shieldops.example.com/api/v1/webhooks/github`, with a long random secret.
   - **Repository permissions:** Contents *Read-only*, Metadata *Read-only*, Packages *Read-only*. Nothing else.
   - **Subscribe to events:** Push.
   - **Where can it be installed:** Only on this account.
2. **Note the app's details.** After creating it, note the **App ID** and the slug (the last part of `github.com/apps/<slug>`). Then generate a **private key**.
3. **Configure the server.** Copy the `.pem` to the server (readable only by the API's user) and set:
   ```
   GITHUB_APP_ID=…
   GITHUB_APP_SLUG=…
   GITHUB_APP_PRIVATE_KEY_FILE=/etc/shieldops/github-app.pem
   GITHUB_WEBHOOK_SECRET=…the same secret…
   ```
   Restart the API.
4. **Install it.** In ShieldOps, open **Integrations → GitHub → Connect**. GitHub asks which repositories the app may see and sends you back. Then add repositories on the Repositories page.

Even if the app were given more, ShieldOps requests installation tokens limited to read-only contents, metadata and packages. Disconnecting GitHub in ShieldOps also uninstalls the app.

## Security operations

**Incidents** get references like INC-0001.

- **Workflow:** new → acknowledged → investigating → remediation in progress → resolved → closed, and can be reopened. Other moves are refused.
- **Evidence:** link alerts, findings and error groups. The timeline records each change and note.
- **Closing critical incidents** needs a post-incident summary of at least 40 characters.
- **Notices:** opening a critical or high incident notifies everyone.

**Remediation tasks** take their priority and SLA due date from the finding (or from the incident's severity). **A task is only done when a recheck confirms the fix:** it cannot be set to verified by hand. Moving it to *ready for verification* starts the recheck that fits what it is about:

| Linked to | Recheck |
| --- | --- |
| SSL, DNS, domain or header finding | That check runs again at once |
| Secret, vulnerability or misconfiguration finding | A new scan of the repository or image; settles when it finishes |
| Error group | Watched for 7 days; fails if the error happens again |
| Incident | Passes when every linked finding, alert and error group is closed |

A pass verifies the task (and the finding). A fail sends the task back to *in progress* with the reason. If the scanner that would confirm a fix fails, the fix is reported as *could not be confirmed*, never as done.

**SLA** (`GET /sla`) counts:

- open, overdue and due-this-week tasks, by priority
- tasks verified in the last 30 days, and the share done on time
- mean time to acknowledge alerts and to resolve incidents, over 30 days

### Slack and webhooks

Alert rules can send to Slack (an incoming-webhook URL) and to your own webhook (https only, through the network guard). Each attempt is recorded on the alert's delivery list, with up to 3 tries for network errors and 5xx answers.

Webhook requests are JSON:

```json
{ "event": "alert.opened", "alert": { "id": "…", "title": "…", "message": "…", "severity": "critical", "application": "…", "environment": "…", "url": "https://shieldops.example.com/alerts" }, "sent_at": "2026-11-21T10:42:07Z" }
```

with these headers:

- `ShieldOps-Signature: sha256=<hex>`: HMAC-SHA256 of the raw body, using the signing secret shown once when you connect.
- `ShieldOps-Event`
- `ShieldOps-Delivery`

Verify the signature before trusting a request. In Node:

```js
const expected = 'sha256=' + crypto.createHmac('sha256', SECRET).update(rawBody).digest('hex');
const ok = crypto.timingSafeEqual(Buffer.from(req.get('ShieldOps-Signature')), Buffer.from(expected));
```

For an internal endpoint with a certificate from your own CA, set `WEBHOOK_CA_FILE`.

## AI and reporting

### AI analyst

The analyst is off until you turn it on in **System settings → AI** and approve sending masked evidence. Choose OpenAI, Anthropic or Azure OpenAI there, and set that provider's key on the server (`.env.example`). Keys are never stored in the database.

For each question, ShieldOps loads the evidence itself (the finding, incident, error group or alert) and masks it before sending:

- emails become `r***@example.com`
- tokens, API keys, JWTs and long hex strings are removed
- IP addresses keep only their network (`203.0.113.x`)
- people's names are left out of incident timelines

The answer shows **exactly what was sent**, and is labelled AI assistance, not scanner evidence. Suggested tasks are only created when someone confirms them.

Each person may ask 10 questions a minute, and every question is in the audit log. With AI off, everything else works as before.

### Recommendations

Recommendations turn open findings into the few fixes that close the most, for example "Upgrade lodash to 4.17.21" (closes 2), "Rebuild acme/shop on a patched base image", "Add the missing security headers" or "Rotate 2 exposed secrets". They are worked out live. Dismissing one needs a reason, and it can be restored.

### Reports

There are six report types: posture, health, vulnerabilities, SSL and domains, incidents, and compliance.

- **Content:** built from live data for a period and an application (or all), then rendered as a multi-page PDF. Tables continue across pages and every page is numbered.
- **Schedules:** weekly reports go out on Mondays at 09:00 and monthly ones on the 1st, in your time zone, by email with the PDF attached. Email needs SMTP in System settings.

### Compliance readiness

Compliance readiness covers ISO/IEC 27001:2022 Annex A, SOC 2 (Security), the CERT-In Directions of 28 April 2022, and the DPDP Act 2023.

- Each control is judged from live data each time: met, partly met, or not met, with the evidence and the gaps.
- Controls ShieldOps cannot see (backups, NTP, change approval) need your evidence: a note of at least 10 characters saying where it lives.
- The score counts met as 1, partly met as 0.5, and evidenced manual controls as 1.

This shows readiness, not certification.

## Advanced (phase 8, part A)

### Releases

Your CI posts each deploy with a server ingestion key:

```bash
curl -X POST https://shieldops.example.com/ingest/v1/releases \
  -H "Authorization: Bearer so_live_…" -H "Content-Type: application/json" \
  -d '{"version":"1.4.0","commit":"'$GIT_SHA'","deployedBy":"github-actions"}'
```

Without CI changes, the first error the SDK reports from a new `release` creates that release automatically.

Each release is compared with the 24 hours before it, up to 24 hours after (or until the next release):

- new error groups
- alerts
- 5xx rate and p95

The verdict is *possible regression* if the release brought new errors or alerts, or made either number clearly worse. Otherwise it is *watching* for the first day, then *healthy*.

### Logs

The Node SDK sends structured logs (`ShieldOps.logger.info('Order paid', { orderId })`), kept for 14 days.

- **Secrets:** fields named like secrets are redacted on arrival, and emails and tokens in messages are masked.
- **Search:** words match the message, and `key=value` matches a field. Filter by level and time range; a histogram shows volume and errors.

### Second probe location

Run the agent in probe mode on a server elsewhere (`agent/README.md`). Remote probes only get monitors on internet-facing assets.

When this server's check fails but an online probe reached the target in the last two intervals, the monitor shows *degraded* with the reason, and no outage is counted.

### Escalation policies

Each policy covers some severities, with steps that run after a number of minutes:

- **Steps:** each notifies people (or everyone) by in-app, email, Slack or webhook.
- **First step:** at 0 minutes, which is the alert's own notification.
- **Later steps:** notified if nobody has acknowledged by then. With *repeat*, the last step repeats (at most 10 times).
- **Overlap:** a severity can belong to only one enabled policy.

### Anomaly detection

Every 5 minutes, ShieldOps compares the last 10 minutes of each metric with the same time of day over the past 7 days:

- requests
- 5xx rate
- p95
- failed logins
- error events

It flags traffic far above or below normal, and the rest when far above. The *Unusual pattern* alert rule turns alerts on or off and sets sensitivity (1 to 3). The Anomalies page shows 8 hours of each metric against its usual range.

## Advanced (phase 8, part B)

### Single sign-on (Google Workspace or Microsoft Entra)

People sign in with their work account and that account's own 2-step verification.

- **Who can get in:** only people already invited to ShieldOps, with an email on your domain. SSO never creates accounts.
- **How it is checked:** OpenID Connect with PKCE and a one-time nonce. The ID token's signature, issuer, audience and expiry are checked against the provider's published keys.

**Google:**

1. In Google Cloud console → APIs & Services → Credentials, create an *OAuth client ID* of type *Web application*.
2. Add the authorised redirect URI `https://shieldops.example.com/api/v1/auth/sso/callback`.
3. Set the OAuth consent screen to *Internal*.

**Entra:**

1. In Entra ID → App registrations → New registration, choose *Accounts in this organizational directory only*.
2. Add the redirect URI (type *Web*) `https://shieldops.example.com/api/v1/auth/sso/callback`.
3. Under *Certificates & secrets*, create a client secret.

Then in ShieldOps open **System settings → Single sign-on**, enter the domain, client ID and secret, and turn it on.

*Password fallback* stays on until someone who has just signed in through SSO turns it off. This proves SSO works before the password route closes, so a misconfiguration cannot lock everyone out. Re-authentication for critical actions still asks for the ShieldOps password.

### Jira

Connect with a Jira site, an account email, an API token (id.atlassian.com → Security) and one project key.

- **Issues:** incidents and tasks get a "Create Jira issue" button. Each creates one issue labelled `shieldops`, linked both ways.
- **Status:** the issue's status is copied back every 10 minutes.
- **Verification:** ShieldOps still decides when a task is verified. Closing the Jira issue does not.

### Cloudflare, Google Workspace and Microsoft Entra

All three are read-only. Their findings belong to a **Shared infrastructure** application, created on first connect, with one asset per account. Checks run when connected and every 6 hours.

**Cloudflare:** create an API token from the read-only template with *Zone: Read* and *DNS: Read*.

- **Checks:** Always Use HTTPS, Full (strict) SSL with TLS 1.2 or newer, and DNSSEC, for every zone.
- **Import:** zones and hostnames can be imported as assets.

**Google Workspace:** create a service account, give it domain-wide delegation for `https://www.googleapis.com/auth/admin.directory.user.readonly`, then paste its JSON key with the domain and an admin to act as.

- **Checks:** admins and everyone use 2-step verification; accounts unused for 90 days.

**Microsoft Entra:** register an app with the *Directory.Read.All* and *AuditLog.Read.All* application permissions, grant admin consent, and create a client secret.

- **Checks:** admins and everyone have MFA registered.

### Connect AWS

ShieldOps runs on your own server, so it has no AWS identity. It uses a small IAM user that can only assume one read-only role, with an external ID.

1. **Create the IAM user** `shieldops-caller` with only this policy, and put its access key in `.env` as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`:

   ```json
   { "Version": "2012-10-17", "Statement": [{ "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/ShieldOpsReadOnly" }] }
   ```

2. **Create the role** `ShieldOpsReadOnly` with the AWS-managed `SecurityAudit` policy and this trust policy. The external ID is shown in ShieldOps when you open Connect AWS.

   ```json
   { "Version": "2012-10-17", "Statement": [{ "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::<ACCOUNT>:user/shieldops-caller" }, "Action": "sts:AssumeRole", "Condition": { "StringEquals": { "sts:ExternalId": "<external ID from ShieldOps>" } } }] }
   ```

3. **Set the regions:** `AWS_REGIONS` (default `ap-south-1`).
4. **Connect:** restart the API and paste the role ARN in Integrations → AWS.

**Checks:**

- root account MFA
- S3 Block Public Access on every bucket
- security groups that open SSH or RDP to the internet
- publicly accessible RDS instances
- active access keys older than 90 days
- a multi-region CloudTrail that is logging

**Import:** EC2 instances and RDS databases can be imported as assets. Only assets ShieldOps finds in the account again at import time are added.

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
3. **Build and start:** `npm ci && npm run build`, then `pm2 start ecosystem.config.cjs && pm2 save`. Keep `agent/dist` with the API: the install script downloads the agent from there.
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
agent/                 the Go server agent, its install script and built binaries (agent/dist)
scripts/               install-scanners.sh: the pinned scanners for code security
test/                  API tests (Vitest + Supertest), including an Express app using the Node SDK
deploy/nginx.conf      single-domain reverse proxy for the frontend, /api and /ingest
```