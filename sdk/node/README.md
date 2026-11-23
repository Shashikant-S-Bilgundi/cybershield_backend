# @shieldops/node

Sends errors, API response times and security events from a Node.js app to ShieldOps.

```bash
npm install /path/to/shieldops-api/sdk/node
```

```js
import express from 'express';
import { ShieldOps } from '@shieldops/node';

const shieldops = ShieldOps.init({
  key: process.env.SHIELDOPS_KEY,            // a server key from ShieldOps → Ingestion keys
  endpoint: 'https://shieldops.example.com/ingest/v1',
  release: process.env.APP_VERSION,
});

const app = express();
app.use(shieldops.requestHandler());          // before your routes
// ...routes...
app.use(shieldops.errorHandler());            // after your routes

// In your login route:
shieldops.security.loginFailed({ account: email, ip: req.ip });
shieldops.security.loginSucceeded({ userId: user.id, ip: req.ip });
```

## Logs

```js
ShieldOps.logger.info('Order paid', { orderId: order.id, amount: order.total });
ShieldOps.logger.error('Payment provider timeout', { provider: 'razorpay' });
```

Logs are searchable on the Logs page for 14 days. Search words match the message; `orderId=123` matches a field.

- **Levels:** set `logLevel` in `init` (default `info`) to choose the lowest level sent.
- **Limits:** at most 1000 lines a minute are sent.
- **Secrets:** fields named like secrets (password, token, authorization…) are redacted by ShieldOps on arrival, and emails and tokens in messages are masked.

## Releases

Pass `release` to `init` (for example your git commit or package version). ShieldOps records a release the first time it sees errors from a new version, and compares errors, 5xx rate and p95 before and after. For exact deploy times, call the release API from your CI, as shown on the Releases page.

## What leaves your server

- **Errors:** type, message, stack frames, and the source line of your own files (not dependencies). Emails and tokens in messages are masked by ShieldOps on arrival.
- **Performance:** one summary per minute: request counts, 5xx counts and a latency histogram per route. Never request bodies or headers.
- **Security events:** the type, IP, route and status. Account names are masked (`r***@example.com`) and hashed before sending; user ids are hashed by ShieldOps.

401, 403 and 429 responses are reported automatically as security events, unless your code already reported one during that request (so a failed login that returns 401 is counted once). If ShieldOps is unreachable, data is retried once and then dropped; the SDK never throws into your app.