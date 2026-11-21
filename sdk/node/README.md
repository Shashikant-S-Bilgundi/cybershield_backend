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

## What leaves your server

- **Errors:** type, message, stack frames, and the source line of your own files (not dependencies). Emails and tokens in messages are masked by ShieldOps on arrival.
- **Performance:** one summary per minute: request counts, 5xx counts and a latency histogram per route. Never request bodies or headers.
- **Security events:** the type, IP, route and status. Account names are masked (`r***@example.com`) and hashed before sending; user ids are hashed by ShieldOps.

401, 403 and 429 responses are reported automatically as security events, unless your code already reported one during that request (so a failed login that returns 401 is counted once). If ShieldOps is unreachable, data is retried once and then dropped; the SDK never throws into your app.