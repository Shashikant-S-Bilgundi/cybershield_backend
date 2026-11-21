# @shieldops/browser

Sends front-end errors (uncaught errors and unhandled promise rejections) to ShieldOps.

```bash
npm install /path/to/shieldops-api/sdk/browser
```

```js
import { ShieldOps } from '@shieldops/browser';

ShieldOps.init({
  key: import.meta.env.VITE_SHIELDOPS_KEY,   // a browser key (so_pub_…)
  endpoint: 'https://shieldops.example.com/ingest/v1',
  release: import.meta.env.VITE_APP_VERSION,
});

ShieldOps.setUser(currentUser.id);            // optional; only a hash is stored
```

Browser keys are visible to anyone who opens your site, so ShieldOps accepts only errors from them, at most 30 per minute per page.