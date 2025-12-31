Workbox integration

Run (from WT.Client):

1. npm ci
2. npm run build:workbox

This will inject a precache manifest into `wwwroot/service-worker.published.js`.

In production deploy `wwwroot` with the generated `service-worker.published.js` (register that file instead of `service-worker.js`).
