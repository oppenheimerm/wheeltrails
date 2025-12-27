// Proxy injector to reliably locate the shared inject-google-key.js script
// This file allows `npm run inject-key` to run when executed from WT.Client
const path = require('path');
const target = path.resolve(__dirname, '..', 'scripts', 'inject-google-key.js');
try {
 require(target);
} catch (err) {
 console.error('Failed to run injector at', target);
 console.error(err && err.stack ? err.stack : err);
 process.exit(1);
}
