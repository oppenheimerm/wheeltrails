const fs = require('fs');
const path = process.argv[2] || 'publish/wwwroot/service-worker.published.js';
const fullPath = path;
console.log(`Checking for file: ${fullPath}`);
if (fs.existsSync(fullPath)) {
 console.log('service-worker.published.js found');
 process.exit(0);
} else {
 console.error('ERROR: service-worker.published.js not found at', fullPath);
 try {
 const dir = require('path').dirname(fullPath);
 console.error('Directory listing for', dir);
 console.error(fs.readdirSync(dir));
 } catch (e) {
 console.error('Failed to list directory', e.message);
 }
 process.exit(1);
}
