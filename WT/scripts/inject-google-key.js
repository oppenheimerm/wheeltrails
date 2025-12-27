// scripts/inject-google-key.js
const fs = require('fs');
const path = require('path');

// diagnostic helper to print a directory listing if available
function listDir(p) {
    try {
        return fs.readdirSync(p).map(f => ({ name: f, size: fs.statSync(path.join(p, f)).size }));
    } catch (e) {
        return null;
    }
}

console.log('inject-google-key starting...');
console.log('__dirname:', __dirname);
console.log('process.cwd():', process.cwd());

const key = process.env.GOOGLE_MAPS_API_KEY;
if (!key) {
    console.error('ERROR: GOOGLE_MAPS_API_KEY not set');
    process.exit(1);
}

// primary expected template path (relative to this script location)
const tpl = path.join(__dirname, 'WT.Client', 'wwwroot', 'index.html.template');
const out = path.join(__dirname, 'WT.Client', 'wwwroot', 'index.html');

console.log('Expected template path:', tpl);

if (!fs.existsSync(tpl)) {
    console.error('Template not found at expected path:', tpl);

    // try some fallback locations and print helpful diagnostics
    const candidates = [
        path.join(process.cwd(), 'WT.Client', 'wwwroot', 'index.html.template'),
        path.join(process.cwd(), 'wwwroot', 'index.html.template'),
        path.join(__dirname, '..', 'WT.Client', 'wwwroot', 'index.html.template'),
        path.join(__dirname, '..', '..', 'WT.Client', 'wwwroot', 'index.html.template')
    ];

    for (const c of candidates) {
        console.log('Checking candidate:', c, 'exists=', fs.existsSync(c));
    }

    // Print directory listings to help locate the file
    const lookups = [
        path.join(__dirname, 'WT.Client', 'wwwroot'),
        path.join(process.cwd(), 'WT.Client', 'wwwroot'),
        path.join(process.cwd(), 'WT.Client'),
        path.join(process.cwd(), 'WT.Client', 'wwwroot')
    ];

    for (const d of lookups) {
        const listing = listDir(d);
        console.log('Listing for', d, ':', listing ? listing.slice(0,50) : 'not available');
    }

    console.error('\nIf the template exists, ensure you are running the script from the repository root or that the file is at one of the checked locations.');
    process.exit(2);
}

let s = fs.readFileSync(tpl, 'utf8');
s = s.replace(/__GOOGLE_MAPS_API_KEY__/g, key);
fs.writeFileSync(out, s, 'utf8');
console.log('Injected Google Maps key to', out);