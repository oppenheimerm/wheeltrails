const fs = require('fs');
const path = require('path');

const versionFile = path.join(__dirname, '../wwwroot/appversion.json');
const data = JSON.parse(fs.readFileSync(versionFile, 'utf8'));

let [major, minor, patch] = data.version.split('.').map(Number);
patch++;

data.version = `${major}.${minor}.${patch}`;

fs.writeFileSync(versionFile, JSON.stringify(data, null, 2));

console.log(`Updated appversion.json to ${data.version}`);