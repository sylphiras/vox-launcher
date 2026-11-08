// Signs release files with the Vox update key (Ed25519) and writes SHA256SUMS.txt.
// Usage: UPDATE_SIGNING_KEY=<base64 pkcs8> node scripts/sign-release.js <file> [<file> ...]
// For every file it writes "<file>.sig" (base64 signature); the launcher refuses updates without a valid one.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const b64 = process.env.UPDATE_SIGNING_KEY;
const files = process.argv.slice(2);
if (!b64) { console.error('UPDATE_SIGNING_KEY is not set.'); process.exit(1); }
if (!files.length) { console.error('No files to sign.'); process.exit(1); }
const key = crypto.createPrivateKey({ key: Buffer.from(b64.trim(), 'base64'), format: 'der', type: 'pkcs8' });
const sums = [];
for (const f of files) {
  const data = fs.readFileSync(f);
  fs.writeFileSync(f + '.sig', crypto.sign(null, data, key).toString('base64'));
  sums.push(`${crypto.createHash('sha256').update(data).digest('hex')}  ${path.basename(f)}`);
  console.log('Signed', path.basename(f));
}
fs.writeFileSync('SHA256SUMS.txt', sums.join('\n') + '\n');
