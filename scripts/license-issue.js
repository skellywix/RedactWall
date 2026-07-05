'use strict';
/**
 * Vendor-side license tooling (offline). NOT part of the running product.
 *
 *   node scripts/license-issue.js --init-keypair <dir>
 *       Generate an Ed25519 signing keypair. Writes the PRIVATE key to
 *       <dir>/license-signing-key.pem (0600) and prints the PUBLIC PEM to embed
 *       in server/license.js EMBEDDED_PUBLIC_KEY_PEM. Keep the private key
 *       OFFLINE and out of the repo.
 *
 *   node scripts/license-issue.js --key <private.pem> --customer "Example CU" \
 *       --customer-id cu-000123 --plan standard --seats 120 --expires 2027-08-01 \
 *       [--grace-days 30] [--features gateway,mcp-guard] [--out promptwall.lic]
 *       Issue a signed promptwall.lic and self-verify it before exiting.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const license = require('../server/license');

function parseArgs(argv) {
  const opts = { features: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--init-keypair') opts.initKeypair = argv[++i];
    else if (a === '--key') opts.key = argv[++i];
    else if (a === '--customer') opts.customer = argv[++i];
    else if (a === '--customer-id') opts.customerId = argv[++i];
    else if (a === '--plan') opts.plan = argv[++i];
    else if (a === '--seats') opts.seats = Number(argv[++i]);
    else if (a === '--expires') opts.expires = argv[++i];
    else if (a === '--grace-days') opts.graceDays = Number(argv[++i]);
    else if (a === '--features') opts.features = String(argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--out') opts.out = argv[++i];
  }
  return opts;
}

function initKeypair(dir, io) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.mkdirSync(dir, { recursive: true });
  const priv = path.join(dir, 'license-signing-key.pem');
  const pub = path.join(dir, 'license-signing-pub.pem');
  fs.writeFileSync(priv, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  fs.writeFileSync(pub, pubPem);
  io.log(`Wrote ${priv} (keep OFFLINE, never commit)`);
  io.log(`Wrote ${pub}`);
  io.log('\nEmbed this PUBLIC key in server/license.js EMBEDDED_PUBLIC_KEY_PEM:\n');
  io.log(pubPem);
}

function issue(opts, io, setExitCode) {
  const priv = crypto.createPrivateKey(fs.readFileSync(opts.key, 'utf8'));
  const payload = {
    customer: opts.customer || 'Unknown',
    customerId: opts.customerId || '',
    plan: opts.plan || 'standard',
    seats: opts.seats || 0,
    features: opts.features || [],
    issued: new Date().toISOString(),
    expires: opts.expires,
    graceDays: Number.isFinite(opts.graceDays) ? opts.graceDays : 30,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const sig = crypto.sign(null, Buffer.from(payloadB64, 'utf8'), priv).toString('base64');
  const licText = `${payloadB64}.${sig}`;
  // Self-verify with the matching public key before writing.
  const pubPem = crypto.createPublicKey(priv).export({ type: 'spki', format: 'pem' }).toString();
  const check = license.verifyLicenseText(licText, { publicKeyPem: pubPem });
  if (!check.ok) { io.error(`self-verify failed: ${check.reason}`); return setExitCode(1); }
  const out = opts.out || 'promptwall.lic';
  fs.writeFileSync(out, licText + '\n');
  io.log(`Wrote ${out} for ${payload.customer} (${payload.plan}, ${payload.seats} seats, expires ${payload.expires})`);
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const setExitCode = deps.setExitCode || ((c) => { process.exitCode = c; });
  const opts = parseArgs(argv);
  try {
    if (opts.initKeypair) return initKeypair(opts.initKeypair, io);
    if (!opts.key || !opts.expires || !opts.plan || !opts.seats) {
      io.error('Usage: --init-keypair <dir>  OR  --key <pem> --customer <name> --customer-id <id> --plan <standard|enterprise> --seats <n> --expires <YYYY-MM-DD> [--grace-days 30] [--features a,b] [--out promptwall.lic]');
      return setExitCode(1);
    }
    return issue(opts, io, setExitCode);
  } catch (err) {
    io.error(err.message || String(err));
    return setExitCode(1);
  }
}

if (require.main === module) main();

module.exports = { main, parseArgs };
