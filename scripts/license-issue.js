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
 *       [--grace-days 30] [--features gateway,mcp-guard] [--out redactwall.lic]
 *       Issue a signed redactwall.lic and self-verify it before exiting.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const license = require('../server/license');
const fileMutationLock = require('../server/file-mutation-lock');
const privatePaths = require('../server/private-path');

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
    else if (a === '--force') opts.force = true;
  }
  return opts;
}

function comparablePath(filePath) {
  const absolute = path.resolve(filePath);
  let resolved = absolute;
  try {
    resolved = fs.realpathSync.native(absolute);
  } catch {
    try { resolved = path.join(fs.realpathSync.native(path.dirname(absolute)), path.basename(absolute)); } catch {}
  }
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function sameFile(left, right) {
  if (comparablePath(left) === comparablePath(right)) return true;
  if (!fs.existsSync(left) || !fs.existsSync(right)) return false;
  const a = fs.statSync(left);
  const b = fs.statSync(right);
  return a.dev === b.dev && a.ino === b.ino;
}

function keypairPaths(dir) {
  return {
    priv: path.join(dir, 'license-signing-key.pem'),
    pub: path.join(dir, 'license-signing-pub.pem'),
  };
}

function assertKeypairAbsent(paths) {
  if (fs.existsSync(paths.priv) || fs.existsSync(paths.pub)) {
    throw new Error('refusing to overwrite an existing license signing keypair');
  }
}

function stagePrivateFile(target, contents, label) {
  const temp = `${target}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    privatePaths.securePrivatePath(temp, {
      fs,
      directory: false,
      fresh: true,
      label,
      ownerLabel: label,
    });
    fs.writeFileSync(fd, contents);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    return temp;
  } catch (error) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    try { fs.unlinkSync(temp); } catch {}
    throw error;
  }
}

function rollbackKeypair(paths, published, originalError) {
  try {
    if (published.pub) fs.unlinkSync(paths.pub);
    if (published.priv) fs.unlinkSync(paths.priv);
    privatePaths.fsyncDirectory(path.dirname(paths.priv), { fs });
  } catch (rollbackError) {
    originalError.rollbackError = rollbackError;
  }
}

function publishKeypair(paths, privatePem, publicPem) {
  const tempPriv = stagePrivateFile(paths.priv, privatePem, 'offline license private-key staging file');
  let tempPub;
  let privPublished = false;
  let pubPublished = false;
  try {
    tempPub = stagePrivateFile(paths.pub, publicPem, 'offline license public-key staging file');
    privatePaths.publishFileExclusiveDurably(tempPriv, paths.priv, { fs });
    privPublished = true;
    privatePaths.publishFileExclusiveDurably(tempPub, paths.pub, { fs });
    pubPublished = true;
  } catch (error) {
    rollbackKeypair(paths, { priv: privPublished, pub: pubPublished }, error);
    throw error;
  } finally {
    for (const temp of [tempPriv, tempPub]) if (temp) try { fs.unlinkSync(temp); } catch {}
  }
}

function initKeypair(dir, io) {
  const resolved = path.resolve(dir);
  return privatePaths.withPrivateDirectoryMutationLockSync(resolved, () => {
    const paths = keypairPaths(resolved);
    assertKeypairAbsent(paths);
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    publishKeypair(paths, privatePem, pubPem);
    io.log(`Wrote ${paths.priv} (keep OFFLINE, never commit)`);
    io.log(`Wrote ${paths.pub}`);
    io.log('\nEmbed this PUBLIC key in server/license.js EMBEDDED_PUBLIC_KEY_PEM:\n');
    io.log(pubPem);
  }, {
    fs,
    label: 'offline license key directory',
    ownerLabel: 'offline license key directory',
  });
}

function readSigningKey(file) {
  const resolved = path.resolve(file);
  privatePaths.assertPrivatePath(resolved, {
    fs,
    directory: false,
    label: 'offline license signing key',
    ownerLabel: 'offline license signing key',
  });
  return privatePaths.readBoundedRegularFile(resolved, {
    fs,
    maxBytes: 64 * 1024,
    label: 'offline license signing key',
  }).toString('utf8');
}

function publishLicense(out, body, force) {
  const target = path.resolve(out);
  const temp = stagePrivateFile(target, body, 'license output staging file');
  try {
    if (force) privatePaths.publishFileDurably(temp, target, { fs });
    else privatePaths.publishFileExclusiveDurably(temp, target, { fs });
    try { fs.unlinkSync(temp); } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }
    privatePaths.assertPrivatePath(target, {
      fs,
      directory: false,
      label: 'license output file',
      ownerLabel: 'license output file',
    });
  } finally {
    try { fs.unlinkSync(temp); } catch {}
  }
}

function issue(opts, io, setExitCode) {
  const out = path.resolve(opts.out || 'redactwall.lic');
  return fileMutationLock.withFileMutationLockSync(out, () => {
    if (sameFile(opts.key, out)) {
      throw new Error('license output path must not be the signing key path');
    }
    const priv = crypto.createPrivateKey(readSigningKey(opts.key));
    const customerId = license.normalizeCustomerId(opts.customerId);
    const payload = {
      customer: opts.customer || 'Unknown',
      customerId,
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
    const pubPem = crypto.createPublicKey(priv).export({ type: 'spki', format: 'pem' }).toString();
    const check = license.verifyLicenseText(licText, { publicKeyPem: pubPem, expectedCustomerId: customerId });
    if (!check.ok) { io.error(`self-verify failed: ${check.reason}`); return setExitCode(1); }
    publishLicense(out, `${licText}\n`, opts.force === true);
    io.log(`Wrote ${out} for ${payload.customer} (${payload.plan}, ${payload.seats} seats, expires ${payload.expires})`);
  }, { fs });
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const setExitCode = deps.setExitCode || ((c) => { process.exitCode = c; });
  const opts = parseArgs(argv);
  try {
    if (opts.initKeypair) return initKeypair(opts.initKeypair, io);
    if (!opts.key || !license.validCustomerId(opts.customerId) || !opts.expires || !opts.plan || !opts.seats) {
      io.error('Usage: --init-keypair <dir>  OR  --key <pem> --customer <name> --customer-id <id> --plan <standard|enterprise> --seats <n> --expires <YYYY-MM-DD> [--grace-days 30] [--features a,b] [--out redactwall.lic] [--force]');
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
