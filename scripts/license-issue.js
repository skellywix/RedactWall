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

function committedCleanupWarning(warning) {
  const retained = warning && warning.retainedPath ? `; retained=${warning.retainedPath}` : '';
  process.stderr.write(`[warn] committed license artifact needs cleanup (${warning.code})${retained}\n`);
}

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

function existingStableFile(filePath, label) {
  let stat;
  try {
    stat = fs.lstatSync(filePath, { bigint: true });
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
      || typeof stat.dev !== 'bigint' || typeof stat.ino !== 'bigint'
      || stat.dev <= 0n || stat.ino <= 0n) {
    throw new Error(`${label} must be a single-link regular file with a stable filesystem identity`);
  }
  return stat;
}

function sameFile(left, right) {
  if (comparablePath(left) === comparablePath(right)) return true;
  const a = existingStableFile(left, 'offline license signing key');
  const b = existingStableFile(right, 'license output');
  if (!a || !b) return false;
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
  let identity;
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
    identity = fs.fstatSync(fd, { bigint: true });
    fs.closeSync(fd);
    fd = undefined;
    return { path: temp, identity };
  } catch (error) {
    if (fd !== undefined) {
      if (!identity) try { identity = fs.fstatSync(fd, { bigint: true }); } catch {}
      try { fs.closeSync(fd); } catch {}
    }
    if (identity) try { privatePaths.removeExactPublicationFile(temp, identity, { fs }); } catch {}
    throw error;
  }
}

function cleanupStagedFile(stage) {
  if (!stage || !stage.identity) return;
  try { privatePaths.removeExactPublicationFile(stage.path, stage.identity, { fs }); } catch {}
}

function verifyPublishedPrivateFile(file, expectedContents, label) {
  privatePaths.assertPrivatePath(file, {
    fs,
    directory: false,
    label,
    ownerLabel: label,
  });
  const expected = Buffer.isBuffer(expectedContents)
    ? expectedContents
    : Buffer.from(expectedContents);
  const published = privatePaths.readBoundedRegularFile(file, {
    fs,
    maxBytes: Math.max(expected.length, 1),
    label,
  });
  if (!published.equals(expected)) throw new Error(`${label} changed during publication verification`);
  const identity = fs.lstatSync(file, { bigint: true });
  if (!identity.isFile() || identity.isSymbolicLink() || identity.nlink !== 1n
      || identity.dev <= 0n || identity.ino <= 0n) {
    throw new Error(`${label} has no stable single-file identity`);
  }
  return identity;
}

function rollbackKeypair(paths, published, originalError) {
  const failures = [];
  for (const [file, identity] of [[paths.pub, published.pub], [paths.priv, published.priv]]) {
    if (!identity) continue;
    try { privatePaths.removeExactPublicationFile(file, identity, { fs }); }
    catch (error) { failures.push(error); }
  }
  try { privatePaths.fsyncDirectory(path.dirname(paths.priv), { fs }); }
  catch (error) { failures.push(error); }
  if (failures.length) {
    [originalError.rollbackError] = failures;
    if (failures.length > 1) originalError.additionalRollbackErrors = failures.slice(1);
  }
}

function publishKeypair(paths, privatePem, publicPem) {
  const tempPriv = stagePrivateFile(paths.priv, privatePem, 'offline license private-key staging file');
  let tempPub;
  let privPublished = false;
  let pubPublished = false;
  let privIdentity;
  let pubIdentity;
  try {
    tempPub = stagePrivateFile(paths.pub, publicPem, 'offline license public-key staging file');
    privatePaths.publishFileExclusiveDurably(tempPriv.path, paths.priv, {
      fs,
      consumeSource: true,
      verifyPublished(publishedFile) {
        privIdentity = verifyPublishedPrivateFile(publishedFile, privatePem, 'offline license private key');
      },
    });
    privPublished = true;
    privatePaths.publishFileExclusiveDurably(tempPub.path, paths.pub, {
      fs,
      consumeSource: true,
      verifyPublished(publishedFile) {
        pubIdentity = verifyPublishedPrivateFile(publishedFile, publicPem, 'offline license public key');
      },
    });
    pubPublished = true;
  } catch (error) {
    rollbackKeypair(paths, {
      priv: privPublished ? privIdentity : null,
      pub: pubPublished ? pubIdentity : null,
    }, error);
    throw error;
  } finally {
    if (!privPublished) cleanupStagedFile(tempPriv);
    if (!pubPublished) cleanupStagedFile(tempPub);
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
  let sourceConsumed = false;
  const verifyPublished = (publishedFile) => {
    verifyPublishedPrivateFile(publishedFile, body, 'license output file');
  };
  try {
    if (force) privatePaths.publishFileDurably(temp.path, target, {
      fs,
      cleanupComponent: 'issued-license-publication',
      onCommittedCleanupWarning: committedCleanupWarning,
      verifyPublished,
    });
    else privatePaths.publishFileExclusiveDurably(temp.path, target, {
      fs,
      consumeSource: true,
      cleanupComponent: 'issued-license-publication',
      verifyPublished,
    });
    sourceConsumed = true;
  } finally {
    if (!sourceConsumed) cleanupStagedFile(temp);
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
  }, {
    fs,
    cleanupComponent: 'issued-license-lock',
    onCommittedCleanupWarning: committedCleanupWarning,
  });
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
