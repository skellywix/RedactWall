'use strict';

const fs = require('node:fs');
const path = require('node:path');
const license = require('../server/license');

function selectedEnvironment(argv = process.argv.slice(2), source = process.env) {
  const env = { ...(source || {}) };
  const index = argv.indexOf('--public-key-file');
  if (index !== -1) {
    const value = argv[index + 1];
    if (!value || argv.length !== 2) throw new Error('usage: npm run license:trust-check -- --public-key-file <public.pem>');
    const target = path.resolve(value);
    env.REDACTWALL_LICENSE_PUBLIC_KEY = readPublicKeyFile(target);
    delete env.REDACTWALL_LICENSE_PUBLIC_KEY_B64;
  } else if (argv.length) {
    throw new Error('usage: npm run license:trust-check -- [--public-key-file <public.pem>]');
  }
  return env;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.nlink === right.nlink
    && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function readPublicKeyFile(target) {
  const before = fs.lstatSync(target, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size <= 0n || before.size > 4096n) {
    throw new Error('license public key file must be a bounded single-link regular file');
  }
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  const descriptor = fs.openSync(target, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const boundPath = fs.lstatSync(target, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameIdentity(before, opened) || !sameIdentity(opened, boundPath)) {
      throw new Error('license public key file changed while opening');
    }
    const contents = fs.readFileSync(descriptor, 'utf8');
    const after = fs.fstatSync(descriptor, { bigint: true });
    const finalPath = fs.lstatSync(target, { bigint: true });
    if (!sameIdentity(opened, after) || !sameIdentity(after, finalPath)) throw new Error('license public key file changed while reading');
    return contents;
  } finally { fs.closeSync(descriptor); }
}

function check(argv, source) {
  const status = license.productionTrustAnchorStatus(selectedEnvironment(argv, source));
  if (!status.ok) {
    if (status.placeholder) throw new Error('production license trust anchor is still the known placeholder');
    throw new Error('production license trust anchor must be a valid Ed25519 public key');
  }
  return status;
}

function main() {
  try {
    const status = check(process.argv.slice(2), process.env);
    console.log(`Production license trust anchor ready (${status.fingerprint}).`);
  } catch (error) {
    console.error(`[license-trust] ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { check, readPublicKeyFile, selectedEnvironment };
