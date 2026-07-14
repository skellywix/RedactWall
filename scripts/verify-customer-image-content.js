'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const {
  CREDENTIAL_FILE_EXTENSIONS,
  CREDENTIAL_FILE_NAMES,
  MAX_ARTIFACT_BYTES,
  containsPgpPrivateArmor,
  containsPrivatePem,
  credentialFilename,
  inspectCustomerArtifact,
} = require('./customer-secret-material-detector');

const IMAGE_SCAN_ROOTS = Object.freeze(['/']);
const VIRTUAL_TOP_LEVEL_DIRECTORIES = new Set(['dev', 'proc', 'sys']);
const GNUTLS_PRIVATE_VECTOR_EXCEPTION = Object.freeze({
  absolutePath: '/usr/lib/x86_64-linux-gnu/libgnutls.so.30.34.3',
  manifestPath: '/var/lib/dpkg/info/libgnutls30:amd64.md5sums',
  md5: 'd37dc553e7856d74d930d695099d5d14',
  mode: 0o644,
  packageName: 'libgnutls30:amd64',
  packageOwner: 'libgnutls30:amd64: /usr/lib/x86_64-linux-gnu/libgnutls.so.30.34.3',
  packageStatus: 'ii \tlibgnutls30:amd64\t3.7.9-2+deb12u7',
  relativePath: 'usr/lib/x86_64-linux-gnu/libgnutls.so.30.34.3',
  sha256: '779b25d20249988bea2c1aa6bbeb218f5ae7ea8a9d30ce4f54ea37372965cc4b',
  size: 2209528,
});

function gnutlsExceptionError(reason) {
  return new Error(`GnuTLS package exception rejected: ${reason}`);
}

function exactProtectedFileStat(stat, expected = {}) {
  return Boolean(stat
    && stat.isFile === true
    && stat.isSymbolicLink === false
    && stat.uid === 0
    && stat.gid === 0
    && stat.nlink === 1
    && stat.mode === (expected.mode ?? 0o644)
    && (expected.size === undefined || stat.size === expected.size));
}

function validateGnutlsExceptionEvidence(evidence) {
  const expected = GNUTLS_PRIVATE_VECTOR_EXCEPTION;
  if (!evidence || evidence.relativePath !== expected.relativePath) {
    throw gnutlsExceptionError('path is not the canonical exception path');
  }
  if (evidence.realPath !== expected.absolutePath) {
    throw gnutlsExceptionError('canonical target identity differs');
  }
  if (!exactProtectedFileStat(evidence.stat, expected)) {
    throw gnutlsExceptionError('library type, owner, mode, link count, or size differs');
  }
  if (evidence.packageOwner !== expected.packageOwner) {
    throw gnutlsExceptionError('dpkg ownership differs');
  }
  if (evidence.packageStatus !== expected.packageStatus) {
    throw gnutlsExceptionError('dpkg installed package identity differs');
  }
  if (!exactProtectedFileStat(evidence.manifestStat)) {
    throw gnutlsExceptionError('dpkg checksum manifest identity differs');
  }
  if (evidence.manifestMatches !== 1 || evidence.md5 !== expected.md5) {
    throw gnutlsExceptionError('dpkg checksum proof differs');
  }
  if (evidence.sha256 !== expected.sha256) {
    throw gnutlsExceptionError('reviewed content identity differs');
  }
  return true;
}

function normalizedStat(stat) {
  return Object.freeze({
    isFile: stat.isFile(),
    isSymbolicLink: stat.isSymbolicLink(),
    uid: stat.uid,
    gid: stat.gid,
    mode: stat.mode & 0o777,
    nlink: stat.nlink,
    size: stat.size,
  });
}

function checkedCommandOutput(command, args) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024,
    shell: false,
    timeout: 5000,
    windowsHide: true,
  });
  if (result.error || result.signal || result.status !== 0 || result.stderr) {
    throw gnutlsExceptionError('package ownership command failed closed');
  }
  if (Buffer.byteLength(result.stdout, 'utf8') > 8192) {
    throw gnutlsExceptionError('package ownership command output is oversized');
  }
  return result.stdout.replace(/\r?\n$/, '');
}

function verifyGnutlsPackageException(absolutePath, relativePath, body) {
  const expected = GNUTLS_PRIVATE_VECTOR_EXCEPTION;
  if (process.platform !== 'linux'
      || relativePath.split(path.sep).join('/') !== expected.relativePath
      || path.resolve(absolutePath) !== expected.absolutePath) return false;
  let realPath;
  let stat;
  let manifestStat;
  let manifestBody;
  try {
    realPath = fs.realpathSync.native(absolutePath);
    stat = fs.lstatSync(absolutePath);
    if (fs.realpathSync.native(expected.manifestPath) !== expected.manifestPath) {
      throw gnutlsExceptionError('dpkg checksum manifest is not canonical');
    }
    manifestStat = fs.lstatSync(expected.manifestPath);
    if (manifestStat.size < 1 || manifestStat.size > 64 * 1024) {
      throw gnutlsExceptionError('dpkg checksum manifest size differs');
    }
    manifestBody = fs.readFileSync(expected.manifestPath, 'utf8');
  } catch (error) {
    if (error.message?.startsWith('GnuTLS package exception rejected:')) throw error;
    throw gnutlsExceptionError('package files are unreadable');
  }
  const checksumLine = `${expected.md5}  ${expected.relativePath}`;
  const manifestMatches = manifestBody.split(/\r?\n/)
    .filter((line) => line === checksumLine).length;
  const packageOwner = checkedCommandOutput('/usr/bin/dpkg-query', ['-S', expected.absolutePath]);
  const packageStatus = checkedCommandOutput('/usr/bin/dpkg-query', [
    '-W', '-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\n', expected.packageName,
  ]);
  return validateGnutlsExceptionEvidence({
    relativePath: relativePath.split(path.sep).join('/'),
    realPath,
    stat: normalizedStat(stat),
    packageOwner,
    packageStatus,
    manifestStat: normalizedStat(manifestStat),
    manifestMatches,
    md5: crypto.createHash('md5').update(body).digest('hex'),
    sha256: crypto.createHash('sha256').update(body).digest('hex'),
  });
}

function inspectImageFile(root, absolutePath, relativePath, stat, options) {
  if (stat.size > MAX_ARTIFACT_BYTES) {
    throw new Error(`customer image contains an artifact above the bounded scan ceiling: ${relativePath}`);
  }
  const body = fs.readFileSync(absolutePath);
  if (body.length !== stat.size) {
    throw new Error(`customer image artifact changed while scanning: ${relativePath}`);
  }
  const finding = inspectCustomerArtifact(relativePath, body);
  if (!finding) return;
  if (finding.kind === 'credential_file') {
    throw new Error(`customer image contains a prohibited credential file: ${relativePath}`);
  }
  if (finding.kind === 'private_key_material'
      && options.allowVerifiedPackageException
      && root === path.parse(root).root
      && verifyGnutlsPackageException(absolutePath, relativePath, body)) return;
  if (finding.kind === 'private_key_material') {
    throw new Error(`customer image contains private key material: ${relativePath}`);
  }
  throw new Error(`customer image contains an artifact above the bounded scan ceiling: ${relativePath}`);
}

function scanDirectory(root, directory, relativeDirectory, counters, options) {
  const entries = fs.readdirSync(directory, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    if (!relativeDirectory && VIRTUAL_TOP_LEVEL_DIRECTORIES.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    const relative = relativeDirectory ? path.join(relativeDirectory, entry.name) : entry.name;
    const stat = fs.lstatSync(absolute);
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) scanDirectory(root, absolute, relative, counters, options);
    else if (stat.isFile()) {
      inspectImageFile(root, absolute, relative, stat, options);
      counters.files += 1;
      counters.bytes += stat.size;
    }
  }
}

function scanCustomerImage(root = '/', options = {}) {
  const resolved = path.resolve(root);
  const stat = fs.lstatSync(resolved);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('customer image scan root must be a directory');
  }
  const scanOptions = Object.freeze({
    allowVerifiedPackageException: options.allowVerifiedPackageException === true,
  });
  const counters = { files: 0, bytes: 0 };
  scanDirectory(resolved, resolved, '', counters, scanOptions);
  return Object.freeze({ root: resolved, files: counters.files, bytes: counters.bytes });
}

function scanCustomerImageRoots(roots, options = {}) {
  if (!Array.isArray(roots) || roots.length < 1) {
    throw new Error('at least one customer image root is required');
  }
  const results = roots.map((root) => scanCustomerImage(root, options));
  return Object.freeze({
    roots: Object.freeze(results.map((result) => result.root)),
    files: results.reduce((sum, result) => sum + result.files, 0),
    bytes: results.reduce((sum, result) => sum + result.bytes, 0),
  });
}

function parseArgs(argv) {
  const roots = [];
  for (let index = 0; index < argv.length; index += 2) {
    if (argv[index] !== '--root' || !argv[index + 1]) {
      throw new Error('Usage: node scripts/verify-customer-image-content.js --root /');
    }
    roots.push(argv[index + 1]);
  }
  if (roots.length !== IMAGE_SCAN_ROOTS.length
      || roots.some((root, index) => root !== IMAGE_SCAN_ROOTS[index])) {
    throw new Error('the customer image build scan must cover the exact filesystem root');
  }
  return roots;
}

function main(argv = process.argv.slice(2), consoleImpl = console) {
  try {
    const result = scanCustomerImageRoots(parseArgs(argv), {
      allowVerifiedPackageException: true,
    });
    consoleImpl.log(`Verified ${result.files} durable image files contain no baked credential or private key material`);
    return 0;
  } catch (error) {
    consoleImpl.error(error.message);
    return 1;
  }
}

if (require.main === module) process.exitCode = main();

module.exports = {
  CREDENTIAL_FILE_EXTENSIONS,
  CREDENTIAL_FILE_NAMES,
  GNUTLS_PRIVATE_VECTOR_EXCEPTION,
  IMAGE_SCAN_ROOTS,
  VIRTUAL_TOP_LEVEL_DIRECTORIES,
  containsPgpPrivateArmor,
  containsPrivatePem,
  credentialFilename,
  main,
  parseArgs,
  scanCustomerImage,
  scanCustomerImageRoots,
  validateGnutlsExceptionEvidence,
  verifyGnutlsPackageException,
};
