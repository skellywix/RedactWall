'use strict';
/** Atomically publish packaged runtime configuration into a writable volume once. */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const fileMutationLock = require('../server/file-mutation-lock');
const privatePaths = require('../server/private-path');

const DEFAULT_POLICY_SOURCE_PATH = path.join(__dirname, '..', 'config', 'policy.json');
const DEFAULT_CUSTOM_DETECTORS_SOURCE_PATH = path.join(__dirname, '..', 'config', 'custom-detectors.json');
const DEFAULT_SOURCE_PATH = DEFAULT_POLICY_SOURCE_PATH;

function pathExists(file, fsImpl = fs) {
  try {
    fsImpl.lstatSync(file);
    return true;
  } catch (err) {
    if (err && err.code === 'ENOENT') return false;
    throw err;
  }
}

function publishRuntimeFile(sourcePath, targetPath, options, fsImpl) {
  if (pathExists(targetPath, fsImpl)) return { seeded: false, reason: options.existingReason };
  fsImpl.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
  const nonce = crypto.randomBytes(8).toString('hex');
  const tempPath = `${targetPath}.seed-${process.pid}-${nonce}`;
  let descriptor;
  try {
    fsImpl.copyFileSync(sourcePath, tempPath, fs.constants.COPYFILE_EXCL);
    fsImpl.chmodSync(tempPath, 0o600);
    descriptor = fsImpl.openSync(tempPath, fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0));
    if (!fsImpl.fstatSync(descriptor).isFile()) throw new Error('runtime configuration staging path is not a regular file');
    fsImpl.fsyncSync(descriptor);
    fsImpl.closeSync(descriptor);
    descriptor = undefined;
    privatePaths.securePrivatePath(tempPath, {
      ...(options.privatePathSecurity || {}),
      fs: fsImpl,
      directory: false,
      fresh: true,
      label: 'runtime configuration staging file',
      ownerLabel: 'runtime configuration staging file',
    });
    try {
      privatePaths.publishFileExclusiveDurably(tempPath, targetPath, {
        ...(options.privatePathSecurity || {}),
        fs: fsImpl,
      });
    } catch (err) {
      if (err && err.code === 'EEXIST') return { seeded: false, reason: options.existingReason };
      throw err;
    }
    return { seeded: true, reason: options.seededReason };
  } finally {
    if (descriptor !== undefined) {
      try { fsImpl.closeSync(descriptor); } catch {}
    }
    fsImpl.rmSync(tempPath, { force: true });
  }
}

function seedRuntimeFile(options = {}) {
  const fsImpl = options.fs || fs;
  const configuredTarget = options.targetPath;
  if (!String(configuredTarget || '').trim()) return { seeded: false, reason: 'target_unset' };
  const sourcePath = path.resolve(options.sourcePath);
  const targetPath = path.resolve(String(configuredTarget));
  const directory = path.dirname(targetPath);
  return privatePaths.withPrivateDirectoryMutationLockSync(directory, () => (
    fileMutationLock.withFileMutationLockSync(
      targetPath,
      () => publishRuntimeFile(sourcePath, targetPath, options, fsImpl),
      options,
    )
  ), {
    ...(options.privatePathSecurity || {}),
    fs: fsImpl,
    directory: true,
    label: 'runtime configuration directory',
    ownerLabel: 'runtime configuration directory',
    ...(options.directoryLockTimeoutMs ? { lockTimeoutMs: options.directoryLockTimeoutMs } : {}),
  });
}

function seedRuntimePolicy(options = {}) {
  return seedRuntimeFile({
    ...options,
    fs: options.fs,
    sourcePath: options.sourcePath || DEFAULT_POLICY_SOURCE_PATH,
    targetPath: options.targetPath ?? process.env.REDACTWALL_POLICY_PATH,
    existingReason: 'existing_policy',
    seededReason: 'packaged_policy',
  });
}

function seedRuntimeCustomDetectors(options = {}) {
  return seedRuntimeFile({
    ...options,
    fs: options.fs,
    sourcePath: options.sourcePath || DEFAULT_CUSTOM_DETECTORS_SOURCE_PATH,
    targetPath: options.targetPath ?? process.env.REDACTWALL_CUSTOM_DETECTORS_PATH,
    existingReason: 'existing_custom_detectors',
    seededReason: 'packaged_custom_detectors',
  });
}

function seedRuntimeConfiguration(options = {}) {
  const fsImpl = options.fs || fs;
  const policy = seedRuntimePolicy({
    privatePathSecurity: options.privatePathSecurity,
    directoryLockTimeoutMs: options.directoryLockTimeoutMs,
    fs: fsImpl,
    sourcePath: options.policySourcePath || process.env.REDACTWALL_POLICY_SEED_PATH,
    targetPath: options.policyTargetPath,
  });
  const customDetectors = seedRuntimeCustomDetectors({
    privatePathSecurity: options.privatePathSecurity,
    directoryLockTimeoutMs: options.directoryLockTimeoutMs,
    fs: fsImpl,
    sourcePath: options.customDetectorsSourcePath || process.env.REDACTWALL_CUSTOM_DETECTORS_SEED_PATH,
    targetPath: options.customDetectorsTargetPath,
  });
  return { policy, customDetectors };
}

function main() {
  const result = seedRuntimeConfiguration();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  return result;
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(`[startup] runtime configuration seed failed: ${err.message || err}`);
    process.exit(1);
  }
}

module.exports = {
  DEFAULT_SOURCE_PATH,
  DEFAULT_POLICY_SOURCE_PATH,
  DEFAULT_CUSTOM_DETECTORS_SOURCE_PATH,
  pathExists,
  seedRuntimeFile,
  seedRuntimePolicy,
  seedRuntimeCustomDetectors,
  seedRuntimeConfiguration,
  main,
};
