'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const protocol = require('./vendor-control-protocol');
const privatePaths = require('./private-path');
const { withFileMutationLockSync } = require('./file-mutation-lock');

const MAX_SIDECAR_BYTES = 4 * 1024 * 1024;
const ZERO_DIGEST = '0'.repeat(64);
const POLICY_TEST_EXTERNAL_ASSURANCE = 'test-reference';

function createFilePolicyExternalState(options = {}) {
  const directory = checkedDirectory(options.directory);
  const security = {
    ...(options.privatePathSecurity || {}),
    label: 'vendor policy external state',
    ownerLabel: 'vendor policy external state',
  };
  ensurePrivateDirectory(directory, security);
  const pendingPath = path.join(directory, 'policy-pending.json');
  const anchorPath = path.join(directory, 'policy-anchor.json');
  const lockTarget = path.join(directory, '.policy-external-state');
  const locked = (callback) => withFileMutationLockSync(lockTarget, callback, {
    ...security,
    lockTimeoutMs: 30_000,
    lockTimeoutMaximumMs: 30_000,
  });
  return Object.freeze({
    kind: 'file',
    assurance: POLICY_TEST_EXTERNAL_ASSURANCE,
    directory,
    async readPending() { return readDocument(pendingPath); },
    async readAnchor() { return readDocument(anchorPath); },
    async preparePending(wrapped) {
      return locked(() => {
        const bytes = canonicalBytes(wrapped);
        if (!writeExclusiveDurable(pendingPath, bytes, security)) return false;
        return digestBytes(bytes);
      });
    },
    async compareAndSetAnchor(expectedSequence, wrapped) {
      return locked(() => {
        const current = readDocument(anchorPath);
        const sequence = current?.payload?.sequence || 0;
        if (sequence !== expectedSequence) return false;
        atomicWriteDurable(anchorPath, canonicalBytes(wrapped), security);
        return true;
      });
    },
    async clearPending(expectedDigest) {
      return locked(() => {
        const bytes = readBytes(pendingPath, true);
        if (bytes === null || digestBytes(bytes) !== expectedDigest) return false;
        privatePaths.assertPrivatePath(pendingPath, { ...security, directory: false });
        fs.unlinkSync(pendingPath);
        privatePaths.fsyncDirectory(directory, security);
        return true;
      });
    },
  });
}

function createMemoryPolicyExternalState(options = {}) {
  if (!options || options.testOnly !== true) {
    throw externalError('policy_external_memory_test_only');
  }
  const seed = options.seed || {};
  let pending = seed.pending ? clone(seed.pending) : null;
  let anchor = seed.anchor ? clone(seed.anchor) : null;
  let faultMode = null;
  return Object.freeze({
    kind: 'memory',
    assurance: POLICY_TEST_EXTERNAL_ASSURANCE,
    async readPending() { return clone(pending); },
    async readAnchor() { return clone(anchor); },
    async preparePending(wrapped) {
      if (faultMode === 'prepare') throw externalError('policy_external_prepare_failed');
      if (pending !== null) return false;
      pending = clone(wrapped);
      return documentDigest(pending);
    },
    async compareAndSetAnchor(expectedSequence, wrapped) {
      if (faultMode === 'anchor') throw externalError('policy_external_anchor_failed');
      if ((anchor?.payload?.sequence || 0) !== expectedSequence) return false;
      anchor = clone(wrapped);
      return true;
    },
    async clearPending(expectedDigest) {
      if (faultMode === 'clear') throw externalError('policy_external_clear_failed');
      if (pending === null || documentDigest(pending) !== expectedDigest) return false;
      pending = null;
      return true;
    },
    setFault(value) { faultMode = value; },
    snapshot() { return { pending: clone(pending), anchor: clone(anchor) }; },
    replacePending(value) { pending = clone(value); },
    replaceAnchor(value) { anchor = clone(value); },
  });
}

function checkedDirectory(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    throw externalError('policy_external_directory_invalid');
  }
  return path.resolve(value);
}

function ensurePrivateDirectory(directory, security) {
  try {
    privatePaths.withPrivateDirectoryMutationLockSync(directory, () => undefined, {
      ...security,
      directory: true,
      lockTimeoutMs: 60_000,
      lockTimeoutMaximumMs: 60_000,
    });
  } catch (error) {
    throw externalError('policy_external_directory_invalid', error);
  }
}

function readDocument(file) {
  const bytes = readBytes(file, true);
  if (bytes === null) return null;
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch { throw externalError('policy_external_state_invalid'); }
  if (protocol.canonicalJson(value) !== bytes.toString('utf8')) {
    throw externalError('policy_external_state_invalid');
  }
  return value;
}

function readBytes(file, missingAllowed) {
  let expected;
  try {
    privatePaths.assertPrivatePath(file, {
      directory: false,
      label: 'vendor policy external state file',
      ownerLabel: 'vendor policy external state file',
    });
    expected = fs.lstatSync(file, { bigint: true });
  } catch (error) {
    if (missingAllowed && error?.code === 'ENOENT') return null;
    throw externalError('policy_external_state_invalid', error);
  }
  let handle;
  try {
    const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
    handle = fs.openSync(file, flags);
  } catch (error) {
    if (missingAllowed && error?.code === 'ENOENT') return null;
    throw externalError('policy_external_read_failed', error);
  }
  try {
    const before = fs.fstatSync(handle, { bigint: true });
    if (expected.dev !== before.dev || expected.ino !== before.ino
        || !before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
        || before.size < 2n || before.size > BigInt(MAX_SIDECAR_BYTES)) {
      throw externalError('policy_external_state_invalid');
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(handle, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw externalError('policy_external_state_invalid');
      offset += count;
    }
    const after = fs.fstatSync(handle, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
        || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
      throw externalError('policy_external_state_changed');
    }
    return bytes;
  } finally { fs.closeSync(handle); }
}

function canonicalBytes(value) {
  let bytes;
  try { bytes = Buffer.from(protocol.canonicalJson(value), 'utf8'); }
  catch { throw externalError('policy_external_state_invalid'); }
  if (bytes.length < 2 || bytes.length > MAX_SIDECAR_BYTES) {
    throw externalError('policy_external_state_invalid');
  }
  return bytes;
}

function writeExclusiveDurable(file, bytes, security) {
  if (fs.existsSync(file)) return false;
  const temporary = temporaryPath(path.dirname(file));
  try {
    writePrivateTemporary(temporary, bytes, security);
    privatePaths.publishFileExclusiveDurably(temporary, file, {
      ...security,
      consumeSource: true,
    });
  } catch (error) {
    try { fs.unlinkSync(temporary); } catch {}
    if (error?.code === 'EEXIST') return false;
    throw externalError('policy_external_prepare_failed', error);
  }
  return true;
}

function atomicWriteDurable(file, bytes, security) {
  const directory = path.dirname(file);
  const temporary = temporaryPath(directory);
  try {
    writePrivateTemporary(temporary, bytes, security);
    privatePaths.publishFileDurably(temporary, file, security);
  } catch (error) {
    try { fs.unlinkSync(temporary); } catch {}
    throw externalError('policy_external_anchor_failed', error);
  }
}

function temporaryPath(directory) {
  return path.join(directory, `.policy-${crypto.randomUUID()}.tmp`);
}

function writePrivateTemporary(file, bytes, security) {
  let handle;
  try {
    handle = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    writeAndFlush(handle, bytes);
    fs.closeSync(handle);
    handle = undefined;
    privatePaths.protectInheritedPrivateFile(file, { ...security, directory: false });
    handle = fs.openSync(file, fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0));
    fs.fsyncSync(handle);
  } finally {
    if (handle !== undefined) fs.closeSync(handle);
  }
}

function writeAndFlush(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) offset += fs.writeSync(handle, bytes, offset, bytes.length - offset, offset);
  fs.fsyncSync(handle);
}

function documentDigest(value) {
  return digestBytes(canonicalBytes(value));
}

function digestBytes(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function clone(value) {
  if (value === null || value === undefined) return null;
  return JSON.parse(protocol.canonicalJson(value));
}

function externalError(code, cause) {
  const error = new Error('policy external state rejected');
  error.code = code;
  if (cause) error.cause = cause;
  return error;
}

module.exports = {
  MAX_SIDECAR_BYTES,
  ZERO_DIGEST,
  createFilePolicyExternalState,
  createMemoryPolicyExternalState,
};
