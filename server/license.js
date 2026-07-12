'use strict';
/**
 * Offline license verification (ROADMAP N7).
 *
 * A `redactwall.lic` file is `base64(payloadJSON).base64(ed25519Signature)`,
 * where the signature is over the UTF-8 bytes of the base64-payload string
 * (signing the encoded form avoids any JSON canonicalization question). It is
 * verified at boot and re-checked daily against an EMBEDDED public key. This is
 * the AIR-GAPPED default — no license server, no phone-home — so offline
 * credit-union deployments work with zero egress.
 *
 * The license never fails OPEN. In the offline model: absence or invalidity =
 * demo mode (zero gating); past the grace window it degrades the ADMIN CONSOLE
 * to read-only for configuration routes while detection, enforcement, the
 * approval workflow, audit, and evidence export keep running.
 *
 * CONNECTED mode (opt-in, server/vendor-link.js) adds a vendor kill-switch: a
 * signed heartbeat verdict from the vendor can move the effective state to
 * 'revoked', which locks the console like readonly AND fail-closed-blocks
 * sensor ingest (`license_revoked`). A revoked customer loses USE of AI through
 * the product — the strongest data protection, not its absence; nothing ever
 * fails open. Revocation is only ever set by a signature-verified vendor
 * verdict (applyVendorVerdict), never by the local file, so it cannot be
 * cleared by a customer reinstalling a license. It is an overlay on top of the
 * file-derived state and survives refresh().
 *
 * The vendor's PRIVATE signing key lives offline (see scripts/license-issue.js
 * --init-keypair) and is never in the repo. Tests inject a throwaway public key
 * via the REDACTWALL_LICENSE_PUBLIC_KEY env override or the publicKeyPem param.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const env = require('./env');
const tenant = require('./tenant');
const privatePaths = require('./private-path');
const fileMutationLock = require('./file-mutation-lock');

// Placeholder public key. Regenerate offline with
// `node scripts/license-issue.js --init-keypair <dir>` before the first
// commercial release and paste the printed public PEM here.
const EMBEDDED_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA0lard41yplR7X9CCdwvvvbjWIPUGOisoi4jfQV1GY6c=
-----END PUBLIC KEY-----`;

const DEFAULT_GRACE_DAYS = 30;
const MAX_LICENSE_FILE_BYTES = 64 * 1024;
const MAX_LICENSE_FILE_BYTES_BIGINT = BigInt(MAX_LICENSE_FILE_BYTES);
const LICENSE_DIRECTORY_INIT_TIMEOUT_MS = 60_000;
const PLANS = ['standard', 'enterprise'];

function embeddedPublicKey() {
  return process.env.REDACTWALL_LICENSE_PUBLIC_KEY || process.env.PROMPTWALL_LICENSE_PUBLIC_KEY || process.env.SENTINEL_LICENSE_PUBLIC_KEY || EMBEDDED_PUBLIC_KEY_PEM;
}

function licensePath() {
  const explicit = process.env.REDACTWALL_LICENSE_PATH || process.env.PROMPTWALL_LICENSE_PATH || process.env.SENTINEL_LICENSE_PATH;
  if (explicit) return explicit;
  const base = typeof env.defaultEnvPath === 'function' ? env.defaultEnvPath() : path.join(process.cwd(), '.env');
  return path.join(path.dirname(base), 'redactwall.lic');
}

function licenseDirectorySecurity(options = {}, fsImpl = options.fs || fs) {
  return {
    ...options,
    fs: fsImpl,
    directory: true,
    label: 'license directory',
    ownerLabel: 'license directory',
    lockTimeoutMs: options.licenseDirectoryLockTimeoutMs || LICENSE_DIRECTORY_INIT_TIMEOUT_MS,
    lockTimeoutMaximumMs: LICENSE_DIRECTORY_INIT_TIMEOUT_MS,
    cleanupComponent: 'license-directory-lock',
  };
}

function writeLicenseBytesAtomicallyUnlocked(contents, options = {}) {
  const fsImpl = options.fs || fs;
  const target = options.path || licensePath();
  const directory = path.dirname(target);
  const temp = path.join(directory, `.${path.basename(target)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`);
  const mode = options.mode == null ? 0o600 : options.mode;
  let descriptor = null;
  let created = false;
  let stagedIdentity = null;
  try {
    fsImpl.mkdirSync(directory, { recursive: true, mode: 0o700 });
    descriptor = fsImpl.openSync(temp, 'wx', mode);
    created = true;
    const openedPath = exactLstat(fsImpl, temp);
    const openedHandle = exactFstat(fsImpl, descriptor);
    if (!sameLicenseSnapshot(openedPath, openedHandle)) {
      throw licenseReadFailure('license staging file changed while opening');
    }
    stagedIdentity = openedPath;
    privatePaths.securePrivatePath(temp, {
      ...options,
      fs: fsImpl,
      directory: false,
      fresh: true,
      label: 'license staging file',
      ownerLabel: 'license file',
    });
    const securedPath = exactLstat(fsImpl, temp);
    const securedHandle = exactFstat(fsImpl, descriptor);
    if (!sameLicenseSnapshot(securedPath, securedHandle)) {
      throw licenseReadFailure('license staging file changed while securing');
    }
    stagedIdentity = securedPath;
    fsImpl.writeFileSync(descriptor, contents);
    fsImpl.fsyncSync(descriptor);
    fsImpl.fchmodSync(descriptor, mode);
    const writtenHandle = exactFstat(fsImpl, descriptor);
    const writtenPath = exactLstat(fsImpl, temp);
    if (!sameLicenseSnapshot(writtenHandle, writtenPath)
        || writtenHandle.size !== BigInt(Buffer.byteLength(contents))) {
      throw licenseReadFailure('license staging file changed while writing');
    }
    stagedIdentity = writtenPath;
    fsImpl.closeSync(descriptor);
    descriptor = null;
    const callerVerify = options.verifyPublished;
    const publish = options.exclusive
      ? privatePaths.publishFileExclusiveDurably
      : privatePaths.publishFileDurably;
    publish(temp, target, {
      ...options,
      fs: fsImpl,
      cleanupComponent: 'license-file-publication',
      ...(options.exclusive ? { consumeSource: true } : {}),
      verifyPublished(published) {
        privatePaths.assertPrivatePath(published, {
          ...options,
          fs: fsImpl,
          directory: false,
          label: 'license file',
          ownerLabel: 'license file',
        });
        const identity = inspectLicenseFile(published, fsImpl);
        if (!identity) throw licenseReadFailure('published license is unavailable');
        if (typeof options.onPublishedIdentity === 'function') options.onPublishedIdentity(identity);
        if (typeof callerVerify === 'function') return callerVerify(published);
        return undefined;
      },
    });
    created = false;
  } catch (error) {
    if (descriptor !== null) {
      try { fsImpl.closeSync(descriptor); } catch {}
    }
    if (created) {
      if (stagedIdentity) {
        try { removeExactLicenseArtifact(temp, stagedIdentity, { ...options, fs: fsImpl }); }
        catch (cleanupError) {
          if (!cleanupError || cleanupError.code !== 'ENOENT') {
            if (error && (typeof error === 'object' || typeof error === 'function')) {
              try { error.cleanupError = cleanupError; } catch {}
              for (const field of ['retainedPath', 'additionalRetainedPath', 'removedPath']) {
                if (cleanupError && cleanupError[field]) {
                  try { if (!error[field]) error[field] = cleanupError[field]; } catch {}
                }
              }
            }
          }
        }
      } else if (error && (typeof error === 'object' || typeof error === 'function')) {
        try { if (!error.retainedPath) error.retainedPath = temp; } catch {}
      }
    }
    throw error;
  }
  return target;
}

function writeLicenseBytesAtomically(contents, options = {}) {
  const fsImpl = options.fs || fs;
  const target = path.resolve(options.path || licensePath());
  return privatePaths.withPrivateDirectoryMutationLockSync(path.dirname(target), () => (
    writeLicenseBytesAtomicallyUnlocked(contents, {
      ...options,
      fs: fsImpl,
      path: target,
    })
  ), licenseDirectorySecurity(options, fsImpl));
}

function licenseTextBytes(text) {
  return Buffer.from(`${String(text || '').trim()}\n`, 'utf8');
}

function writeLicenseAtomicallyUnlocked(text, options = {}) {
  return writeLicenseBytesAtomicallyUnlocked(licenseTextBytes(text), options);
}

function writeLicenseAtomically(text, options = {}) {
  return writeLicenseBytesAtomically(licenseTextBytes(text), options);
}

function exactLstat(fsImpl, target) {
  return fsImpl.lstatSync(target, { bigint: true });
}

function exactFstat(fsImpl, descriptor) {
  return fsImpl.fstatSync(descriptor, { bigint: true });
}

function stableLicenseFile(stat) {
  return !!stat && typeof stat.dev === 'bigint' && typeof stat.ino === 'bigint'
    && typeof stat.size === 'bigint' && typeof stat.mode === 'bigint'
    && stat.dev > 0n && stat.ino > 0n && stat.size >= 0n
    && stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1n;
}

function sameStatTime(left, right, name) {
  const ns = `${name}Ns`;
  if (left[ns] !== undefined || right[ns] !== undefined) {
    return left[ns] !== undefined && right[ns] !== undefined && left[ns] === right[ns];
  }
  const ms = `${name}Ms`;
  return left[ms] !== undefined && right[ms] !== undefined && left[ms] === right[ms];
}

function sameLicenseSnapshot(left, right) {
  return stableLicenseFile(left) && stableLicenseFile(right)
    && left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && sameStatTime(left, right, 'mtime') && sameStatTime(left, right, 'ctime');
}

function licenseReadFailure(message, cause) {
  const error = new Error(message);
  error.code = 'LICENSE_FILE_READ_FAILED';
  if (cause) error.cause = cause;
  return error;
}

function inspectLicenseFile(target, fsImpl) {
  let before;
  try {
    before = exactLstat(fsImpl, target);
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw licenseReadFailure('license file could not be inspected', error);
  }
  if (!stableLicenseFile(before) || before.size > MAX_LICENSE_FILE_BYTES_BIGINT) {
    throw licenseReadFailure('license path is not a bounded regular file');
  }
  return before;
}

function readLicenseSnapshot(target, before, fsImpl) {
  const output = Buffer.alloc(MAX_LICENSE_FILE_BYTES + 1);
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let descriptor;
  try {
    descriptor = fsImpl.openSync(target, fs.constants.O_RDONLY | noFollow);
    const opened = exactFstat(fsImpl, descriptor);
    if (!sameLicenseSnapshot(before, opened)) throw licenseReadFailure('license file changed while opening');
    let offset = 0;
    while (offset < output.length) {
      const count = fsImpl.readSync(descriptor, output, offset, output.length - offset, null);
      if (!count) break;
      offset += count;
    }
    const after = exactFstat(fsImpl, descriptor);
    const pathAfter = exactLstat(fsImpl, target);
    if (offset > MAX_LICENSE_FILE_BYTES || BigInt(offset) !== opened.size
        || !sameLicenseSnapshot(opened, after) || !sameLicenseSnapshot(after, pathAfter)) {
      throw licenseReadFailure('license file changed while reading');
    }
    return output.subarray(0, offset);
  } catch (error) {
    if (error && error.code === 'LICENSE_FILE_READ_FAILED') throw error;
    throw licenseReadFailure('license file could not be read', error);
  } finally {
    if (descriptor !== undefined) try { fsImpl.closeSync(descriptor); } catch {}
  }
}

function licenseFileSnapshot(target, options = {}) {
  const fsImpl = options.fs || fs;
  const before = inspectLicenseFile(target, fsImpl);
  if (!before) return { exists: false };
  const contents = readLicenseSnapshot(target, before, fsImpl);
  const after = inspectLicenseFile(target, fsImpl);
  if (!after || !sameLicenseSnapshot(before, after)) {
    throw licenseReadFailure('license file changed after reading');
  }
  return { exists: true, contents, mode: Number(before.mode & 0o777n), identity: after };
}

function restoreLicenseSnapshotUnlocked(target, snapshot, options = {}) {
  if (snapshot.exists) {
    writeLicenseBytesAtomicallyUnlocked(snapshot.contents, {
      ...options,
      path: target,
      mode: snapshot.mode,
      exclusive: true,
    });
    return;
  }
  const current = inspectLicenseFile(target, options.fs || fs);
  if (current) {
    throw licenseReadFailure('a replacement license appeared during rollback');
  }
}

function restoreLicenseSnapshot(target, snapshot, options = {}) {
  const fsImpl = options.fs || fs;
  const resolved = path.resolve(target);
  return privatePaths.withPrivateDirectoryMutationLockSync(path.dirname(resolved), () => (
    restoreLicenseSnapshotUnlocked(resolved, snapshot, { ...options, fs: fsImpl })
  ), licenseDirectorySecurity(options, fsImpl));
}

function licenseRollbackFailure(message, cause, details = {}) {
  const error = new Error(message);
  error.code = 'LICENSE_ROLLBACK_FAILED';
  error.cause = cause;
  Object.assign(error, details);
  return error;
}

function sameLicenseCandidate(left, right) {
  return !!left?.exists && !!right?.exists
    && stableLicenseFile(left.identity) && stableLicenseFile(right.identity)
    && left.identity.dev === right.identity.dev && left.identity.ino === right.identity.ino
    && left.identity.nlink === 1n && right.identity.nlink === 1n
    && Buffer.isBuffer(left.contents) && Buffer.isBuffer(right.contents)
    && left.contents.equals(right.contents);
}

function linkedLicenseStat(target, expectedLinks, fsImpl) {
  const stat = exactLstat(fsImpl, target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.dev <= 0n || stat.ino <= 0n
      || stat.nlink !== BigInt(expectedLinks)) {
    throw new Error('retained license artifact has no stable identity');
  }
  return stat;
}

function sameLinkedLicense(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && sameStatTime(left, right, 'mtime');
}

function removeExactLicenseArtifact(target, expected, options = {}) {
  const fsImpl = options.fs || fs;
  try {
    privatePaths.removeExactPublicationFile(target, expected, { ...options, fs: fsImpl });
    if ((options.platform || process.platform) !== 'win32') {
      privatePaths.fsyncDirectory(path.dirname(target), { ...options, fs: fsImpl });
    }
  } catch (error) {
    if (!error.retainedPath && !error.additionalRetainedPath && !error.removedPath) {
      try { exactLstat(fsImpl, target); error.retainedPath = target; }
      catch (inspectError) {
        if (inspectError && inspectError.code === 'ENOENT') error.removedPath = target;
      }
    }
    throw error;
  }
}

function restoreChangedLicense(quarantine, target, options, originalError) {
  const fsImpl = options.fs || fs;
  const guard = `${quarantine}.restore.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  let quarantinePresent = true;
  let guardPresent = false;
  try {
    const source = licenseFileSnapshot(quarantine, { ...options, fs: fsImpl });
    if (!source.exists) throw new Error('changed license replacement is unavailable');
    fsImpl.linkSync(quarantine, target);
    fsImpl.linkSync(quarantine, guard);
    guardPresent = true;
    let restored = linkedLicenseStat(target, 3, fsImpl);
    let retained = linkedLicenseStat(guard, 3, fsImpl);
    const sourceLink = linkedLicenseStat(quarantine, 3, fsImpl);
    if (!sameLinkedLicense(source.identity, restored) || !sameLinkedLicense(source.identity, retained)
        || !sameLinkedLicense(source.identity, sourceLink)) {
      throw new Error('changed license replacement could not be identity-bound');
    }
    removeExactLicenseArtifact(quarantine, sourceLink, options);
    quarantinePresent = false;
    restored = linkedLicenseStat(target, 2, fsImpl);
    retained = linkedLicenseStat(guard, 2, fsImpl);
    if (!sameLinkedLicense(source.identity, restored) || !sameLinkedLicense(source.identity, retained)) {
      throw new Error('changed license replacement changed during restoration');
    }
    removeExactLicenseArtifact(guard, retained, options);
    guardPresent = false;
    restored = linkedLicenseStat(target, 1, fsImpl);
    if (!sameLinkedLicense(source.identity, restored)) {
      throw new Error('changed license replacement changed after restoration');
    }
  } catch (error) {
    throw licenseRollbackFailure('changed license replacement was retained for recovery', originalError || error, {
      ...(error.retainedPath
        ? { retainedPath: error.retainedPath }
        : (quarantinePresent ? { retainedPath: quarantine } : {})),
      ...(error.additionalRetainedPath
        ? { additionalRetainedPath: error.additionalRetainedPath }
        : (guardPresent ? { additionalRetainedPath: guard } : {})),
      ...(error.removedPath ? { removedPath: error.removedPath } : {}),
      replacementPath: target,
    });
  }
  throw licenseRollbackFailure('license changed during rollback; replacement was preserved', originalError, {
    replacementPath: target,
  });
}

function rollbackLicenseCandidate(target, before, candidate, options, originalError) {
  const fsImpl = options.fs || fs;
  const quarantine = `${target}.failed-install.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  try {
    fsImpl.renameSync(target, quarantine);
  } catch (error) {
    throw licenseRollbackFailure('license rollback could not quarantine the installed candidate', originalError || error);
  }
  let quarantined;
  try { quarantined = licenseFileSnapshot(quarantine, { ...options, fs: fsImpl }); }
  catch (error) {
    throw licenseRollbackFailure('license rollback retained an unverifiable replacement', originalError || error, {
      retainedPath: quarantine,
    });
  }
  if (!sameLicenseCandidate(candidate, quarantined)) {
    restoreChangedLicense(quarantine, target, options, originalError);
  }
  try {
    restoreLicenseSnapshotUnlocked(target, before, options);
  } catch (error) {
    throw licenseRollbackFailure('prior license could not be restored', originalError || error, {
      retainedPath: quarantine,
    });
  }
  let exact;
  try { exact = licenseFileSnapshot(quarantine, { ...options, fs: fsImpl }); }
  catch (error) {
    throw licenseRollbackFailure('installed license quarantine could not be reverified', originalError || error, {
      retainedPath: quarantine,
    });
  }
  if (!sameLicenseCandidate(candidate, exact)) {
    throw licenseRollbackFailure('installed license quarantine changed before cleanup', originalError, {
      retainedPath: quarantine,
    });
  }
  const cleanupGuard = `${quarantine}.cleanup.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  let quarantinePresent = true;
  let guardPresent = false;
  try {
    fsImpl.linkSync(quarantine, cleanupGuard);
    guardPresent = true;
    const source = linkedLicenseStat(quarantine, 2, fsImpl);
    const guard = linkedLicenseStat(cleanupGuard, 2, fsImpl);
    if (!sameLinkedLicense(candidate.identity, source) || !sameLinkedLicense(candidate.identity, guard)) {
      throw new Error('installed license cleanup guard changed');
    }
    removeExactLicenseArtifact(quarantine, source, options);
    quarantinePresent = false;
    const retained = licenseFileSnapshot(cleanupGuard, { ...options, fs: fsImpl });
    if (!sameLicenseCandidate(candidate, retained)) {
      throw new Error('installed license cleanup guard changed after quarantine removal');
    }
    removeExactLicenseArtifact(cleanupGuard, retained.identity, options);
    guardPresent = false;
  } catch (error) {
    throw licenseRollbackFailure('installed license quarantine could not be removed', originalError || error, {
      ...(error.retainedPath
        ? { retainedPath: error.retainedPath }
        : (quarantinePresent ? { retainedPath: quarantine } : {})),
      ...(error.additionalRetainedPath
        ? { additionalRetainedPath: error.additionalRetainedPath }
        : (guardPresent ? { additionalRetainedPath: cleanupGuard } : {})),
      ...(error.removedPath ? { removedPath: error.removedPath } : {}),
    });
  }
}

function runLicenseFileMutation(target, callback, options) {
  const before = licenseFileSnapshot(target, options);
  let candidate = null;
  let publicationCommitted = false;
  const write = (text) => {
    const expectedContents = Buffer.from(`${String(text || '').trim()}\n`, 'utf8');
    let publishedIdentity = null;
    const priorIdentityObserver = options.onPublishedIdentity;
    const result = writeLicenseAtomicallyUnlocked(text, {
      ...options,
      path: target,
      onPublishedIdentity(identity) {
        publishedIdentity = identity;
        if (typeof priorIdentityObserver === 'function') priorIdentityObserver(identity);
      },
    });
    publicationCommitted = true;
    if (!publishedIdentity) throw licenseReadFailure('installed license identity was not captured');
    candidate = {
      exists: true,
      contents: expectedContents,
      mode: Number(publishedIdentity.mode & 0o777n),
      identity: publishedIdentity,
    };
    const verified = licenseFileSnapshot(target, options);
    if (!sameLicenseCandidate(candidate, verified)) {
      throw licenseReadFailure('installed license could not be verified');
    }
    candidate = verified;
    return result;
  };
  try {
    const result = callback({ write });
    if (result && typeof result.then === 'function') {
      throw new TypeError('license mutation callback must be synchronous');
    }
    return result;
  } catch (error) {
    if (!publicationCommitted || !candidate) throw error;
    try {
      rollbackLicenseCandidate(target, before, candidate, options, error);
      refresh();
    } catch (rollbackError) {
      if (rollbackError && rollbackError.code === 'LICENSE_ROLLBACK_FAILED') {
        rollbackError.originalCause = error;
        throw rollbackError;
      }
      throw licenseRollbackFailure('license rollback failed after control-plane commit error', error, {
        rollbackCause: rollbackError,
      });
    }
    throw error;
  }
}

function mutationOptions(options, fsImpl) {
  return { ...options, fs: fsImpl };
}

function withLicenseFileMutation(callback, options = {}) {
  const fsImpl = options.fs || fs;
  const target = path.resolve(options.path || licensePath());
  return privatePaths.withPrivateDirectoryMutationLockSync(path.dirname(target), () => (
    fileMutationLock.withFileMutationLockSync(
      target,
      () => runLicenseFileMutation(target, callback, {
        ...mutationOptions(options, fsImpl),
      }),
      { ...mutationOptions(options, fsImpl), cleanupComponent: 'license-file-lock' },
    )
  ), licenseDirectorySecurity(options, fsImpl));
}

async function withLicenseFileMutationAsync(callback, options = {}) {
  const fsImpl = options.fs || fs;
  const target = path.resolve(options.path || licensePath());
  return privatePaths.withPrivateDirectoryMutationLock(path.dirname(target), () => (
    fileMutationLock.withFileMutationLock(
      target,
      () => runLicenseFileMutation(target, callback, {
        ...mutationOptions(options, fsImpl),
      }),
      { ...mutationOptions(options, fsImpl), cleanupComponent: 'license-file-lock' },
    )
  ), licenseDirectorySecurity(options, fsImpl));
}

function normalizeCustomerId(value) {
  return String(value || '').trim().toLowerCase();
}

function validCustomerId(value) {
  return tenant.validTenantId(value);
}

function configuredCustomerBinding(source = process.env) {
  const resolved = typeof env.withEnvAliases === 'function' ? env.withEnvAliases(source) : source;
  const explicitValue = String(resolved.REDACTWALL_LICENSE_CUSTOMER_ID || '').trim();
  const tenantValue = String(resolved.REDACTWALL_TENANT_ID || '').trim();
  if ((explicitValue && !validCustomerId(explicitValue)) || (tenantValue && !validCustomerId(tenantValue))) {
    return { ok: false, reason: 'customer_binding_invalid', expectedCustomerId: null };
  }
  const explicit = normalizeCustomerId(explicitValue);
  const tenantId = normalizeCustomerId(tenantValue);
  if (explicit && tenantId && explicit !== tenantId) {
    return { ok: false, reason: 'customer_binding_conflict', expectedCustomerId: null };
  }
  const expectedCustomerId = explicit || tenantId;
  if (!expectedCustomerId) {
    return { ok: false, reason: 'customer_binding_missing', expectedCustomerId: null };
  }
  return { ok: true, reason: null, expectedCustomerId };
}

function customerBinding(options) {
  if (Object.prototype.hasOwnProperty.call(options, 'expectedCustomerId')) {
    const value = String(options.expectedCustomerId || '').trim();
    if (!value) {
      return { ok: false, reason: 'customer_binding_missing', expectedCustomerId: null };
    }
    if (!validCustomerId(value)) {
      return { ok: false, reason: 'customer_binding_invalid', expectedCustomerId: null };
    }
    return { ok: true, reason: null, expectedCustomerId: normalizeCustomerId(value) };
  }
  return configuredCustomerBinding(options.env || process.env);
}

// Never throws, never echoes file content. Returns { ok, payload } | { ok:false, reason }.
function verifyLicenseText(text, options = {}) {
  const { publicKeyPem = embeddedPublicKey() } = options;
  const raw = String(text || '').trim();
  if (!raw) return { ok: false, reason: 'missing' };
  const dot = raw.indexOf('.');
  if (dot <= 0 || dot === raw.length - 1) return { ok: false, reason: 'malformed' };
  const payloadB64 = raw.slice(0, dot);
  const sigB64 = raw.slice(dot + 1);
  let pub;
  try { pub = crypto.createPublicKey(publicKeyPem); } catch (_) { return { ok: false, reason: 'bad_public_key' }; }
  let valid = false;
  try { valid = crypto.verify(null, Buffer.from(payloadB64, 'utf8'), pub, Buffer.from(sigB64, 'base64')); } catch (_) { valid = false; }
  if (!valid) return { ok: false, reason: 'bad_signature' };
  let payload;
  try { payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8')); } catch (_) { return { ok: false, reason: 'bad_payload' }; }
  if (!payload || typeof payload !== 'object') return { ok: false, reason: 'bad_payload' };
  if (!PLANS.includes(String(payload.plan))) return { ok: false, reason: 'bad_payload' };
  if (!Number.isFinite(Number(payload.seats)) || Number(payload.seats) <= 0) return { ok: false, reason: 'bad_payload' };
  const rawCustomerId = typeof payload.customerId === 'string' ? payload.customerId.trim() : '';
  const customerId = normalizeCustomerId(rawCustomerId);
  if (!customerId) return { ok: false, reason: 'customer_id_missing' };
  if (!validCustomerId(rawCustomerId)) return { ok: false, reason: 'customer_id_invalid' };
  // Validate the signed payload completely before comparing it with local
  // deployment configuration so malformed licenses retain a stable reason.
  if (!Number.isFinite(Date.parse(payload.expires))) return { ok: false, reason: 'bad_payload' };
  const binding = customerBinding(options);
  if (!binding.ok) return { ok: false, reason: binding.reason };
  if (binding.expectedCustomerId && customerId !== binding.expectedCustomerId) {
    return { ok: false, reason: 'customer_mismatch' };
  }
  return { ok: true, payload: { ...payload, customerId } };
}

// missing/invalid -> 'unlicensed'; before expiry -> 'active'; within grace ->
// 'grace'; past grace -> 'readonly'.
function evaluate(payload, now = Date.now()) {
  if (!payload) return 'unlicensed';
  const expires = Date.parse(payload.expires);
  if (!Number.isFinite(expires)) return 'unlicensed';
  if (now < expires) return 'active';
  const graceDays = Number.isFinite(Number(payload.graceDays)) ? Math.max(0, Number(payload.graceDays)) : DEFAULT_GRACE_DAYS;
  const graceEnds = expires + graceDays * 24 * 3600 * 1000;
  return now < graceEnds ? 'grace' : 'readonly';
}

let _status = { state: 'unlicensed', payload: null, reason: 'missing' };
// Vendor kill-switch overlay (connected mode). TWO independent inputs, both
// driven by server/vendor-link.js:
//  - _vendorRevoked: an explicit signature-verified 'revoked' verdict.
//  - _vendorStale:   heartbeat-or-die — no successful vendor contact within the
//                    tolerance window. This is what defeats a hostile
//                    self-hosted customer who blocks egress: without a fresh
//                    signed 'active' verdict the install fails CLOSED, it does
//                    not drift back to active.
// Either flag blocks; both survive refresh() (file reload never clears them).
let _vendorRevoked = false;
let _vendorStale = false;

function killed() { return _vendorRevoked || _vendorStale; }

function readTrustedLicenseText(target, options = {}) {
  const fsImpl = options.fs || fs;
  try { exactLstat(fsImpl, target); }
  catch (error) {
    if (error && error.code === 'ENOENT') throw error;
    throw licenseReadFailure('license file could not be inspected', error);
  }
  const directory = path.dirname(path.resolve(target));
  privatePaths.assertPrivatePath(directory, {
    ...options,
    fs: fsImpl,
    directory: true,
    label: 'license directory',
    ownerLabel: 'license directory',
  });
  privatePaths.assertPrivatePath(target, {
    ...options,
    fs: fsImpl,
    directory: false,
    label: 'license file',
    ownerLabel: 'license file',
  });
  const snapshot = licenseFileSnapshot(target, { ...options, fs: fsImpl });
  if (!snapshot.exists) {
    const error = new Error('license file is missing');
    error.code = 'ENOENT';
    throw error;
  }
  privatePaths.assertPrivatePath(directory, {
    ...options,
    fs: fsImpl,
    directory: true,
    label: 'license directory',
    ownerLabel: 'license directory',
  });
  return snapshot.contents.toString('utf8');
}

function loadStatus(now = Date.now(), deps = {}) {
  const suppliedRead = typeof deps.readFile === 'function' ? deps.readFile : null;
  const read = suppliedRead || ((p) => readTrustedLicenseText(p, deps));
  let text = '';
  try { text = read(deps.licensePath || licensePath()); }
  catch (error) {
    const missing = suppliedRead || (error && error.code === 'ENOENT');
    return { state: 'unlicensed', payload: null, reason: missing ? 'missing' : 'storage_unavailable' };
  }
  const verifyOptions = { now };
  for (const key of ['publicKeyPem', 'expectedCustomerId', 'env']) {
    if (Object.prototype.hasOwnProperty.call(deps, key)) verifyOptions[key] = deps[key];
  }
  const v = verifyLicenseText(text, verifyOptions);
  if (!v.ok) return { state: 'unlicensed', payload: null, reason: v.reason };
  return { state: evaluate(v.payload, now), payload: v.payload, reason: null };
}

// Effective state = file-derived state, overridden to 'revoked' when the vendor
// kill-switch is active (explicit revoke OR stale). Payload/reason are
// preserved so publicStatus and entitlement still describe the customer.
function effectiveStatus() {
  if (killed()) return { ..._status, state: 'revoked' };
  return _status;
}

function refresh(deps = {}) {
  const now = deps.now || Date.now();
  const next = loadStatus(now, deps);
  const previous = _status;
  const prevEffective = effectiveStatus().state;
  _status = next;
  const nextEffective = effectiveStatus().state;
  try {
    if (deps.appendAudit && (prevEffective !== nextEffective)) {
      deps.appendAudit({
        action: 'LICENSE_STATE_CHANGED',
        actor: 'system',
        detail: `from=${prevEffective}; to=${nextEffective}; plan=${next.payload ? next.payload.plan : 'none'}; expires=${next.payload ? next.payload.expires : 'none'}`,
      });
    }
  } catch (error) {
    _status = previous;
    throw error;
  }
  return effectiveStatus();
}

function auditKillSwitch(prevEffective, source, deps) {
  const nextEffective = effectiveStatus().state;
  if (deps.appendAudit && (prevEffective !== nextEffective)) {
    deps.appendAudit({
      action: 'LICENSE_STATE_CHANGED',
      actor: source,
      detail: `from=${prevEffective}; to=${nextEffective}; source=${source}`,
    });
  }
  return effectiveStatus();
}

function vendorStateSnapshot() {
  return { revoked: _vendorRevoked, stale: _vendorStale };
}

function restoreVendorState(snapshot) {
  _vendorRevoked = snapshot.revoked === true;
  _vendorStale = snapshot.stale === true;
  return effectiveStatus();
}

function applyVendorState(next = {}, deps = {}) {
  const previous = vendorStateSnapshot();
  const prevEffective = effectiveStatus().state;
  if (Object.prototype.hasOwnProperty.call(next, 'revoked')) _vendorRevoked = next.revoked === true;
  if (Object.prototype.hasOwnProperty.call(next, 'stale')) _vendorStale = next.stale === true;
  try {
    return auditKillSwitch(prevEffective, deps.source || 'vendor', deps);
  } catch (error) {
    restoreVendorState(previous);
    throw error;
  }
}

// Apply a signature-verified vendor 'revoked'/'active' verdict (connected mode
// only, driven by vendor-link after freshness + customer-binding checks).
function applyVendorVerdict(revoked, deps = {}) {
  return applyVendorState({ revoked }, { ...deps, source: 'vendor' });
}

// Heartbeat-or-die: vendor-link sets this true when contact is stale beyond
// the tolerance window and false on a successful heartbeat.
function setVendorStale(stale, deps = {}) {
  return applyVendorState({ stale }, { ...deps, source: 'vendor_staleness' });
}

function isRevoked() { return killed(); }

function status() { return effectiveStatus(); }

function graceEndsAt(payload) {
  if (!payload) return null;
  const expires = Date.parse(payload.expires);
  if (!Number.isFinite(expires)) return null;
  const graceDays = Number.isFinite(Number(payload.graceDays)) ? Math.max(0, Number(payload.graceDays)) : DEFAULT_GRACE_DAYS;
  return new Date(expires + graceDays * 24 * 3600 * 1000).toISOString();
}

function publicStatus() {
  const s = effectiveStatus();
  const p = s.payload;
  const days = p ? Math.ceil((Date.parse(p.expires) - Date.now()) / (24 * 3600 * 1000)) : null;
  return {
    state: s.state,
    plan: p ? p.plan : null,
    seats: p ? Number(p.seats) : null,
    customer: p ? p.customer || null : null,
    customerId: p ? p.customerId || null : null,
    features: p && Array.isArray(p.features) ? p.features : [],
    expires: p ? p.expires : null,
    graceEndsAt: graceEndsAt(p),
    daysRemaining: days,
    reason: _vendorRevoked ? 'vendor_revoked' : (_vendorStale ? 'vendor_unreachable' : (s.reason || null)),
  };
}

// Feature entitlement for licensed console modules (first consumer: the NCUA
// Readiness Center). Unlicensed = demo mode, which shows every module — the
// license philosophy above gates nothing until a customer is licensed. For
// licensed installs the feature flag or the enterprise plan grants access;
// the payload persists through 'grace' and 'readonly', so entitlement
// correctly survives expiry (readonly already blocks writes elsewhere).
function entitled(feature) {
  const s = status();
  if (s.state === 'unlicensed') return true;
  const p = s.payload || {};
  const features = Array.isArray(p.features) ? p.features : [];
  return features.includes(feature) || p.plan === 'enterprise';
}

// Express middleware: in 'readonly' or vendor-'revoked' state, block admin
// configuration writes EXCEPT under /api/queries/ (reveal/assign support the
// approval workflow, which must never be impaired) and the license-install
// route itself (renewal must always be installable). A revoked install can
// still install a fresh license, but only a signed vendor 'active' verdict
// clears the revocation.
function requireWritable(req, res, next) {
  const state = status().state;
  if (state !== 'readonly' && state !== 'revoked') return next();
  if (req.path.startsWith('/api/queries/')) return next();
  if (req.path === '/api/billing/license' && req.method === 'POST') return next();
  if (req.path === '/api/admin/license/install' && req.method === 'POST') return next();
  return res.status(403).json({ error: state === 'revoked' ? 'license_revoked' : 'license_readonly' });
}

module.exports = {
  verifyLicenseText,
  evaluate,
  loadStatus,
  refresh,
  applyVendorVerdict,
  setVendorStale,
  isRevoked,
  status,
  publicStatus,
  entitled,
  requireWritable,
  licensePath,
  writeLicenseAtomically,
  withLicenseFileMutation,
  withLicenseFileMutationAsync,
  configuredCustomerBinding,
  normalizeCustomerId,
  validCustomerId,
  EMBEDDED_PUBLIC_KEY_PEM,
  DEFAULT_GRACE_DAYS,
  _internal: {
    applyVendorState,
    vendorStateSnapshot,
    restoreVendorState,
    licenseFileSnapshot,
    restoreLicenseSnapshot,
  },
};
