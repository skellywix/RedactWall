'use strict';
/**
 * Agent token store for the AI Gateway.
 *
 * Each caller authenticates with a bearer token (`pw_gw_...`) that maps to a
 * managed identity + orgId. Only domain-separated SHA-256 hashes are persisted, never the
 * raw token — same discipline as release tokens and receipts. Tokens are minted
 * out-of-band (mintToken) and revoked by removing them from the store file.
 */
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const { spawnSync } = require('child_process');
const fileMutationLock = require('../server/file-mutation-lock');
const privatePaths = require('../server/private-path');
const TOKEN_LOCK_TIMEOUT_MS = 30_000;
const TOKEN_DIRECTORY_INIT_TIMEOUT_MS = 60_000;
const TOKEN_STORE_MAX_BYTES = 16 * 1024 * 1024;
const _securedParents = new Map();
let _windowsPrincipal = '';

function windowsPrincipal(spawn = spawnSync) {
  if (spawn === spawnSync && _windowsPrincipal) return _windowsPrincipal;
  const principal = privatePaths.windowsPrincipal(spawn, 'gateway token store');
  if (spawn === spawnSync) _windowsPrincipal = principal;
  return principal;
}

function restrictPrivatePath(target, opts = {}) {
  return privatePaths.restrictPrivatePath(target, {
    label: 'the gateway token store',
    ownerLabel: 'gateway token store',
    ...opts,
  });
}

const privateAclListing = privatePaths.privateAclListing;

function secureParent(p) {
  const dir = path.resolve(path.dirname(p));
  const security = {
    fs,
    directory: true,
    label: 'gateway token directory',
    ownerLabel: 'gateway token directory',
    lockTimeoutMs: TOKEN_DIRECTORY_INIT_TIMEOUT_MS,
    lockTimeoutMaximumMs: TOKEN_DIRECTORY_INIT_TIMEOUT_MS,
  };
  const exactDirectoryIdentity = () => {
    const stat = fs.lstatSync(dir, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.dev === 0n || stat.ino === 0n) {
      throw new Error('gateway token directory has no stable filesystem identity');
    }
    return { dev: stat.dev, ino: stat.ino, birthtime: stat.birthtimeNs ?? stat.birthtimeMs };
  };
  const sameDirectoryIdentity = (left, right) => left.dev === right.dev && left.ino === right.ino
    && String(left.birthtime) === String(right.birthtime);
  const proof = _securedParents.get(dir);
  if (!proof) {
    let initialized;
    privatePaths.withPrivateDirectoryMutationLockSync(dir, () => { initialized = exactDirectoryIdentity(); }, security);
    _securedParents.set(dir, initialized);
  } else {
    const before = exactDirectoryIdentity();
    if (!sameDirectoryIdentity(proof, before)) throw new Error('gateway token directory identity changed');
    privatePaths.assertPrivatePathDacl(dir, security);
    if (!sameDirectoryIdentity(proof, exactDirectoryIdentity())) {
      throw new Error('gateway token directory identity changed');
    }
  }
  return dir;
}

function assertPrivateStore(p) {
  return privatePaths.assertPrivatePath(p, {
    fs,
    directory: false,
    label: 'gateway token store',
    ownerLabel: 'gateway token store',
  });
}

function defaultTokensPath() {
  const dataDir = process.env.REDACTWALL_DATA_DIR || process.env.PROMPTWALL_DATA_DIR || process.env.SENTINEL_DATA_DIR || path.join(__dirname, '..', 'data');
  return path.join(dataDir, 'gateway-agent-tokens.json');
}

function tokenHash(raw) {
  return crypto.createHash('sha256').update('redactwall:gateway-token:v1:' + String(raw || '')).digest('hex');
}

// Cache the parsed store per path, keyed on file identity and timestamps, so the hot
// resolveToken path (called on every authenticated gateway request) does not
// re-read and JSON.parse the file each time. mint/revoke rewrite the file, which
// changes the stamp, so revocation still takes effect on the next request.
const _storeCache = new Map(); // path -> { stamp, store }
function storeStamp(stat) {
  return stat ? [stat.mtimeNs ?? stat.mtimeMs, stat.ctimeNs ?? stat.ctimeMs,
    stat.birthtimeNs ?? stat.birthtimeMs, stat.size, stat.dev, stat.ino].join(':') : 'none';
}

function readStoreFresh(p, strict = false) {
  try {
    const body = privatePaths.readBoundedRegularFile(p, {
      fs,
      maxBytes: TOKEN_STORE_MAX_BYTES,
      label: 'gateway token store',
    });
    const parsed = JSON.parse(body.toString('utf8'));
    if (!parsed || !Array.isArray(parsed.tokens)) throw new Error('gateway token store is malformed');
    return parsed;
  } catch (err) {
    if (err && err.code === 'ENOENT') return { tokens: [] };
    if (strict) throw new Error('gateway token store is unreadable');
    return { tokens: [] };
  }
}

function secureStoreForRead(p) {
  secureParent(p);
  try {
    assertPrivateStore(p);
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error;
  }
}

function loadStore(tokensPath) {
  const p = path.resolve(tokensPath || defaultTokensPath());
  secureStoreForRead(p);
  let stamp = 'none';
  try {
    const st = fs.lstatSync(p, { bigint: true });
    stamp = storeStamp(st);
  } catch { /* missing file — stamp stays 'none' */ }
  const cached = _storeCache.get(p);
  if (cached && cached.stamp === stamp) return cached.store;
  const store = readStoreFresh(p);
  _storeCache.set(p, { stamp, store });
  return store;
}

function acquireStoreLock(p) {
  return fileMutationLock.acquireFileMutationLockSync(p, {
    lockTimeoutMs: TOKEN_LOCK_TIMEOUT_MS,
    lockTimeoutMaximumMs: TOKEN_LOCK_TIMEOUT_MS,
  });
}

function releaseStoreLock(lock) {
  fileMutationLock.releaseFileMutationLock(lock);
}

function storeFileIdentity(file) {
  const stat = fs.lstatSync(file, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.dev === 0n || stat.ino === 0n
      || stat.nlink !== 1n || stat.size <= 0n) {
    throw new Error('gateway token store has no stable filesystem identity');
  }
  return stat;
}

function sameStoreFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && left.nlink === 1n && right.nlink === 1n;
}

function saveStoreAtomic(store, p) {
  const dir = path.resolve(path.dirname(p));
  const temp = path.join(dir, `.${path.basename(p)}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  let fd;
  let publicationStarted = false;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    privatePaths.protectInheritedPrivateFile(temp, {
      directory: false,
      label: 'gateway token store staging file',
      ownerLabel: 'gateway token store',
      verifyOwner: false,
    });
    fs.writeFileSync(fd, JSON.stringify(store, null, 2) + '\n', { encoding: 'utf8' });
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    const staged = storeFileIdentity(temp);
    publicationStarted = true;
    privatePaths.publishFileDurably(temp, p, {
      fs,
      cleanupComponent: 'gateway-token-store',
      verifyPublished(publishedPath) {
        const published = storeFileIdentity(publishedPath);
        if (!sameStoreFileIdentity(staged, published)) {
          throw new Error('gateway token store changed during publication');
        }
        privatePaths.assertPrivatePathDacl(publishedPath, {
          fs,
          directory: false,
          label: 'gateway token store',
          ownerLabel: 'gateway token store',
        });
        privatePaths.assertPrivatePathDacl(dir, {
          fs,
          directory: true,
          label: 'gateway token directory',
          ownerLabel: 'gateway token directory',
        });
      },
    });
    _storeCache.delete(p);
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* best effort */ }
    if (!publicationStarted) try { fs.unlinkSync(temp); } catch { /* staging cleanup only */ }
  }
}

function mutateStore(tokensPath, mutate) {
  const p = path.resolve(tokensPath || defaultTokensPath());
  secureParent(p);
  return fileMutationLock.withFileMutationLockSync(p, () => {
    secureParent(p);
    try {
      assertPrivateStore(p);
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
    }
    const store = readStoreFresh(p, true);
    const result = mutate(store);
    if (result.changed !== false) saveStoreAtomic(store, p);
    return result.value;
  }, {
    lockTimeoutMs: TOKEN_LOCK_TIMEOUT_MS,
    lockTimeoutMaximumMs: TOKEN_LOCK_TIMEOUT_MS,
    cleanupComponent: 'gateway-token-store-lock',
  });
}

function storageHealth() {
  const publication = privatePaths.committedCleanupHealth();
  const locking = fileMutationLock.committedCleanupHealth();
  return {
    ok: publication.ok && locking.ok,
    reason: publication.ok && locking.ok ? null : 'gateway-token-storage-cleanup-degraded',
  };
}

// Create a token, persist only its hash, and return the raw token ONCE.
function mintToken({ user, orgId, label } = {}, tokensPath) {
  const raw = 'pw_gw_' + crypto.randomBytes(24).toString('hex');
  const entry = {
    id: 'tok_' + crypto.randomBytes(6).toString('hex'),
    hash: tokenHash(raw),
    user: String(user || 'agent@gateway').slice(0, 200),
    orgId: orgId ? String(orgId).slice(0, 200) : null,
    label: String(label || '').slice(0, 120),
    revoked: false,
  };
  mutateStore(tokensPath, (store) => {
    store.tokens.push(entry);
    return { value: true };
  });
  return { token: raw, id: entry.id, user: entry.user, orgId: entry.orgId };
}

function revokeToken(id, tokensPath) {
  return mutateStore(tokensPath, (store) => {
    let changed = false;
    for (const t of store.tokens) if (t.id === id && !t.revoked) { t.revoked = true; changed = true; }
    return { changed, value: changed };
  });
}

// Resolve a raw bearer token to its identity, or null if unknown/revoked.
function resolveToken(raw, tokensPath) {
  if (!raw) return null;
  const h = tokenHash(raw);
  const store = loadStore(tokensPath);
  const entry = store.tokens.find((t) => t.hash === h && !t.revoked);
  return entry ? { id: entry.id, user: entry.user, orgId: entry.orgId } : null;
}

function listTokens(tokensPath) {
  return loadStore(tokensPath).tokens.map((t) => ({ id: t.id, user: t.user, orgId: t.orgId, label: t.label, revoked: !!t.revoked }));
}

module.exports = {
  mintToken,
  revokeToken,
  resolveToken,
  listTokens,
  tokenHash,
  defaultTokensPath,
  storageHealth,
  _internal: {
    restrictPrivatePath,
    windowsPrincipal,
    privateAclListing,
    acquireStoreLock,
    releaseStoreLock,
  },
};
