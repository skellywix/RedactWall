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
const _securedParents = new Set();
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
  if (!_securedParents.has(dir)) {
    privatePaths.withPrivateDirectoryMutationLockSync(dir, () => {}, security);
    _securedParents.add(dir);
  } else {
    privatePaths.assertPrivatePath(dir, security);
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
  return stat ? [stat.mtimeMs, stat.ctimeMs, stat.birthtimeMs, stat.size, stat.ino].join(':') : 'none';
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
    const st = fs.lstatSync(p);
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

function saveStoreAtomic(store, p) {
  const dir = path.resolve(path.dirname(p));
  const temp = path.join(dir, `.${path.basename(p)}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    privatePaths.securePrivatePath(temp, {
      directory: false,
      fresh: true,
      label: 'gateway token store staging file',
      ownerLabel: 'gateway token store',
    });
    fs.writeFileSync(fd, JSON.stringify(store, null, 2) + '\n', { encoding: 'utf8' });
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    const staged = fs.lstatSync(temp);
    privatePaths.publishFileDurably(temp, p, { fs });
    const published = fs.lstatSync(p);
    if (!published.isFile() || published.isSymbolicLink() || published.nlink !== 1
        || (staged.dev && published.dev && staged.dev !== published.dev)
        || (staged.ino && published.ino && staged.ino !== published.ino)) {
      throw new Error('gateway token store changed during publication');
    }
    _storeCache.delete(p);
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* best effort */ }
    try { fs.unlinkSync(temp); } catch { /* already published or best effort */ }
  }
}

function mutateStore(tokensPath, mutate) {
  const p = path.resolve(tokensPath || defaultTokensPath());
  secureParent(p);
  const lock = acquireStoreLock(p);
  try {
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
  } finally {
    releaseStoreLock(lock);
  }
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
  _internal: {
    restrictPrivatePath,
    windowsPrincipal,
    privateAclListing,
    acquireStoreLock,
    releaseStoreLock,
  },
};
