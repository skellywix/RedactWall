'use strict';
/**
 * Agent token store for the AI Gateway.
 *
 * Each caller authenticates with a bearer token (`pw_gw_...`) that maps to a
 * managed identity + orgId. Only salted SHA-256 hashes are persisted, never the
 * raw token — same discipline as release tokens and receipts. Tokens are minted
 * out-of-band (mintToken) and revoked by removing them from the store file.
 */
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

function defaultTokensPath() {
  const dataDir = process.env.SENTINEL_DATA_DIR || process.env.PROMPTWALL_DATA_DIR || path.join(__dirname, '..', 'data');
  return path.join(dataDir, 'gateway-agent-tokens.json');
}

function tokenHash(raw) {
  return crypto.createHash('sha256').update('promptwall:gateway-token:v1:' + String(raw || '')).digest('hex');
}

// Cache the parsed store per path, keyed on the file's mtime+size, so the hot
// resolveToken path (called on every authenticated gateway request) does not
// re-read and JSON.parse the file each time. mint/revoke rewrite the file, which
// changes the stamp, so revocation still takes effect on the next request.
const _storeCache = new Map(); // path -> { stamp, store }
function loadStore(tokensPath) {
  const p = tokensPath || defaultTokensPath();
  let stamp = 'none';
  try {
    const st = fs.statSync(p);
    stamp = st.mtimeMs + ':' + st.size;
  } catch { /* missing file — stamp stays 'none' */ }
  const cached = _storeCache.get(p);
  if (cached && cached.stamp === stamp) return cached.store;
  let store = { tokens: [] };
  try {
    if (stamp !== 'none') {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
      if (parsed && Array.isArray(parsed.tokens)) store = parsed;
    }
  } catch (e) { store = { tokens: [] }; }
  _storeCache.set(p, { stamp, store });
  return store;
}

function saveStore(store, tokensPath) {
  const p = tokensPath || defaultTokensPath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(store, null, 2) + '\n');
}

// Create a token, persist only its hash, and return the raw token ONCE.
function mintToken({ user, orgId, label } = {}, tokensPath) {
  const raw = 'pw_gw_' + crypto.randomBytes(24).toString('hex');
  const store = loadStore(tokensPath);
  const entry = {
    id: 'tok_' + crypto.randomBytes(6).toString('hex'),
    hash: tokenHash(raw),
    user: String(user || 'agent@gateway').slice(0, 200),
    orgId: orgId ? String(orgId).slice(0, 200) : null,
    label: String(label || '').slice(0, 120),
    revoked: false,
  };
  store.tokens.push(entry);
  saveStore(store, tokensPath);
  return { token: raw, id: entry.id, user: entry.user, orgId: entry.orgId };
}

function revokeToken(id, tokensPath) {
  const store = loadStore(tokensPath);
  let changed = false;
  for (const t of store.tokens) if (t.id === id && !t.revoked) { t.revoked = true; changed = true; }
  if (changed) saveStore(store, tokensPath);
  return changed;
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

module.exports = { mintToken, revokeToken, resolveToken, listTokens, tokenHash, defaultTokensPath };
