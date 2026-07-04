'use strict';
/**
 * Signed, versioned sensor policy bundles.
 *
 * Sensors currently fetch plain policy from /api/v1/policy. A bundle wraps the
 * sensor-safe policy with a version, issue time, and expiry, and signs it with
 * an Ed25519 key. Sensors verify with the PUBLIC key (no shared secret needed),
 * and FAIL CLOSED — treat policy as unavailable → block — when a bundle is
 * unverifiable, tampered, or stale. This moves policy trust to the sensor edge
 * and closes the "sensor trusts whatever the network returns" gap.
 *
 * The private key is persisted under the data dir (0600), like the session
 * secret; the public key is published via /api/v1/policy/pubkey and distributed
 * to sensors.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.SENTINEL_DATA_DIR || process.env.PROMPTWALL_DATA_DIR || path.join(__dirname, '..', 'data');
const KEY_FILE = path.join(DATA_DIR, '.policy-bundle-key.pem');
const BUNDLE_VERSION = 1;
const DEFAULT_TTL_MS = 15 * 60 * 1000; // sensors refresh well inside this window

function loadOrCreateKeypair() {
  try {
    if (fs.existsSync(KEY_FILE)) {
      const pem = fs.readFileSync(KEY_FILE, 'utf8');
      const privateKey = crypto.createPrivateKey(pem);
      return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
    }
  } catch (e) { /* regenerate below */ }
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  } catch (e) { /* ephemeral keypair if the dir is read-only */ }
  return { privateKey, publicKey };
}

let _keys = null;
function keys() {
  if (!_keys) _keys = loadOrCreateKeypair();
  return _keys;
}

function publicKeyPem() {
  return keys().publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

// Canonical signing input: the exact bytes both sides hash. Sorted-key JSON of
// the signed header + a sha256 of the policy so the policy body can't be swapped.
function signingInput({ version, issuedAt, expiresAt, policy }) {
  const policyHash = crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex');
  return JSON.stringify({ version, issuedAt, expiresAt, policyHash });
}

// Build a signed bundle around a sensor-safe policy object. `now`/`ttlMs` are
// injectable for tests.
function buildBundle(policy, { now = new Date().toISOString(), ttlMs = DEFAULT_TTL_MS } = {}) {
  const issuedAt = now;
  const expiresAt = new Date(Date.parse(now) + ttlMs).toISOString();
  const header = { version: BUNDLE_VERSION, issuedAt, expiresAt, policy };
  const signature = crypto.sign(null, Buffer.from(signingInput(header)), keys().privateKey).toString('base64');
  return { ...header, signature };
}

// Verify a bundle against a public key (PEM). Returns { ok } or { ok:false, reason }.
// Sensors call this and block when ok is false.
function verifyBundle(bundle, publicKeyPemStr, { now = new Date().toISOString() } = {}) {
  if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'no_bundle' };
  if (bundle.version !== BUNDLE_VERSION) return { ok: false, reason: 'version_mismatch' };
  if (!bundle.signature) return { ok: false, reason: 'no_signature' };
  let pub;
  try { pub = crypto.createPublicKey(publicKeyPemStr); } catch (e) { return { ok: false, reason: 'bad_public_key' }; }
  const input = Buffer.from(signingInput(bundle));
  let valid = false;
  try { valid = crypto.verify(null, input, pub, Buffer.from(bundle.signature, 'base64')); } catch (e) { valid = false; }
  if (!valid) return { ok: false, reason: 'bad_signature' };
  if (Date.parse(bundle.expiresAt) <= Date.parse(now)) return { ok: false, reason: 'expired' };
  return { ok: true };
}

function isFresh(bundle, now = new Date().toISOString()) {
  return !!bundle && Date.parse(bundle.expiresAt || 0) > Date.parse(now);
}

module.exports = { buildBundle, verifyBundle, isFresh, publicKeyPem, signingInput, BUNDLE_VERSION, DEFAULT_TTL_MS, KEY_FILE };
