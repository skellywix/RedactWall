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

function writeLicenseBytesAtomically(contents, options = {}) {
  const fsImpl = options.fs || fs;
  const target = options.path || licensePath();
  const directory = path.dirname(target);
  const temp = path.join(directory, `.${path.basename(target)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`);
  const mode = options.mode == null ? 0o600 : options.mode;
  let descriptor = null;
  let created = false;
  try {
    fsImpl.mkdirSync(directory, { recursive: true, mode: 0o700 });
    descriptor = fsImpl.openSync(temp, 'wx', mode);
    created = true;
    fsImpl.writeFileSync(descriptor, contents);
    fsImpl.fsyncSync(descriptor);
    fsImpl.fchmodSync(descriptor, mode);
    fsImpl.closeSync(descriptor);
    descriptor = null;
    privatePaths.publishFileDurably(temp, target, { ...options, fs: fsImpl });
    created = false;
    try { fsImpl.chmodSync(target, mode); } catch {}
  } catch (error) {
    if (descriptor !== null) {
      try { fsImpl.closeSync(descriptor); } catch {}
    }
    if (created) {
      try { fsImpl.unlinkSync(temp); } catch {}
    }
    throw error;
  }
  return target;
}

function writeLicenseAtomically(text, options = {}) {
  return writeLicenseBytesAtomically(
    Buffer.from(`${String(text || '').trim()}\n`, 'utf8'),
    options,
  );
}

function removeLicenseFile(options = {}) {
  const fsImpl = options.fs || fs;
  const target = options.path || licensePath();
  try {
    fsImpl.unlinkSync(target);
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error;
  }
  privatePaths.fsyncDirectory(path.dirname(target), { ...options, fs: fsImpl });
}

function licenseFileSnapshot(target, options = {}) {
  const fsImpl = options.fs || fs;
  let before;
  try {
    before = fsImpl.lstatSync(target);
  } catch (error) {
    if (error && error.code === 'ENOENT') return { exists: false };
    const wrapped = new Error('license file could not be inspected');
    wrapped.code = 'LICENSE_FILE_READ_FAILED';
    wrapped.cause = error;
    throw wrapped;
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.size > MAX_LICENSE_FILE_BYTES) {
    const error = new Error('license path is not a bounded regular file');
    error.code = 'LICENSE_FILE_READ_FAILED';
    throw error;
  }
  let contents;
  let after;
  try {
    contents = fsImpl.readFileSync(target);
    after = fsImpl.lstatSync(target);
  } catch (error) {
    const wrapped = new Error('license file could not be read');
    wrapped.code = 'LICENSE_FILE_READ_FAILED';
    wrapped.cause = error;
    throw wrapped;
  }
  if (!after.isFile() || after.isSymbolicLink() || after.nlink !== 1
      || contents.length !== before.size || after.size !== before.size
      || (before.dev && after.dev && before.dev !== after.dev)
      || (before.ino && after.ino && before.ino !== after.ino)
      || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
    const error = new Error('license file changed while reading');
    error.code = 'LICENSE_FILE_READ_FAILED';
    throw error;
  }
  return { exists: true, contents, mode: before.mode & 0o777 };
}

function restoreLicenseSnapshot(target, snapshot, options = {}) {
  if (snapshot.exists) {
    writeLicenseBytesAtomically(snapshot.contents, {
      ...options,
      path: target,
      mode: snapshot.mode,
    });
  } else {
    removeLicenseFile({ ...options, path: target });
  }
}

function runLicenseFileMutation(target, callback, options) {
  const before = licenseFileSnapshot(target, options);
  let written = false;
  const write = (text) => {
    const result = writeLicenseAtomically(text, { ...options, path: target });
    written = true;
    return result;
  };
  try {
    const result = callback({ write });
    if (result && typeof result.then === 'function') {
      throw new TypeError('license mutation callback must be synchronous');
    }
    return result;
  } catch (error) {
    if (!written) throw error;
    try {
      restoreLicenseSnapshot(target, before, options);
      refresh();
    } catch (rollbackError) {
      const failure = new Error('license rollback failed after control-plane commit error');
      failure.code = 'LICENSE_ROLLBACK_FAILED';
      failure.cause = error;
      failure.rollbackCause = rollbackError;
      throw failure;
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
  fsImpl.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  return fileMutationLock.withFileMutationLockSync(
    target,
    () => runLicenseFileMutation(target, callback, mutationOptions(options, fsImpl)),
    mutationOptions(options, fsImpl),
  );
}

async function withLicenseFileMutationAsync(callback, options = {}) {
  const fsImpl = options.fs || fs;
  const target = path.resolve(options.path || licensePath());
  fsImpl.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  return fileMutationLock.withFileMutationLock(
    target,
    () => runLicenseFileMutation(target, callback, mutationOptions(options, fsImpl)),
    mutationOptions(options, fsImpl),
  );
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

function loadStatus(now = Date.now(), deps = {}) {
  const read = deps.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  let text = '';
  try { text = read(deps.licensePath || licensePath()); } catch (_) { return { state: 'unlicensed', payload: null, reason: 'missing' }; }
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
  removeLicenseFile,
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
