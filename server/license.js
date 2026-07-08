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

// Placeholder public key. Regenerate offline with
// `node scripts/license-issue.js --init-keypair <dir>` before the first
// commercial release and paste the printed public PEM here.
const EMBEDDED_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA0lard41yplR7X9CCdwvvvbjWIPUGOisoi4jfQV1GY6c=
-----END PUBLIC KEY-----`;

const DEFAULT_GRACE_DAYS = 30;
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

// Never throws, never echoes file content. Returns { ok, payload } | { ok:false, reason }.
function verifyLicenseText(text, { publicKeyPem = embeddedPublicKey(), now = Date.now() } = {}) {
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
  // Fail closed on an unparseable expiry (NaN comparisons would otherwise read
  // as never-expiring).
  if (!Number.isFinite(Date.parse(payload.expires))) return { ok: false, reason: 'bad_payload' };
  return { ok: true, payload };
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
// Vendor kill-switch overlay (connected mode). Set only by a signature-verified
// heartbeat verdict; survives refresh() so a customer cannot clear it by
// reinstalling a license.
let _vendorRevoked = false;

function loadStatus(now = Date.now(), deps = {}) {
  const read = deps.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  let text = '';
  try { text = read(deps.licensePath || licensePath()); } catch (_) { return { state: 'unlicensed', payload: null, reason: 'missing' }; }
  const v = verifyLicenseText(text, { now, ...(deps.publicKeyPem ? { publicKeyPem: deps.publicKeyPem } : {}) });
  if (!v.ok) return { state: 'unlicensed', payload: null, reason: v.reason };
  return { state: evaluate(v.payload, now), payload: v.payload, reason: null };
}

// Effective state = file-derived state, overridden to 'revoked' when the vendor
// has revoked. Payload/reason are preserved so publicStatus and entitlement
// still describe the licensed customer.
function effectiveStatus() {
  if (_vendorRevoked) return { ..._status, state: 'revoked' };
  return _status;
}

function refresh(deps = {}) {
  const now = deps.now || Date.now();
  const next = loadStatus(now, deps);
  const prevEffective = effectiveStatus().state;
  _status = next;
  const nextEffective = effectiveStatus().state;
  if (deps.appendAudit && (prevEffective !== nextEffective)) {
    deps.appendAudit({
      action: 'LICENSE_STATE_CHANGED',
      actor: 'system',
      detail: `from=${prevEffective}; to=${nextEffective}; plan=${next.payload ? next.payload.plan : 'none'}; expires=${next.payload ? next.payload.expires : 'none'}`,
    });
  }
  return effectiveStatus();
}

// Apply a signature-verified vendor heartbeat verdict (connected mode only).
// `revoked` flips the kill-switch; audits an effective-state transition.
function applyVendorVerdict(revoked, deps = {}) {
  const prevEffective = effectiveStatus().state;
  _vendorRevoked = revoked === true;
  const nextEffective = effectiveStatus().state;
  if (deps.appendAudit && (prevEffective !== nextEffective)) {
    deps.appendAudit({
      action: 'LICENSE_STATE_CHANGED',
      actor: 'vendor',
      detail: `from=${prevEffective}; to=${nextEffective}; source=vendor_link`,
    });
  }
  return effectiveStatus();
}

function isRevoked() { return effectiveStatus().state === 'revoked'; }

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
    reason: s.state === 'revoked' ? 'vendor_revoked' : (s.reason || null),
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
  return res.status(403).json({ error: state === 'revoked' ? 'license_revoked' : 'license_readonly' });
}

module.exports = {
  verifyLicenseText,
  evaluate,
  loadStatus,
  refresh,
  applyVendorVerdict,
  isRevoked,
  status,
  publicStatus,
  entitled,
  requireWritable,
  licensePath,
  EMBEDDED_PUBLIC_KEY_PEM,
  DEFAULT_GRACE_DAYS,
};
