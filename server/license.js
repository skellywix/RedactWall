'use strict';
/**
 * Offline license verification (ROADMAP N7).
 *
 * A `promptwall.lic` file is `base64(payloadJSON).base64(ed25519Signature)`,
 * where the signature is over the UTF-8 bytes of the base64-payload string
 * (signing the encoded form avoids any JSON canonicalization question). It is
 * verified at boot and re-checked daily against an EMBEDDED public key — no
 * license server, no phone-home, so air-gapped credit-union deployments work.
 *
 * The license NEVER disables the security function. Absence or invalidity =
 * demo mode (zero gating). Past the grace window it only degrades the ADMIN
 * CONSOLE to read-only for configuration routes; detection, enforcement, the
 * approval workflow, audit, and evidence export always keep running.
 *
 * The vendor's PRIVATE signing key lives offline (see scripts/license-issue.js
 * --init-keypair) and is never in the repo. Tests inject a throwaway public key
 * via the SENTINEL_LICENSE_PUBLIC_KEY env override or the publicKeyPem param.
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
  return process.env.SENTINEL_LICENSE_PUBLIC_KEY || process.env.PROMPTWALL_LICENSE_PUBLIC_KEY || EMBEDDED_PUBLIC_KEY_PEM;
}

function licensePath() {
  const explicit = process.env.SENTINEL_LICENSE_PATH || process.env.PROMPTWALL_LICENSE_PATH;
  if (explicit) return explicit;
  const base = typeof env.defaultEnvPath === 'function' ? env.defaultEnvPath() : path.join(process.cwd(), '.env');
  return path.join(path.dirname(base), 'promptwall.lic');
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

function loadStatus(now = Date.now(), deps = {}) {
  const read = deps.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  let text = '';
  try { text = read(deps.licensePath || licensePath()); } catch (_) { return { state: 'unlicensed', payload: null, reason: 'missing' }; }
  const v = verifyLicenseText(text, { now, ...(deps.publicKeyPem ? { publicKeyPem: deps.publicKeyPem } : {}) });
  if (!v.ok) return { state: 'unlicensed', payload: null, reason: v.reason };
  return { state: evaluate(v.payload, now), payload: v.payload, reason: null };
}

function refresh(deps = {}) {
  const now = deps.now || Date.now();
  const next = loadStatus(now, deps);
  const prev = _status;
  _status = next;
  if (deps.appendAudit && (prev.state !== next.state)) {
    deps.appendAudit({
      action: 'LICENSE_STATE_CHANGED',
      actor: 'system',
      detail: `from=${prev.state}; to=${next.state}; plan=${next.payload ? next.payload.plan : 'none'}; expires=${next.payload ? next.payload.expires : 'none'}`,
    });
  }
  return next;
}

function status() { return _status; }

function graceEndsAt(payload) {
  if (!payload) return null;
  const expires = Date.parse(payload.expires);
  if (!Number.isFinite(expires)) return null;
  const graceDays = Number.isFinite(Number(payload.graceDays)) ? Math.max(0, Number(payload.graceDays)) : DEFAULT_GRACE_DAYS;
  return new Date(expires + graceDays * 24 * 3600 * 1000).toISOString();
}

function publicStatus() {
  const s = _status;
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
    reason: s.reason || null,
  };
}

// Express middleware: in 'readonly' state, block admin configuration writes
// EXCEPT under /api/queries/ (reveal/assign support the approval workflow, which
// must never be impaired) and the license-install route itself.
function requireWritable(req, res, next) {
  if (status().state !== 'readonly') return next();
  if (req.path.startsWith('/api/queries/')) return next();
  if (req.path === '/api/billing/license' && req.method === 'POST') return next();
  return res.status(403).json({ error: 'license_readonly' });
}

module.exports = {
  verifyLicenseText,
  evaluate,
  loadStatus,
  refresh,
  status,
  publicStatus,
  requireWritable,
  licensePath,
  EMBEDDED_PUBLIC_KEY_PEM,
  DEFAULT_GRACE_DAYS,
};
