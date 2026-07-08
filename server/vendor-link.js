'use strict';
/**
 * Vendor link — connected-mode license heartbeat (PLANS/vendor-connected-
 * deployment.md, Phase A).
 *
 * OPT-IN and dormant unless REDACTWALL_LICENSE_SERVER_URL is set: this is the
 * ONLY vendor-bound egress in the product, and the air-gapped default never
 * enables it. On the daily license cadence it POSTs a prompt-free heartbeat
 * { customerId, licenseId, plan, seatsUsed, seatLimit, version, sentAt } to the
 * vendor's license server and applies the SIGNED verdict it returns.
 *
 * Trust boundary: the verdict is base64(json).base64(ed25519sig), verified with
 * the SAME embedded public key the license file uses. A network attacker can
 * therefore neither spoof a 'revoked' verdict nor forge an 'active' one to lift
 * a real revocation, and the verdict's customerId must match the installed
 * license (no cross-tenant replay). An unreachable or unverifiable server NEVER
 * changes state on its own — the last verified verdict holds; the link only
 * logs. Nothing here fails open.
 *
 * The heartbeat carries seat COUNTS and license identifiers only — never
 * prompts, findings, member data, or the per-user roster.
 */
const crypto = require('crypto');
const env = require('./env');
const license = require('./license');
const { outboundHttpsUrl } = require('./url-policy');

const DEFAULT_TIMEOUT_MS = 8000;

function settings(rawEnv = process.env) {
  const resolved = env.withEnvAliases(rawEnv);
  const url = outboundHttpsUrl(resolved.REDACTWALL_LICENSE_SERVER_URL || '');
  const timeout = Number(resolved.REDACTWALL_LICENSE_SERVER_TIMEOUT_MS);
  return {
    enabled: !!url,
    url,
    timeoutMs: Number.isFinite(timeout) && timeout > 0 ? Math.min(timeout, 30000) : DEFAULT_TIMEOUT_MS,
  };
}

function enabled(rawEnv = process.env) {
  return settings(rawEnv).enabled;
}

// Verify a vendor verdict: base64(payload).base64(ed25519sig) over the
// base64-payload bytes, mirroring the license-file scheme. Returns the parsed
// payload or null — never throws, never echoes body content.
function verifyVerdict(text, publicKeyPem) {
  const raw = String(text || '').trim();
  const dot = raw.indexOf('.');
  if (dot <= 0 || dot === raw.length - 1) return null;
  const payloadB64 = raw.slice(0, dot);
  const sigB64 = raw.slice(dot + 1);
  let pub;
  try { pub = crypto.createPublicKey(publicKeyPem); } catch (_) { return null; }
  let valid = false;
  try { valid = crypto.verify(null, Buffer.from(payloadB64, 'utf8'), pub, Buffer.from(sigB64, 'base64')); } catch (_) { valid = false; }
  if (!valid) return null;
  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
    return payload && typeof payload === 'object' ? payload : null;
  } catch (_) { return null; }
}

function heartbeatBody(deps) {
  const pub = license.publicStatus();
  const seats = deps.seatReport || {};
  return {
    customerId: pub.customerId || null,
    plan: pub.plan || null,
    seatsUsed: Number(seats.seatsUsed || 0),
    seatLimit: Number(seats.seatLimit || 0) || null,
    version: deps.version || null,
    sentAt: deps.now || new Date().toISOString(),
  };
}

// Run one heartbeat. Returns { ok, verdict?, reason? }. Applies a verified
// verdict to the license kill-switch; an unverifiable/unreachable response
// leaves state unchanged.
async function heartbeat(deps = {}) {
  const cfg = deps.settings || settings();
  if (!cfg.enabled) return { ok: false, reason: 'disabled' };
  const publicKeyPem = deps.publicKeyPem
    || process.env.REDACTWALL_LICENSE_PUBLIC_KEY
    || license.EMBEDDED_PUBLIC_KEY_PEM;
  const fetchImpl = deps.fetchImpl || fetch;
  const body = heartbeatBody(deps);

  let text;
  try {
    const res = await fetchImpl(cfg.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) ? AbortSignal.timeout(cfg.timeoutMs) : undefined,
    });
    if (!res || !res.ok) return { ok: false, reason: 'http_' + (res ? res.status : 'error') };
    text = await res.text();
  } catch (_) {
    return { ok: false, reason: 'unreachable' };
  }

  const verdict = verifyVerdict(text, publicKeyPem);
  if (!verdict) return { ok: false, reason: 'bad_verdict' };
  // Bind the verdict to the installed customer so a valid verdict for another
  // tenant cannot be replayed here.
  const installedCustomer = license.publicStatus().customerId;
  if (installedCustomer && verdict.customerId && String(verdict.customerId) !== String(installedCustomer)) {
    return { ok: false, reason: 'customer_mismatch' };
  }
  const revoked = String(verdict.status) === 'revoked';
  license.applyVendorVerdict(revoked, { appendAudit: deps.appendAudit });
  return { ok: true, verdict: { status: revoked ? 'revoked' : 'active' } };
}

module.exports = { settings, enabled, verifyVerdict, heartbeat, _internal: { heartbeatBody } };
