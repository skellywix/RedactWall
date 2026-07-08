'use strict';
/**
 * Vendor link — connected-mode license heartbeat and kill-switch
 * (PLANS/vendor-connected-deployment.md, Phase A).
 *
 * OPT-IN and dormant unless REDACTWALL_LICENSE_SERVER_URL is set: this is the
 * ONLY vendor-bound egress in the product, and the air-gapped default never
 * enables it. When enabled, the control plane must maintain vendor contact to
 * keep serving — "heartbeat or die":
 *
 *  - On the daily license cadence it POSTs a prompt-free heartbeat
 *    { customerId, plan, seatsUsed, seatLimit, version, sentAt } and expects a
 *    FRESH signed verdict base64(json).base64(ed25519sig) over
 *    { status:'active'|'revoked', customerId, issuedAt }.
 *  - The verdict is verified with the SAME embedded public key the license file
 *    uses, must be bound to the installed customerId, and its issuedAt must be
 *    strictly greater than the last applied (monotonic). Only such a FRESH
 *    verdict counts as vendor contact and can change the revoked state — so a
 *    captured old 'active' verdict cannot be replayed to keep an install alive
 *    or to lift a revocation (downgrade attack), and a customer who blocks
 *    egress simply stops getting fresh verdicts.
 *  - The last verdict + last-contact time are PERSISTED and restored at boot
 *    BEFORE the server accepts ingest, so a revocation survives restart. If no
 *    fresh contact occurs within the tolerance window
 *    (REDACTWALL_LICENSE_MAX_STALENESS_DAYS, default 7) the install fails
 *    CLOSED (blocked), it never drifts back to active.
 *
 * A revoked/stale install blocks all AI use (maximal data protection) while
 * detection, approvals, audit, and evidence export keep running. Nothing here
 * fails open. The heartbeat carries seat COUNTS and license identifiers only —
 * never prompts, findings, member data, or the per-user roster.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const env = require('./env');
const license = require('./license');
const { outboundHttpsUrl } = require('./url-policy');

const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_MAX_STALENESS_DAYS = 7;

// In-memory connected-mode state (mirrored to disk). appliedIssuedAt gates
// monotonic freshness; lastContactMs drives staleness.
let _appliedIssuedAt = 0;
let _lastContactMs = 0;

function settings(rawEnv = process.env) {
  const resolved = env.withEnvAliases(rawEnv);
  const url = outboundHttpsUrl(resolved.REDACTWALL_LICENSE_SERVER_URL || '');
  const timeout = Number(resolved.REDACTWALL_LICENSE_SERVER_TIMEOUT_MS);
  const staleness = Number(resolved.REDACTWALL_LICENSE_MAX_STALENESS_DAYS);
  return {
    enabled: !!url,
    url,
    timeoutMs: Number.isFinite(timeout) && timeout > 0 ? Math.min(timeout, 30000) : DEFAULT_TIMEOUT_MS,
    maxStalenessMs: (Number.isFinite(staleness) && staleness >= 0 ? staleness : DEFAULT_MAX_STALENESS_DAYS) * 24 * 60 * 60 * 1000,
  };
}

function enabled(rawEnv = process.env) {
  return settings(rawEnv).enabled;
}

function statePath() {
  const explicit = process.env.REDACTWALL_VENDOR_STATE_PATH;
  if (explicit) return explicit;
  return path.join(path.dirname(license.licensePath()), 'redactwall.vendor');
}

function publicKey(deps) {
  return deps.publicKeyPem || process.env.REDACTWALL_LICENSE_PUBLIC_KEY || license.EMBEDDED_PUBLIC_KEY_PEM;
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

function verdictIssuedAtMs(payload) {
  const raw = payload && payload.issuedAt;
  if (typeof raw === 'number' && Number.isFinite(raw)) return raw;
  const parsed = Date.parse(String(raw || ''));
  return Number.isFinite(parsed) ? parsed : NaN;
}

// A verdict is applicable to THIS install only if it is bound to the installed
// customer (both ids present and equal) and strictly newer than the last
// applied. Returns { ok, reason?, issuedAt? }.
function applicable(payload) {
  const installed = license.publicStatus().customerId;
  if (!installed || !payload.customerId || String(payload.customerId) !== String(installed)) {
    return { ok: false, reason: 'customer_mismatch' };
  }
  const issuedAt = verdictIssuedAtMs(payload);
  if (!Number.isFinite(issuedAt)) return { ok: false, reason: 'no_issued_at' };
  if (issuedAt <= _appliedIssuedAt) return { ok: false, reason: 'stale_verdict' };
  return { ok: true, issuedAt };
}

function persist(deps, verdictText, status) {
  const write = deps.writeFile || ((p, d) => fs.writeFileSync(p, d, { mode: 0o600 }));
  try {
    write(deps.statePath || statePath(), JSON.stringify({
      verdict: verdictText,
      status,
      appliedIssuedAt: _appliedIssuedAt,
      lastContactAt: new Date(_lastContactMs).toISOString(),
    }));
  } catch (_) { /* best-effort; staleness still fails closed on restart */ }
}

// Restore connected-mode state at boot, BEFORE the server accepts ingest, so a
// revocation survives restart and heartbeat-or-die cannot be reset.
//
// The kill-switch is anchored in the tamper-evident, hash-chained AUDIT (via the
// injected durable/installAt readers), NOT the state file: the file is
// operator-writable and deletable, so trusting its self-reported contact time or
// treating its absence as a fresh install would let an adversary lift a
// revocation or reset the staleness clock simply by deleting/editing it. The
// audit cannot be edited without breaking verifyAuditChain.
//
// This also requires the license to be loaded already (the caller refreshes it
// first): the verdict's customer binding is checked against the installed
// customerId, which would otherwise be null and drop a persisted revocation.
function restore(deps = {}) {
  const cfg = deps.settings || settings();
  const nowMs = deps.nowMs || Date.now();
  if (!cfg.enabled) { _lastContactMs = nowMs; _appliedIssuedAt = 0; return { ok: true, restored: false }; }

  // Durable, tamper-evident facts from the audit chain.
  const durable = (deps.lastVendorHeartbeat && deps.lastVendorHeartbeat()) || null; // { issuedAt, contactAt, status }
  const installMs = (deps.firstAuditAt && deps.firstAuditAt()) || nowMs;             // install age anchor

  // State file: a fast cache only. Its signed verdict can RAISE the monotonic
  // issuedAt floor (never lower it) and can carry a revocation forward, but it
  // can never relax an audit-anchored fact.
  const read = deps.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  let saved;
  try { saved = JSON.parse(read(deps.statePath || statePath())); } catch (_) { saved = null; }
  let fileRevoked = false;
  let fileVerdictIssuedAt = 0;
  if (saved) {
    const payload = verifyVerdict(saved.verdict, publicKey(deps));
    const installed = license.publicStatus().customerId;
    const bound = payload && installed && payload.customerId && String(payload.customerId) === String(installed);
    if (bound) { fileVerdictIssuedAt = verdictIssuedAtMs(payload) || 0; fileRevoked = String(payload.status) === 'revoked'; }
  }

  // Monotonic issuedAt floor = the max of every durable/cached source, so a
  // rolled-back file cannot re-open a replay-downgrade window.
  const durableIssuedAt = durable && Number.isFinite(durable.issuedAt) ? durable.issuedAt : 0;
  _appliedIssuedAt = Math.max(durableIssuedAt, fileVerdictIssuedAt, 0);

  // Last contact comes from the audit, not the file. With no durable contact
  // record the staleness window is measured from install age (also durable), so
  // an install that never reached the vendor cannot buy a fresh window by
  // deleting the file — it stays within, and eventually past, its window.
  _lastContactMs = durable && Number.isFinite(durable.contactAt) ? durable.contactAt : installMs;

  const revoked = (durable && String(durable.status) === 'revoked') || fileRevoked;
  if (revoked) license.applyVendorVerdict(true, { appendAudit: deps.appendAudit });

  return evaluateStaleness(deps, nowMs);
}

// Heartbeat-or-die staleness: block when the last FRESH vendor contact is older
// than the tolerance window. Connected mode only.
function evaluateStaleness(deps = {}, nowMs = Date.now()) {
  const cfg = deps.settings || settings();
  if (!cfg.enabled) { license.setVendorStale(false, { appendAudit: deps.appendAudit }); return { ok: true, stale: false }; }
  const stale = (nowMs - _lastContactMs) > cfg.maxStalenessMs;
  license.setVendorStale(stale, { appendAudit: deps.appendAudit });
  return { ok: true, stale };
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

// Run one heartbeat. Only a FRESH, customer-bound, signature-valid verdict
// counts as contact and can change state; anything else leaves state unchanged
// (and, being non-contact, lets staleness eventually fail closed).
async function heartbeat(deps = {}) {
  const cfg = deps.settings || settings();
  if (!cfg.enabled) return { ok: false, reason: 'disabled' };
  const nowMs = deps.nowMs || Date.now();
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
    if (!res || !res.ok) { evaluateStaleness(deps, nowMs); return { ok: false, reason: 'http_' + (res ? res.status : 'error') }; }
    text = await res.text();
  } catch (_) {
    evaluateStaleness(deps, nowMs);
    return { ok: false, reason: 'unreachable' };
  }

  const payload = verifyVerdict(text, publicKey(deps));
  if (!payload) { evaluateStaleness(deps, nowMs); return { ok: false, reason: 'bad_verdict' }; }
  const check = applicable(payload);
  if (!check.ok) { evaluateStaleness(deps, nowMs); return { ok: false, reason: check.reason }; }

  // Fresh, bound verdict = proof of live vendor contact.
  _appliedIssuedAt = check.issuedAt;
  _lastContactMs = nowMs;
  const revoked = String(payload.status) === 'revoked';
  license.applyVendorVerdict(revoked, { appendAudit: deps.appendAudit });
  license.setVendorStale(false, { appendAudit: deps.appendAudit });
  // Durable, tamper-evident record of this contact (see restore()): the audit
  // chain is the authoritative anchor, the state file only a cache. Written on
  // every genuinely fresh verdict (monotonic issuedAt already gates duplicates),
  // so its growth tracks the vendor's issuance cadence, not reboot frequency.
  if (deps.appendAudit) {
    deps.appendAudit({
      action: 'VENDOR_HEARTBEAT_OK',
      actor: 'vendor',
      detail: JSON.stringify({ issuedAt: check.issuedAt, contactAt: nowMs, status: revoked ? 'revoked' : 'active' }),
    });
  }
  persist(deps, text, revoked ? 'revoked' : 'active');
  return { ok: true, verdict: { status: revoked ? 'revoked' : 'active' } };
}

module.exports = {
  settings,
  enabled,
  verifyVerdict,
  restore,
  evaluateStaleness,
  heartbeat,
  statePath,
  _internal: { heartbeatBody, applicable, verdictIssuedAtMs, reset: () => { _appliedIssuedAt = 0; _lastContactMs = 0; } },
};
