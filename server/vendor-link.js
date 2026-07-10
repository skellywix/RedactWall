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
 *    FRESH, domain-separated signed verdict base64(json).base64(ed25519sig)
 *    over { kind, status:'active'|'revoked', customerId, issuedAt }.
 *  - The verdict is verified with a dedicated online-verdict public key, must
 *    be bound to the installed customerId, and its issuedAt must be
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
const { opaqueReference } = require('./audit-reference');
const { outboundHttpsUrlWithoutParameters } = require('./url-policy');
const { cancelResponseBody, readBoundedText } = require('../sensors/shared/bounded-response');

const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_MAX_STALENESS_DAYS = 7;
const MAX_VERDICT_BYTES = 64 * 1024;
const VERDICT_DOMAIN = 'redactwall.connected-license-verdict.v1';
const HEARTBEAT_TOKEN_RE = /^[A-Za-z0-9._~+/=-]{32,256}$/;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const ISSUED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_VERDICT_CLOCK_SKEW_MS = 5 * 60 * 1000;

// In-memory connected-mode state (mirrored to disk). appliedIssuedAt gates
// monotonic freshness; lastContactMs drives staleness.
let _appliedIssuedAt = 0;
let _lastContactMs = 0;

function settings(rawEnv = process.env) {
  const resolved = env.withEnvAliases(rawEnv);
  const url = outboundHttpsUrlWithoutParameters(resolved.REDACTWALL_LICENSE_SERVER_URL || '');
  const timeout = Number(resolved.REDACTWALL_LICENSE_SERVER_TIMEOUT_MS);
  const staleness = Number(resolved.REDACTWALL_LICENSE_MAX_STALENESS_DAYS);
  const token = typeof resolved.REDACTWALL_LICENSE_SERVER_TOKEN === 'string'
    && HEARTBEAT_TOKEN_RE.test(resolved.REDACTWALL_LICENSE_SERVER_TOKEN)
    ? resolved.REDACTWALL_LICENSE_SERVER_TOKEN
    : '';
  return {
    enabled: !!url,
    url,
    token,
    timeoutMs: Number.isFinite(timeout) && timeout > 0 ? Math.min(timeout, 30000) : DEFAULT_TIMEOUT_MS,
    maxStalenessMs: (Number.isFinite(staleness) && staleness >= 0 ? staleness : DEFAULT_MAX_STALENESS_DAYS) * 24 * 60 * 60 * 1000,
  };
}

function enabled(rawEnv = process.env) {
  return settings(rawEnv).enabled;
}

function customerAuditReference(customerId, deps = {}) {
  if (!customerId) return '';
  return (deps.opaqueReference || opaqueReference)('license', customerId);
}

function statePath() {
  const explicit = process.env.REDACTWALL_VENDOR_STATE_PATH;
  if (explicit) return explicit;
  return path.join(path.dirname(license.licensePath()), 'redactwall.vendor');
}

function verdictPublicKey(deps) {
  return deps.verdictPublicKeyPem || process.env.REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY || '';
}

// Verify a vendor verdict under its dedicated online key and signature domain.
// The offline license root is deliberately never a fallback here.
function verifyVerdict(text, publicKeyPem) {
  const raw = String(text || '').trim();
  const dot = raw.indexOf('.');
  if (dot <= 0 || dot === raw.length - 1) return null;
  const payloadB64 = raw.slice(0, dot);
  const sigB64 = raw.slice(dot + 1);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(payloadB64)
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(sigB64)) return null;
  let pub;
  try { pub = crypto.createPublicKey(publicKeyPem); } catch (_) { return null; }
  if (pub.asymmetricKeyType !== 'ed25519') return null;
  let valid = false;
  const signedInput = Buffer.from(`${VERDICT_DOMAIN}\0${payloadB64}`, 'utf8');
  try { valid = crypto.verify(null, signedInput, pub, Buffer.from(sigB64, 'base64')); } catch (_) { valid = false; }
  if (!valid) return null;
  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    if (payload.kind !== VERDICT_DOMAIN || !['active', 'revoked'].includes(payload.status)) return null;
    const keys = Object.keys(payload);
    if (keys.length !== 4 || !['kind', 'status', 'customerId', 'issuedAt'].every((key) => keys.includes(key))) return null;
    if (typeof payload.customerId !== 'string' || !CUSTOMER_ID_RE.test(payload.customerId)) return null;
    if (typeof payload.issuedAt !== 'string' || !ISSUED_AT_RE.test(payload.issuedAt)
        || !Number.isFinite(Date.parse(payload.issuedAt))) return null;
    return payload;
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
function applicable(payload, nowMs = Date.now()) {
  const installed = license.publicStatus().customerId;
  if (!installed || !payload.customerId || String(payload.customerId) !== String(installed)) {
    return { ok: false, reason: 'customer_mismatch' };
  }
  const issuedAt = verdictIssuedAtMs(payload);
  if (!Number.isFinite(issuedAt)) return { ok: false, reason: 'no_issued_at' };
  if (Math.abs(issuedAt - nowMs) > MAX_VERDICT_CLOCK_SKEW_MS) {
    return { ok: false, reason: 'clock_skew' };
  }
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
  const installedCustomerId = license.publicStatus().customerId || '';
  const customerRef = customerAuditReference(installedCustomerId, deps);
  let durable = null;
  try {
    durable = (deps.lastVendorHeartbeat && deps.lastVendorHeartbeat(installedCustomerId, customerRef)) || null;
  } catch {
    _lastContactMs = nowMs + MAX_VERDICT_CLOCK_SKEW_MS + 1;
    return failClosedSharedState('state_sync_failed');
  }
  const rawInstallMs = (deps.firstAuditAt && deps.firstAuditAt()) || nowMs;          // install age anchor
  const installMs = Number.isFinite(rawInstallMs) ? rawInstallMs : nowMs;

  // State file: a fast cache only. Its signed verdict can RAISE the monotonic
  // issuedAt floor (never lower it) and can carry a revocation forward, but it
  // can never relax an audit-anchored fact.
  const read = deps.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  let saved;
  try { saved = JSON.parse(read(deps.statePath || statePath())); } catch (_) { saved = null; }
  let fileRevoked = false;
  let fileVerdictIssuedAt = 0;
  if (saved) {
    const payload = verifyVerdict(saved.verdict, verdictPublicKey(deps));
    const installed = license.publicStatus().customerId;
    const bound = payload && installed && payload.customerId && String(payload.customerId) === String(installed);
    if (bound) {
      const candidateIssuedAt = verdictIssuedAtMs(payload) || 0;
      if (candidateIssuedAt <= nowMs + MAX_VERDICT_CLOCK_SKEW_MS) fileVerdictIssuedAt = candidateIssuedAt;
      fileRevoked = String(payload.status) === 'revoked';
    }
  }

  // Monotonic issuedAt floor = the max of every durable/cached source, so a
  // rolled-back file cannot re-open a replay-downgrade window.
  const durableIssuedAt = durable && Number.isFinite(durable.issuedAt)
    && durable.issuedAt <= nowMs + MAX_VERDICT_CLOCK_SKEW_MS ? durable.issuedAt : 0;
  _appliedIssuedAt = Math.max(durableIssuedAt, fileVerdictIssuedAt, 0);

  // Last contact comes from the audit, not the file. With no durable contact
  // record the staleness window is measured from install age (also durable), so
  // an install that never reached the vendor cannot buy a fresh window by
  // deleting the file — it stays within, and eventually past, its window.
  const durableContactAt = durable && Number.isFinite(durable.contactAt) ? durable.contactAt : null;
  const futureClockAnchor = installMs > nowMs + MAX_VERDICT_CLOCK_SKEW_MS
    || (durableContactAt !== null && durableContactAt > nowMs + MAX_VERDICT_CLOCK_SKEW_MS);
  _lastContactMs = futureClockAnchor ? nowMs + MAX_VERDICT_CLOCK_SKEW_MS + 1
    : durableContactAt !== null ? durableContactAt : installMs;

  const durableRevoked = durable && String(durable.status) === 'revoked';
  const fileCarriesNewerRevocation = fileRevoked && fileVerdictIssuedAt >= durableIssuedAt;
  const revoked = durableRevoked || fileCarriesNewerRevocation;
  if (revoked) license.applyVendorVerdict(true, { appendAudit: deps.appendAudit });

  return evaluateStaleness(deps, nowMs);
}

// Heartbeat-or-die staleness: block when the last FRESH vendor contact is older
// than the tolerance window. Connected mode only.
function evaluateStaleness(deps = {}, nowMs = Date.now()) {
  const cfg = deps.settings || settings();
  if (!cfg.enabled) { license.setVendorStale(false, { appendAudit: deps.appendAudit }); return { ok: true, stale: false }; }
  const stale = _lastContactMs > nowMs + MAX_VERDICT_CLOCK_SKEW_MS
    || (nowMs - _lastContactMs) > cfg.maxStalenessMs;
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

function normalizedDurableState(state, customerId) {
  if (!state || typeof state !== 'object') return null;
  const durableCustomerId = String(state.customerId || customerId || '').trim();
  const issuedAt = Number(state.issuedAt);
  const contactAt = Number(state.contactAt);
  const status = String(state.status || '');
  if (!durableCustomerId || durableCustomerId !== String(customerId || '')
      || !Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(contactAt)
      || issuedAt < 0 || contactAt < 0 || !['active', 'revoked'].includes(status)) return null;
  return { customerId: durableCustomerId, issuedAt, contactAt, status };
}

function adoptDurableState(state, cfg, nowMs, customerId) {
  const durable = normalizedDurableState(state, customerId);
  if (!durable || durable.issuedAt < _appliedIssuedAt) return false;
  _appliedIssuedAt = durable.issuedAt;
  _lastContactMs = durable.contactAt;
  const stale = _lastContactMs > nowMs + MAX_VERDICT_CLOCK_SKEW_MS
    || (nowMs - _lastContactMs) > cfg.maxStalenessMs;
  license._internal.applyVendorState({ revoked: durable.status === 'revoked', stale }, {
    source: 'vendor_shared_state',
  });
  return true;
}

function failClosedSharedState(reason = 'state_sync_failed') {
  license._internal.applyVendorState({ stale: true }, { source: 'vendor_shared_state' });
  return { ok: false, reason, stale: true };
}

function reconcileSharedState(deps = {}, nowMs = Date.now()) {
  const cfg = deps.settings || settings();
  if (!cfg.enabled || !deps.lastVendorHeartbeat) return { ok: true, synced: false };
  const customerId = license.publicStatus().customerId || '';
  if (!customerId) return failClosedSharedState('customer_binding_missing');
  let shared;
  try {
    shared = deps.lastVendorHeartbeat(customerId, customerAuditReference(customerId, deps));
  } catch {
    return failClosedSharedState('state_sync_failed');
  }
  if (!shared) {
    evaluateStaleness(deps, nowMs);
    return { ok: true, synced: false };
  }
  const durable = normalizedDurableState(shared, customerId);
  if (!durable) return failClosedSharedState('state_sync_failed');
  if (durable.issuedAt >= _appliedIssuedAt) adoptDurableState(durable, cfg, nowMs, customerId);
  else evaluateStaleness(deps, nowMs);
  return { ok: true, synced: true, state: durable };
}

async function requestVerdict(cfg, body, fetchImpl) {
  if (!cfg.token || !HEARTBEAT_TOKEN_RE.test(cfg.token)) {
    return { ok: false, reason: 'configuration' };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
  let res;
  try {
    res = await fetchImpl(cfg.url, {
      method: 'POST',
      redirect: 'error',
      headers: {
        authorization: `Bearer ${cfg.token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch {
    return { ok: false, reason: 'unreachable' };
  } finally {
    clearTimeout(timer);
  }
  if (!res || !res.ok) {
    await cancelResponseBody(res);
    return { ok: false, reason: 'http_' + (res ? res.status : 'error') };
  }
  try {
    const { text } = await readBoundedText(res, {
      maxBytes: MAX_VERDICT_BYTES,
      timeoutMs: cfg.timeoutMs,
      label: 'vendor verdict',
    });
    return { ok: true, text };
  } catch {
    return { ok: false, reason: 'unreachable' };
  }
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

  // Reconcile the shared verdict before network I/O. Every scheduled replica
  // therefore enforces a peer's newer revocation even when its own vendor
  // request is unreachable, and an old response cannot preserve local state.
  const sharedSync = reconcileSharedState(deps, nowMs);
  if (!sharedSync.ok) return { ok: false, reason: sharedSync.reason };

  if (!cfg.token || !verdictPublicKey(deps)) {
    evaluateStaleness(deps, nowMs);
    return { ok: false, reason: 'configuration' };
  }

  const result = await requestVerdict(cfg, body, fetchImpl);
  if (!result.ok) {
    evaluateStaleness(deps, nowMs);
    return result;
  }
  const text = result.text;

  const payload = verifyVerdict(text, verdictPublicKey(deps));
  if (!payload) { evaluateStaleness(deps, nowMs); return { ok: false, reason: 'bad_verdict' }; }
  const check = applicable(payload, nowMs);
  if (!check.ok) {
    if (check.reason === 'stale_verdict' && deps.lastVendorHeartbeat) {
      const sync = reconcileSharedState(deps, nowMs);
      if (!sync.ok) return { ok: false, reason: sync.reason };
    }
    evaluateStaleness(deps, nowMs);
    return { ok: false, reason: check.reason };
  }

  // Stage state and immutable evidence before advancing process high-water.
  // A failed audit cannot lift a prior revocation/staleness decision in memory.
  const revoked = String(payload.status) === 'revoked';
  const previousVendor = license._internal.vendorStateSnapshot();
  const auditEvents = [];
  license._internal.applyVendorState({ revoked, stale: false }, {
    source: 'vendor',
    appendAudit: (event) => auditEvents.push(event),
  });
  // Durable, tamper-evident record of this contact (see restore()): the audit
  // chain is the authoritative anchor, the state file only a cache. Written on
  // every genuinely fresh verdict (monotonic issuedAt already gates duplicates),
  // so its growth tracks the vendor's issuance cadence, not reboot frequency.
  auditEvents.push({
      action: 'VENDOR_HEARTBEAT_OK',
      actor: 'vendor',
      detail: JSON.stringify({
        customerRef: customerAuditReference(payload.customerId, deps),
        issuedAt: check.issuedAt,
        contactAt: nowMs,
        status: revoked ? 'revoked' : 'active',
      }),
  });
  let sharedResult = null;
  try {
    if (deps.applyVendorHeartbeat) {
      sharedResult = deps.applyVendorHeartbeat({
        customerId: payload.customerId,
        customerRef: customerAuditReference(payload.customerId, deps),
        issuedAt: check.issuedAt,
        contactAt: nowMs,
        status: revoked ? 'revoked' : 'active',
        audits: auditEvents,
      });
    } else if (deps.appendAudits) deps.appendAudits(auditEvents);
    else if (deps.appendAudit) for (const event of auditEvents) deps.appendAudit(event);
  } catch (error) {
    license._internal.restoreVendorState(previousVendor);
    throw error;
  }
  if (deps.applyVendorHeartbeat && (!sharedResult || sharedResult.applied !== true)) {
    license._internal.restoreVendorState(previousVendor);
    if (!sharedResult || !adoptDurableState(sharedResult.state, cfg, nowMs, payload.customerId)) {
      license._internal.applyVendorState({ stale: true }, { source: 'vendor_shared_state' });
      return { ok: false, reason: 'state_sync_failed' };
    }
    return { ok: false, reason: 'stale_verdict' };
  }
  if (deps.applyVendorHeartbeat) {
    const committed = normalizedDurableState(sharedResult.state, payload.customerId);
    if (!committed || committed.issuedAt !== check.issuedAt
        || committed.contactAt !== nowMs || committed.status !== (revoked ? 'revoked' : 'active')) {
      license._internal.restoreVendorState(previousVendor);
      license._internal.applyVendorState({ stale: true }, { source: 'vendor_shared_state' });
      return { ok: false, reason: 'state_sync_failed' };
    }
  }
  _appliedIssuedAt = check.issuedAt;
  _lastContactMs = nowMs;
  persist(deps, text, revoked ? 'revoked' : 'active');
  return { ok: true, verdict: { status: revoked ? 'revoked' : 'active' } };
}

module.exports = {
  settings,
  enabled,
  verifyVerdict,
  restore,
  evaluateStaleness,
  reconcileSharedState,
  heartbeat,
  statePath,
  _internal: { heartbeatBody, applicable, verdictIssuedAtMs, reset: () => { _appliedIssuedAt = 0; _lastContactMs = 0; } },
};
