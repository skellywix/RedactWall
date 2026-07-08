'use strict';
/**
 * Connected-mode license heartbeat + kill-switch (server/vendor-link.js).
 * Opt-in egress; heartbeat-or-die. Verdicts must be signature-valid,
 * customer-bound, and monotonically FRESH to count as vendor contact or change
 * state, so a captured verdict cannot be replayed to keep an install alive or
 * lift a revocation; revocation persists across restart; and a stale link fails
 * CLOSED. The body carries seat counts and license ids only.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const { privateKey: attackerKey } = crypto.generateKeyPairSync('ed25519');

process.env.REDACTWALL_LICENSE_PUBLIC_KEY = PUB;
const license = require('../server/license');
const vendorLink = require('../server/vendor-link');

const T0 = Date.parse('2026-07-08T00:00:00Z');
const DAY = 24 * 60 * 60 * 1000;
const CFG = { enabled: true, url: 'https://vendor.example.com/hb', timeoutMs: 8000, maxStalenessMs: 7 * DAY };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-vendor-link-'));
const STATE = path.join(tmp, 'redactwall.vendor');

function signLicense(over = {}) {
  const payload = { customer: 'CU', customerId: 'cu-42', plan: 'enterprise', seats: 50, features: [], issued: '2026-01-01T00:00:00Z', expires: '2027-01-01T00:00:00Z', ...over };
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  return `${b64}.${crypto.sign(null, Buffer.from(b64, 'utf8'), privateKey).toString('base64')}`;
}
function verdict(payload, key = privateKey) {
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  return `${b64}.${crypto.sign(null, Buffer.from(b64, 'utf8'), key).toString('base64')}`;
}
function fetchReturning(text, ok = true, status = 200) {
  return async () => ({ ok, status, text: async () => text });
}
function deps(over = {}) {
  return { settings: CFG, publicKeyPem: PUB, statePath: STATE, seatReport: { seatsUsed: 5, seatLimit: 50 }, ...over };
}

test.beforeEach(() => {
  fs.rmSync(STATE, { force: true });
  vendorLink._internal.reset();
  license.refresh({ publicKeyPem: PUB, now: T0, readFile: () => signLicense() });
  license.applyVendorVerdict(false);
  license.setVendorStale(false);
});
test.after(() => { license.applyVendorVerdict(false); license.setVendorStale(false); fs.rmSync(tmp, { recursive: true, force: true }); });

test('opt-in gating: disabled without a URL, http/metadata rejected, https enabled', () => {
  assert.strictEqual(vendorLink.enabled({}), false);
  assert.strictEqual(vendorLink.enabled({ REDACTWALL_LICENSE_SERVER_URL: 'http://plain.example.com' }), false);
  assert.strictEqual(vendorLink.enabled({ REDACTWALL_LICENSE_SERVER_URL: 'https://169.254.169.254/hb' }), false);
  assert.strictEqual(vendorLink.enabled({ REDACTWALL_LICENSE_SERVER_URL: 'https://vendor.example.com/hb' }), true);
});

test('a disabled link never calls fetch (air-gapped default stays offline)', async () => {
  let called = false;
  const r = await vendorLink.heartbeat({ settings: { enabled: false }, fetchImpl: async () => { called = true; return { ok: true, text: async () => '' }; } });
  assert.deepStrictEqual(r, { ok: false, reason: 'disabled' });
  assert.strictEqual(called, false);
});

test('heartbeat body is prompt-free: seat counts and license ids only, never the roster', () => {
  const body = vendorLink._internal.heartbeatBody({ seatReport: { seatsUsed: 12, seatLimit: 50, users: [{ user: 'roster@cu.test' }] }, version: '0.3.0', now: '2026-07-08T00:00:00Z' });
  assert.deepStrictEqual(body, { customerId: 'cu-42', plan: 'enterprise', seatsUsed: 12, seatLimit: 50, version: '0.3.0', sentAt: '2026-07-08T00:00:00Z' });
  assert.ok(!JSON.stringify(body).includes('roster@cu.test'));
});

test('a fresh signed revoked verdict trips the kill-switch; a fresh newer active clears it', async () => {
  let r = await vendorLink.heartbeat(deps({ nowMs: T0, fetchImpl: fetchReturning(verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 })) }));
  assert.deepStrictEqual(r, { ok: true, verdict: { status: 'revoked' } });
  assert.strictEqual(license.isRevoked(), true);
  assert.strictEqual(license.publicStatus().reason, 'vendor_revoked');

  r = await vendorLink.heartbeat(deps({ nowMs: T0 + 1000, fetchImpl: fetchReturning(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 + 1000 })) }));
  assert.deepStrictEqual(r, { ok: true, verdict: { status: 'active' } });
  assert.strictEqual(license.isRevoked(), false);
});

test('a captured OLDER active verdict cannot be replayed to lift a fresh revocation', async () => {
  await vendorLink.heartbeat(deps({ nowMs: T0, fetchImpl: fetchReturning(verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 })) }));
  assert.strictEqual(license.isRevoked(), true);
  const replay = await vendorLink.heartbeat(deps({ nowMs: T0 + 5000, fetchImpl: fetchReturning(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 - 1000 })) }));
  assert.strictEqual(replay.reason, 'stale_verdict');
  assert.strictEqual(license.isRevoked(), true);
});

test('revocation survives a process restart via persisted, re-verified state', async () => {
  await vendorLink.heartbeat(deps({ nowMs: T0, fetchImpl: fetchReturning(verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 })) }));
  assert.strictEqual(license.isRevoked(), true);
  assert.ok(fs.existsSync(STATE));

  // Simulate restart: clear in-memory state, then restore before serving.
  vendorLink._internal.reset();
  license.applyVendorVerdict(false);
  assert.strictEqual(license.isRevoked(), false);
  vendorLink.restore(deps({ nowMs: T0 + 2000 }));
  assert.strictEqual(license.isRevoked(), true);
});

// A durable, tamper-evident audit anchor: heartbeat appends VENDOR_HEARTBEAT_OK,
// restore reads it back. Simulates db.appendAudit / db.lastVendorHeartbeat.
function auditAnchor() {
  const rows = [];
  return {
    appendAudit: (rec) => { rows.push(rec); },
    lastVendorHeartbeat: () => {
      for (let i = rows.length - 1; i >= 0; i -= 1) {
        if (rows[i].action === 'VENDOR_HEARTBEAT_OK') {
          const d = JSON.parse(rows[i].detail);
          return { issuedAt: Number(d.issuedAt), contactAt: Number(d.contactAt), status: String(d.status) };
        }
      }
      return null;
    },
    firstAuditAt: () => T0,
  };
}

test('deleting the state file cannot lift a revocation or reset the staleness clock', async () => {
  const anchor = auditAnchor();
  await vendorLink.heartbeat(deps({ nowMs: T0, appendAudit: anchor.appendAudit, fetchImpl: fetchReturning(verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 })) }));
  assert.strictEqual(license.isRevoked(), true);

  // Attacker restarts and deletes the operator-writable cache file.
  fs.rmSync(STATE, { force: true });
  vendorLink._internal.reset();
  license.applyVendorVerdict(false);
  assert.strictEqual(license.isRevoked(), false);

  // Restore reads the tamper-evident audit anchor, not the (now-missing) file.
  vendorLink.restore(deps({ nowMs: T0 + 2000, appendAudit: anchor.appendAudit, lastVendorHeartbeat: anchor.lastVendorHeartbeat, firstAuditAt: anchor.firstAuditAt }));
  assert.strictEqual(license.isRevoked(), true, 'revocation must survive file deletion');
});

test('a deleted file cannot buy a fresh staleness window when the audit shows stale contact', () => {
  const anchor = auditAnchor();
  // Durable record: last active contact was 8 days ago.
  anchor.appendAudit({ action: 'VENDOR_HEARTBEAT_OK', actor: 'vendor', detail: JSON.stringify({ issuedAt: T0 - 8 * DAY, contactAt: T0 - 8 * DAY, status: 'active' }) });
  fs.rmSync(STATE, { force: true });
  vendorLink._internal.reset();
  license.applyVendorVerdict(false); license.setVendorStale(false);

  vendorLink.restore(deps({ nowMs: T0, appendAudit: anchor.appendAudit, lastVendorHeartbeat: anchor.lastVendorHeartbeat, firstAuditAt: anchor.firstAuditAt }));
  assert.strictEqual(license.isRevoked(), true, 'stale contact from the audit must fail closed despite the missing file');
});

test('an install that never reached the vendor fails closed once past its window from install age', () => {
  const anchor = auditAnchor(); // firstAuditAt = T0, no heartbeat rows
  vendorLink._internal.reset();
  license.applyVendorVerdict(false); license.setVendorStale(false);
  // 8 days after install, still no successful contact -> stale -> closed.
  vendorLink.restore(deps({ nowMs: T0 + 8 * DAY, appendAudit: anchor.appendAudit, lastVendorHeartbeat: anchor.lastVendorHeartbeat, firstAuditAt: anchor.firstAuditAt }));
  assert.strictEqual(license.isRevoked(), true);
});

test('a stale link (no fresh contact within tolerance) fails CLOSED; contact clears it', async () => {
  // Fresh active contact at T0.
  await vendorLink.heartbeat(deps({ nowMs: T0, fetchImpl: fetchReturning(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 })) }));
  assert.strictEqual(license.isRevoked(), false);

  // 8 days later with no contact -> stale -> blocked.
  vendorLink.evaluateStaleness(deps(), T0 + 8 * DAY);
  assert.strictEqual(license.isRevoked(), true);
  assert.strictEqual(license.publicStatus().reason, 'vendor_unreachable');

  // A fresh contact restores service.
  await vendorLink.heartbeat(deps({ nowMs: T0 + 9 * DAY, fetchImpl: fetchReturning(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 + 9 * DAY })) }));
  assert.strictEqual(license.isRevoked(), false);
});

test('an unreachable heartbeat holds the current state and never fails open', async () => {
  await vendorLink.heartbeat(deps({ nowMs: T0, fetchImpl: fetchReturning(verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 })) }));
  const r = await vendorLink.heartbeat(deps({ nowMs: T0 + DAY, fetchImpl: async () => { throw new Error('network down'); } }));
  assert.strictEqual(r.reason, 'unreachable');
  assert.strictEqual(license.isRevoked(), true);
});

test('forged, unbound, cross-customer, and no-issuedAt verdicts never change state', async () => {
  vendorLink.restore(deps({ nowMs: T0 })); // booted install, contact baseline at T0
  const cases = [
    ['bad_verdict', verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 }, attackerKey)],
    ['customer_mismatch', verdict({ status: 'revoked', customerId: 'cu-OTHER', issuedAt: T0 })],
    ['customer_mismatch', verdict({ status: 'revoked', issuedAt: T0 })], // unbound (no customerId)
    ['no_issued_at', verdict({ status: 'revoked', customerId: 'cu-42' })],
  ];
  for (const [reason, text] of cases) {
    const r = await vendorLink.heartbeat(deps({ nowMs: T0, fetchImpl: fetchReturning(text) }));
    assert.strictEqual(r.reason, reason, `expected ${reason}`);
    assert.strictEqual(license.isRevoked(), false, `must not revoke on ${reason}`);
  }
});

test('a forged active verdict cannot lift a genuine revocation', async () => {
  await vendorLink.heartbeat(deps({ nowMs: T0, fetchImpl: fetchReturning(verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 })) }));
  const forged = await vendorLink.heartbeat(deps({ nowMs: T0 + DAY, fetchImpl: fetchReturning(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 + 2 * DAY }, attackerKey)) }));
  assert.strictEqual(forged.reason, 'bad_verdict');
  assert.strictEqual(license.isRevoked(), true);
});

test('verifyVerdict accepts a valid signature and rejects a forged one', () => {
  assert.ok(vendorLink.verifyVerdict(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 }), PUB));
  assert.strictEqual(vendorLink.verifyVerdict(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 }, attackerKey), PUB), null);
  assert.strictEqual(vendorLink.verifyVerdict('not-a-token', PUB), null);
});
