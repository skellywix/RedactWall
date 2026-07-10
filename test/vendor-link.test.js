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
const { privateKey: verdictPrivateKey, publicKey: verdictPublicKey } = crypto.generateKeyPairSync('ed25519');
const VERDICT_PUB = verdictPublicKey.export({ type: 'spki', format: 'pem' }).toString();
const { privateKey: attackerKey } = crypto.generateKeyPairSync('ed25519');
const VERDICT_DOMAIN = 'redactwall.connected-license-verdict.v1';
const HEARTBEAT_TOKEN = 'rwls_test_customer_token_0123456789abcdef';

process.env.REDACTWALL_LICENSE_PUBLIC_KEY = PUB;
process.env.REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY = VERDICT_PUB;
process.env.REDACTWALL_LICENSE_SERVER_TOKEN = HEARTBEAT_TOKEN;
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
const license = require('../server/license');
const vendorLink = require('../server/vendor-link');

const T0 = Date.parse('2026-07-08T00:00:00Z');
const DAY = 24 * 60 * 60 * 1000;
const CLOCK_SKEW = 5 * 60 * 1000;
const CFG = {
  enabled: true,
  url: 'https://vendor.example.com/hb',
  token: HEARTBEAT_TOKEN,
  timeoutMs: 8000,
  maxStalenessMs: 7 * DAY,
};
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-vendor-link-'));
const STATE = path.join(tmp, 'redactwall.vendor');

function signLicense(over = {}) {
  const payload = { customer: 'CU', customerId: 'cu-42', plan: 'enterprise', seats: 50, features: [], issued: '2026-01-01T00:00:00Z', expires: '2027-01-01T00:00:00Z', ...over };
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  return `${b64}.${crypto.sign(null, Buffer.from(b64, 'utf8'), privateKey).toString('base64')}`;
}
function verdict(payload, key = verdictPrivateKey, domain = VERDICT_DOMAIN) {
  const body = { kind: VERDICT_DOMAIN, ...payload };
  if (typeof body.issuedAt === 'number') body.issuedAt = new Date(body.issuedAt).toISOString();
  const b64 = Buffer.from(JSON.stringify(body), 'utf8').toString('base64');
  const signed = Buffer.from(`${domain}\0${b64}`, 'utf8');
  return `${b64}.${crypto.sign(null, signed, key).toString('base64')}`;
}
function fetchReturning(text, ok = true, status = 200) {
  return async () => new Response(text, { status: ok ? status : Math.max(400, status) });
}
function deps(over = {}) {
  return {
    settings: CFG,
    verdictPublicKeyPem: VERDICT_PUB,
    statePath: STATE,
    seatReport: { seatsUsed: 5, seatLimit: 50 },
    ...over,
  };
}

test.beforeEach(() => {
  fs.rmSync(STATE, { force: true });
  vendorLink._internal.reset();
  license.refresh({ publicKeyPem: PUB, expectedCustomerId: 'cu-42', now: T0, readFile: () => signLicense() });
  license.applyVendorVerdict(false);
  license.setVendorStale(false);
});
test.after(() => { license.applyVendorVerdict(false); license.setVendorStale(false); fs.rmSync(tmp, { recursive: true, force: true }); });

test('opt-in gating: disabled without a URL, http/metadata rejected, https enabled', () => {
  assert.strictEqual(vendorLink.enabled({}), false);
  assert.strictEqual(vendorLink.enabled({ REDACTWALL_LICENSE_SERVER_URL: 'http://plain.example.com' }), false);
  assert.strictEqual(vendorLink.enabled({ REDACTWALL_LICENSE_SERVER_URL: 'https://169.254.169.254/hb' }), false);
  assert.strictEqual(vendorLink.enabled({ REDACTWALL_LICENSE_SERVER_URL: 'https://vendor.example.com/hb?token=secret' }), false);
  assert.strictEqual(vendorLink.enabled({ REDACTWALL_LICENSE_SERVER_URL: 'https://vendor.example.com/hb#fragment' }), false);
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

test('heartbeat rejects redirects and sends only its prompt-free JSON body', async () => {
  let request;
  const signed = verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 });
  const requestDeps = deps({
    nowMs: T0,
    now: '2026-07-08T00:00:00.000Z',
    fetchImpl: async (url, options) => {
      request = { url, options };
      return new Response(signed);
    },
  });
  const result = await vendorLink.heartbeat(requestDeps);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(request.options.redirect, 'error');
  assert.strictEqual(request.options.headers.authorization, `Bearer ${HEARTBEAT_TOKEN}`);
  assert.deepStrictEqual(JSON.parse(request.options.body), vendorLink._internal.heartbeatBody(requestDeps));
});

test('connected mode never sends without a configured customer credential', async () => {
  let called = false;
  const result = await vendorLink.heartbeat(deps({
    settings: { ...CFG, token: '' },
    fetchImpl: async () => { called = true; return new Response('should not be called'); },
  }));
  assert.deepStrictEqual(result, { ok: false, reason: 'configuration' });
  assert.strictEqual(called, false);
});

test('heartbeat bounds, times out, and rejects unstreamable signed-verdict responses', async () => {
  const oversized = await vendorLink.heartbeat(deps({
    fetchImpl: async () => new Response(Buffer.alloc(65 * 1024)),
  }));
  assert.strictEqual(oversized.reason, 'unreachable');

  let cancelled = false;
  const stalled = await vendorLink.heartbeat(deps({
    settings: { ...CFG, timeoutMs: 20 },
    fetchImpl: async () => ({
      ok: true,
      headers: new Headers(),
      body: { getReader: () => ({
        read: async () => new Promise(() => {}),
        cancel: async () => { cancelled = true; },
      }) },
    }),
  }));
  assert.strictEqual(stalled.reason, 'unreachable');
  assert.strictEqual(cancelled, true);

  let failedBodyCancelled = false;
  const rejected = await vendorLink.heartbeat(deps({
    fetchImpl: async () => ({
      ok: false,
      status: 503,
      body: { cancel: async () => { failedBodyCancelled = true; } },
    }),
  }));
  assert.strictEqual(rejected.reason, 'http_503');
  assert.strictEqual(failedBodyCancelled, true);

  let textCalled = false;
  const unstreamable = await vendorLink.heartbeat(deps({
    fetchImpl: async () => ({
      ok: true,
      text: async () => { textCalled = true; return 'unsafe-buffered-verdict'; },
    }),
  }));
  assert.strictEqual(unstreamable.reason, 'unreachable');
  assert.strictEqual(textCalled, false);
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

test('a second replica cannot overwrite a newer durable verdict and adopts it locally', async () => {
  let durable = null;
  let heartbeatEvidence = null;
  const applyVendorHeartbeat = (candidate) => {
    heartbeatEvidence = candidate.audits.find((event) => event.action === 'VENDOR_HEARTBEAT_OK');
    if (durable && candidate.issuedAt <= durable.issuedAt) {
      return { applied: false, state: { ...durable } };
    }
    durable = {
      customerId: candidate.customerId,
      issuedAt: candidate.issuedAt,
      contactAt: candidate.contactAt,
      status: candidate.status,
    };
    return { applied: true, state: { ...durable } };
  };

  const newer = await vendorLink.heartbeat(deps({
    nowMs: T0 + 2000,
    applyVendorHeartbeat,
    fetchImpl: fetchReturning(verdict({
      status: 'revoked', customerId: 'cu-42', issuedAt: T0 + 2000,
    })),
  }));
  assert.strictEqual(newer.ok, true);
  assert.strictEqual(license.isRevoked(), true);

  // Replica B starts with no process-local high-water and an active overlay.
  vendorLink._internal.reset();
  license.applyVendorVerdict(false);
  assert.strictEqual(license.isRevoked(), false);

  const older = await vendorLink.heartbeat(deps({
    nowMs: T0 + 3000,
    applyVendorHeartbeat,
    fetchImpl: fetchReturning(verdict({
      status: 'active', customerId: 'cu-42', issuedAt: T0 + 1000,
    })),
  }));
  assert.deepStrictEqual(older, { ok: false, reason: 'stale_verdict' });
  assert.strictEqual(license.isRevoked(), true, 'losing replica enforces the durable newer revocation');
  assert.strictEqual(durable.status, 'revoked');
  assert.strictEqual(durable.issuedAt, T0 + 2000);
  assert.match(JSON.parse(heartbeatEvidence.detail).customerRef, /^license_[A-Za-z0-9_-]{24}$/);
  assert.ok(!heartbeatEvidence.detail.includes('cu-42'), 'raw customer id is not copied into audit text');
});

test('rotating the heartbeat bearer token does not rotate the durable audit reference', async () => {
  const refs = [];
  const applyVendorHeartbeat = (candidate) => {
    refs.push(candidate.customerRef);
    return {
      applied: true,
      state: {
        customerId: candidate.customerId,
        issuedAt: candidate.issuedAt,
        contactAt: candidate.contactAt,
        status: candidate.status,
      },
    };
  };
  await vendorLink.heartbeat(deps({
    nowMs: T0,
    applyVendorHeartbeat,
    fetchImpl: fetchReturning(verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 })),
  }));
  await vendorLink.heartbeat(deps({
    settings: { ...CFG, token: 'rwls_rotated_customer_token_abcdef0123456789' },
    nowMs: T0 + 1000,
    applyVendorHeartbeat,
    fetchImpl: fetchReturning(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 + 1000 })),
  }));
  assert.strictEqual(refs.length, 2);
  assert.strictEqual(refs[0], refs[1]);
});

test('a locally stale replay still refreshes a newer shared revocation', async () => {
  await vendorLink.heartbeat(deps({
    nowMs: T0 + 1000,
    fetchImpl: fetchReturning(verdict({
      status: 'active', customerId: 'cu-42', issuedAt: T0 + 1000,
    })),
  }));
  assert.strictEqual(license.isRevoked(), false);

  let casCalled = false;
  const replay = await vendorLink.heartbeat(deps({
    nowMs: T0 + 3000,
    lastVendorHeartbeat: () => ({
      customerId: 'cu-42', issuedAt: T0 + 2500, contactAt: T0 + 2500, status: 'revoked',
    }),
    applyVendorHeartbeat: () => { casCalled = true; throw new Error('local replay should not reach CAS'); },
    fetchImpl: fetchReturning(verdict({
      status: 'active', customerId: 'cu-42', issuedAt: T0 + 500,
    })),
  }));
  assert.deepStrictEqual(replay, { ok: false, reason: 'stale_verdict' });
  assert.strictEqual(casCalled, false);
  assert.strictEqual(license.isRevoked(), true, 'replica adopts the newer shared revocation');
});

test('misclocked verdicts cannot poison replay high-water or delay a later revocation', async () => {
  vendorLink.restore(deps({ nowMs: T0 }));

  const future = await vendorLink.heartbeat(deps({
    nowMs: T0,
    fetchImpl: fetchReturning(verdict({
      status: 'active',
      customerId: 'cu-42',
      issuedAt: T0 + CLOCK_SKEW + 1,
    })),
  }));
  assert.strictEqual(future.reason, 'clock_skew');
  assert.strictEqual(license.isRevoked(), false);

  const old = await vendorLink.heartbeat(deps({
    nowMs: T0,
    fetchImpl: fetchReturning(verdict({
      status: 'active',
      customerId: 'cu-42',
      issuedAt: T0 - CLOCK_SKEW - 1,
    })),
  }));
  assert.strictEqual(old.reason, 'clock_skew');

  const revoked = await vendorLink.heartbeat(deps({
    nowMs: T0,
    fetchImpl: fetchReturning(verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 })),
  }));
  assert.deepStrictEqual(revoked, { ok: true, verdict: { status: 'revoked' } });
  assert.strictEqual(license.isRevoked(), true, 'rejected future active verdict did not poison high-water');
});

test('a local clock rollback rejects future state changes until the clock is corrected', async () => {
  const correctTime = T0 + 2 * CLOCK_SKEW;
  await vendorLink.heartbeat(deps({
    nowMs: correctTime,
    fetchImpl: fetchReturning(verdict({ status: 'active', customerId: 'cu-42', issuedAt: correctTime })),
  }));

  const rolledBack = await vendorLink.heartbeat(deps({
    nowMs: T0,
    fetchImpl: fetchReturning(verdict({ status: 'active', customerId: 'cu-42', issuedAt: correctTime + 1 })),
  }));
  assert.strictEqual(rolledBack.reason, 'clock_skew');
  assert.strictEqual(license.isRevoked(), true, 'clock rollback fails closed instead of extending contact freshness');

  const recovered = await vendorLink.heartbeat(deps({
    nowMs: correctTime + 1,
    fetchImpl: fetchReturning(verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: correctTime + 1 })),
  }));
  assert.strictEqual(recovered.ok, true);
  assert.strictEqual(license.isRevoked(), true);
});

test('future durable clock anchors fail closed during restart restore', () => {
  const future = T0 + CLOCK_SKEW + 1;
  vendorLink.restore(deps({
    nowMs: T0,
    lastVendorHeartbeat: () => ({ issuedAt: future, contactAt: future, status: 'active' }),
    firstAuditAt: () => future,
  }));
  assert.strictEqual(license.isRevoked(), true);
  assert.strictEqual(license.publicStatus().reason, 'vendor_unreachable');
});

test('an older revoked cache cannot override a newer shared active verdict on restore', () => {
  fs.writeFileSync(STATE, JSON.stringify({
    verdict: verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 }),
    status: 'revoked',
    appliedIssuedAt: T0,
    lastContactAt: new Date(T0).toISOString(),
  }));
  vendorLink.restore(deps({
    nowMs: T0 + 2000,
    lastVendorHeartbeat: () => ({
      customerId: 'cu-42', issuedAt: T0 + 1000, contactAt: T0 + 1000, status: 'active',
    }),
    firstAuditAt: () => T0,
  }));
  assert.strictEqual(license.isRevoked(), false);
});

test('heartbeat audit failure preserves kill-switch state and does not advance replay high-water', async () => {
  await vendorLink.heartbeat(deps({
    nowMs: T0,
    fetchImpl: fetchReturning(verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 })),
  }));
  assert.strictEqual(license.isRevoked(), true);
  const activeText = verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 + 1000 });
  await assert.rejects(vendorLink.heartbeat(deps({
    nowMs: T0 + 1000,
    appendAudits: () => { throw new Error('audit down'); },
    fetchImpl: fetchReturning(activeText),
  })), /audit down/);
  assert.strictEqual(license.isRevoked(), true);

  const retry = await vendorLink.heartbeat(deps({
    nowMs: T0 + 1000,
    fetchImpl: fetchReturning(activeText),
  }));
  assert.strictEqual(retry.ok, true, 'failed audit did not consume the verdict high-water');
  assert.strictEqual(license.isRevoked(), false);

  license.setVendorStale(true);
  const fresherText = verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 + 2000 });
  await assert.rejects(vendorLink.heartbeat(deps({
    nowMs: T0 + 2000,
    appendAudits: () => { throw new Error('audit down'); },
    fetchImpl: fetchReturning(fresherText),
  })), /audit down/);
  assert.strictEqual(license.isRevoked(), true, 'staleness remains fail-closed after audit failure');
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

test('an unreachable replica still enforces a newer shared revocation', async () => {
  const result = await vendorLink.heartbeat(deps({
    nowMs: T0 + 3000,
    lastVendorHeartbeat: () => ({
      customerId: 'cu-42', issuedAt: T0 + 2000, contactAt: T0 + 2000, status: 'revoked',
    }),
    fetchImpl: async () => { throw new Error('network down'); },
  }));
  assert.strictEqual(result.reason, 'unreachable');
  assert.strictEqual(license.isRevoked(), true);
  assert.strictEqual(license.publicStatus().reason, 'vendor_revoked');
});

test('forged, unbound, cross-customer, and no-issuedAt verdicts never change state', async () => {
  vendorLink.restore(deps({ nowMs: T0 })); // booted install, contact baseline at T0
  const cases = [
    ['bad_verdict', verdict({ status: 'revoked', customerId: 'cu-42', issuedAt: T0 }, attackerKey)],
    ['customer_mismatch', verdict({ status: 'revoked', customerId: 'cu-other', issuedAt: T0 })],
    ['bad_verdict', verdict({ status: 'revoked', customerId: 'cu-OTHER', issuedAt: T0 })],
    ['bad_verdict', verdict({ status: 'revoked', issuedAt: T0 })], // malformed: no customer binding
    ['bad_verdict', verdict({ status: 'revoked', customerId: 'cu-42' })], // malformed: no issuance time
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
  assert.ok(vendorLink.verifyVerdict(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 }), VERDICT_PUB));
  assert.strictEqual(vendorLink.verifyVerdict(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 }, attackerKey), VERDICT_PUB), null);
  assert.strictEqual(vendorLink.verifyVerdict(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 }, privateKey), VERDICT_PUB), null,
    'the offline license root cannot sign online verdicts');
  assert.strictEqual(vendorLink.verifyVerdict(verdict({ status: 'active', customerId: 'cu-42', issuedAt: T0 }, verdictPrivateKey, 'wrong-domain'), VERDICT_PUB), null);
  assert.strictEqual(vendorLink.verifyVerdict('not-a-token', VERDICT_PUB), null);
});
