'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-connected-app-'));
const policyPath = path.join(tempRoot, 'policy.json');
process.env.NODE_ENV = 'test';
process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.REDACTWALL_AUDIT_KEY = crypto.randomBytes(32).toString('base64');
process.env.REDACTWALL_DB_PATH = path.join(tempRoot, 'redactwall.db');
process.env.REDACTWALL_AUDIT_STATE_DIR = path.join(tempRoot, 'audit-state');
process.env.REDACTWALL_POLICY_PATH = policyPath;
process.env.REDACTWALL_LICENSE_PATH = path.join(tempRoot, 'license.key');
process.env.REDACTWALL_LICENSE_MODE = 'connected';
process.env.REDACTWALL_TENANT_ID = 'customer_connected_app';
process.env.REDACTWALL_SEAT_LIMIT = '100';
process.env.REDACTWALL_LICENSE_SERVER_URL = 'https://license.vendor.example/';
process.env.REDACTWALL_CONNECTED_DEPLOYMENT_ID = 'dep_0123456789abcdef0123456789abcdef';
process.env.REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN = 'rwcp_heartbeat_0123456789abcdef0123456789';
process.env.REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN = 'rwcp_acknowledgement_0123456789abcdef01';
process.env.REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED = 'false';
process.env.REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED = 'false';
const offlineKey = crypto.generateKeyPairSync('ed25519').publicKey;
const verdictKey = crypto.generateKeyPairSync('ed25519').publicKey;
const entitlementKey = crypto.generateKeyPairSync('ed25519').publicKey;
const entitlementFingerprint = crypto.createHash('sha256')
  .update(entitlementKey.export({ type: 'spki', format: 'der' })).digest('hex');
process.env.REDACTWALL_LICENSE_PUBLIC_KEY = offlineKey.export({ type: 'spki', format: 'pem' });
process.env.REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY = verdictKey.export({ type: 'spki', format: 'pem' });
process.env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY = entitlementKey.export({ type: 'spki', format: 'pem' });
process.env.REDACTWALL_ENTITLEMENT_KEY_ID = `rw-entitlement-${entitlementFingerprint}`;
process.env.INGEST_API_KEY = 'unit-connected-ingest-key';
fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), policyPath);
fs.writeFileSync(process.env.REDACTWALL_LICENSE_PATH, 'vendor-provisioned-fallback-bytes', 'utf8');

let egressAllowed = true;
let readinessOverride = null;
let dispositionOverride = null;
let seatAuthorityOverride = {
  configured: true, seatLimit: 10, source: 'connected_entitlement',
};
function disposition() {
  if (dispositionOverride) return dispositionOverride;
  return egressAllowed
    ? {
      protectedEgress: 'allow', mode: 'connected', reason: null,
      fallbackDeadline: '2026-07-16T15:00:00.000Z',
      authority: { plan: 'enterprise', seats: 10, features: ['ncua_readiness'] },
    }
    : {
      protectedEgress: 'block', mode: 'revoked', reason: 'vendor_revoked',
      fallbackDeadline: '2026-07-16T15:00:00.000Z',
      authority: { plan: 'enterprise', seats: 10, features: ['ncua_readiness'] },
    };
}

const fakeRuntime = {
  configurationHealth: () => ({ ok: true, connected: true }),
  disposition,
  protectedEgressAllowed: () => disposition().protectedEgress === 'allow',
  ordinaryLicensedActionAllowed: () => disposition().protectedEgress === 'allow',
  publicStatus: () => ({
    state: disposition().protectedEgress === 'allow' ? 'active' : disposition().mode,
    connected: true, managedExternally: true,
    plan: 'enterprise', seats: 10, features: ['ncua_readiness'], reason: disposition().reason,
  }),
  featureEnabled: (feature) => feature === 'ncua_readiness',
  seatAuthority: () => {
    if (seatAuthorityOverride === 'throw') throw new Error('synthetic seat authority failure');
    return seatAuthorityOverride;
  },
  safeHeartbeatSnapshot: () => ({
    plan: 'enterprise', seatsUsed: 0, seatLimit: 10, version: '1.0.0',
    lastAppliedPolicyVersion: 0, lastAppliedCatalogVersion: 0,
  }),
  readiness: () => {
    const current = disposition();
    return {
      ok: current.protectedEgress === 'allow', connected: true,
      mode: current.mode, reason: current.reason,
    };
  },
  serviceReadiness: () => {
    if (readinessOverride === 'throw') throw new Error('synthetic runtime failure');
    const current = disposition();
    return readinessOverride || {
      ok: current.protectedEgress === 'allow',
      serviceReady: current.protectedEgress === 'allow'
        || current.reason !== 'connected_initial_acknowledgement_pending',
      connected: true, mode: current.mode, reason: current.reason,
    };
  },
  start: () => ({ ok: true }),
  stop: async () => ({ ok: true }),
  synchronize: async () => ({ ok: true }),
  sendDiagnostic: async () => ({ ok: true }),
  sendShadowCandidate: async () => ({ ok: true }),
};
fakeRuntime.requireWritable = (_req, res, next) => {
  const current = disposition();
  return current.protectedEgress === 'allow'
    ? next()
    : res.status(403).json({ error: 'license_restricted', reason: current.reason });
};
fakeRuntime.requireProtectedEgress = fakeRuntime.requireWritable;

const runtimePath = require.resolve('../server/connected-license-runtime');
const actualRuntimeModule = require(runtimePath);
require.cache[runtimePath].exports = {
  ...actualRuntimeModule,
  connectedLicenseMode: () => true,
  createConnectedLicenseRuntimeFromEnvironment: () => fakeRuntime,
};

const app = require('../server/app');
const db = require('../server/db');
const dataCrypto = require('../server/crypto');
const releaseTokens = require('../server/release-token');
const { listen, loopbackHttpFetch } = require('./support/listen');

async function post(base, apiPath, body, headers = {}) {
  const response = await loopbackHttpFetch(`${base}${apiPath}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json', 'x-api-key': process.env.INGEST_API_KEY, ...headers,
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function get(base, apiPath, headers = {}) {
  const response = await loopbackHttpFetch(`${base}${apiPath}`, {
    headers: { 'x-api-key': process.env.INGEST_API_KEY, ...headers },
  });
  return { status: response.status, body: await response.json() };
}

async function login(base) {
  const raw = await loopbackHttpFetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user: 'admin', password: process.env.ADMIN_PASSWORD }),
  });
  assert.equal(raw.status, 200);
  const cookie = (raw.headers.get('set-cookie') || '').split(';')[0];
  const csrfResponse = await loopbackHttpFetch(`${base}/api/csrf`, { headers: { cookie } });
  assert.equal(csrfResponse.status, 200);
  const { csrfToken } = await csrfResponse.json();
  return { cookie, csrfToken };
}

function seededReleaseQuery(status, mode, extra = {}) {
  const release = releaseTokens.issueReleaseToken();
  const write = db.createQueryWithAudit({
    status,
    mode,
    user: 'operator@example.test',
    orgId: process.env.REDACTWALL_TENANT_ID,
    destination: 'chatgpt.com',
    source: 'endpoint_agent',
    channel: 'submit',
    redactedPrompt: '[seeded connected release test]',
    findings: [],
    categories: [],
    entityCounts: {},
    riskScore: 0,
    maxSeverity: 0,
    maxSeverityLabel: 'none',
    reasons: ['synthetic connected release test'],
    _releaseTokenHash: release.hash,
    ...extra,
  }, { action: 'TEST_CONNECTED_RELEASE_SEEDED', actor: 'test', detail: 'synthetic' });
  return { row: write.row, token: release.token };
}

test('connected restriction overlays cached and newly inspected gate authorizations', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const firstBody = {
    prompt: 'Draft a public lobby update.',
    user: 'operator@example.test',
    orgId: process.env.REDACTWALL_TENANT_ID,
    destination: 'chatgpt.com',
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: { name: 'endpoint_agent', version: '1.0.0', platform: 'test' },
    idempotency: { scope: 'native_handoff_v1', key: 'a'.repeat(64) },
  };

  egressAllowed = true;
  const first = await post(base, '/api/v1/gate', firstBody);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.body.decision, 'allow');
  assert.ok(first.body.receipt);
  const auditCount = db.listAudit(1000).length;

  egressAllowed = false;
  const replay = await post(base, '/api/v1/gate', firstBody);
  assert.equal(replay.status, 403);
  assert.equal(replay.body.id, first.body.id);
  assert.equal(replay.body.decision, 'block');
  assert.equal(replay.body.status, 'license_restricted');
  assert.equal(replay.body.reason, 'vendor_revoked');
  assert.equal(replay.body.idempotentReplay, true);
  assert.equal(Object.hasOwn(replay.body, 'receipt'), false);
  assert.equal(db.listAudit(1000).length, auditCount, 'dynamic replay overlay adds no duplicate evidence');

  const newlyRestricted = await post(base, '/api/v1/gate', {
    ...firstBody,
    idempotency: { scope: 'native_handoff_v1', key: 'b'.repeat(64) },
  });
  assert.equal(newlyRestricted.status, 403);
  assert.equal(newlyRestricted.body.status, 'license_restricted');
  const stored = db.getQuery(newlyRestricted.body.id);
  assert.equal(stored.status, 'license_restricted');
  assert.equal(db.listAudit(1000).filter((entry) => (
    entry.queryId === stored.id && entry.action === 'LICENSE_EGRESS_RESTRICTED'
  )).length, 1);
});

test('historical vendor-license rows cannot authorize or revoke connected decisions', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const customerId = 'customer_historical_vendor_row';
  const row = db._db.prepare(`
    INSERT INTO vendor_license_state ("customerId", "issuedAt", "contactAt", status)
    VALUES (?, ?, ?, ?)
    ON CONFLICT("customerId") DO UPDATE SET
      "issuedAt" = excluded."issuedAt", "contactAt" = excluded."contactAt", status = excluded.status
  `);
  t.after(() => db._db.prepare(
    'DELETE FROM vendor_license_state WHERE "customerId" = ?',
  ).run(customerId));

  row.run(customerId, 1, 1, 'active');
  egressAllowed = false;
  const blocked = await post(base, '/api/v1/gate', {
    prompt: 'Public information only.',
    user: 'operator@example.test',
    orgId: process.env.REDACTWALL_TENANT_ID,
    destination: 'chatgpt.com',
  });
  assert.equal(blocked.status, 403);
  assert.equal(blocked.body.status, 'license_restricted', 'an old active row grants nothing');

  row.run(customerId, 2, 2, 'revoked');
  egressAllowed = true;
  const allowed = await post(base, '/api/v1/gate', {
    prompt: 'Public information only.',
    user: 'operator@example.test',
    orgId: process.env.REDACTWALL_TENANT_ID,
    destination: 'chatgpt.com',
  });
  assert.equal(allowed.status, 200, JSON.stringify(allowed.body));
  assert.equal(allowed.body.decision, 'allow', 'an old revoked row cannot override connected authority');
});

test('file and response inspection complete but cannot authorize egress while restricted', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  egressAllowed = false;

  const file = await post(base, '/api/v1/scan-file', {
    filename: 'public-note.txt',
    contentBase64: Buffer.from('Public meeting notes only.', 'utf8').toString('base64'),
    user: 'operator@example.test',
    orgId: process.env.REDACTWALL_TENANT_ID,
    destination: 'chatgpt.com',
  });
  assert.equal(file.status, 403, JSON.stringify(file.body));
  assert.equal(file.body.decision, 'block');
  assert.equal(file.body.status, 'license_restricted');
  assert.equal(Object.hasOwn(file.body, 'tokenizedPrompt'), false);
  assert.equal(Object.hasOwn(file.body, 'releaseToken'), false);

  const response = await post(base, '/api/v1/scan-response', {
    text: 'Public response text only.',
    user: 'operator@example.test',
    orgId: process.env.REDACTWALL_TENANT_ID,
    destination: 'chatgpt.com',
  });
  assert.equal(response.status, 403);
  assert.equal(response.body.decision, 'block');
  assert.equal(response.body.status, 'license_restricted');
});

test('connected release checks preserve token ordering and allow non-egress cancellation', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  egressAllowed = false;

  const rehydrate = seededReleaseQuery('redacted', 'redact', {
    _tokenVault: dataCrypto.seal('{}'),
  });
  const badRehydrate = await post(base, '/api/v1/rehydrate', {
    id: rehydrate.row.id, text: '[REDACTWALL_TOKEN]',
  }, { 'x-release-token': 'wrong-token' });
  assert.equal(badRehydrate.status, 401);
  const rehydrateAuditBefore = db.listAudit(1000).filter((entry) => (
    entry.queryId === rehydrate.row.id && entry.action === 'REHYDRATE'
  )).length;
  const blockedRehydrate = await post(base, '/api/v1/rehydrate', {
    id: rehydrate.row.id, text: '[REDACTWALL_TOKEN]',
  }, { 'x-release-token': rehydrate.token });
  assert.equal(blockedRehydrate.status, 403);
  assert.equal(blockedRehydrate.body.status, 'license_restricted');
  assert.equal(Object.hasOwn(blockedRehydrate.body, 'text'), false);
  assert.equal(db.listAudit(1000).filter((entry) => (
    entry.queryId === rehydrate.row.id && entry.action === 'REHYDRATE'
  )).length, rehydrateAuditBefore);

  const approved = seededReleaseQuery('approved', 'block');
  const badStatus = await get(base, `/api/v1/status/${approved.row.id}`, {
    'x-release-token': 'wrong-token',
  });
  assert.equal(badStatus.status, 401);
  const blockedStatus = await get(base, `/api/v1/status/${approved.row.id}`, {
    'x-release-token': approved.token,
  });
  assert.equal(blockedStatus.status, 403);
  assert.equal(blockedStatus.body.released, false);
  assert.equal(blockedStatus.body.status, 'license_restricted');

  const cancelled = seededReleaseQuery('pending_justification', 'justify');
  const cancellation = await post(base, `/api/v1/justify/${cancelled.row.id}`, {
    outcome: 'blocked_by_user', note: '',
  }, { 'x-release-token': cancelled.token });
  assert.equal(cancellation.status, 200);
  assert.equal(cancellation.body.status, 'blocked_by_user');
  assert.equal(db.getQuery(cancelled.row.id).status, 'blocked_by_user');

  const justified = seededReleaseQuery('pending_justification', 'justify');
  const blockedJustification = await post(base, `/api/v1/justify/${justified.row.id}`, {
    outcome: 'justified', note: 'approved business use',
  }, { 'x-release-token': justified.token });
  assert.equal(blockedJustification.status, 403);
  assert.equal(blockedJustification.body.released, false);
  assert.equal(db.getQuery(justified.row.id).status, 'pending_justification');
});

test('initial connected ACK pending keeps readyz, gate, rehydrate, and release status closed', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  t.after(() => {
    dispositionOverride = null;
    egressAllowed = true;
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  egressAllowed = true;
  dispositionOverride = {
    protectedEgress: 'block',
    mode: 'blocked',
    reason: 'connected_initial_acknowledgement_pending',
    authority: null,
  };

  let raw = await loopbackHttpFetch(`${base}/readyz`);
  let body = await raw.json();
  assert.equal(raw.status, 503, JSON.stringify(body));
  assert.equal(body.ready, false);
  assert.equal(body.licensingReason, 'connected_initial_acknowledgement_pending');

  const gate = await post(base, '/api/v1/gate', {
    prompt: 'Public information only.',
    user: 'initial-ack@example.test',
    orgId: process.env.REDACTWALL_TENANT_ID,
    destination: 'chatgpt.com',
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: { name: 'endpoint_agent', version: '1.0.0', platform: 'test' },
    idempotency: { scope: 'native_handoff_v1', key: 'e'.repeat(64) },
  });
  assert.equal(gate.status, 403, JSON.stringify(gate.body));
  assert.equal(gate.body.reason, 'connected_initial_acknowledgement_pending');

  const rehydrate = seededReleaseQuery('redacted', 'redact', {
    _tokenVault: dataCrypto.seal('{}'),
  });
  const blockedRehydrate = await post(base, '/api/v1/rehydrate', {
    id: rehydrate.row.id, text: '[REDACTWALL_TOKEN]',
  }, { 'x-release-token': rehydrate.token });
  assert.equal(blockedRehydrate.status, 403);
  assert.equal(blockedRehydrate.body.reason, 'connected_initial_acknowledgement_pending');

  const approved = seededReleaseQuery('approved', 'block');
  const blockedStatus = await get(base, `/api/v1/status/${approved.row.id}`, {
    'x-release-token': approved.token,
  });
  assert.equal(blockedStatus.status, 403);
  assert.equal(blockedStatus.body.released, false);
  assert.equal(blockedStatus.body.reason, 'connected_initial_acknowledgement_pending');

  dispositionOverride = null;
  raw = await loopbackHttpFetch(`${base}/readyz`);
  body = await raw.json();
  assert.equal(raw.status, 200, JSON.stringify(body));
  assert.equal(body.ready, true);
  const allowedGate = await post(base, '/api/v1/gate', {
    prompt: 'Public information only.',
    user: 'acknowledged@example.test',
    orgId: process.env.REDACTWALL_TENANT_ID,
    destination: 'chatgpt.com',
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: { name: 'endpoint_agent', version: '1.0.0', platform: 'test' },
    idempotency: { scope: 'native_handoff_v1', key: 'f'.repeat(64) },
  });
  assert.equal(allowedGate.status, 200, JSON.stringify(allowedGate.body));
  assert.equal(allowedGate.body.decision, 'allow');
});

test('initial restrictive pairs keep readyz closed while preserving their enforcement reason', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  t.after(() => {
    dispositionOverride = null;
    readinessOverride = null;
    egressAllowed = true;
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const cases = [
    ['paused', 'vendor_paused'],
    ['revoked', 'vendor_revoked'],
    ['revoked', 'vendor_registry_revoked'],
  ];
  for (const [mode, enforcementReason] of cases) {
    dispositionOverride = {
      protectedEgress: 'block',
      mode,
      reason: enforcementReason,
      authority: null,
      initialAcknowledgementRequired: true,
    };
    readinessOverride = {
      ok: false,
      serviceReady: false,
      connected: true,
      mode,
      reason: 'connected_initial_acknowledgement_pending',
      enforcementReason,
    };
    const response = await loopbackHttpFetch(`${base}/readyz`);
    const body = await response.json();
    assert.equal(response.status, 503, `${enforcementReason}: ${JSON.stringify(body)}`);
    assert.equal(body.ready, false);
    assert.equal(body.licensingReason, 'connected_initial_acknowledgement_pending');

    const gate = await post(base, '/api/v1/gate', {
      prompt: 'Public information only.',
      user: `${enforcementReason}@example.test`,
      orgId: process.env.REDACTWALL_TENANT_ID,
      destination: 'chatgpt.com',
      source: 'endpoint_agent',
      channel: 'file_upload',
      sensor: { name: 'endpoint_agent', version: '1.0.0', platform: 'test' },
      idempotency: {
        scope: 'native_handoff_v1',
        key: crypto.createHash('sha256').update(enforcementReason).digest('hex'),
      },
    });
    assert.equal(gate.status, 403, enforcementReason);
    assert.equal(gate.body.reason, enforcementReason);
  }
});

test('service readiness stays online for business restrictions without hiding integrity failures', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;

  readinessOverride = null;
  egressAllowed = false;
  let response = await loopbackHttpFetch(`${base}/readyz`);
  let body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(body.ready, true);
  assert.equal(body.database, true);
  assert.equal(body.licensing, 'restricted');
  assert.equal(body.licensingReason, 'vendor_revoked');

  readinessOverride = {
    ok: false, serviceReady: false, connected: false, reason: 'connected_state_invalid',
  };
  response = await loopbackHttpFetch(`${base}/readyz`);
  body = await response.json();
  assert.equal(response.status, 503);
  assert.equal(body.database, true);
  assert.equal(body.licensing, 'restricted');
  assert.equal(body.licensingReason, 'connected_state_invalid');

  readinessOverride = 'throw';
  response = await loopbackHttpFetch(`${base}/readyz`);
  body = await response.json();
  assert.equal(response.status, 503);
  assert.equal(body.database, true);
  assert.equal(body.licensing, 'unavailable');
  assert.equal(body.error, 'connected_licensing_unavailable');

  readinessOverride = null;
  egressAllowed = true;
});

test('connected mode rejects both customer-side fallback license installers without mutation', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const auth = await login(base);
  const beforeBytes = fs.readFileSync(process.env.REDACTWALL_LICENSE_PATH);
  const beforeAudit = db.listAudit(1000).length;

  for (const [route, body] of [
    ['/api/admin/license/install', { license: 'invalid.local.replacement', reason: 'replace fallback' }],
    ['/api/billing/license', { license: 'invalid.local.replacement' }],
  ]) {
    const response = await loopbackHttpFetch(`${base}${route}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json', cookie: auth.cookie,
        'x-csrf-token': auth.csrfToken,
      },
      body: JSON.stringify(body),
    });
    assert.equal(response.status, 409, route);
    assert.deepStrictEqual(await response.json(), { error: 'license_managed_externally' });
    assert.deepStrictEqual(fs.readFileSync(process.env.REDACTWALL_LICENSE_PATH), beforeBytes);
    assert.equal(db.listAudit(1000).length, beforeAudit, `${route} must add no install audit`);
  }
});

test('malformed connected seat authority fails closed instead of restoring the static limit', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const auth = await login(base);
  egressAllowed = true;

  const malformedAuthorities = [
    'throw', { configured: false }, { configured: true, seatLimit: '100' },
  ];
  for (const [index, malformed] of malformedAuthorities.entries()) {
    seatAuthorityOverride = malformed;
    const gate = await post(base, '/api/v1/gate', {
      prompt: 'Public information only.',
      user: `malformed-seat-${index}@example.test`,
      orgId: process.env.REDACTWALL_TENANT_ID,
      destination: 'chatgpt.com',
      source: 'endpoint_agent',
      channel: 'submit',
    });
    assert.equal(gate.status, 503, JSON.stringify(gate.body));
    assert.equal(gate.body.status, 'seat_limit_not_configured');

    const billingResponse = await loopbackHttpFetch(`${base}/api/billing/seats`, {
      headers: { cookie: auth.cookie },
    });
    assert.equal(billingResponse.status, 200);
    const billing = await billingResponse.json();
    assert.equal(billing.seatLimit, 0);
    assert.equal(billing.seatLimitConfigured, true);
    assert.equal(billing.seatLimitValid, false);
  }

  seatAuthorityOverride = { configured: true, seatLimit: 10, source: 'connected_entitlement' };
});

test('a signed zero-seat authority is preserved in enforcement evidence and response', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  seatAuthorityOverride = { configured: true, seatLimit: 0, source: 'connected_entitlement' };
  egressAllowed = true;

  const request = {
    prompt: 'Public information only.',
    user: 'zero-seat@example.test',
    orgId: process.env.REDACTWALL_TENANT_ID,
    destination: 'chatgpt.com',
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: { name: 'endpoint_agent', version: '1.0.0', platform: 'test' },
    idempotency: { scope: 'native_handoff_v1', key: 'c'.repeat(64) },
  };
  const gate = await post(base, '/api/v1/gate', request);
  assert.equal(gate.status, 402, JSON.stringify(gate.body));
  assert.equal(gate.body.status, 'seat_limit_blocked');
  assert.equal(gate.body.seatLimit, 0);
  assert.equal(typeof gate.body.seatsUsed, 'number');
  const stored = db.getQuery(gate.body.id);
  assert.equal(stored.seatLimit, 0);
  assert.equal(typeof stored.seatsUsed, 'number');

  const replay = await post(base, '/api/v1/gate', request);
  assert.equal(replay.status, 200, JSON.stringify(replay.body));
  assert.equal(replay.body.id, gate.body.id);
  assert.equal(replay.body.status, 'seat_limit_blocked');
  assert.equal(replay.body.decision, 'block');
  assert.equal(replay.body.seatLimit, 0);
  assert.equal(typeof replay.body.seatsUsed, 'number');
  assert.equal(replay.body.idempotentReplay, true);

  const mapping = db._db.prepare(
    'SELECT replaySnapshot FROM ingest_idempotency WHERE queryId = ?',
  ).get(gate.body.id);
  const snapshot = JSON.parse(mapping.replaySnapshot);
  db._db.prepare('UPDATE ingest_idempotency SET replaySnapshot = ? WHERE queryId = ?')
    .run(JSON.stringify({ ...snapshot, seatLimit: 1 }), gate.body.id);
  const tamperedReplay = await post(base, '/api/v1/gate', request);
  assert.equal(tamperedReplay.status, 500);
  assert.deepStrictEqual(tamperedReplay.body, { error: 'internal_error' });
  db._db.prepare('UPDATE ingest_idempotency SET replaySnapshot = ? WHERE queryId = ?')
    .run(mapping.replaySnapshot, gate.body.id);

  seatAuthorityOverride = { configured: true, seatLimit: 10, source: 'connected_entitlement' };
});

test.after(() => {
  try { db._db.close(); } catch {}
  try { fs.rmSync(tempRoot, { recursive: true, force: true }); } catch {}
});
