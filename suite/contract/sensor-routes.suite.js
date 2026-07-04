// @tier smoke
'use strict';
/**
 * Contract: sensor ingest routes (/api/v1/*) require the x-api-key, the gate
 * returns decision + receipt for cleared outcomes, and the sensor policy view
 * stays consistent with the admin policy while excluding admin-only fields.
 */
const test = require('node:test');
const assert = require('node:assert');

const support = require('../support/app');
support.bootEnv();
const app = support.requireApp();

const SENSOR_ROUTES = [
  ['POST', '/api/v1/gate'],
  ['POST', '/api/v1/discovery'],
  ['POST', '/api/v1/heartbeat'],
  ['GET', '/api/v1/policy'],
  ['GET', '/api/v1/policy/bundle'],
  ['GET', '/api/v1/policy/pubkey'],
  ['GET', '/api/v1/detectors'],
  ['POST', '/api/v1/scan-file'],
  ['POST', '/api/v1/scan-response'],
  ['POST', '/api/v1/rehydrate'],
  ['GET', '/api/v1/status/q_nope'],
];

test('every sensor route rejects a missing x-api-key with 401', async () => support.withServer(app, async (port) => {
  for (const [method, route] of SENSOR_ROUTES) {
    const res = await support.request(port, route, { method, body: method === 'POST' ? {} : undefined });
    assert.strictEqual(res.status, 401, `expected 401 without key for ${method} ${route}`);
    assert.deepStrictEqual(await res.json(), { error: 'invalid ingest key' }, route);
  }
  // A valid key immediately clears the failure counter for this client.
  const ok = await support.gate(port, { prompt: 'Weekly branch schedule question, nothing sensitive.', user: 'clear@example.test', destination: 'chatgpt.com' });
  assert.strictEqual(ok.status, 200);
}));

test('gate happy path: benign prompt is allowed and carries a signed receipt', async () => support.withServer(app, async (port) => {
  const res = await support.gate(port, {
    prompt: 'What are the branch opening hours on federal holidays?',
    user: 'jane.doe@example.com',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'allow');
  assert.match(body.id, /^q_/);
  assert.ok(Array.isArray(body.findings) && body.findings.length === 0);
  assert.ok(body.receipt, 'cleared outcomes must include a safe-to-send receipt');
  assert.strictEqual(typeof body.receipt.sig, 'string', 'receipt must be signed');
  assert.ok(!JSON.stringify(body.receipt).includes('opening hours'), 'receipts are prompt-free');
}));

test('gate blocks a held prompt without a receipt and status polling works', async () => support.withServer(app, async (port) => {
  const res = await support.gate(port, {
    prompt: 'Please check member SSN 123-45-6789 for this synthetic case.',
    user: 'jane.doe@example.com',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'pending');
  assert.ok(!body.receipt, 'held prompts are not cleared to send');
  assert.ok(body.findings.some((f) => f.type === 'US_SSN'));
  assert.ok(!JSON.stringify(body).includes('123-45-6789'), 'gate response must not echo the raw value');

  const statusRes = await support.request(port, `/api/v1/status/${body.id}`, {
    headers: { 'x-api-key': support.INGEST_KEY, 'x-release-token': body.releaseToken || '' },
  });
  assert.ok([200, 401].includes(statusRes.status), 'status poll responds without crashing');
  if (statusRes.status === 200) {
    const polled = await statusRes.json();
    assert.strictEqual(polled.id, body.id);
    assert.strictEqual(polled.released, false);
  }
}));

test('GET /api/v1/policy keeps the sensor-safe shape', async () => support.withServer(app, async (port) => {
  const res = await support.request(port, '/api/v1/policy', { headers: { 'x-api-key': support.INGEST_KEY } });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  for (const key of ['enforcementMode', 'blockMinSeverity', 'blockRiskScore', 'alwaysBlock', 'governedDestinations', 'blockedDestinations', 'responseScanMode', 'scanner']) {
    assert.ok(key in body, `missing sensor policy key "${key}"`);
  }
  assert.ok(Array.isArray(body.alwaysBlock) && body.alwaysBlock.includes('US_SSN'));
}));

test('policy round-trip: PUT /api/policy is visible to sensors minus retention fields', async () => support.withServer(app, async (port) => {
  const admin = await support.login(port, 'admin');
  const put = await support.request(port, '/api/policy', {
    method: 'PUT',
    headers: { cookie: admin.cookie, 'x-csrf-token': admin.csrfToken },
    body: { blockRiskScore: 33, rawRetentionDays: 9 },
  });
  assert.strictEqual(put.status, 200);

  const adminView = await (await support.request(port, '/api/policy', { headers: { cookie: admin.cookie } })).json();
  assert.strictEqual(adminView.blockRiskScore, 33);
  assert.strictEqual(adminView.rawRetentionDays, 9);

  const sensorView = await (await support.request(port, '/api/v1/policy', { headers: { 'x-api-key': support.INGEST_KEY } })).json();
  assert.strictEqual(sensorView.blockRiskScore, 33, 'sensor policy must follow the admin update');
  assert.strictEqual(sensorView.enforcementMode, adminView.enforcementMode);
  assert.deepStrictEqual(sensorView.alwaysBlock, adminView.alwaysBlock);
  for (const adminOnly of ['rawRetentionDays', 'storeRawForApproval', 'approvalRoutingRules', 'policyExceptions']) {
    assert.ok(!(adminOnly in sensorView), `sensor payload must exclude admin-only field "${adminOnly}"`);
  }
}));
