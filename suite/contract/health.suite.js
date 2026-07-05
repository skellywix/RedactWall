// @tier smoke
'use strict';
/** Contract: public health endpoints keep their shape (no auth required). */
const test = require('node:test');
const assert = require('node:assert');

const support = require('../support/app');
support.bootEnv();
const app = support.requireApp();

test('GET /healthz returns status/service/version and needs no credentials', async () => support.withServer(app, async (port) => {
  const res = await support.request(port, '/healthz');
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'ok');
  assert.strictEqual(body.service, 'redactwall');
  assert.match(String(body.version), /^\d+\.\d+\.\d+/);
}));

test('GET /readyz reports readiness with database and configuration fields', async () => support.withServer(app, async (port) => {
  const res = await support.request(port, '/readyz');
  assert.ok([200, 503].includes(res.status), `unexpected status ${res.status}`);
  const body = await res.json();
  assert.strictEqual(typeof body.ready, 'boolean');
  assert.strictEqual(body.database, true);
  assert.strictEqual(typeof body.configuration, 'string');
}));

test('GET /api/login-options is public and never leaks credentials', async () => support.withServer(app, async (port) => {
  const res = await support.request(port, '/api/login-options');
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.ok('oidc' in body);
  assert.strictEqual(typeof body.defaultAdminCredential, 'boolean');
  assert.ok(!JSON.stringify(body).includes(support.CREDENTIALS.admin.password));
}));
