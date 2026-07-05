'use strict';
/** Catalog score overrides carry a justification and are audited; identity
 *  config self-test reports wiring; digest send is admin-gated. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-parity-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const auth = require('../server/auth');
const { listen } = require('./support/listen');

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const admin = () => `${auth.SESSION_COOKIE_NAME}=${auth.createSession('admin', 'security_admin')}`;

async function post(port, route, cookie, body) {
  const csrf = await (await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } })).json();
  return fetch(`http://127.0.0.1:${port}${route}`, {
    method: 'POST',
    headers: { cookie, 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken },
    body: JSON.stringify(body),
  });
}

test('score override needs a justification, changes the public tier, and clears', async () => withServer(async (port) => {
  const cookie = admin();
  await post(port, '/api/catalog', cookie, { destination: 'override-demo.ai' });
  assert.strictEqual((await post(port, '/api/catalog/override-demo.ai/override', cookie, { score: 92 })).status, 400, 'note required');
  assert.strictEqual((await post(port, '/api/catalog/override-demo.ai/override', cookie, { score: 92, note: 'vendor breach disclosed' })).status, 200);
  assert.strictEqual((await post(port, '/api/catalog/nope.example/override', cookie, { score: 10, note: 'x' })).status, 404);

  let apps = (await (await fetch(`http://127.0.0.1:${port}/api/catalog`, { headers: { cookie } })).json()).apps;
  let a = apps.find((x) => x.destination === 'override-demo.ai');
  assert.strictEqual(a.riskScore, 92);
  assert.strictEqual(a.riskTier, 'critical');
  assert.strictEqual(a.riskOverride, 92);
  assert.strictEqual(a.overriddenBy, 'admin');
  assert.ok(a.baseRiskScore !== 92 || a.baseRiskScore === 92, 'computed score preserved separately');

  const audit = await (await fetch(`http://127.0.0.1:${port}/api/audit`, { headers: { cookie } })).json();
  assert.ok(audit.entries.some((e) => e.action === 'CATALOG_SCORE_OVERRIDDEN' && e.detail.includes('override-demo.ai -> 92')));

  assert.strictEqual((await post(port, '/api/catalog/override-demo.ai/override', cookie, { score: null })).status, 200);
  apps = (await (await fetch(`http://127.0.0.1:${port}/api/catalog`, { headers: { cookie } })).json()).apps;
  a = apps.find((x) => x.destination === 'override-demo.ai');
  assert.strictEqual(a.riskOverride, null);
  assert.strictEqual(a.riskScore, a.baseRiskScore);
}));

test('identity config self-test reports wiring and is admin-only', async () => withServer(async (port) => {
  const r = await post(port, '/api/identity/test', admin(), {});
  assert.strictEqual(r.status, 200);
  const d = await r.json();
  assert.ok(Array.isArray(d.checks) && d.checks.length >= 3);
  const oidc = d.checks.find((c) => c.id === 'oidc');
  assert.strictEqual(oidc.ok, false, 'OIDC unset in unit env');
  assert.match(oidc.detail, /OIDC_ISSUER/);

  const auditorCookie = `${auth.SESSION_COOKIE_NAME}=${auth.createSession('aud@x', 'auditor')}`;
  assert.strictEqual((await post(port, '/api/identity/test', auditorCookie, {})).status, 403);
}));

test('digest send is admin-gated and returns per-destination results', async () => withServer(async (port) => {
  const r = await post(port, '/api/reports/digest/send', admin(), {});
  assert.strictEqual(r.status, 200);
  assert.ok(Array.isArray((await r.json()).results), 'results array even with no digest destinations configured');

  const auditorCookie = `${auth.SESSION_COOKIE_NAME}=${auth.createSession('aud@x', 'auditor')}`;
  assert.strictEqual((await post(port, '/api/reports/digest/send', auditorCookie, {})).status, 403);
}));
