'use strict';
/** AI app catalog HTTP routes: discovery via gate, GET, import, manual add,
 *  and review that writes BOTH policy and catalog status. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_USER = 'admin';
process.env.ADMIN_PASSWORD = 'unit-pass-catalog';
process.env.REDACTWALL_SECRET = 'unit-secret-stable-catalog';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable-catalog';
process.env.INGEST_API_KEY = 'unit-ingest-key-catalog';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-catalog-api-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-catalog-api-policy-' + crypto.randomBytes(6).toString('hex') + '.json');
delete process.env.ADMIN_TOTP_SECRET;

const app = require('../server/app');
const { listen } = require('./support/listen');
const policy = require('../server/policy');

test.after(() => {
  for (const p of [process.env.REDACTWALL_DB_PATH, process.env.REDACTWALL_POLICY_PATH]) { try { fs.rmSync(p, { force: true }); } catch (e) { /* ignore */ } }
});

async function withServer(fn) {
  const server = await listen(app);
  try { return await fn(server.address().port); } finally { await new Promise((r) => server.close(r)); }
}

async function adminSession(port) {
  const res = await fetch(`http://127.0.0.1:${port}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user: 'admin', password: 'unit-pass-catalog' }) });
  assert.strictEqual(res.status, 200, 'admin login succeeds');
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  const csrf = await (await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } })).json();
  return { cookie, csrf: csrf.csrfToken };
}

function ingest(port, body) {
  return fetch(`http://127.0.0.1:${port}/api/v1/gate`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'unit-ingest-key-catalog' }, body: JSON.stringify(body) });
}

test('gate visits populate the catalog and review writes policy + status', async () => {
  await withServer(async (port) => {
    // Discovery: a shadow-AI visit and a governed visit.
    await ingest(port, { prompt: 'x', user: 'eve@cu.org', destination: 'chat.deepseek.com', clientOutcome: 'shadow_ai' });
    await ingest(port, { prompt: 'hello', user: 'a@cu.org', destination: 'claude.ai' });
    const { cookie, csrf } = await adminSession(port);

    // Catalog reflects both, prompt-free, with transparent risk tiers.
    const cat = await (await fetch(`http://127.0.0.1:${port}/api/catalog`, { headers: { cookie } })).json();
    const deepseek = cat.apps.find((a) => a.destination === 'chat.deepseek.com');
    const claude = cat.apps.find((a) => a.destination === 'claude.ai');
    assert.ok(deepseek && claude, 'both apps discovered');
    assert.strictEqual(deepseek.riskTier, 'critical');
    assert.ok(deepseek.riskScore > claude.riskScore);
    assert.ok(!JSON.stringify(cat).match(/hello/), 'no prompt content in catalog');

    // CSV import.
    const imp = await (await fetch(`http://127.0.0.1:${port}/api/catalog/import`, { method: 'POST', headers: { cookie, 'content-type': 'application/json', 'x-csrf-token': csrf }, body: JSON.stringify({ csv: 'perplexity.ai\npoe.com,3\nnot a host!!!' }) })).json();
    assert.strictEqual(imp.imported, 2);
    assert.ok(imp.skipped >= 1);

    // Review deepseek -> block: policy now blocks it AND catalog status updates.
    const rev = await (await fetch(`http://127.0.0.1:${port}/api/catalog/chat.deepseek.com/review`, { method: 'POST', headers: { cookie, 'content-type': 'application/json', 'x-csrf-token': csrf }, body: JSON.stringify({ decision: 'block', reason: 'CN trains on data', owner: 'sec@cu.org' }) })).json();
    assert.strictEqual(rev.decision, 'block');
    assert.strictEqual(rev.app.sanctionedStatus, 'blocked');
    assert.strictEqual(rev.app.owner, 'sec@cu.org');
    assert.ok(policy.destinationBlocked('chat.deepseek.com', policy.loadPolicy()), 'policy now blocks the reviewed app');
  });
});

test('catalog routes require admin auth', async () => {
  await withServer(async (port) => {
    assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/catalog`)).status, 401);
  });
});
