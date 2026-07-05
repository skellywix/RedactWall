'use strict';
/** Security Admin login can require TOTP MFA without blocking auditor review. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const totpSecret = 'JBSWY3DPEHPK3PXP';

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.ADMIN_TOTP_SECRET = totpSecret;
process.env.AUDITOR_USER = 'auditor';
process.env.AUDITOR_PASSWORD = 'auditor-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-admin-mfa-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-admin-mfa-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
  rawRetentionDays: 30,
}, null, 2));

const app = require('../server/app');
const { listen } = require('./support/listen');
const auth = require('../server/auth');


function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await close(server);
  }
}

async function login(port, body) {
  return fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function setCookieHeader(response) {
  return response.headers.get('set-cookie') || '';
}

test('security admin login requires totp while auditor login remains password-only', async () => withServer(async (port) => {
  const badPassword = await login(port, { user: 'admin', password: 'wrong-pass' });
  assert.strictEqual(badPassword.status, 401);
  assert.strictEqual((await badPassword.json()).error, 'invalid credentials');
  assert.doesNotMatch(setCookieHeader(badPassword), /redactwall_session=/);

  const missing = await login(port, { user: 'admin', password: 'unit-pass' });
  assert.strictEqual(missing.status, 401);
  assert.strictEqual((await missing.json()).mfaRequired, true);
  assert.doesNotMatch(setCookieHeader(missing), /redactwall_session=/);

  const wrongCode = auth.totpCode(totpSecret) === '000000' ? '000001' : '000000';
  const wrong = await login(port, { user: 'admin', password: 'unit-pass', otp: wrongCode });
  assert.strictEqual(wrong.status, 401);
  assert.strictEqual((await wrong.json()).mfaRequired, true);
  assert.doesNotMatch(setCookieHeader(wrong), /redactwall_session=/);

  const ok = await login(port, { user: 'admin', password: 'unit-pass', otp: auth.totpCode(totpSecret) });
  assert.strictEqual(ok.status, 200);
  assert.strictEqual((await ok.json()).role, 'security_admin');
  assert.match(setCookieHeader(ok), /redactwall_session=/);

  const auditor = await login(port, { user: 'auditor', password: 'auditor-pass' });
  assert.strictEqual(auditor.status, 200);
  assert.strictEqual((await auditor.json()).role, 'auditor');
  assert.match(setCookieHeader(auditor), /redactwall_session=/);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.REDACTWALL_POLICY_PATH); } catch {}
});
