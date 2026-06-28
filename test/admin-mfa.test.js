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
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-admin-mfa-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-admin-mfa-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
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

test('security admin login requires totp while auditor login remains password-only', async () => withServer(async (port) => {
  const missing = await login(port, { user: 'admin', password: 'unit-pass' });
  assert.strictEqual(missing.status, 401);
  assert.strictEqual((await missing.json()).mfaRequired, true);

  const wrongCode = auth.totpCode(totpSecret) === '000000' ? '000001' : '000000';
  const wrong = await login(port, { user: 'admin', password: 'unit-pass', otp: wrongCode });
  assert.strictEqual(wrong.status, 401);
  assert.strictEqual((await wrong.json()).mfaRequired, true);

  const ok = await login(port, { user: 'admin', password: 'unit-pass', otp: auth.totpCode(totpSecret) });
  assert.strictEqual(ok.status, 200);
  assert.strictEqual((await ok.json()).role, 'security_admin');

  const auditor = await login(port, { user: 'auditor', password: 'auditor-pass' });
  assert.strictEqual(auditor.status, 200);
  assert.strictEqual((await auditor.json()).role, 'auditor');
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
