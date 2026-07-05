'use strict';
/** SCIM deactivation must revoke live sessions, seats, and sensor ingest. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.ADMIN_TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DP';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-identity-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const db = require('../server/db');
const auth = require('../server/auth');
const tenant = require('../server/tenant');

test('scim deactivation revokes already-issued sessions', async () => {
  auth.setSessionRevokedCheck((session) => db.identityRevokedSince(session.user, session.iat));
  const saved = db.saveScimUser({
    userName: 'analyst@example.test',
    emails: [{ value: 'Analyst.Alias@Example.Test', primary: true }],
    active: true,
  });
  const byUserName = auth.createSession('analyst@example.test', 'security_admin');
  const byEmail = auth.createSession('analyst.alias@example.test', 'security_admin');
  const bystander = auth.createSession('other@example.test', 'security_admin');
  assert.ok(auth.verify(byUserName), 'session valid while active');

  db.deactivateScimUser(saved.id);
  assert.strictEqual(auth.verify(byUserName), null, 'userName session revoked');
  assert.strictEqual(auth.verify(byEmail), null, 'email alias session revoked');
  assert.ok(auth.verify(bystander), 'unrelated sessions stay valid');

  await new Promise((resolve) => setTimeout(resolve, 5)); // revocation is same-ms fail-closed
  const relogin = auth.createSession('analyst@example.test', 'security_admin');
  assert.ok(auth.verify(relogin), 'sessions issued after revocation are valid again');
  auth.setSessionRevokedCheck(null);
});

test('scim deactivation releases the seat and blocks sensor ingest', () => {
  const seatUser = 'seatholder@example.test';
  db.createQuery({ status: 'allowed', user: seatUser, destination: 'chatgpt.com', source: 'browser_extension' });
  assert.ok(db.seatStats({}).users.some((item) => item.user === seatUser), 'active user occupies a seat');

  const saved = db.saveScimUser({ userName: seatUser, active: true });
  db.deactivateScimUser(saved.id);
  assert.ok(!db.seatStats({}).users.some((item) => item.user === seatUser), 'deactivation releases the seat');

  const denied = tenant.validateSensorAccess({ body: { user: seatUser, destination: 'chatgpt.com' }, db, env: {} });
  assert.strictEqual(denied.ok, false);
  assert.strictEqual(denied.status, 'user_deactivated');
  assert.strictEqual(denied.statusCode, 403);
  assert.strictEqual(denied.audit, true);

  const allowed = tenant.validateSensorAccess({ body: { user: 'other@example.test' }, db, env: {} });
  assert.strictEqual(allowed.ok, true);
});

test('dedicated step-up elevation window is signed into the session', () => {
  const base = auth.verify(auth.createSession('admin', 'security_admin'));
  assert.strictEqual(auth.stepUpSatisfied(base), false, 'fresh local session is not elevated');

  const elevated = auth.verify(auth.elevateSession(base));
  assert.ok(elevated, 'elevated session verifies');
  assert.ok(auth.stepUpSatisfied(elevated), 'elevated session satisfies step-up');
  assert.strictEqual(elevated.exp, base.exp, 'elevation never extends the session lifetime');
  assert.ok(elevated.stepUpUntil <= Date.now() + auth.STEP_UP_TTL_MS, 'elevation is short-lived');
});

test('mfa recovery codes derive from the enrolled secret and are single-use', () => {
  const codes = auth.recoveryCodes();
  assert.strictEqual(codes.length, auth.MFA_RECOVERY_CODE_COUNT);
  assert.ok(codes.every((code) => /^[0-9A-F]{5}-[0-9A-F]{5}$/.test(code)));
  assert.strictEqual(new Set(codes).size, codes.length, 'codes are distinct');

  const index = auth.recoveryCodeIndex(codes[2]);
  assert.strictEqual(index, 2);
  assert.strictEqual(auth.recoveryCodeIndex('AAAAA-AAAAA'), -1);
  assert.strictEqual(auth.recoveryCodeIndex('123456'), -1, 'totp-shaped input never matches');

  assert.strictEqual(db.consumeMfaRecoveryCode(index), true, 'first use consumes the code');
  assert.strictEqual(db.consumeMfaRecoveryCode(index), false, 'second use is refused');
  assert.strictEqual(db.mfaRecoveryCodeUsed(index), true);
});
