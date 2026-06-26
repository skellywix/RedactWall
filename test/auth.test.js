'use strict';
/** Admin auth: password check, brute-force lockout, session signing. node --test */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.AUDITOR_USER = 'auditor';
process.env.AUDITOR_PASSWORD = 'auditor-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.LOGIN_MAX_ATTEMPTS = '3';
process.env.LOGIN_WINDOW_MS = '100000';
const auth = require('../src/auth');

function signedSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', process.env.SENTINEL_SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}

test('verifyPassword accepts only the right user+password', () => {
  assert.ok(auth.verifyPassword('admin', 'unit-pass'));
  assert.ok(auth.verifyPassword('auditor', 'auditor-pass'));
  assert.ok(!auth.verifyPassword('admin', 'wrong'));
  assert.ok(!auth.verifyPassword('auditor', 'unit-pass'));
  assert.ok(!auth.verifyPassword('mallory', 'unit-pass'));
});

test('authenticate returns the account role without leaking hashes', () => {
  assert.deepStrictEqual(auth.authenticate('admin', 'unit-pass'), {
    user: 'admin',
    role: 'security_admin',
  });
  assert.deepStrictEqual(auth.authenticate('auditor', 'auditor-pass'), {
    user: 'auditor',
    role: 'auditor',
  });
  assert.strictEqual(auth.authenticate('auditor', 'wrong'), null);
  assert.strictEqual(auth.AUDITOR_ENABLED, true);
});

test('locks out after the configured number of failures, resets on success', () => {
  const k = 'admin|10.0.0.5';
  assert.strictEqual(auth.loginStatus(k).locked, false);
  auth.registerFail(k); auth.registerFail(k);
  assert.strictEqual(auth.loginStatus(k).locked, false, 'not locked before threshold');
  const r = auth.registerFail(k); // 3rd
  assert.ok(r.locked && auth.loginStatus(k).locked, 'locked at threshold');
  assert.ok(auth.loginStatus(k).retryMs > 0);
  auth.registerSuccess(k);
  assert.strictEqual(auth.loginStatus(k).locked, false, 'success clears the lock');
});

test('session token signs and verifies; tampered/none rejected', () => {
  const t = auth.createSession('admin');
  assert.strictEqual(auth.verify(t).user, 'admin');
  assert.strictEqual(auth.verify(t).role, 'security_admin');
  const auditor = auth.createSession('auditor', 'auditor');
  assert.strictEqual(auth.verify(auditor).user, 'auditor');
  assert.strictEqual(auth.verify(auditor).role, 'auditor');
  assert.strictEqual(auth.verify('bad.token'), null);
  assert.strictEqual(auth.verify(null), null);
});

test('session verification preserves legacy admin cookies and rejects unknown roles', () => {
  const legacy = signedSession({ user: 'admin', iat: Date.now(), exp: Date.now() + 60000 });
  const verifiedLegacy = auth.verify(legacy);
  assert.deepStrictEqual(verifiedLegacy, {
    user: 'admin',
    role: 'security_admin',
    iat: verifiedLegacy.iat,
    exp: verifiedLegacy.exp,
  });

  const unknownRole = signedSession({ user: 'admin', role: 'owner', iat: Date.now(), exp: Date.now() + 60000 });
  assert.strictEqual(auth.verify(unknownRole), null);
  const missingUser = signedSession({ role: 'security_admin', iat: Date.now(), exp: Date.now() + 60000 });
  assert.strictEqual(auth.verify(missingUser), null);
});

test('duplicate auditor username is not enabled at runtime', () => {
  const script = [
    "const auth = require('./src/auth');",
    "console.log(JSON.stringify({ enabled: auth.AUDITOR_ENABLED, admin: auth.authenticate('admin', 'unit-pass'), duplicate: auth.authenticate('admin', 'auditor-pass') }));",
  ].join('');
  const output = execFileSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      ADMIN_USER: 'admin',
      ADMIN_PASSWORD: 'unit-pass',
      AUDITOR_USER: ' admin ',
      AUDITOR_PASSWORD: 'auditor-pass',
      SENTINEL_SECRET: 'unit-secret-stable',
    },
    encoding: 'utf8',
  });
  const result = JSON.parse(output);
  assert.strictEqual(result.enabled, false);
  assert.deepStrictEqual(result.admin, { user: 'admin', role: 'security_admin' });
  assert.strictEqual(result.duplicate, null);
});

test('csrf token is bound to the signed session token', () => {
  const t = auth.createSession('admin');
  const csrf = auth.createCsrfToken(t);
  assert.ok(csrf);
  assert.strictEqual(auth.verifyCsrfToken(t, csrf), true);
  assert.strictEqual(auth.verifyCsrfToken(t, csrf + 'x'), false);
  assert.strictEqual(auth.verifyCsrfToken(auth.createSession('other-admin'), csrf), false);
});

test('secret from env is reported stable (survives restarts / multi-instance)', () => {
  assert.strictEqual(auth.SECRET_IS_STABLE, true);
});
