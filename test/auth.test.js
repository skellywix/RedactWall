'use strict';
/** Admin auth: password check, brute-force lockout, session signing. node --test */
const test = require('node:test');
const assert = require('node:assert');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.AUDITOR_USER = 'auditor';
process.env.AUDITOR_PASSWORD = 'auditor-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.LOGIN_MAX_ATTEMPTS = '3';
process.env.LOGIN_WINDOW_MS = '100000';
const auth = require('../src/auth');

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
