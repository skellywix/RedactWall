'use strict';
/**
 * Security: login brute force is throttled. server/auth.js locks a user+IP
 * key after LOGIN_MAX_ATTEMPTS failures within LOGIN_WINDOW_MS; the login
 * route then answers 429 (even for the correct password) until the window
 * passes or a success clears it.
 */
const test = require('node:test');
const assert = require('node:assert');

const support = require('../support/app');
support.bootEnv({ env: { LOGIN_MAX_ATTEMPTS: '3', LOGIN_WINDOW_MS: '120000' } });
const app = support.requireApp();

function attempt(port, user, password) {
  return support.request(port, '/api/login', { method: 'POST', body: { user, password } });
}

test('repeated bad passwords lock the account and return 429', async () => support.withServer(app, async (port) => {
  const first = await attempt(port, 'admin', 'wrong-password-1');
  assert.strictEqual(first.status, 401);
  const firstBody = await first.json();
  assert.strictEqual(firstBody.error, 'invalid credentials');
  assert.strictEqual(typeof firstBody.remaining, 'number');

  const second = await attempt(port, 'admin', 'wrong-password-2');
  assert.strictEqual(second.status, 401);
  const third = await attempt(port, 'admin', 'wrong-password-3');
  assert.strictEqual(third.status, 401, 'threshold attempt still reports invalid credentials');

  const locked = await attempt(port, 'admin', 'wrong-password-4');
  assert.strictEqual(locked.status, 429, 'after LOGIN_MAX_ATTEMPTS failures the key is locked');
  const lockedBody = await locked.json();
  assert.ok(lockedBody.retryMs > 0, 'lockout advertises a retry window');

  const correctWhileLocked = await attempt(port, 'admin', support.CREDENTIALS.admin.password);
  assert.strictEqual(correctWhileLocked.status, 429, 'lockout applies even to the correct password');
}));

test('lockout is per user key: another account still logs in', async () => support.withServer(app, async (port) => {
  const auditor = await attempt(port, support.CREDENTIALS.auditor.user, support.CREDENTIALS.auditor.password);
  assert.strictEqual(auditor.status, 200);
  assert.strictEqual((await auditor.json()).role, 'auditor');
}));

test('failed logins never echo the submitted password', async () => support.withServer(app, async (port) => {
  const res = await attempt(port, support.CREDENTIALS.approver.user, 'super-secret-guess');
  assert.ok([401, 429].includes(res.status));
  assert.ok(!(await res.text()).includes('super-secret-guess'));
}));
