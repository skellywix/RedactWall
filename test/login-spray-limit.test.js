'use strict';

const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-login-spray';
process.env.REDACTWALL_DATA_KEY = 'unit-data-login-spray';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'rw-login-spray-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.LOGIN_MAX_ATTEMPTS = '3';
process.env.LOGIN_MAX_TRACKED_KEYS = '4';

const auth = require('../server/auth');
const app = require('../server/app');
const db = require('../server/db');
const { listen } = require('./support/listen');

test('one client cannot bypass the scrypt limiter by rotating usernames', async () => {
  const server = await listen(app);
  const originalAuthenticate = auth.authenticate;
  let authenticateCalls = 0;
  auth.authenticate = (...args) => {
    authenticateCalls += 1;
    return originalAuthenticate(...args);
  };
  try {
    const statuses = [];
    for (let index = 0; index < 4; index += 1) {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: `spray-${index}@example.test`, password: 'wrong-password' }),
      });
      statuses.push(response.status);
    }
    assert.deepStrictEqual(statuses, [401, 401, 401, 429]);
    assert.strictEqual(authenticateCalls, 3, 'locked IP is rejected before another scrypt call');
    assert.ok(auth._internal.attemptCount() <= 4);

    const lockedCount = db.listAudit(100).filter((entry) => entry.action === 'LOGIN_LOCKED').length;
    for (let index = 0; index < 50; index += 1) {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: `locked-${index}@example.test`, password: 'wrong-password' }),
      });
      assert.strictEqual(response.status, 429);
    }
    assert.strictEqual(
      db.listAudit(500).filter((entry) => entry.action === 'LOGIN_LOCKED').length,
      lockedCount,
      'requests inside one lockout window do not grow the immutable audit log',
    );

    auth._internal.resetAttempts();
    const syntheticSsn = '524-71-9043';
    const piiAttempt = await fetch(`http://127.0.0.1:${server.address().port}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: syntheticSsn, password: 'wrong-password' }),
    });
    assert.strictEqual(piiAttempt.status, 401);
    const failed = db.listAudit(20).find((entry) => entry.action === 'LOGIN_FAILED');
    assert.match(failed.actor, /^login_[A-Za-z0-9_-]{24}$/);
    assert.ok(!JSON.stringify(failed).includes(syntheticSsn));
  } finally {
    auth.authenticate = originalAuthenticate;
    await new Promise((resolve) => server.close(resolve));
  }
});
