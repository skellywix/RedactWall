'use strict';

const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-login-audit-order-'));
process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-login-audit-order';
process.env.REDACTWALL_DATA_KEY = 'unit-data-login-audit-order';
process.env.REDACTWALL_DB_PATH = path.join(tmp, 'test.db');
process.env.ADMIN_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';

const auth = require('../server/auth');
const db = require('../server/db');
const oidc = require('../server/oidc');
const app = require('../server/app');
const { listen } = require('./support/listen');

test('successful credentials never receive a session cookie when login audit append fails', async () => {
  const password = 'Accepted-pass-2026';
  const passwordRecord = auth.hashPassword(password);
  db.saveAdminUser({
    userName: 'audit-order@example.test',
    displayName: 'Audit Order',
    role: 'auditor',
    active: true,
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash,
    passwordAlgorithm: passwordRecord.algorithm,
  });

  const originalAppendAudit = db.appendAudit;
  const server = await listen(app);
  db.appendAudit = (event) => {
    if (event && event.action === 'AUDITOR_LOGIN') throw new Error('synthetic audit outage');
    return originalAppendAudit(event);
  };
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: 'audit-order@example.test', password }),
    });
    assert.strictEqual(response.status, 500);
    const setCookie = response.headers.getSetCookie ? response.headers.getSetCookie() : [response.headers.get('set-cookie') || ''];
    assert.ok(!setCookie.some((value) => value.startsWith(`${auth.SESSION_COOKIE_NAME}=`)));
  } finally {
    db.appendAudit = originalAppendAudit;
    await new Promise((resolve) => server.close(resolve));
  }
});

test('successful OIDC callback never receives a session cookie when login audit append fails', async () => {
  const originalAppendAudit = db.appendAudit;
  const originalHandleCallback = oidc.handleCallback;
  const server = await listen(app);
  oidc.handleCallback = async () => ({
    account: {
      user: 'oidc-audit-order@example.test',
      role: 'auditor',
      scimUserId: 'su_oidc_audit_order',
      subject: 'oidc-audit-order-subject',
    },
    returnTo: '/app/',
    sessionExtras: {
      provider: 'oidc',
      idpIssuer: 'https://login.example.test',
      idpSubject: 'oidc-audit-order-subject',
      scimUserId: 'su_oidc_audit_order',
    },
  });
  db.appendAudit = (event) => {
    if (event && event.action === 'AUDITOR_LOGIN') throw new Error('synthetic OIDC audit outage');
    return originalAppendAudit(event);
  };
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/auth/oidc/callback?code=ok&state=ok`, {
      redirect: 'manual',
      headers: { cookie: `${oidc.STATE_COOKIE_NAME}=synthetic` },
    });
    assert.strictEqual(response.status, 302);
    assert.strictEqual(response.headers.get('location'), '/login.html?oidc=failed');
    const setCookie = response.headers.getSetCookie ? response.headers.getSetCookie() : [response.headers.get('set-cookie') || ''];
    assert.ok(!setCookie.some((value) => value.startsWith(`${auth.SESSION_COOKIE_NAME}=`)));
  } finally {
    db.appendAudit = originalAppendAudit;
    oidc.handleCallback = originalHandleCallback;
    await new Promise((resolve) => server.close(resolve));
  }
});

test('recovery code consumption and both successful-login audits roll back together', async () => {
  const recoveryCode = auth.recoveryCodes()[0];
  db._db.exec(`
    CREATE TRIGGER fail_recovery_login_audit
    BEFORE INSERT ON audit
    WHEN NEW.action = 'ADMIN_LOGIN'
    BEGIN
      SELECT RAISE(ABORT, 'synthetic recovery login audit outage');
    END;
  `);
  const server = await listen(app);
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: auth.ADMIN_USER, password: 'unit-pass', otp: recoveryCode }),
    });
    assert.strictEqual(response.status, 500);
    const setCookie = response.headers.getSetCookie ? response.headers.getSetCookie() : [response.headers.get('set-cookie') || ''];
    assert.ok(!setCookie.some((value) => value.startsWith(`${auth.SESSION_COOKIE_NAME}=`)));
    assert.strictEqual(db.mfaRecoveryCodeUsed(0), false, 'failed login evidence restores the one-time code');
    assert.ok(!db.listAudit(100).some((entry) => entry.action === 'ADMIN_MFA_RECOVERY_USED'));
  } finally {
    db._db.exec('DROP TRIGGER IF EXISTS fail_recovery_login_audit');
    await new Promise((resolve) => server.close(resolve));
  }
});

test('logout session revocation rolls back when its audit append fails', async () => {
  const token = auth.createSession(auth.ADMIN_USER, 'security_admin');
  const session = auth.verify(token);
  const cookie = `${auth.SESSION_COOKIE_NAME}=${token}`;
  const revocationKey = `session:${session.jti}`;
  db._db.exec(`
    CREATE TRIGGER fail_logout_audit
    BEFORE INSERT ON audit
    WHEN NEW.action = 'LOGOUT'
    BEGIN
      SELECT RAISE(ABORT, 'synthetic logout audit outage');
    END;
  `);
  const server = await listen(app);
  try {
    const csrfResponse = await fetch(`http://127.0.0.1:${server.address().port}/api/csrf`, {
      headers: { cookie },
    });
    assert.strictEqual(csrfResponse.status, 200);
    const csrfToken = (await csrfResponse.json()).csrfToken;
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/logout`, {
      method: 'POST',
      headers: { cookie, 'x-csrf-token': csrfToken },
    });
    assert.strictEqual(response.status, 500);
    const setCookie = response.headers.getSetCookie ? response.headers.getSetCookie() : [response.headers.get('set-cookie') || ''];
    assert.ok(!setCookie.some((value) => value.startsWith(`${auth.SESSION_COOKIE_NAME}=`)));
    assert.strictEqual(db.identityRevokedSince(revocationKey, session.iat), false);
    assert.ok(auth.verify(token), 'the failed audit restores the session revocation row');
    assert.ok(!db.listAudit(100).some((entry) => entry.action === 'LOGOUT'));
  } finally {
    db._db.exec('DROP TRIGGER IF EXISTS fail_logout_audit');
    await new Promise((resolve) => server.close(resolve));
  }
});

test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(tmp, { recursive: true, force: true });
});
