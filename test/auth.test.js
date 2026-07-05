'use strict';
/** Admin auth: password check, brute-force lockout, session signing. node --test */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.ADMIN_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
process.env.APPROVER_USER = 'approver';
process.env.APPROVER_PASSWORD = 'approver-pass';
process.env.AUDITOR_USER = 'auditor';
process.env.AUDITOR_PASSWORD = 'auditor-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.LOGIN_MAX_ATTEMPTS = '3';
process.env.LOGIN_WINDOW_MS = '100000';
const auth = require('../server/auth');

function signedSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', process.env.REDACTWALL_SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function responseCapture() {
  return {
    statusCode: null,
    body: null,
    redirectTo: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
    redirect(url) {
      this.redirectTo = url;
      return this;
    },
  };
}

test('verifyPassword accepts only the right user+password', () => {
  assert.ok(auth.verifyPassword('admin', 'unit-pass'));
  assert.ok(auth.verifyPassword('approver', 'approver-pass'));
  assert.ok(auth.verifyPassword('auditor', 'auditor-pass'));
  assert.ok(!auth.verifyPassword('admin', 'wrong'));
  assert.ok(!auth.verifyPassword('approver', 'unit-pass'));
  assert.ok(!auth.verifyPassword('auditor', 'unit-pass'));
  assert.ok(!auth.verifyPassword('mallory', 'unit-pass'));
});

test('authenticate returns the account role without leaking hashes', () => {
  assert.deepStrictEqual(auth.authenticate('admin', 'unit-pass'), {
    user: 'admin',
    role: 'security_admin',
  });
  assert.deepStrictEqual(auth.authenticate('approver', 'approver-pass'), {
    user: 'approver',
    role: 'approver',
  });
  assert.deepStrictEqual(auth.authenticate('auditor', 'auditor-pass'), {
    user: 'auditor',
    role: 'auditor',
  });
  assert.strictEqual(auth.authenticate('approver', 'wrong'), null);
  assert.strictEqual(auth.authenticate('auditor', 'wrong'), null);
  assert.strictEqual(auth.APPROVER_ENABLED, true);
  assert.strictEqual(auth.AUDITOR_ENABLED, true);
});

test('totp codes verify for the configured admin mfa secret', () => {
  const now = 1700000000000;
  const code = auth.totpCode(process.env.ADMIN_TOTP_SECRET, now);
  assert.match(code, /^\d{6}$/);
  assert.strictEqual(auth.verifyTotpCode(code, now), true);
  assert.strictEqual(auth.verifyTotpCode(code, now + 30000), true, 'one time step of skew is accepted');
  assert.strictEqual(auth.verifyTotpCode(code, now + 90000), false, 'wide clock skew is rejected');
  assert.strictEqual(auth.verifyTotpCode(code === '000000' ? '111111' : '000000', now), false);
  assert.strictEqual(auth.totpCode('not-valid', now), null);
  assert.strictEqual(auth.ADMIN_MFA_REQUIRED, true);
  assert.strictEqual(auth.ADMIN_MFA_CONFIGURED, true);
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

test('lockout expires after the configured window and a correct login succeeds again', () => {
  const script = [
    "const auth = require('./server/auth');",
    "const k = 'admin|10.0.0.9';",
    "auth.registerFail(k); auth.registerFail(k);",
    "const locked = auth.registerFail(k).locked && auth.loginStatus(k).locked;",
    "setTimeout(() => {",
    "  console.log(JSON.stringify({ locked, after: auth.loginStatus(k), login: auth.authenticate('admin', 'unit-pass') }));",
    "}, 150);",
  ].join('');
  const output = execFileSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      LOGIN_MAX_ATTEMPTS: '3',
      LOGIN_WINDOW_MS: '50',
      REDACTWALL_SECRET: 'unit-secret-stable',
    },
    encoding: 'utf8',
  });
  const result = JSON.parse(output);
  assert.strictEqual(result.locked, true, 'locked at threshold before the window elapses');
  assert.deepStrictEqual(result.after, { locked: false }, 'lock releases once the window passes');
  assert.deepStrictEqual(result.login, { user: 'admin', role: 'security_admin' });
});

test('session token signs and verifies; tampered/none rejected', () => {
  const t = auth.createSession('admin');
  assert.strictEqual(auth.verify(t).user, 'admin');
  assert.strictEqual(auth.verify(t).role, 'security_admin');
  const auditor = auth.createSession('auditor', 'auditor');
  assert.strictEqual(auth.verify(auditor).user, 'auditor');
  assert.strictEqual(auth.verify(auditor).role, 'auditor');
  const approver = auth.createSession('approver', 'approver');
  assert.strictEqual(auth.verify(approver).user, 'approver');
  assert.strictEqual(auth.verify(approver).role, 'approver');
  assert.strictEqual(auth.verify('bad.token'), null);
  assert.strictEqual(auth.verify(null), null);
});

test('session secret resolution uses stable storage before ephemeral fallback', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-auth-secret-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  assert.deepStrictEqual(auth._internal.resolveSecret({
    env: { REDACTWALL_SECRET: 'env-secret' },
    dataDir: dir,
  }), {
    secret: 'env-secret',
    source: 'env',
  });

  const existingDir = path.join(dir, 'existing');
  fs.mkdirSync(existingDir);
  fs.writeFileSync(path.join(existingDir, '.session-secret'), ' file-secret \n');
  assert.deepStrictEqual(auth._internal.resolveSecret({
    env: {},
    dataDir: existingDir,
  }), {
    secret: 'file-secret',
    source: 'file',
  });

  const generatedDir = path.join(dir, 'generated');
  const generated = auth._internal.resolveSecret({
    env: {},
    dataDir: generatedDir,
    randomBytes: () => Buffer.alloc(32, 0xab),
  });
  assert.deepStrictEqual(generated, {
    secret: 'ab'.repeat(32),
    source: 'generated',
  });
  assert.strictEqual(fs.readFileSync(path.join(generatedDir, '.session-secret'), 'utf8'), generated.secret);

  const ephemeral = auth._internal.resolveSecret({
    env: {},
    fs: {
      existsSync() {
        throw new Error('storage denied');
      },
    },
    randomBytes: () => Buffer.alloc(32, 0xcd),
  });
  assert.deepStrictEqual(ephemeral, {
    secret: 'cd'.repeat(32),
    source: 'ephemeral',
  });
});

test('oidc session extras are signed and can satisfy fresh step-up', () => {
  const now = Date.now();
  const token = auth.createSession('reviewer@example.test', 'approver', {
    provider: 'oidc',
    idpSubject: 'subject-1',
    idpIssuer: 'https://login.example.test',
    stepUpUntil: now + 60000,
  });
  const verified = auth.verify(token);
  assert.strictEqual(verified.user, 'reviewer@example.test');
  assert.strictEqual(verified.role, 'approver');
  assert.strictEqual(verified.provider, 'oidc');
  assert.strictEqual(verified.idpSubject, 'subject-1');
  assert.strictEqual(verified.idpIssuer, 'https://login.example.test');
  assert.strictEqual(auth.oidcStepUpSatisfied(verified, now), true);
  assert.strictEqual(auth.oidcStepUpSatisfied({ ...verified, stepUpUntil: now - 1 }, now), false);
  assert.strictEqual(auth.oidcStepUpSatisfied({ user: 'admin', role: 'security_admin' }, now), false);
});

test('session verification preserves legacy admin cookies and rejects unknown roles', () => {
  const legacy = signedSession({ user: 'admin', iat: Date.now(), exp: Date.now() + 60000 });
  const verifiedLegacy = auth.verify(legacy);
  assert.deepStrictEqual(verifiedLegacy, {
    user: 'admin',
    role: 'security_admin',
    iat: verifiedLegacy.iat,
    exp: verifiedLegacy.exp,
    stepUpUntil: 0,
  });

  const unknownRole = signedSession({ user: 'admin', role: 'owner', iat: Date.now(), exp: Date.now() + 60000 });
  assert.strictEqual(auth.verify(unknownRole), null);
  const missingUser = signedSession({ role: 'security_admin', iat: Date.now(), exp: Date.now() + 60000 });
  assert.strictEqual(auth.verify(missingUser), null);
});

test('duplicate auditor username is not enabled at runtime', () => {
  const script = [
    "const auth = require('./server/auth');",
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
      REDACTWALL_SECRET: 'unit-secret-stable',
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

test('auth middleware protects API and page routes and enforces roles', () => {
  const apiRes = responseCapture();
  auth.requireAuth({ path: '/api/audit', cookies: {} }, apiRes, () => {
    throw new Error('unauthenticated API should not continue');
  });
  assert.strictEqual(apiRes.statusCode, 401);
  assert.deepStrictEqual(apiRes.body, { error: 'unauthenticated' });

  const pageRes = responseCapture();
  auth.requireAuth({ path: '/index.html', cookies: {} }, pageRes, () => {
    throw new Error('unauthenticated page should not continue');
  });
  assert.strictEqual(pageRes.redirectTo, '/login.html');

  const req = { path: '/api/me', cookies: { [auth.SESSION_COOKIE_NAME]: auth.createSession('admin') } };
  let continued = false;
  auth.requireAuth(req, responseCapture(), () => { continued = true; });
  assert.strictEqual(continued, true);
  assert.strictEqual(req.user.role, 'security_admin');

  const forbidden = responseCapture();
  auth.requireRole('auditor')(req, forbidden, () => {
    throw new Error('wrong role should not continue');
  });
  assert.strictEqual(forbidden.statusCode, 403);
  assert.deepStrictEqual(forbidden.body, { error: 'forbidden' });

  let allowed = false;
  auth.requireRole('security_admin')(req, responseCapture(), () => { allowed = true; });
  assert.strictEqual(allowed, true);
});

test('requireRole with multiple roles allows any listed role and rejects unlisted ones', () => {
  const middleware = auth.requireRole('security_admin', 'approver');

  let allowed = false;
  middleware({ user: { user: 'approver', role: 'approver' } }, responseCapture(), () => { allowed = true; });
  assert.strictEqual(allowed, true, 'second listed role passes');

  const forbidden = responseCapture();
  middleware({ user: { user: 'auditor', role: 'auditor' } }, forbidden, () => {
    throw new Error('unlisted role should not continue');
  });
  assert.strictEqual(forbidden.statusCode, 403);
  assert.deepStrictEqual(forbidden.body, { error: 'forbidden' });
});

test('session verification strips forged idp extras from non-oidc cookies', () => {
  const forged = signedSession({
    user: 'admin',
    role: 'security_admin',
    provider: 'password',
    idpSubject: 'forged-subject',
    idpIssuer: 'https://forged-issuer.example.test',
    iat: Date.now(),
    exp: Date.now() + 60000,
  });
  const verified = auth.verify(forged);
  assert.strictEqual(verified.user, 'admin');
  assert.strictEqual(verified.role, 'security_admin');
  assert.ok(!('provider' in verified), 'non-oidc provider marker is dropped');
  assert.ok(!('idpSubject' in verified), 'forged idpSubject is stripped');
  assert.ok(!('idpIssuer' in verified), 'forged idpIssuer is stripped');
});

test('csrf middleware allows safe methods and rejects missing or wrong tokens', () => {
  const session = auth.createSession('admin');
  let safeContinued = false;
  auth.requireCsrf({ method: 'GET', cookies: {}, get: () => '' }, responseCapture(), () => { safeContinued = true; });
  assert.strictEqual(safeContinued, true);

  const rejected = responseCapture();
  auth.requireCsrf({
    method: 'POST',
    cookies: { [auth.SESSION_COOKIE_NAME]: session },
    get: () => '',
  }, rejected, () => {
    throw new Error('missing csrf should not continue');
  });
  assert.strictEqual(rejected.statusCode, 403);
  assert.deepStrictEqual(rejected.body, { error: 'invalid csrf token' });

  let unsafeContinued = false;
  auth.requireCsrf({
    method: 'POST',
    cookies: { [auth.SESSION_COOKIE_NAME]: session },
    get: (name) => (name === 'x-csrf-token' ? auth.createCsrfToken(session) : ''),
  }, responseCapture(), () => { unsafeContinued = true; });
  assert.strictEqual(unsafeContinued, true);
});

test('derived auth keys are purpose scoped and deterministic', () => {
  assert.strictEqual(auth.deriveKey('receipts').equals(auth.deriveKey('receipts')), true);
  assert.strictEqual(auth.deriveKey('receipts').equals(auth.deriveKey('other-purpose')), false);
});

test('session token lookup prefers RedactWall cookie with legacy fallback', () => {
  const redactwall = auth.createSession('admin');
  const legacy = auth.createSession('auditor', 'auditor');

  assert.strictEqual(auth.sessionTokenFromRequest({ cookies: { redactwall_session: redactwall } }), redactwall);
  assert.strictEqual(auth.sessionTokenFromRequest({ cookies: { sentinel_session: legacy } }), legacy);
  assert.strictEqual(auth.sessionTokenFromRequest({
    cookies: {
      redactwall_session: redactwall,
      sentinel_session: legacy,
    },
  }), redactwall);
  assert.strictEqual(auth.sessionTokenFromRequest({ cookies: {} }), '');
});

test('duplicate approver username is not enabled at runtime', () => {
  const script = [
    "const auth = require('./server/auth');",
    "console.log(JSON.stringify({ enabled: auth.APPROVER_ENABLED, admin: auth.authenticate('admin', 'unit-pass'), duplicate: auth.authenticate('admin', 'approver-pass') }));",
  ].join('');
  const output = execFileSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      ADMIN_USER: 'admin',
      ADMIN_PASSWORD: 'unit-pass',
      APPROVER_USER: ' admin ',
      APPROVER_PASSWORD: 'approver-pass',
      REDACTWALL_SECRET: 'unit-secret-stable',
    },
    encoding: 'utf8',
  });
  const result = JSON.parse(output);
  assert.strictEqual(result.enabled, false);
  assert.deepStrictEqual(result.admin, { user: 'admin', role: 'security_admin' });
  assert.strictEqual(result.duplicate, null);
});

test('secret from env is reported stable (survives restarts / multi-instance)', () => {
  assert.strictEqual(auth.SECRET_IS_STABLE, true);
});
