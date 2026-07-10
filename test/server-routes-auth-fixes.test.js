'use strict';
/**
 * Regression tests for the server-routes-auth audit fixes.
 *
 * Covers the two HIGH findings directly:
 *   - app.js:201  sensor-version-gap alert must NOT scan listQueries(5000) on the
 *                 gate hot path when the reporting sensor is already current.
 *   - scim.js:210 SCIM `active` string "False" (Azure AD) must deactivate, not
 *                 silently re-activate a terminated user.
 * Plus focused checks for the SCIM group-remove array form and the OIDC
 * email_verified gate.
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable-routes-auth-fixes-00001';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable-routes-auth-fixes-001';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SCIM_BEARER_TOKEN = 'unit-scim-token-routes-auth-fixes-00000001';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-routes-auth-fixes-' + crypto.randomBytes(6).toString('hex') + '.db');
const policyPath = path.join(os.tmpdir(), 'ps-routes-auth-fixes-policy-' + crypto.randomBytes(6).toString('hex') + '.json');
process.env.REDACTWALL_POLICY_PATH = policyPath;
fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), policyPath);

const app = require('../server/app');
const db = require('../server/db');
const coverage = require('../server/coverage');
const scim = require('../server/scim');
const oidc = require('../server/oidc');
const auth = require('../server/auth');
const pkg = require('../package.json');
const { listen } = require('./support/listen');

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

async function jsonFetch(port, apiPath, { method = 'POST', body, headers = {} } = {}) {
  return fetch(`http://127.0.0.1:${port}${apiPath}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

// HIGH — app.js:201. The version-gap alert uniquely runs coverage.summarize over
// listQueries(5000); gating it behind an actual mismatch means a current sensor
// pays none of that cost on the gate hot path. (fleet.recordPresence does its own
// scan on every event, so we count the coverage.summarize work specifically.)
async function coverageScansForSensor(port, version) {
  const original = coverage.summarize;
  let scans = 0;
  coverage.summarize = (...args) => { scans += 1; return original.apply(coverage, args); };
  try {
    const res = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: 'Draft a generic lobby announcement with no member details.',
        user: 'pilot@example.test',
        destination: 'chatgpt.com',
        source: 'browser_extension',
        channel: 'submit',
        sensor: { name: 'browser_extension', version, platform: 'chrome_mv3' },
      },
    });
    assert.strictEqual(res.status, 200);
    await new Promise((resolve) => setTimeout(resolve, 50));
    return scans;
  } finally {
    coverage.summarize = original;
  }
}

test('current-version sensor events skip the coverage scan on the gate hot path', async () => withServer(async (port) => {
  // matches the default desiredSensorVersions (pkg.version) => no gap
  assert.strictEqual(await coverageScansForSensor(port, pkg.version), 0);
}));

test('an actually outdated sensor still triggers the version-gap coverage scan', async () => withServer(async (port) => {
  assert.ok(await coverageScansForSensor(port, '0.0.1-outdated') >= 1);
}));

// HIGH — scim.js:210
test('SCIM PATCH active:"False" deactivates the user (Azure AD string boolean)', async () => withServer(async (port) => {
  const scimHeaders = { Authorization: 'Bearer ' + process.env.SCIM_BEARER_TOKEN };
  const created = await jsonFetch(port, '/scim/v2/Users', {
    headers: scimHeaders,
    body: { schemas: [scim.USER_SCHEMA], userName: 'terminated@example.test', active: true },
  });
  assert.strictEqual(created.status, 201);
  const user = await created.json();
  assert.strictEqual(user.active, true);

  const patched = await jsonFetch(port, `/scim/v2/Users/${user.id}`, {
    method: 'PATCH',
    headers: scimHeaders,
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{ op: 'Replace', path: 'active', value: 'False' }],
    },
  });
  assert.strictEqual(patched.status, 200);
  assert.strictEqual((await patched.json()).active, false, 'string "False" must deactivate');
  assert.strictEqual(db.getScimUser(user.id).active, false);

  // PUT with the same string boolean must also deactivate.
  const putUser = await jsonFetch(port, '/scim/v2/Users', {
    headers: scimHeaders,
    body: { schemas: [scim.USER_SCHEMA], userName: 'put-term@example.test', active: true },
  });
  const put = await putUser.json();
  const replaced = await jsonFetch(port, `/scim/v2/Users/${put.id}`, {
    method: 'PUT',
    headers: scimHeaders,
    body: { schemas: [scim.USER_SCHEMA], userName: 'put-term@example.test', active: 'False' },
  });
  assert.strictEqual(replaced.status, 200);
  assert.strictEqual((await replaced.json()).active, false);
}));

// scim.js:219 — group-member remove in RFC 7644 value-array form
test('SCIM group remove in the value-array form actually removes the member', async () => withServer(async (port) => {
  const scimHeaders = { Authorization: 'Bearer ' + process.env.SCIM_BEARER_TOKEN };
  const u = await (await jsonFetch(port, '/scim/v2/Users', {
    headers: scimHeaders,
    body: { schemas: [scim.USER_SCHEMA], userName: 'grpmember@example.test', active: true },
  })).json();
  const g = await (await jsonFetch(port, '/scim/v2/Groups', {
    headers: scimHeaders,
    body: { schemas: [scim.GROUP_SCHEMA], displayName: 'RedactWall Admins', members: [{ value: u.id }] },
  })).json();
  assert.strictEqual(g.members.length, 1);

  const patched = await jsonFetch(port, `/scim/v2/Groups/${g.id}`, {
    method: 'PATCH',
    headers: scimHeaders,
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{ op: 'remove', path: 'members', value: [{ value: u.id }] }],
    },
  });
  assert.strictEqual(patched.status, 200);
  assert.deepStrictEqual((await patched.json()).members, [], 'array-form remove clears the member');
}));

test('OIDC identity mapping requires the immutable subject bound as SCIM externalId', () => {
  db.saveScimUser({
    userName: 'oidc-admin@example.test',
    externalId: 'victim-object-id',
    active: true,
    role: 'security_admin',
  });
  assert.throws(
    () => oidc.scimAccountForClaims({
      sub: 'attacker-subject',
      preferred_username: 'oidc-admin@example.test',
      email: 'oidc-admin@example.test',
      email_verified: true,
    }),
    /not active in SCIM/,
    'mutable username/email claims cannot impersonate a bound privileged subject',
  );
  const account = oidc.scimAccountForClaims({
    sub: 'victim-object-id',
    preferred_username: 'renamed-admin@example.test',
  });
  assert.strictEqual(account.role, 'security_admin');
  assert.strictEqual(account.user, 'oidc-admin@example.test');
});

// auth.js:281 — CSRF token survives a step-up cookie re-issue
test('CSRF token stays valid after elevateSession re-issues the session cookie', () => {
  const session = auth.verify(auth.createSession('admin', 'security_admin'));
  const csrf = auth.createCsrfToken(auth.createSession('admin', 'security_admin', {}));
  // Re-derive from the actual issued token to compare stable subject binding.
  const token = auth.createSession('admin', 'security_admin');
  const original = auth.createCsrfToken(token);
  const elevated = auth.elevateSession(auth.verify(token));
  assert.strictEqual(auth.createCsrfToken(elevated), original, 'step-up must not rotate the CSRF token');
  assert.strictEqual(auth.verifyCsrfToken(elevated, original), true);
  assert.ok(session && csrf);
});

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(policyPath); } catch {}
});
