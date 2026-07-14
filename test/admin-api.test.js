'use strict';
/** Customer Administration APIs: users, roles, invites, seats, and renewal. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.OPERATOR_USER = 'ops@example.test';
process.env.OPERATOR_PASSWORD = 'ops-pass';
process.env.AUDITOR_USER = 'audit@example.test';
process.env.AUDITOR_PASSWORD = 'audit-pass';
process.env.APPROVER_USER = 'reviewer@example.test';
process.env.APPROVER_PASSWORD = 'reviewer-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_TENANT_ID = 'example-fi';
process.env.REDACTWALL_SEAT_LIMIT = '2';
delete process.env.REDACTWALL_PUBLIC_URL;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-admin-api-'));
const licenseDir = path.join(tmp, 'license');
require('../server/private-path').withPrivateDirectoryMutationLockSync(licenseDir, () => {}, {
  fs,
  directory: true,
  label: 'test license directory',
  ownerLabel: 'test license directory',
  lockTimeoutMs: 60_000,
  lockTimeoutMaximumMs: 60_000,
});
process.env.REDACTWALL_DB_PATH = path.join(tmp, 'test.db');
process.env.REDACTWALL_LICENSE_PATH = path.join(licenseDir, 'redactwall.lic');

const app = require('../server/app');
const auth = require('../server/auth');
const db = require('../server/db');
const adminDomain = require('../server/admin');
const { listen } = require('./support/listen');

test.after(() => { try { db._db.close(); } catch {} fs.rmSync(tmp, { recursive: true, force: true }); });

function cookieFor(user, role) {
  return `${auth.SESSION_COOKIE_NAME}=${auth.createSession(user, role)}`;
}

const sessions = {
  admin: cookieFor('admin', 'security_admin'),
  operator: cookieFor('ops@example.test', 'operator'),
  auditor: cookieFor('audit@example.test', 'auditor'),
  approver: cookieFor('reviewer@example.test', 'approver'),
};

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port, server);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function inviteToken(inviteUrl, port) {
  const url = new URL(inviteUrl, `http://127.0.0.1:${port}`);
  assert.strictEqual(url.search, '', 'bearer token must never appear in the request query');
  return new URLSearchParams(url.hash.replace(/^#/, '')).get('token');
}

async function csrf(port, cookie) {
  const res = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } });
  assert.strictEqual(res.status, 200);
  return (await res.json()).csrfToken;
}

async function json(port, route, { method = 'GET', body, cookie = sessions.admin, headers: extraHeaders = {} } = {}) {
  const headers = { cookie, 'Content-Type': 'application/json', ...extraHeaders };
  if (!['GET', 'HEAD'].includes(method)) headers['x-csrf-token'] = await csrf(port, cookie);
  return fetch(`http://127.0.0.1:${port}${route}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function createObservedQuery(query) {
  return db.createQueryWithAudit(query, { action: 'ALLOWED', actor: 'admin-api-test' });
}

test('administration read routes expose institution role labels and directory sources', async () => withServer(async (port) => {
  db.saveScimUser({ userName: 'scim-admin@example.test', displayName: 'SCIM Admin', active: true, role: 'security_admin' });
  createObservedQuery({ status: 'allowed', user: 'lender@example.test', orgId: 'example-fi', destination: 'chatgpt.com' });

  const rolesRes = await json(port, '/api/admin/roles', { cookie: sessions.operator });
  assert.strictEqual(rolesRes.status, 200);
  const roleBody = await rolesRes.json();
  assert.ok(roleBody.roles.some((role) => role.label === 'Global Administrator'));
  assert.ok(roleBody.roles.some((role) => role.label === 'Member Data Reviewer'));

  const directoryRes = await json(port, '/api/admin/users', { cookie: sessions.auditor });
  assert.strictEqual(directoryRes.status, 200);
  const directory = await directoryRes.json();
  assert.ok(directory.users.some((user) => user.sourceLabel === 'Break-glass' && user.roleLabel === 'Global Administrator'));
  assert.ok(directory.users.some((user) => user.userName === 'scim-admin@example.test' && user.sourceLabel === 'SCIM'));
  assert.ok(directory.users.some((user) => user.userName === 'lender@example.test' && user.sourceLabel === 'Observed by sensor'));

  assert.strictEqual((await json(port, '/api/admin/users', { cookie: sessions.approver })).status, 403);
}));

test('directory activity merges preserve authoritative identity state and controls', () => {
  const localActive = db.saveAdminUser({
    userName: 'directory-local-active@example.test',
    displayName: 'Directory Local Active',
    role: 'operator',
    active: true,
  });
  const localInactive = db.saveAdminUser({
    userName: 'directory-local-inactive@example.test',
    displayName: 'Directory Local Inactive',
    role: 'auditor',
    active: false,
  });
  const scimActive = db.saveScimUser({
    userName: 'directory-scim-active@example.test',
    displayName: 'Directory SCIM Active',
    role: 'approver',
    active: true,
  });
  const scimInactive = db.saveScimUser({
    userName: 'directory-scim-inactive@example.test',
    displayName: 'Directory SCIM Inactive',
    role: 'auditor',
    active: false,
  });
  for (const user of [
    'admin',
    localActive.userName,
    localInactive.userName,
    scimActive.userName,
    scimInactive.userName,
  ]) {
    createObservedQuery({ status: 'allowed', user, orgId: 'example-fi', destination: 'chatgpt.com' });
  }

  const byUser = new Map(adminDomain.directory(db, auth).users.map((user) => [user.userName.toLowerCase(), user]));
  const expected = [
    ['admin', 'break:admin', 'break_glass', 'security_admin', true, false, 1],
    [localActive.userName, `local:${localActive.id}`, 'local_invite', 'operator', true, true, 1],
    [localInactive.userName, `local:${localInactive.id}`, 'local_invite', 'auditor', false, true, 1],
    [scimActive.userName, `scim:${scimActive.id}`, 'scim', 'approver', true, true, 1],
    // Inactive SCIM users are deliberately removed from billable seat activity,
    // but their authoritative directory record must remain manageable/inactive.
    [scimInactive.userName, `scim:${scimInactive.id}`, 'scim', 'auditor', false, true, 0],
  ];
  for (const [userName, id, source, role, active, mutable, events] of expected) {
    const row = byUser.get(userName);
    assert.ok(row, `${userName} stays in the directory`);
    assert.strictEqual(row.id, id, `${userName} keeps its authoritative id`);
    assert.strictEqual(row.source, source, `${userName} keeps its authoritative source`);
    assert.strictEqual(row.role, role, `${userName} keeps its authoritative role`);
    assert.strictEqual(row.active, active, `${userName} keeps its authoritative active state`);
    assert.strictEqual(row.mutable, mutable, `${userName} keeps its authoritative mutability`);
    assert.strictEqual(row.events, events, `${userName} reports the expected billable activity`);
  }
});

test('admin seat projections honor an exact connected seat limit including zero', () => {
  const env = {
    ...process.env,
    REDACTWALL_TENANT_ID: 'example-fi',
    REDACTWALL_SEAT_LIMIT: '99',
  };
  const connectedSeatAuthority = { seatLimitOverride: 0 };

  const directory = adminDomain.directory(db, auth, env, connectedSeatAuthority);
  assert.strictEqual(directory.seatReport.seatLimit, 0);
  assert.strictEqual(directory.seatReport.seatLimitConfigured, true);
  assert.strictEqual(directory.seatReport.seatLimitValid, true);
  assert.strictEqual(directory.seatReport.overLimit, directory.seatReport.seatsUsed > 0);

  const seats = adminDomain.seats(
    db,
    auth,
    { state: 'active', managedExternally: true },
    env,
    connectedSeatAuthority,
  );
  assert.strictEqual(seats.seatLimit, 0);
  assert.strictEqual(seats.seatLimitConfigured, true);
  assert.strictEqual(seats.seatLimitValid, true);
  assert.strictEqual(seats.overLimit, seats.seatsUsed > 0);

  const malformedAuthority = adminDomain.directory(db, auth, env, {
    seatLimitOverride: undefined,
  });
  assert.strictEqual(malformedAuthority.seatReport.seatLimit, 0);
  assert.strictEqual(malformedAuthority.seatReport.seatLimitConfigured, true);
  assert.strictEqual(malformedAuthority.seatReport.seatLimitValid, false);

  const offlineDirectory = adminDomain.directory(db, auth, env);
  assert.strictEqual(offlineDirectory.seatReport.seatLimit, 99);
});

test('local-account login throttling canonicalizes whitespace and case variants', async () => withServer(async (port) => {
  const userName = 'throttle.target@example.test';
  const password = 'Correct-local-pass-2026';
  const passwordRecord = auth.hashPassword(password);
  db.saveAdminUser({
    userName,
    displayName: 'Throttle Target',
    role: 'auditor',
    active: true,
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash,
    passwordAlgorithm: passwordRecord.algorithm,
  });
  const variants = [
    ' Throttle.Target@example.test',
    '  throttle.target@example.test',
    'THROTTLE.TARGET@EXAMPLE.TEST ',
    ' throttle.target@EXAMPLE.TEST  ',
    '   Throttle.Target@Example.Test ',
    'THROTTLE.target@example.test   ',
    ' throttle.TARGET@example.test ',
  ];
  for (const user of variants) {
    const res = await fetch(`http://127.0.0.1:${port}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user, password: 'wrong-password' }),
    });
    assert.strictEqual(res.status, 401);
  }

  const locked = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: '  ThRoTtLe.Target@Example.Test  ', password }),
  });
  assert.strictEqual(locked.status, 429, 'canonical identity shares one limiter bucket');
  const audit = db.listAudit(20).find((entry) => entry.action === 'LOGIN_LOCKED');
  assert.ok(audit);
  assert.match(audit.actor, /^login_[A-Za-z0-9_-]{24}$/);
  assert.ok(!audit.actor.includes(userName));
  assert.ok(audit.actor.length <= 128);
  // This file reuses one in-process app across otherwise independent fixtures.
  // Release only its synthetic client bucket after proving the lockout so the
  // following invitation/login scenario represents a different client.
  auth._internal.resetAttempts();
}));

test('global admin can invite a local user, accepted invite can authenticate, and operator cannot mutate', async () => withServer(async (port, server) => {
  const denied = await json(port, '/api/admin/users/invitations', {
    method: 'POST',
    cookie: sessions.operator,
    body: { userName: 'blocked@example.test', role: 'auditor', reason: 'should not work' },
  });
  assert.strictEqual(denied.status, 403);

  const inviteRes = await json(port, '/api/admin/users/invitations', {
    method: 'POST',
    headers: {
      'x-forwarded-proto': 'https',
      'x-forwarded-host': 'attacker.example.test',
    },
    body: {
      userName: 'branch-auditor@example.test',
      displayName: 'Branch Auditor',
      role: 'auditor',
      reason: 'Supervisory committee evidence access',
    },
  });
  assert.strictEqual(inviteRes.status, 201);
  const invite = await inviteRes.json();
  assert.match(invite.inviteUrl, /accept-invite/);
  assert.ok(invite.inviteUrl.startsWith('/'), 'unconfigured secret link stays same-origin relative');
  assert.ok(!invite.inviteUrl.includes('attacker.example.test'));
  const token = inviteToken(invite.inviteUrl, port);
  assert.ok(token);

  const requestTargets = [];
  server.on('request', (req) => {
    if (String(req.url || '').startsWith('/accept-invite.html')) requestTargets.push(req.url);
  });
  const invitePage = await fetch(new URL(invite.inviteUrl, `http://127.0.0.1:${port}`));
  assert.strictEqual(invitePage.status, 200);
  assert.deepStrictEqual(requestTargets, ['/accept-invite.html']);
  assert.ok(!requestTargets.some((target) => target.includes(token)), 'HTTP request target excludes the bearer token');

  const accept = await fetch(`http://127.0.0.1:${port}/api/invitations/accept`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, password: 'Accepted-pass-2026', displayName: 'Accepted Auditor' }),
  });
  assert.strictEqual(accept.status, 200);
  assert.strictEqual((await accept.json()).role, 'auditor');

  const login = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: 'branch-auditor@example.test', password: 'Accepted-pass-2026' }),
  });
  assert.strictEqual(login.status, 200);
  assert.strictEqual((await login.json()).role, 'auditor');

  const directory = await (await json(port, '/api/admin/users')).json();
  assert.ok(directory.users.some((user) => user.userName === 'branch-auditor@example.test' && user.sourceLabel === 'Local invite'));
  assert.ok(db.listAudit(50).some((entry) => entry.action === 'ADMIN_USER_INVITE_ACCEPTED'));
}));

test('invitation links use only a validated configured public origin', async () => withServer(async (port) => {
  const previous = process.env.REDACTWALL_PUBLIC_URL;
  const previousNodeEnv = process.env.NODE_ENV;
  try {
    process.env.REDACTWALL_PUBLIC_URL = 'https://redactwall.example.test/customer/path';
    const configured = await json(port, '/api/admin/users/invitations', {
      method: 'POST',
      headers: {
        'x-forwarded-proto': 'https',
        'x-forwarded-host': 'attacker.example.test',
      },
      body: {
        userName: 'configured-link@example.test',
        role: 'auditor',
        reason: 'validate configured invite origin',
      },
    });
    assert.strictEqual(configured.status, 201);
    const configuredBody = await configured.json();
    assert.ok(configuredBody.inviteUrl.startsWith('https://redactwall.example.test/accept-invite.html#token='));
    assert.ok(inviteToken(configuredBody.inviteUrl, port));
    assert.ok(!configuredBody.inviteUrl.includes('attacker.example.test'));

    process.env.NODE_ENV = 'production';
    process.env.REDACTWALL_PUBLIC_URL = 'http://redactwall.example.test';
    assert.strictEqual(adminDomain.publicInviteBaseUrl(process.env), '');

    process.env.REDACTWALL_PUBLIC_URL = 'javascript://attacker.example.test';
    const invalid = await json(port, '/api/admin/users/invitations', {
      method: 'POST',
      headers: {
        'x-forwarded-proto': 'https',
        'x-forwarded-host': 'attacker.example.test',
      },
      body: {
        userName: 'invalid-link@example.test',
        role: 'auditor',
        reason: 'invalid configured origin falls back safely',
      },
    });
    assert.strictEqual(invalid.status, 201);
    const invalidBody = await invalid.json();
    assert.ok(invalidBody.inviteUrl.startsWith('/accept-invite.html#token='));
    assert.ok(inviteToken(invalidBody.inviteUrl, port));
    assert.ok(!invalidBody.inviteUrl.includes('attacker.example.test'));
  } finally {
    if (previous === undefined) delete process.env.REDACTWALL_PUBLIC_URL;
    else process.env.REDACTWALL_PUBLIC_URL = previous;
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
  }
}));

test('administration audit entries use opaque references instead of identity or reason PII', async () => withServer(async (port) => {
  const existingAuditIds = new Set(db.listAudit(5000).map((entry) => entry.id));
  const acceptedEmail = 'privacy-jane@example.test';
  const revokedEmail = 'privacy-revoked@example.test';
  const localEmail = 'privacy-local@example.test';
  const seatEmail = 'privacy-seat@example.test';
  const licenseEmail = 'privacy-license@example.test';
  const privateReason = `Access approved for Jane Doe ${acceptedEmail} with synthetic SSN 524-71-9043`;
  const confidentialReason = 'Do not forward: we are switching our card processor and terminating the current vendor.';

  const createdRes = await json(port, '/api/admin/users/invitations', {
    method: 'POST',
    body: { userName: acceptedEmail, displayName: 'Jane Doe', role: 'auditor', reason: privateReason },
  });
  assert.strictEqual(createdRes.status, 201);
  const created = await createdRes.json();
  assert.ok(!created.reason.includes(acceptedEmail));
  assert.ok(!created.reason.includes('524-71-9043'));
  assert.match(created.reason, /\[EMAIL_ADDRESS\]/);
  assert.match(created.reason, /\[US_SSN\]/);
  const originalToken = inviteToken(created.inviteUrl, port);

  const resentRes = await json(port, `/api/admin/users/invitations/${created.id}/resend`, {
    method: 'POST',
    body: { reason: `Resend for Jane Doe ${acceptedEmail}` },
  });
  assert.strictEqual(resentRes.status, 200);
  const resent = await resentRes.json();
  const replacementToken = inviteToken(resent.inviteUrl, port);
  assert.ok(replacementToken);
  assert.notStrictEqual(replacementToken, originalToken);
  assert.strictEqual((await acceptInvitation(port, originalToken)).status, 400, 'resend invalidates the old token');
  assert.strictEqual((await acceptInvitation(port, replacementToken)).status, 200);

  const revokeCreate = await json(port, '/api/admin/users/invitations', {
    method: 'POST',
    body: { userName: revokedEmail, displayName: 'Jane Doe Revoked', role: 'auditor', reason: confidentialReason },
  });
  const revokeInvite = await revokeCreate.json();
  assert.strictEqual(revokeInvite.reason, '[REDACTED: CONFIDENTIAL_BUSINESS]');
  const revoked = await json(port, `/api/admin/users/invitations/${revokeInvite.id}/revoke`, {
    method: 'POST',
    body: { reason: `Revoke for Jane Doe ${revokedEmail}` },
  });
  assert.strictEqual(revoked.status, 200);

  const local = db.saveAdminUser({ userName: localEmail, displayName: 'Jane Doe Local', role: 'operator', active: true });
  assert.strictEqual((await json(port, `/api/admin/users/local:${local.id}`, {
    method: 'PATCH',
    body: { role: 'approver', reason: `Role change for Jane Doe ${localEmail}` },
  })).status, 200);
  assert.strictEqual((await json(port, `/api/admin/users/local:${local.id}/disable`, {
    method: 'POST',
    body: { reason: `Disable Jane Doe ${localEmail}` },
  })).status, 200);
  assert.strictEqual((await json(port, `/api/admin/users/local:${local.id}/reactivate`, {
    method: 'POST',
    body: { reason: `Reactivate Jane Doe ${localEmail}` },
  })).status, 200);

  assert.strictEqual((await json(port, '/api/admin/license/seats/release', {
    method: 'POST',
    body: { userKey: seatEmail, reason: `Release seat for Jane Doe ${seatEmail}` },
  })).status, 200);
  assert.strictEqual((await json(port, '/api/admin/license/seats/assign', {
    method: 'POST',
    body: { userKey: seatEmail, reason: `Assign seat for Jane Doe ${seatEmail}` },
  })).status, 200);

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const licensePayload = {
    customer: 'Example Financial Institution',
    customerId: 'example-fi',
    plan: 'standard',
    seats: 2,
    features: [],
    issued: '2026-07-09T00:00:00Z',
    expires: '2099-01-01T00:00:00Z',
    graceDays: 30,
  };
  const payloadB64 = Buffer.from(JSON.stringify(licensePayload)).toString('base64');
  const licenseText = `${payloadB64}.${crypto.sign(null, Buffer.from(payloadB64), privateKey).toString('base64')}`;
  const previousPublicKey = process.env.REDACTWALL_LICENSE_PUBLIC_KEY;
  try {
    process.env.REDACTWALL_LICENSE_PUBLIC_KEY = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const install = await json(port, '/api/admin/license/install', {
      method: 'POST',
      body: { license: licenseText, reason: `License install for Jane Doe ${licenseEmail}` },
    });
    assert.strictEqual(install.status, 200);
  } finally {
    if (previousPublicKey === undefined) delete process.env.REDACTWALL_LICENSE_PUBLIC_KEY;
    else process.env.REDACTWALL_LICENSE_PUBLIC_KEY = previousPublicKey;
  }

  const newEntries = db.listAudit(5000).filter((entry) => !existingAuditIds.has(entry.id));
  const serialized = JSON.stringify(newEntries).toLowerCase();
  for (const privateValue of [acceptedEmail, revokedEmail, localEmail, seatEmail, licenseEmail, 'Jane Doe']) {
    assert.ok(!serialized.includes(privateValue.toLowerCase()), `audit entry excludes ${privateValue}`);
  }
  assert.strictEqual(db.getAdminUserByUserName(acceptedEmail).displayName, 'Jane Doe', 'authorized user table retains identity');
  assert.ok(!db.getAdminInvitation(created.id).reason.includes(acceptedEmail));
  assert.ok(!db.getAdminInvitation(created.id).reason.includes('524-71-9043'));
  assert.strictEqual(db.getAdminInvitation(revokeInvite.id).userName, revokedEmail, 'authorized invitation table retains identity');
  assert.strictEqual(db.getAdminInvitation(revokeInvite.id).reason, '[REDACTED: CONFIDENTIAL_BUSINESS]');
  assert.strictEqual(db.getLicenseSeatAssignment(seatEmail).userName, seatEmail, 'authorized seat table retains identity');
  assert.ok(!db.getLicenseSeatAssignment(seatEmail).reason.includes(seatEmail));
  const privacyAuditIntegrity = db.verifyAuditChain();
  assert.strictEqual(privacyAuditIntegrity.ok, true, JSON.stringify(privacyAuditIntegrity));
}));

test('invitations reject existing identities and local security administrators', async () => withServer(async (port) => {
  db.saveAdminUser({ userName: 'existing-local@example.test', displayName: 'Existing Local', role: 'auditor', active: true });
  db.saveScimUser({ userName: 'existing-scim@example.test', displayName: 'Existing SCIM', role: 'auditor', active: true });
  for (const userName of ['ops@example.test', 'existing-local@example.test', 'existing-scim@example.test']) {
    const res = await json(port, '/api/admin/users/invitations', {
      method: 'POST',
      body: { userName, role: 'auditor', reason: 'duplicate identity regression' },
    });
    assert.strictEqual(res.status, 409, `${userName} should conflict`);
    assert.deepStrictEqual(await res.json(), { error: 'identity_already_exists' });
  }

  const privileged = await json(port, '/api/admin/users/invitations', {
    method: 'POST',
    body: {
      userName: 'local-global-admin@example.test',
      role: 'security_admin',
      reason: 'must wait for per-user MFA enrollment',
    },
  });
  assert.strictEqual(privileged.status, 400);
  assert.deepStrictEqual(await privileged.json(), { error: 'invalid request body', fields: ['role'] });

  const promotable = db.saveAdminUser({
    userName: 'promotable-local@example.test',
    displayName: 'Promotable Local',
    role: 'auditor',
    active: true,
  });
  const promote = await json(port, `/api/admin/users/local:${promotable.id}`, {
    method: 'PATCH',
    body: { role: 'security_admin', reason: 'must enroll per-user MFA first' },
  });
  assert.strictEqual(promote.status, 409);
  assert.deepStrictEqual(await promote.json(), { error: 'per_user_mfa_required' });
}));

function seedInvitation(userName, { role = 'auditor', status = 'pending', expiresAt } = {}) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.saveAdminInvitation({
    userName,
    displayName: userName,
    role,
    status,
    tokenHash: adminDomain.hashToken(token),
    expiresAt: expiresAt || new Date(Date.now() + 86400000).toISOString(),
    actor: 'admin',
  });
  return token;
}

async function acceptInvitation(port, token) {
  return fetch(`http://127.0.0.1:${port}/api/invitations/accept`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, password: 'Accepted-pass-2026' }),
  });
}

test('invitation acceptance revalidates status, expiry, role, and every identity source before scrypt', async () => withServer(async (port) => {
  db.saveAdminUser({ userName: 'accept-local@example.test', displayName: 'Accept Local', role: 'auditor', active: true });
  db.saveScimUser({ userName: 'accept-scim@example.test', displayName: 'Accept SCIM', role: 'auditor', active: true });
  const cases = [
    seedInvitation('ops@example.test'),
    seedInvitation('accept-local@example.test'),
    seedInvitation('accept-scim@example.test'),
    seedInvitation('legacy-local-admin@example.test', { role: 'security_admin' }),
    seedInvitation('revoked-invite@example.test', { status: 'revoked' }),
    seedInvitation('expired-invite@example.test', { expiresAt: new Date(Date.now() - 1000).toISOString() }),
    crypto.randomBytes(32).toString('base64url'),
  ];
  const originalHashPassword = auth.hashPassword;
  let hashCalls = 0;
  auth.hashPassword = (...args) => {
    hashCalls += 1;
    return originalHashPassword(...args);
  };
  try {
    for (const token of cases) {
      const res = await acceptInvitation(port, token);
      assert.strictEqual(res.status, 400);
      assert.deepStrictEqual(await res.json(), { error: 'invalid_or_expired_invitation' });
    }
  } finally {
    auth.hashPassword = originalHashPassword;
  }
  assert.strictEqual(hashCalls, 0, 'invalid invitations are rejected before expensive password hashing');
  assert.strictEqual(db.getAdminUserByUserName('legacy-local-admin@example.test'), null);
}));

test('invitation acceptance attempts are bounded per client', async () => withServer(async (port) => {
  const token = crypto.randomBytes(32).toString('base64url');
  let locked = null;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const res = await acceptInvitation(port, token);
    if (res.status === 429) {
      locked = await res.json();
      break;
    }
    assert.strictEqual(res.status, 400);
  }
  assert.ok(locked, 'acceptance attempts should eventually lock');
  assert.strictEqual(locked.error, 'too_many_invitation_attempts');
  assert.ok(Number(locked.retryMs) > 0);
}));

test('user lifecycle routes enforce last global administrator and audit changes', async () => withServer(async (port) => {
  const originalStatic = auth.listStaticAccounts;
  try {
    auth.listStaticAccounts = () => [];
    const scimAdmin = db.getScimUserByUserName('scim-admin@example.test');
    if (scimAdmin) db.deactivateScimUser(scimAdmin.id);
    const localAdmin = db.saveAdminUser({
      userName: 'only-admin@example.test',
      displayName: 'Only Admin',
      role: 'security_admin',
      active: true,
      passwordSalt: 'not-used',
      passwordHash: 'not-used',
    });
    const demote = await json(port, `/api/admin/users/local:${localAdmin.id}`, {
      method: 'PATCH',
      cookie: cookieFor(localAdmin.userName, 'security_admin'),
      body: { role: 'auditor', reason: 'test last admin guard' },
    });
    assert.strictEqual(demote.status, 409);
    assert.strictEqual((await demote.json()).error, 'last_global_administrator');
  } finally {
    auth.listStaticAccounts = originalStatic;
  }

  const user = db.saveAdminUser({
    userName: 'ops-admin@example.test',
    displayName: 'Ops Admin',
    role: 'operator',
    active: true,
  });
  const patch = await json(port, `/api/admin/users/local:${user.id}`, {
    method: 'PATCH',
    body: { role: 'approver', reason: 'move to member data review queue' },
  });
  assert.strictEqual(patch.status, 200);

  const disable = await json(port, `/api/admin/users/local:${user.id}/disable`, {
    method: 'POST',
    body: { reason: 'staff transfer' },
  });
  assert.strictEqual(disable.status, 200);

  const reactivate = await json(port, `/api/admin/users/local:${user.id}/reactivate`, {
    method: 'POST',
    body: { reason: 'returned to AI oversight' },
  });
  assert.strictEqual(reactivate.status, 200);

  const audit = db.listAudit(100);
  assert.ok(audit.some((entry) => entry.action === 'ADMIN_USER_UPDATED'));
  assert.ok(audit.some((entry) => entry.action === 'ADMIN_USER_DISABLED'));
  assert.ok(audit.some((entry) => entry.action === 'ADMIN_USER_REACTIVATED'));
}));

test('licensing routes keep user PII out of request targets while releasing and assigning seats', async () => withServer(async (port, server) => {
  createObservedQuery({ status: 'allowed', user: 'loan-officer@example.test', orgId: 'example-fi', destination: 'chatgpt.com' });
  const requestTargets = [];
  server.on('request', (req) => {
    if (String(req.url || '').startsWith('/api/admin/license/seats/')) requestTargets.push(req.url);
  });

  const seatsRes = await json(port, '/api/admin/license/seats');
  assert.strictEqual(seatsRes.status, 200);
  const seats = await seatsRes.json();
  assert.ok(seats.users.some((user) => user.userName === 'loan-officer@example.test'));

  const release = await json(port, '/api/admin/license/seats/release', {
    method: 'POST',
    body: { userKey: 'loan-officer@example.test', reason: 'staff left lending department' },
  });
  assert.strictEqual(release.status, 200);
  const releaseBody = await release.json();
  assert.strictEqual(releaseBody.assignment.status, 'released');
  assert.ok(releaseBody.seats.users.some((user) => (
    user.userName === 'loan-officer@example.test' && user.licenseState === 'released'
  )), 'released observed users remain visible so an administrator can reassign them');

  const assign = await json(port, '/api/admin/license/seats/assign', {
    method: 'POST',
    body: { userKey: 'loan-officer@example.test', reason: 'staff returned to AI review workflow' },
  });
  assert.strictEqual(assign.status, 200);
  assert.strictEqual((await assign.json()).assignment.status, 'assigned');
  assert.deepStrictEqual(requestTargets, [
    '/api/admin/license/seats/release',
    '/api/admin/license/seats/assign',
  ]);
  assert.ok(requestTargets.every((target) => !target.includes('loan-officer')));

  const renewal = await json(port, '/api/admin/license/renewal-request', {
    method: 'POST',
    body: {
      requestedSeats: 12,
      contactEmail: 'admin@example.test',
      note: 'Do not forward: we are switching our card processor and terminating the current vendor.',
    },
  });
  assert.strictEqual(renewal.status, 201);
  const renewalBody = await renewal.json();
  assert.strictEqual(renewalBody.request.requestedSeats, 12);
  assert.strictEqual(renewalBody.request.note, '[REDACTED: CONFIDENTIAL_BUSINESS]');
  assert.strictEqual(renewalBody.renewal.tenantId, 'example-fi');

  const licenseStatus = await json(port, '/api/admin/license');
  assert.strictEqual(licenseStatus.status, 200);
  assert.ok((await licenseStatus.json()).renewalRequests.some((request) => request.id === renewalBody.request.id));
}));

test('administration license install requires a reason and rejects invalid license text safely', async () => withServer(async (port) => {
  const missingReason = await json(port, '/api/admin/license/install', {
    method: 'POST',
    body: { license: 'garbage.garbage' },
  });
  assert.strictEqual(missingReason.status, 400);
  assert.deepStrictEqual((await missingReason.json()).fields, ['reason']);

  const invalid = await json(port, '/api/admin/license/install', {
    method: 'POST',
    body: { license: 'garbage.garbage', reason: 'renewal file from vendor' },
  });
  assert.strictEqual(invalid.status, 400);
  assert.strictEqual((await invalid.json()).error, 'invalid_license');
  const invalidLicenseAuditIntegrity = db.verifyAuditChain();
  assert.strictEqual(invalidLicenseAuditIntegrity.ok, true, JSON.stringify(invalidLicenseAuditIntegrity));
}));
