'use strict';
/** SCIM deactivation must revoke live sessions, seats, and sensor ingest. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.ADMIN_TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DP';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-identity-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const db = require('../server/db');
const auth = require('../server/auth');
const tenant = require('../server/tenant');
const roles = require('../server/roles');
const scim = require('../server/scim');
const oidc = require('../server/oidc');
const adminDomain = require('../server/admin');
const { createSessionAuthorizationCheck } = require('../server/session-authorization');

test('sessions minted from stale local and OIDC role reads are rejected while break-glass remains valid', async () => {
  const issuer = 'https://login.session-recheck.example.test';
  auth.setSessionRevokedCheck(createSessionAuthorizationCheck({
    auth,
    db,
    oidcConfig: () => ({ enabled: true, issuer }),
    roles,
    scim,
  }));
  try {
    const local = db.saveAdminUser({
      userName: 'stale-local-admin@example.test',
      role: 'security_admin',
      active: true,
    });
    const staleLocalRead = { user: local.userName, role: local.role };
    db.saveAdminUser({ ...local, role: 'auditor' });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const lateLocalToken = auth.createSession(staleLocalRead.user, staleLocalRead.role);
    assert.strictEqual(auth.verify(lateLocalToken), null, 'current local role defeats a post-revocation stale mint');

    const provisioned = db.saveScimUser({
      externalId: 'immutable-stale-oidc-subject',
      userName: 'stale-oidc-admin@example.test',
      role: 'security_admin',
      active: true,
    });
    const staleOidcRead = oidc.scimAccountForClaims({ sub: provisioned.externalId });
    db.saveScimUser({ ...provisioned, role: 'auditor' });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const lateOidcToken = auth.createSession(staleOidcRead.user, staleOidcRead.role, {
      provider: 'oidc',
      idpIssuer: issuer,
      idpSubject: staleOidcRead.subject,
      scimUserId: staleOidcRead.scimUserId,
    });
    assert.strictEqual(auth.verify(lateOidcToken), null, 'current SCIM role defeats a post-revocation stale mint');

    const rebound = db.saveScimUser({ ...db.getScimUser(provisioned.id), externalId: 'replacement-subject' });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const reboundToken = auth.createSession(rebound.userName, rebound.role, {
      provider: 'oidc',
      idpIssuer: issuer,
      idpSubject: staleOidcRead.subject,
      scimUserId: rebound.id,
    });
    assert.strictEqual(auth.verify(reboundToken), null, 'OIDC subject rebinding invalidates the old subject');

    const unique = db.saveScimUser({
      externalId: 'subject-that-must-stay-unique',
      userName: 'unique-subject@example.test',
      role: 'auditor',
      active: true,
    });
    const uniqueToken = auth.createSession(unique.userName, unique.role, {
      provider: 'oidc',
      idpIssuer: issuer,
      idpSubject: unique.externalId,
      scimUserId: unique.id,
    });
    assert.ok(auth.verify(uniqueToken), 'unique immutable subject is valid');
    db.saveScimUser({
      externalId: unique.externalId,
      userName: 'duplicate-subject@example.test',
      role: 'auditor',
      active: true,
    });
    assert.strictEqual(auth.verify(uniqueToken), null, 'an ambiguous active subject invalidates the session');

    const breakGlass = auth.createSession(auth.ADMIN_USER, 'security_admin');
    assert.ok(auth.verify(breakGlass), 'configured break-glass account keeps its existing semantics');
  } finally {
    auth.setSessionRevokedCheck(null);
  }
});

test('a stable-secret cookie is rejected after its static username moves to a lower role across restart', () => {
  const childDb = path.join(os.tmpdir(), `ps-static-role-restart-${crypto.randomBytes(6).toString('hex')}.db`);
  const shared = {
    ...process.env,
    REDACTWALL_SECRET: 'stable-secret-for-static-role-restart',
    REDACTWALL_DATA_KEY: 'stable-data-key-for-static-role-restart',
    REDACTWALL_DB_PATH: childDb,
    INGEST_API_KEY: 'static-role-restart-ingest-key',
  };
  const minted = spawnSync(process.execPath, ['-e', `
    const auth = require('./server/auth');
    process.stdout.write(auth.createSession('moved-admin', 'security_admin'));
  `], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...shared,
      ADMIN_USER: 'moved-admin',
      ADMIN_PASSWORD: 'first-role-password',
      AUDITOR_USER: '',
      AUDITOR_PASSWORD: '',
    },
    encoding: 'utf8',
  });
  assert.strictEqual(minted.status, 0, minted.stderr);
  assert.match(minted.stdout, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

  const verified = spawnSync(process.execPath, ['-e', `
    require('./server/app');
    const auth = require('./server/auth');
    process.exit(auth.verify(process.env.STALE_SESSION) === null ? 0 : 2);
  `], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...shared,
      ADMIN_USER: 'replacement-admin',
      ADMIN_PASSWORD: 'replacement-role-password',
      AUDITOR_USER: 'moved-admin',
      AUDITOR_PASSWORD: 'moved-auditor-password',
      STALE_SESSION: minted.stdout,
    },
    encoding: 'utf8',
  });
  for (const suffix of ['', '-wal', '-shm']) {
    try { require('node:fs').unlinkSync(childDb + suffix); } catch {}
  }
  assert.strictEqual(verified.status, 0, verified.stderr || verified.stdout);
});

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

test('identity role changes roll back when durable session revocation cannot be written', () => {
  const local = db.saveAdminUser({
    userName: 'atomic-local-admin@example.test',
    displayName: 'Atomic Local Admin',
    role: 'security_admin',
    active: true,
  });
  const scim = db.saveScimUser({
    externalId: 'atomic-scim-subject',
    userName: 'atomic-scim-admin@example.test',
    displayName: 'Atomic SCIM Admin',
    role: 'security_admin',
    active: true,
  });

  db._db.exec(`
    CREATE TRIGGER fail_identity_revocation
    BEFORE INSERT ON identity_revocations
    BEGIN
      SELECT RAISE(ABORT, 'synthetic revocation failure');
    END;
  `);
  try {
    assert.throws(
      () => db.saveAdminUser({ ...local, role: 'auditor' }),
      /synthetic revocation failure/,
    );
    assert.throws(
      () => db.saveScimUser({ ...scim, role: 'auditor' }),
      /synthetic revocation failure/,
    );
  } finally {
    db._db.exec('DROP TRIGGER fail_identity_revocation');
  }

  assert.strictEqual(db.getAdminUser(local.id).role, 'security_admin');
  assert.strictEqual(db.getScimUser(scim.id).role, 'security_admin');
});

test('versioned identity writes reject stale privilege snapshots and cross-source duplicates', () => {
  const local = db.saveAdminUser({
    userName: 'cas-local@example.test',
    displayName: 'CAS Local',
    role: 'security_admin',
    active: true,
  });
  const staleLocal = { ...local };
  const demotedLocal = db.saveAdminUser({ ...local, role: 'auditor' });
  assert.throws(
    () => db.saveAdminUser({ ...staleLocal, displayName: 'Stale Display Edit' }),
    (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
  );
  assert.strictEqual(db.getAdminUser(local.id).role, 'auditor');
  assert.strictEqual(db.getAdminUser(local.id).version, demotedLocal.version);

  const scimUser = db.saveScimUser({
    userName: 'cas-scim@example.test',
    displayName: 'CAS SCIM',
    role: 'security_admin',
    active: true,
  });
  const staleScim = { ...scimUser };
  db.saveScimUser({ ...scimUser, role: 'auditor' });
  assert.throws(
    () => db.saveScimUser({ ...staleScim, displayName: 'Stale SCIM Edit' }),
    (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
  );
  assert.strictEqual(db.getScimUser(scimUser.id).role, 'auditor');

  const group = db.saveScimGroup({ displayName: 'CAS Admins', members: [{ value: scimUser.id }] });
  const staleGroup = { ...group };
  db.saveScimGroup({ ...group, members: [] });
  assert.throws(
    () => db.saveScimGroup({ ...staleGroup, displayName: 'Stale CAS Admins' }),
    (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
  );
  assert.deepStrictEqual(db.getScimGroup(group.id).members, []);

  const deletedGroup = db.saveScimGroup({
    displayName: 'Deleted CAS Admins',
    members: [{ value: scimUser.id }],
  });
  const staleDeletedGroup = { ...deletedGroup };
  db.deleteScimGroup(deletedGroup.id);
  assert.throws(
    () => db.saveScimGroup({ ...staleDeletedGroup, displayName: 'Resurrected CAS Admins' }),
    (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
  );
  assert.strictEqual(db.getScimGroup(deletedGroup.id), null);

  assert.throws(
    () => db.saveScimUser({ userName: local.userName, role: 'auditor', active: true }),
    (error) => error && error.code === 'IDENTITY_ALREADY_EXISTS',
  );
  assert.throws(
    () => db.saveAdminUser({ userName: scimUser.userName, role: 'auditor', active: true }),
    (error) => error && error.code === 'IDENTITY_ALREADY_EXISTS',
  );
});

test('invitation transitions reject stale status and token snapshots', () => {
  const acceptedToken = crypto.randomBytes(32).toString('base64url');
  const acceptedTokenHash = adminDomain.hashToken(acceptedToken);
  const acceptedSeed = db.saveAdminInvitation({
    userName: 'cas-invite-accepted@example.test',
    displayName: 'CAS Invite Accepted',
    role: 'auditor',
    status: 'pending',
    tokenHash: acceptedTokenHash,
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
  });
  const staleAccepted = { ...acceptedSeed };
  const accepted = db.acceptAdminInvitation(acceptedTokenHash, {
    salt: 'synthetic-salt',
    hash: 'synthetic-hash',
    algorithm: 'scrypt',
  });
  assert.strictEqual(accepted.invitation.status, 'accepted');
  assert.throws(
    () => db.saveAdminInvitation({
      ...staleAccepted,
      status: 'revoked',
      expectedVersion: staleAccepted.version,
      expectedStatus: 'pending',
      expectedTokenHash: acceptedTokenHash,
    }),
    (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
  );
  assert.throws(
    () => db.saveAdminInvitation({
      ...accepted.invitation,
      status: 'pending',
      expectedVersion: accepted.invitation.version,
      expectedStatus: 'accepted',
      expectedTokenHash: acceptedTokenHash,
    }),
    (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
  );
  assert.strictEqual(db.getAdminInvitation(acceptedSeed.id).status, 'accepted');

  const revokedTokenHash = adminDomain.hashToken(crypto.randomBytes(32).toString('base64url'));
  const revokedSeed = db.saveAdminInvitation({
    userName: 'cas-invite-revoked@example.test',
    role: 'auditor',
    status: 'pending',
    tokenHash: revokedTokenHash,
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
  });
  const staleRevoked = { ...revokedSeed };
  const revoked = adminDomain.revokeInvitation(db, revokedSeed.id, 'admin', 'access withdrawn');
  assert.strictEqual(revoked.status, 'revoked');
  assert.strictEqual(adminDomain.resendInvitation(db, revoked.id, 'admin', ''), null);
  assert.throws(
    () => db.saveAdminInvitation({
      ...staleRevoked,
      status: 'pending',
      tokenHash: adminDomain.hashToken(crypto.randomBytes(32).toString('base64url')),
      expectedVersion: staleRevoked.version,
      expectedStatus: 'pending',
      expectedTokenHash: revokedTokenHash,
    }),
    (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
  );
  assert.strictEqual(db.getAdminInvitation(revoked.id).status, 'revoked');

  const originalResendHash = adminDomain.hashToken(crypto.randomBytes(32).toString('base64url'));
  const resendSeed = db.saveAdminInvitation({
    userName: 'cas-invite-resend@example.test',
    role: 'auditor',
    status: 'pending',
    tokenHash: originalResendHash,
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
  });
  const staleResend = { ...resendSeed };
  assert.throws(
    () => db.saveAdminInvitation({ ...resendSeed, actor: 'missing-state-cas' }),
    (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
  );
  const resent = adminDomain.resendInvitation(db, resendSeed.id, 'admin', '');
  const resentStored = db.getAdminInvitation(resendSeed.id);
  assert.ok(resent.inviteToken);
  assert.notStrictEqual(resentStored.tokenHash, originalResendHash);
  assert.strictEqual(db.expireAdminInvitation(originalResendHash, Date.now() + 8 * 86400000), null);
  assert.throws(
    () => db.saveAdminInvitation({
      ...staleResend,
      status: 'expired',
      expectedVersion: staleResend.version,
      expectedStatus: 'pending',
      expectedTokenHash: originalResendHash,
    }),
    (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
  );

  const expiredTokenHash = adminDomain.hashToken(crypto.randomBytes(32).toString('base64url'));
  const expiredSeed = db.saveAdminInvitation({
    userName: 'cas-invite-expired@example.test',
    role: 'auditor',
    status: 'pending',
    tokenHash: expiredTokenHash,
    expiresAt: new Date(Date.now() - 1000).toISOString(),
  });
  const staleExpired = { ...expiredSeed };
  const expired = db.expireAdminInvitation(expiredTokenHash);
  assert.strictEqual(expired.status, 'expired');
  assert.strictEqual(db.acceptAdminInvitation(expiredTokenHash, {}), null);
  assert.throws(
    () => db.saveAdminInvitation({
      ...staleExpired,
      status: 'revoked',
      expectedVersion: staleExpired.version,
      expectedStatus: 'pending',
      expectedTokenHash: expiredTokenHash,
    }),
    (error) => error && error.code === 'IDENTITY_WRITE_CONFLICT',
  );
  assert.strictEqual(db.getAdminInvitation(expiredSeed.id).status, 'expired');
});

test('expired inactive-identity cache rebuilds even when count and updatedAt are unchanged', () => {
  const childDb = path.join(os.tmpdir(), `ps-identity-cache-${crypto.randomBytes(6).toString('hex')}.db`);
  const script = `
    const db = require('./server/db');
    const user = db.saveScimUser({ userName: 'cross-instance@example.test', active: true });
    if (db.scimIdentityInactive(user.userName)) process.exit(2);
    const changed = { ...db.getScimUser(user.id), active: false };
    db._db.prepare('UPDATE scim_users SET active = ?, data = ? WHERE id = ?')
      .run(0, JSON.stringify(changed), user.id);
    if (!db.scimIdentityInactive(user.userName)) process.exit(3);
    db._db.close();
  `;
  const child = spawnSync(process.execPath, ['-e', script], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      REDACTWALL_DB_PATH: childDb,
      REDACTWALL_SCIM_CACHE_TTL_MS: '0',
    },
    encoding: 'utf8',
  });
  for (const suffix of ['', '-wal', '-shm']) {
    try { require('node:fs').unlinkSync(childDb + suffix); } catch {}
  }
  assert.strictEqual(child.status, 0, child.stderr || child.stdout);
});

test('scim username changes revoke sessions for both old and new identities', async () => {
  auth.setSessionRevokedCheck((session) => db.identityRevokedSince(session.user, session.iat));
  try {
    const saved = db.saveScimUser({
      userName: 'renamed-old@example.test',
      active: true,
    });
    const oldIdentity = auth.createSession('renamed-old@example.test', 'auditor');
    const newIdentity = auth.createSession('renamed-new@example.test', 'auditor');

    db.saveScimUser({ ...saved, userName: 'renamed-new@example.test' });

    assert.strictEqual(auth.verify(oldIdentity), null, 'old username session is revoked');
    assert.strictEqual(auth.verify(newIdentity), null, 'pre-existing new-name session is revoked');
  } finally {
    auth.setSessionRevokedCheck(null);
  }
});

test('scim group membership, rename, and delete changes revoke affected sessions', async () => {
  auth.setSessionRevokedCheck((session) => db.identityRevokedSince(session.user, session.iat));
  try {
    const user = db.saveScimUser({ userName: 'group-admin@example.test', active: true });
    const group = db.saveScimGroup({
      displayName: 'RedactWall Admins',
      members: [{ value: user.id }],
    });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const membershipSession = auth.createSession(user.userName, 'security_admin');

    const withoutMembers = db.saveScimGroup({ ...group, members: [] });
    assert.strictEqual(auth.verify(membershipSession), null, 'membership removal revokes the embedded role');

    await new Promise((resolve) => setTimeout(resolve, 5));
    const renamed = db.saveScimGroup({ ...withoutMembers, members: [{ value: user.id }] });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const renameSession = auth.createSession(user.userName, 'security_admin');
    db.saveScimGroup({ ...renamed, displayName: 'RedactWall Auditors' });
    assert.strictEqual(auth.verify(renameSession), null, 'role-bearing group rename revokes the embedded role');

    await new Promise((resolve) => setTimeout(resolve, 5));
    const deleteGroup = db.saveScimGroup({
      displayName: 'RedactWall Admins',
      members: [{ value: user.id }],
    });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const deleteSession = auth.createSession(user.userName, 'security_admin');
    db.deleteScimGroup(deleteGroup.id);
    assert.strictEqual(auth.verify(deleteSession), null, 'role-bearing group delete revokes the embedded role');
  } finally {
    auth.setSessionRevokedCheck(null);
  }
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

test('released license seats free capacity while the released identity stays blocked', () => {
  const env = {
    REDACTWALL_TENANT_ID: 'seat-release-fi',
    REDACTWALL_SEAT_LIMIT: '1',
  };
  const releasedUser = 'released-seat@example.test';
  db.createQuery({
    status: 'allowed',
    user: releasedUser,
    orgId: 'seat-release-fi',
    destination: 'chatgpt.com',
  });
  assert.strictEqual(tenant.seatReport(db, env).seatsUsed, 1);

  db.saveLicenseSeatAssignment({
    userKey: releasedUser,
    userName: releasedUser,
    status: 'released',
    reason: 'staff transfer',
    actor: 'admin',
  });
  assert.strictEqual(tenant.seatReport(db, env).seatsUsed, 0, 'release frees the consumed seat');

  const released = tenant.validateSensorAccess({
    body: { user: releasedUser, orgId: 'seat-release-fi', destination: 'chatgpt.com' },
    db,
    env,
  });
  assert.strictEqual(released.ok, false);
  assert.strictEqual(released.status, 'seat_released');
  assert.strictEqual(released.statusCode, 403);

  const replacement = tenant.validateSensorAccess({
    body: { user: 'replacement@example.test', orgId: 'seat-release-fi', destination: 'chatgpt.com' },
    db,
    env,
  });
  assert.strictEqual(replacement.ok, true, 'a replacement identity can consume the freed seat');

  db.saveLicenseSeatAssignment({
    userKey: releasedUser,
    userName: releasedUser,
    status: 'assigned',
    reason: 'staff returned',
    actor: 'admin',
  });
  const reassigned = tenant.validateSensorAccess({
    body: { user: releasedUser, orgId: 'seat-release-fi', destination: 'chatgpt.com' },
    db,
    env,
  });
  assert.strictEqual(reassigned.ok, true, 'explicit reassignment restores access');
});

test('released license seats block the identity outside SaaS mode too', () => {
  const releasedUser = 'released-standalone@example.test';
  db.saveLicenseSeatAssignment({
    userKey: releasedUser,
    userName: releasedUser,
    status: 'released',
    reason: 'standalone workstation retired',
    actor: 'admin',
  });

  const result = tenant.validateSensorAccess({
    body: { user: releasedUser, destination: 'chatgpt.com' },
    db,
    env: {},
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 'seat_released');
  assert.strictEqual(result.statusCode, 403);
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

test('session-specific revocation invalidates only the logged-out token', () => {
  auth.setSessionRevokedCheck((session) => db.identityRevokedSince(session.user, session.iat)
    || (session.jti && db.identityRevokedSince(`session:${session.jti}`, session.iat)));
  try {
    const firstToken = auth.createSession('logout-user@example.test', 'auditor');
    const secondToken = auth.createSession('logout-user@example.test', 'auditor');
    const first = auth.verify(firstToken);
    const second = auth.verify(secondToken);
    assert.ok(first.jti);
    assert.ok(second.jti);
    assert.notStrictEqual(first.jti, second.jti);

    db.revokeIdentity(`session:${first.jti}`);
    assert.strictEqual(auth.verify(firstToken), null);
    assert.ok(auth.verify(secondToken), 'another session for the same user remains valid');
  } finally {
    auth.setSessionRevokedCheck(null);
  }
});

test('expired session-token revocations are pruned from the persistent denylist', () => {
  const identity = 'session:expired-session-revocation';
  const revokedAt = Date.now() - (25 * 60 * 60 * 1000);
  db.revokeIdentity(identity, revokedAt);
  assert.strictEqual(db.identityRevokedSince(identity, revokedAt - 1), false);
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
