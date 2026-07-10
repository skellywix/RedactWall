'use strict';
/** SCIM provisioning stores identity lifecycle state without granting raw prompt access. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SCIM_BEARER_TOKEN = 'unit-scim-token-with-32-plus-characters';
process.env.OIDC_ISSUER = 'https://login.scim-test.example';
process.env.OIDC_CLIENT_ID = 'scim-test-client';
process.env.OIDC_CLIENT_SECRET = 'scim-test-client-secret';
process.env.OIDC_REDIRECT_URI = 'https://redactwall.scim-test.example/auth/oidc/callback';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-scim-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const { listen } = require('./support/listen');
const db = require('../server/db');
const scim = require('../server/scim');
const auth = require('../server/auth');
const oidc = require('../server/oidc');

function sessionForScimUser(resource, role) {
  let user = db.getScimUser(resource.id);
  if (!user.externalId) user = db.saveScimUser({ ...user, externalId: `subject-${user.id}` });
  return auth.createSession(user.userName, role, {
    provider: 'oidc',
    idpIssuer: process.env.OIDC_ISSUER,
    idpSubject: user.externalId,
    scimUserId: user.id,
  });
}


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

async function scimFetch(port, apiPath, { method = 'GET', body, token = process.env.SCIM_BEARER_TOKEN } = {}) {
  return fetch(`http://127.0.0.1:${port}/scim/v2${apiPath}`, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/scim+json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

test('scim endpoints require configured bearer token', async () => withServer(async (port) => {
  const original = process.env.SCIM_BEARER_TOKEN;
  try {
    process.env.SCIM_BEARER_TOKEN = '';
    const disabled = await scimFetch(port, '/ServiceProviderConfig', { token: '' });
    assert.strictEqual(disabled.status, 404);

    process.env.SCIM_BEARER_TOKEN = original;
    const denied = await scimFetch(port, '/ServiceProviderConfig', { token: 'wrong-token' });
    assert.strictEqual(denied.status, 401);
    assert.match(denied.headers.get('www-authenticate') || '', /Bearer/);

    const ok = await scimFetch(port, '/ServiceProviderConfig');
    assert.strictEqual(ok.status, 200);
    const body = await ok.json();
    assert.strictEqual(body.patch.supported, true);
    assert.strictEqual(body.filter.supported, true);
  } finally {
    process.env.SCIM_BEARER_TOKEN = original;
  }
}));

test('scim role helpers map known groups and reject unknown display names', () => {
  assert.strictEqual(scim.roleFromDisplayName('RedactWall Security Admins'), 'security_admin');
  assert.strictEqual(scim.roleFromDisplayName('read only'), 'auditor');
  assert.strictEqual(scim.roleFromDisplayName('Facilities Team'), '');
  assert.strictEqual(scim.effectiveUserRole({ id: 'unassigned-user', role: '' }, []), '');
});

test('scim provisions users and groups, maps redactwall approver group to approver role, and deactivates users', async () => withServer(async (port) => {
  const groupRes = await scimFetch(port, '/Groups', {
    method: 'POST',
    body: {
      schemas: [scim.GROUP_SCHEMA],
      externalId: 'entra-group-approvers',
      displayName: 'RedactWall Approvers',
    },
  });
  assert.strictEqual(groupRes.status, 201);
  const group = await groupRes.json();
  assert.strictEqual(group.displayName, 'RedactWall Approvers');

  const duplicateGroupRes = await scimFetch(port, '/Groups', {
    method: 'POST',
    body: {
      schemas: [scim.GROUP_SCHEMA],
      displayName: 'RedactWall Approvers',
    },
  });
  assert.strictEqual(duplicateGroupRes.status, 409);
  assert.strictEqual((await duplicateGroupRes.json()).scimType, 'uniqueness');

  const userRes = await scimFetch(port, '/Users', {
    method: 'POST',
    body: {
      schemas: [scim.USER_SCHEMA],
      externalId: 'entra-user-1',
      userName: 'reviewer@example.test',
      displayName: 'Routed Reviewer',
      active: true,
    },
  });
  assert.strictEqual(userRes.status, 201);
  const user = await userRes.json();
  assert.strictEqual(user.userName, 'reviewer@example.test');
  assert.deepStrictEqual(user.roles, []);
  assert.throws(
    () => oidc.scimAccountForClaims({ sub: user.externalId }),
    /OIDC user is not active in SCIM/,
    'a provisioned identity without an assigned role cannot sign in',
  );

  const duplicateUserRes = await scimFetch(port, '/Users', {
    method: 'POST',
    body: {
      schemas: [scim.USER_SCHEMA],
      userName: 'reviewer@example.test',
    },
  });
  assert.strictEqual(duplicateUserRes.status, 409);
  assert.strictEqual((await duplicateUserRes.json()).scimType, 'uniqueness');

  const patchGroup = await scimFetch(port, `/Groups/${group.id}`, {
    method: 'PATCH',
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{
        op: 'add',
        path: 'members',
        value: [{ value: user.id, display: user.userName }],
      }],
    },
  });
  assert.strictEqual(patchGroup.status, 200);
  const patchedGroup = await patchGroup.json();
  assert.deepStrictEqual(patchedGroup.members.map((m) => m.value), [user.id]);

  const storedUser = await scimFetch(port, `/Users/${user.id}`);
  assert.strictEqual(storedUser.status, 200);
  const mapped = await storedUser.json();
  assert.strictEqual(mapped.roles[0].value, 'approver');
  assert.deepStrictEqual(mapped.groups.map((g) => g.display), ['RedactWall Approvers']);
  assert.strictEqual(oidc.scimAccountForClaims({ sub: user.externalId }).role, 'approver');

  const removeMember = await scimFetch(port, `/Groups/${group.id}`, {
    method: 'PATCH',
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{ op: 'remove', path: `members[value eq "${user.id}"]` }],
    },
  });
  assert.strictEqual(removeMember.status, 200);
  assert.deepStrictEqual((await removeMember.json()).members, []);

  const pathlessGroupPatch = await scimFetch(port, `/Groups/${group.id}`, {
    method: 'PATCH',
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{
        op: 'replace',
        value: { members: [{ value: user.id, display: user.userName }] },
      }],
    },
  });
  assert.strictEqual(pathlessGroupPatch.status, 200);
  assert.deepStrictEqual((await pathlessGroupPatch.json()).members.map((m) => m.value), [user.id]);

  const filtered = await scimFetch(port, '/Users?filter=userName%20eq%20%22reviewer%40example.test%22');
  assert.strictEqual(filtered.status, 200);
  const filteredBody = await filtered.json();
  assert.strictEqual(filteredBody.totalResults, 1);
  assert.strictEqual(filteredBody.Resources[0].id, user.id);

  const deactivate = await scimFetch(port, `/Users/${user.id}`, {
    method: 'PATCH',
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{ op: 'replace', value: { active: false } }],
    },
  });
  assert.strictEqual(deactivate.status, 200);
  assert.strictEqual((await deactivate.json()).active, false);
  assert.strictEqual(db.getScimUser(user.id).active, false);

  const audit = db.listAudit(20);
  assert.ok(audit.some((entry) => entry.action === 'SCIM_USER_UPSERTED'));
  assert.ok(audit.some((entry) => entry.action === 'SCIM_GROUP_PATCHED'));
  const auditWire = JSON.stringify(audit);
  assert.ok(!auditWire.includes('reviewer@example.test'));
  assert.ok(!auditWire.includes('RedactWall Approvers'));
  assert.ok(audit.some((entry) => /^userRef=scim_user_[A-Za-z0-9_-]{24}; active=(true|false)$/.test(entry.detail || '')));
  assert.ok(audit.some((entry) => /^groupRef=scim_group_[A-Za-z0-9_-]{24}; members=\d+$/.test(entry.detail || '')));
  assert.strictEqual(db.verifyAuditChain().ok, true);
}));

test('scim supports user and group lifecycle routes without leaking identity secrets', async () => withServer(async (port) => {
  const groupRes = await scimFetch(port, '/Groups', {
    method: 'POST',
    body: {
      schemas: [scim.GROUP_SCHEMA],
      externalId: 'entra-group-lifecycle',
      displayName: 'Operations',
    },
  });
  assert.strictEqual(groupRes.status, 201);
  const group = await groupRes.json();

  const userRes = await scimFetch(port, '/Users', {
    method: 'POST',
    body: {
      schemas: [scim.USER_SCHEMA],
      externalId: 'entra-user-lifecycle',
      userName: 'operator@example.test',
      displayName: 'Lifecycle Operator',
      roles: [{ value: 'operator', display: 'Operator' }],
    },
  });
  assert.strictEqual(userRes.status, 201);
  const user = await userRes.json();
  assert.strictEqual(user.roles[0].value, 'operator');

  const putUser = await scimFetch(port, `/Users/${user.id}`, {
    method: 'PUT',
    body: {
      schemas: [scim.USER_SCHEMA],
      externalId: 'entra-user-lifecycle-updated',
      userName: 'operator@example.test',
      displayName: 'Updated Operator',
      active: true,
      roles: [{ display: 'auditor' }],
    },
  });
  assert.strictEqual(putUser.status, 200);
  const updatedUser = await putUser.json();
  assert.strictEqual(updatedUser.externalId, 'entra-user-lifecycle-updated');
  assert.strictEqual(updatedUser.displayName, 'Updated Operator');
  assert.strictEqual(updatedUser.roles[0].value, 'auditor');

  const putGroup = await scimFetch(port, `/Groups/${group.id}`, {
    method: 'PUT',
    body: {
      schemas: [scim.GROUP_SCHEMA],
      externalId: 'entra-group-lifecycle-updated',
      displayName: 'RedactWall Operators',
      members: [{ value: user.id, display: updatedUser.userName }],
    },
  });
  assert.strictEqual(putGroup.status, 200);
  const updatedGroup = await putGroup.json();
  assert.strictEqual(updatedGroup.externalId, 'entra-group-lifecycle-updated');
  assert.strictEqual(updatedGroup.members[0].value, user.id);

  const groupLookup = await scimFetch(port, `/Groups/${group.id}`);
  assert.strictEqual(groupLookup.status, 200);
  assert.strictEqual((await groupLookup.json()).displayName, 'RedactWall Operators');

  const filteredGroups = await scimFetch(port, '/Groups?filter=displayName%20eq%20%22RedactWall%20Operators%22');
  assert.strictEqual(filteredGroups.status, 200);
  const filteredGroupsBody = await filteredGroups.json();
  assert.strictEqual(filteredGroupsBody.totalResults, 1);
  assert.strictEqual(filteredGroupsBody.Resources[0].id, group.id);

  const removeAllMembers = await scimFetch(port, `/Groups/${group.id}`, {
    method: 'PATCH',
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{ op: 'remove', path: 'members' }],
    },
  });
  assert.strictEqual(removeAllMembers.status, 200);
  assert.deepStrictEqual((await removeAllMembers.json()).members, []);

  const deleteUser = await scimFetch(port, `/Users/${user.id}`, { method: 'DELETE' });
  assert.strictEqual(deleteUser.status, 204);
  assert.strictEqual(db.getScimUser(user.id).active, false);

  const deleteGroup = await scimFetch(port, `/Groups/${group.id}`, { method: 'DELETE' });
  assert.strictEqual(deleteGroup.status, 204);

  const missingGroup = await scimFetch(port, `/Groups/${group.id}`);
  assert.strictEqual(missingGroup.status, 404);

  const wire = JSON.stringify({ updatedUser, updatedGroup, filteredGroupsBody });
  assert.ok(!wire.includes(process.env.SCIM_BEARER_TOKEN));
}));

test('scim replace operations remove omitted group members and clear direct privileged roles', async () => withServer(async (port) => {
  const removedUserResponse = await scimFetch(port, '/Users', {
    method: 'POST',
    body: {
      schemas: [scim.USER_SCHEMA],
      userName: 'replace-removed-admin@example.test',
      active: true,
    },
  });
  assert.strictEqual(removedUserResponse.status, 201);
  const removedUser = await removedUserResponse.json();

  const keptUserResponse = await scimFetch(port, '/Users', {
    method: 'POST',
    body: {
      schemas: [scim.USER_SCHEMA],
      userName: 'replace-kept-admin@example.test',
      active: true,
    },
  });
  assert.strictEqual(keptUserResponse.status, 201);
  const keptUser = await keptUserResponse.json();

  const groupResponse = await scimFetch(port, '/Groups', {
    method: 'POST',
    body: {
      schemas: [scim.GROUP_SCHEMA],
      displayName: 'RedactWall Security Admins',
      members: [{ value: removedUser.id }, { value: keptUser.id }],
    },
  });
  assert.strictEqual(groupResponse.status, 201);
  const group = await groupResponse.json();
  await new Promise((resolve) => setTimeout(resolve, 2));
  const removedGroupRoleSession = sessionForScimUser(removedUser, 'security_admin');
  const groupRoleSessionBeforeReplace = await fetch(`http://127.0.0.1:${port}/api/me`, {
    headers: { cookie: `${auth.SESSION_COOKIE_NAME}=${removedGroupRoleSession}` },
  });
  assert.strictEqual(groupRoleSessionBeforeReplace.status, 200, 'group-role session starts valid');

  const replaceMembers = await scimFetch(port, `/Groups/${group.id}`, {
    method: 'PATCH',
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{ op: 'replace', path: 'members', value: [{ value: keptUser.id }] }],
    },
  });
  assert.strictEqual(replaceMembers.status, 200);
  assert.deepStrictEqual((await replaceMembers.json()).members.map((member) => member.value), [keptUser.id]);

  const removedAfterReplace = await scimFetch(port, `/Users/${removedUser.id}`);
  assert.deepStrictEqual((await removedAfterReplace.json()).roles, []);
  const removedGroupRoleSessionCheck = await fetch(`http://127.0.0.1:${port}/api/me`, {
    headers: { cookie: `${auth.SESSION_COOKIE_NAME}=${removedGroupRoleSession}` },
  });
  assert.strictEqual(removedGroupRoleSessionCheck.status, 401, 'removing a group role revokes the embedded privileged session');

  await new Promise((resolve) => setTimeout(resolve, 2));
  const keptGroupRoleSession = sessionForScimUser(keptUser, 'security_admin');
  const replaceGroupWithoutMembers = await scimFetch(port, `/Groups/${group.id}`, {
    method: 'PUT',
    body: {
      schemas: [scim.GROUP_SCHEMA],
      displayName: group.displayName,
    },
  });
  assert.strictEqual(replaceGroupWithoutMembers.status, 200);
  assert.deepStrictEqual((await replaceGroupWithoutMembers.json()).members, [], 'PUT omission clears all group members');
  const keptGroupRoleSessionCheck = await fetch(`http://127.0.0.1:${port}/api/me`, {
    headers: { cookie: `${auth.SESSION_COOKIE_NAME}=${keptGroupRoleSession}` },
  });
  assert.strictEqual(keptGroupRoleSessionCheck.status, 401, 'PUT omission revokes removed members embedded privileged sessions');

  const directUserResponse = await scimFetch(port, '/Users', {
    method: 'POST',
    body: {
      schemas: [scim.USER_SCHEMA],
      userName: 'replace-direct-admin@example.test',
      active: true,
      roles: [{ value: 'security_admin' }],
    },
  });
  assert.strictEqual(directUserResponse.status, 201);
  const directUser = await directUserResponse.json();
  const directRoleSession = sessionForScimUser(directUser, 'security_admin');

  const clearDirectRole = await scimFetch(port, `/Users/${directUser.id}`, {
    method: 'PATCH',
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{ op: 'replace', path: 'roles', value: [] }],
    },
  });
  assert.strictEqual(clearDirectRole.status, 200);
  assert.deepStrictEqual((await clearDirectRole.json()).roles, []);
  const directRoleSessionCheck = await fetch(`http://127.0.0.1:${port}/api/me`, {
    headers: { cookie: `${auth.SESSION_COOKIE_NAME}=${directRoleSession}` },
  });
  assert.strictEqual(directRoleSessionCheck.status, 401, 'clearing a direct role revokes the embedded privileged session');

  const restoreDirectRole = await scimFetch(port, `/Users/${directUser.id}`, {
    method: 'PATCH',
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{ op: 'replace', path: 'roles', value: [{ value: 'security_admin' }] }],
    },
  });
  assert.strictEqual(restoreDirectRole.status, 200);
  assert.strictEqual((await restoreDirectRole.json()).roles[0].value, 'security_admin');
  await new Promise((resolve) => setTimeout(resolve, 2));
  const putRoleSession = sessionForScimUser(directUser, 'security_admin');
  const putRoleSessionBeforeReplace = await fetch(`http://127.0.0.1:${port}/api/me`, {
    headers: { cookie: `${auth.SESSION_COOKIE_NAME}=${putRoleSession}` },
  });
  assert.strictEqual(putRoleSessionBeforeReplace.status, 200, 'direct-role session starts valid');
  const replaceUserWithoutRole = await scimFetch(port, `/Users/${directUser.id}`, {
    method: 'PUT',
    body: {
      schemas: [scim.USER_SCHEMA],
      userName: directUser.userName,
      displayName: 'Direct admin replaced without a role',
      active: true,
    },
  });
  assert.strictEqual(replaceUserWithoutRole.status, 200);
  assert.deepStrictEqual((await replaceUserWithoutRole.json()).roles, []);
  const putRoleSessionCheck = await fetch(`http://127.0.0.1:${port}/api/me`, {
    headers: { cookie: `${auth.SESSION_COOKIE_NAME}=${putRoleSession}` },
  });
  assert.strictEqual(putRoleSessionCheck.status, 401, 'PUT omission clears a direct role and revokes the old session');
}));

test('scim PUT clears omitted OIDC and group external ids and revokes the old subject session', async () => withServer(async (port) => {
  const createdResponse = await scimFetch(port, '/Users', {
    method: 'POST',
    body: {
      schemas: [scim.USER_SCHEMA],
      externalId: 'oidc-subject-before-replace',
      userName: 'subject-replace-admin@example.test',
      displayName: 'Subject Replace Admin',
      active: true,
      roles: [{ value: 'security_admin' }],
    },
  });
  assert.strictEqual(createdResponse.status, 201);
  const created = await createdResponse.json();
  const session = sessionForScimUser(created, 'security_admin');
  const cookie = `${auth.SESSION_COOKIE_NAME}=${session}`;
  assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/me`, { headers: { cookie } })).status, 200);

  const replacedResponse = await scimFetch(port, `/Users/${created.id}`, {
    method: 'PUT',
    body: {
      schemas: [scim.USER_SCHEMA],
      userName: created.userName,
      displayName: created.displayName,
      active: true,
      roles: [{ value: 'security_admin' }],
    },
  });
  assert.strictEqual(replacedResponse.status, 200);
  const replaced = await replacedResponse.json();
  assert.strictEqual(replaced.externalId, undefined);
  assert.strictEqual(db.getScimUser(created.id).externalId, undefined);
  assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/me`, { headers: { cookie } })).status, 401);
  assert.throws(
    () => oidc.scimAccountForClaims({ sub: 'oidc-subject-before-replace' }),
    /OIDC user is not active in SCIM/,
  );

  const groupResponse = await scimFetch(port, '/Groups', {
    method: 'POST',
    body: {
      schemas: [scim.GROUP_SCHEMA],
      externalId: 'group-before-replace',
      displayName: 'Subject Replace Group',
    },
  });
  assert.strictEqual(groupResponse.status, 201);
  const group = await groupResponse.json();
  const groupPut = await scimFetch(port, `/Groups/${group.id}`, {
    method: 'PUT',
    body: { schemas: [scim.GROUP_SCHEMA], displayName: group.displayName },
  });
  assert.strictEqual(groupPut.status, 200);
  assert.strictEqual((await groupPut.json()).externalId, undefined);
  assert.strictEqual(db.getScimGroup(group.id).externalId, undefined);
}));

test('scim rejects cross-source username collisions and deactivation cannot fall through to a local password', async () => withServer(async (port) => {
  const password = 'Local-collision-pass-2026';
  const passwordRecord = auth.hashPassword(password);
  db.saveAdminUser({
    userName: 'local-collision@example.test',
    displayName: 'Local Collision',
    role: 'auditor',
    active: true,
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash,
    passwordAlgorithm: passwordRecord.algorithm,
  });

  for (const userName of [' LOCAL-COLLISION@example.test ', ' ADMIN ']) {
    const create = await scimFetch(port, '/Users', {
      method: 'POST',
      body: { schemas: [scim.USER_SCHEMA], userName, active: true },
    });
    assert.strictEqual(create.status, 409, `${userName} collides with another authentication source`);
    assert.strictEqual((await create.json()).scimType, 'uniqueness');
  }

  const managedCreate = await scimFetch(port, '/Users', {
    method: 'POST',
    body: { schemas: [scim.USER_SCHEMA], userName: 'managed-current@example.test', active: true },
  });
  assert.strictEqual(managedCreate.status, 201);
  const managed = await managedCreate.json();
  const sameUserPut = await scimFetch(port, `/Users/${managed.id}`, {
    method: 'PUT',
    body: { schemas: [scim.USER_SCHEMA], userName: managed.userName, displayName: 'Still Current', active: true },
  });
  assert.strictEqual(sameUserPut.status, 200, 'the current SCIM record is not its own collision');

  for (const userName of ['local-collision@example.test', 'admin']) {
    const collidingPut = await scimFetch(port, `/Users/${managed.id}`, {
      method: 'PUT',
      body: { schemas: [scim.USER_SCHEMA], userName, active: true },
    });
    assert.strictEqual(collidingPut.status, 409, `PUT rejects ${userName}`);

    const collidingPatch = await scimFetch(port, `/Users/${managed.id}`, {
      method: 'PATCH',
      body: {
        schemas: [scim.PATCH_SCHEMA],
        Operations: [{ op: 'replace', path: 'userName', value: userName }],
      },
    });
    assert.strictEqual(collidingPatch.status, 409, `PATCH rejects ${userName}`);
  }

  const legacyPassword = auth.hashPassword(password);
  db.saveAdminUser({
    userName: 'legacy-duplicate@example.test',
    displayName: 'Legacy Local Duplicate',
    role: 'auditor',
    active: true,
    passwordSalt: legacyPassword.salt,
    passwordHash: legacyPassword.hash,
    passwordAlgorithm: legacyPassword.algorithm,
  });
  const preexistingLocalSession = auth.createSession('legacy-duplicate@example.test', 'auditor');
  const legacyScim = {
    id: 'su_legacy_duplicate',
    userName: 'legacy-duplicate@example.test',
    displayName: 'Legacy SCIM Duplicate',
    role: 'auditor',
    active: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    version: 0,
  };
  db._db.prepare(
    'INSERT INTO scim_users (id, userName, active, createdAt, updatedAt, data) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(
    legacyScim.id,
    legacyScim.userName,
    1,
    legacyScim.createdAt,
    legacyScim.updatedAt,
    JSON.stringify(legacyScim),
  );
  const shadowedSession = await fetch(`http://127.0.0.1:${port}/api/me`, {
    headers: { cookie: `${auth.SESSION_COOKIE_NAME}=${preexistingLocalSession}` },
  });
  assert.strictEqual(shadowedSession.status, 401, 'SCIM ownership invalidates a preexisting local session');
  const deactivate = await scimFetch(port, `/Users/${legacyScim.id}`, {
    method: 'PATCH',
    body: {
      schemas: [scim.PATCH_SCHEMA],
      Operations: [{ op: 'replace', path: 'active', value: false }],
    },
  });
  assert.strictEqual(deactivate.status, 200, 'preexisting duplicate can still be deprovisioned');
  assert.strictEqual((await deactivate.json()).active, false);

  const localFallback = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: 'legacy-duplicate@example.test', password }),
  });
  assert.strictEqual(localFallback.status, 401, 'inactive SCIM ownership blocks local credential fallback');
}));

test('scim converts datastore uniqueness races into SCIM conflict responses', async () => withServer(async (port) => {
  const originalLookup = db.getScimUserByUserName;
  const originalSave = db.saveScimUser;
  try {
    db.getScimUserByUserName = () => null;
    db.saveScimUser = () => {
      const err = new Error('UNIQUE constraint failed: scim_users.userName');
      err.code = 'SQLITE_CONSTRAINT_UNIQUE';
      throw err;
    };

    const response = await scimFetch(port, '/Users', {
      method: 'POST',
      body: {
        schemas: [scim.USER_SCHEMA],
        userName: 'race@example.test',
      },
    });

    assert.strictEqual(response.status, 409);
    const body = await response.json();
    assert.strictEqual(body.scimType, 'uniqueness');
    assert.ok(!JSON.stringify(body).includes(process.env.SCIM_BEARER_TOKEN));
  } finally {
    db.getScimUserByUserName = originalLookup;
    db.saveScimUser = originalSave;
  }
}));

test('scim save conflict helper rethrows unexpected datastore failures', () => {
  const calls = [];
  const res = {
    status: (code) => {
      calls.push(['status', code]);
      return {
        json: (body) => calls.push(['json', body]),
      };
    },
  };

  assert.throws(
    () => scim._internal.saveOrConflict(res, 'userName already exists', () => {
      throw new Error('database unavailable');
    }),
    /database unavailable/
  );
  assert.deepStrictEqual(calls, []);
});

test('scim rejects authorization headers without the Bearer scheme', async () => withServer(async (port) => {
  const res = await fetch(`http://127.0.0.1:${port}/scim/v2/Users`, {
    headers: { authorization: process.env.SCIM_BEARER_TOKEN },
  });
  assert.strictEqual(res.status, 401);
  assert.match(res.headers.get('www-authenticate') || '', /Bearer/);
}));

test('scim returns 404 for lookups and updates of unknown resource ids', async () => withServer(async (port) => {
  const missingUser = await scimFetch(port, '/Users/su_missing');
  assert.strictEqual(missingUser.status, 404);

  const putUser = await scimFetch(port, '/Users/su_missing', {
    method: 'PUT',
    body: { schemas: [scim.USER_SCHEMA], userName: 'ghost@example.test' },
  });
  assert.strictEqual(putUser.status, 404);

  const patchUser = await scimFetch(port, '/Users/su_missing', {
    method: 'PATCH',
    body: { schemas: [scim.PATCH_SCHEMA], Operations: [{ op: 'replace', path: 'active', value: false }] },
  });
  assert.strictEqual(patchUser.status, 404);

  const putGroup = await scimFetch(port, '/Groups/sg_missing', {
    method: 'PUT',
    body: { schemas: [scim.GROUP_SCHEMA], displayName: 'Ghost Group' },
  });
  assert.strictEqual(putGroup.status, 404);

  const patchGroup = await scimFetch(port, '/Groups/sg_missing', {
    method: 'PATCH',
    body: { schemas: [scim.PATCH_SCHEMA], Operations: [{ op: 'remove', path: 'members' }] },
  });
  assert.strictEqual(patchGroup.status, 404);
}));

test('scim rejects creates that omit required naming attributes', async () => withServer(async (port) => {
  const user = await scimFetch(port, '/Users', {
    method: 'POST',
    body: { schemas: [scim.USER_SCHEMA], displayName: 'No UserName' },
  });
  assert.strictEqual(user.status, 400);
  assert.strictEqual((await user.json()).scimType, 'invalidValue');

  const group = await scimFetch(port, '/Groups', {
    method: 'POST',
    body: { schemas: [scim.GROUP_SCHEMA], externalId: 'entra-group-unnamed' },
  });
  assert.strictEqual(group.status, 400);
  assert.strictEqual((await group.json()).scimType, 'invalidValue');
}));

test('scim applies path-based user patch ops and treats attribute removes as no-ops', async () => withServer(async (port) => {
  const created = await scimFetch(port, '/Users', {
    method: 'POST',
    body: {
      schemas: [scim.USER_SCHEMA],
      userName: 'pathpatch@example.test',
      displayName: 'Path Patch',
      active: true,
    },
  });
  assert.strictEqual(created.status, 201);
  const user = await created.json();

  const renamed = await scimFetch(port, `/Users/${user.id}`, {
    method: 'PATCH',
    body: { schemas: [scim.PATCH_SCHEMA], Operations: [{ op: 'replace', path: 'displayName', value: 'Renamed Patch' }] },
  });
  assert.strictEqual(renamed.status, 200);
  assert.strictEqual((await renamed.json()).displayName, 'Renamed Patch');

  const deactivated = await scimFetch(port, `/Users/${user.id}`, {
    method: 'PATCH',
    body: { schemas: [scim.PATCH_SCHEMA], Operations: [{ op: 'replace', path: 'active', value: false }] },
  });
  assert.strictEqual(deactivated.status, 200);
  assert.strictEqual((await deactivated.json()).active, false);
  assert.strictEqual(db.getScimUser(user.id).active, false);

  const removed = await scimFetch(port, `/Users/${user.id}`, {
    method: 'PATCH',
    body: { schemas: [scim.PATCH_SCHEMA], Operations: [{ op: 'remove', path: 'displayName' }] },
  });
  assert.strictEqual(removed.status, 200);
  assert.strictEqual((await removed.json()).displayName, 'Renamed Patch', 'user attribute remove is ignored');
}));

test('scim filters on unsupported fields or malformed filters return no resources', async () => withServer(async (port) => {
  const disallowed = await scimFetch(port, '/Users?filter=displayName%20eq%20%22Renamed%20Patch%22');
  assert.strictEqual(disallowed.status, 200);
  const disallowedBody = await disallowed.json();
  assert.strictEqual(disallowedBody.totalResults, 0);
  assert.deepStrictEqual(disallowedBody.Resources, []);

  const malformed = await scimFetch(port, '/Users?filter=userName%20gibberish');
  assert.strictEqual(malformed.status, 200);
  const malformedBody = await malformed.json();
  assert.strictEqual(malformedBody.totalResults, 0);
  assert.deepStrictEqual(malformedBody.Resources, []);
}));

test('scim list responses paginate from startIndex and clamp oversized counts', async () => withServer(async (port) => {
  for (let i = 0; i < 3; i += 1) {
    db.saveScimUser({ userName: `page-${i}@example.test`, displayName: `Page User ${i}`, active: true });
  }

  const all = await (await scimFetch(port, '/Users?count=200')).json();
  assert.ok(all.totalResults >= 3);

  const slice = await (await scimFetch(port, '/Users?startIndex=2&count=1')).json();
  assert.strictEqual(slice.startIndex, 2);
  assert.strictEqual(slice.itemsPerPage, 1);
  assert.strictEqual(slice.totalResults, all.totalResults);
  assert.strictEqual(slice.Resources.length, 1);
  assert.strictEqual(slice.Resources[0].id, all.Resources[1].id);

  for (let i = 0; i < 210; i += 1) {
    db.saveScimUser({ userName: `bulk-${i}@example.test`, active: true });
  }
  const clamped = await (await scimFetch(port, '/Users?count=500')).json();
  assert.strictEqual(clamped.itemsPerPage, 200, 'count above 200 clamps to the filter maxResults');
  assert.strictEqual(clamped.Resources.length, 200);
  assert.ok(clamped.totalResults > 200);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
});
