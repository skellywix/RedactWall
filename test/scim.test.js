'use strict';
/** SCIM provisioning stores identity lifecycle state without granting raw prompt access. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SCIM_BEARER_TOKEN = 'unit-scim-token-with-32-plus-characters';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-scim-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const { listen } = require('./support/listen');
const db = require('../server/db');
const scim = require('../server/scim');


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
  assert.strictEqual(scim.roleFromDisplayName('PromptWall Security Admins'), 'security_admin');
  assert.strictEqual(scim.roleFromDisplayName('read only'), 'auditor');
  assert.strictEqual(scim.roleFromDisplayName('Facilities Team'), '');
});

test('scim provisions users and groups, maps promptwall approver group to approver role, and deactivates users', async () => withServer(async (port) => {
  const groupRes = await scimFetch(port, '/Groups', {
    method: 'POST',
    body: {
      schemas: [scim.GROUP_SCHEMA],
      externalId: 'entra-group-approvers',
      displayName: 'PromptWall Approvers',
    },
  });
  assert.strictEqual(groupRes.status, 201);
  const group = await groupRes.json();
  assert.strictEqual(group.displayName, 'PromptWall Approvers');

  const duplicateGroupRes = await scimFetch(port, '/Groups', {
    method: 'POST',
    body: {
      schemas: [scim.GROUP_SCHEMA],
      displayName: 'PromptWall Approvers',
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
  assert.strictEqual(user.roles[0].value, 'auditor');

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
  assert.deepStrictEqual(mapped.groups.map((g) => g.display), ['PromptWall Approvers']);

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
      displayName: 'PromptWall Operators',
      members: [{ value: user.id, display: updatedUser.userName }],
    },
  });
  assert.strictEqual(putGroup.status, 200);
  const updatedGroup = await putGroup.json();
  assert.strictEqual(updatedGroup.externalId, 'entra-group-lifecycle-updated');
  assert.strictEqual(updatedGroup.members[0].value, user.id);

  const groupLookup = await scimFetch(port, `/Groups/${group.id}`);
  assert.strictEqual(groupLookup.status, 200);
  assert.strictEqual((await groupLookup.json()).displayName, 'PromptWall Operators');

  const filteredGroups = await scimFetch(port, '/Groups?filter=displayName%20eq%20%22PromptWall%20Operators%22');
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
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
});
