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
const db = require('../server/db');
const scim = require('../server/scim');

function listen(appUnderTest) {
  return new Promise((resolve, reject) => {
    const server = appUnderTest.listen(0, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
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

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
});
