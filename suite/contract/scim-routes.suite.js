'use strict';
/**
 * Contract: SCIM 2.0 provisioning routes (/scim/v2) require the bearer token
 * and speak the SCIM schema envelope for users and groups.
 */
const test = require('node:test');
const assert = require('node:assert');

const support = require('../support/app');
support.bootEnv({ env: { SCIM_BEARER_TOKEN: support.SCIM_TOKEN } });
const app = support.requireApp();

const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';

function scim(port, apiPath, opts = {}) {
  return support.request(port, `/scim/v2${apiPath}`, {
    ...opts,
    headers: { authorization: `Bearer ${support.SCIM_TOKEN}`, ...(opts.headers || {}) },
  });
}

test('SCIM routes reject missing and wrong bearer tokens with 401', async () => support.withServer(app, async (port) => {
  for (const route of ['/ServiceProviderConfig', '/Users', '/Groups']) {
    const missing = await support.request(port, `/scim/v2${route}`);
    assert.strictEqual(missing.status, 401, `expected 401 without bearer for ${route}`);
    const body = await missing.json();
    assert.ok(body.schemas.includes('urn:ietf:params:scim:api:messages:2.0:Error'));
    const wrong = await support.request(port, `/scim/v2${route}`, { headers: { authorization: 'Bearer wrong-token' } });
    assert.strictEqual(wrong.status, 401, `expected 401 with bad bearer for ${route}`);
  }
}));

test('ServiceProviderConfig advertises SCIM capabilities', async () => support.withServer(app, async (port) => {
  const res = await scim(port, '/ServiceProviderConfig');
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.ok(Array.isArray(body.schemas));
  assert.ok('patch' in body && 'filter' in body, `unexpected keys ${Object.keys(body)}`);
}));

test('SCIM user lifecycle: create, read, filter, deactivate', async () => support.withServer(app, async (port) => {
  const created = await scim(port, '/Users', {
    method: 'POST',
    body: {
      schemas: [USER_SCHEMA],
      userName: 'jane.doe@example.com',
      externalId: 'ext-jane-1',
      displayName: 'Jane Doe',
      active: true,
    },
  });
  assert.strictEqual(created.status, 201);
  const user = await created.json();
  assert.ok(user.id, 'created user gets an id');
  assert.strictEqual(user.userName, 'jane.doe@example.com');
  assert.ok(user.schemas.includes(USER_SCHEMA));

  const list = await scim(port, '/Users?filter=' + encodeURIComponent('userName eq "jane.doe@example.com"'));
  assert.strictEqual(list.status, 200);
  const listBody = await list.json();
  assert.ok(listBody.schemas.includes(LIST_SCHEMA));
  assert.strictEqual(listBody.totalResults, 1);
  assert.strictEqual(listBody.Resources[0].id, user.id);

  const one = await scim(port, `/Users/${user.id}`);
  assert.strictEqual(one.status, 200);
  assert.strictEqual((await one.json()).id, user.id);

  const gone = await scim(port, `/Users/${user.id}`, { method: 'DELETE' });
  assert.ok([200, 204].includes(gone.status), `unexpected delete status ${gone.status}`);
  const after = await scim(port, `/Users/${user.id}`);
  if (after.status === 200) assert.strictEqual((await after.json()).active, false, 'deleted SCIM user is deactivated');
}));

test('SCIM groups list responds with the SCIM list envelope', async () => support.withServer(app, async (port) => {
  const res = await scim(port, '/Groups');
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.ok(body.schemas.includes(LIST_SCHEMA));
  assert.ok(Array.isArray(body.Resources));
  assert.strictEqual(typeof body.totalResults, 'number');
}));
