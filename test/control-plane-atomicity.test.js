'use strict';

const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-control-plane-atomic-'));
process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-control-plane-atomic';
process.env.REDACTWALL_DATA_KEY = 'unit-data-control-plane-atomic';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SCIM_BEARER_TOKEN = 'unit-scim-token-with-32-plus-characters';
process.env.REDACTWALL_DB_PATH = path.join(tmp, 'test.db');
process.env.REDACTWALL_POLICY_PATH = path.join(tmp, 'policy.json');
fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), process.env.REDACTWALL_POLICY_PATH);

const auth = require('../server/auth');
const db = require('../server/db');
const app = require('../server/app');
const policy = require('../server/policy');
const fileMutationLock = require('../server/file-mutation-lock');
const { listen } = require('./support/listen');

const mutationWorker = path.join(__dirname, 'support', 'file-mutation-worker.js');

const adminCookie = `${auth.SESSION_COOKIE_NAME}=${auth.createSession('admin', 'security_admin')}`;

async function csrf(port) {
  const response = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie: adminCookie } });
  assert.strictEqual(response.status, 200);
  return (await response.json()).csrfToken;
}

async function adminPost(port, route, body, method = 'POST') {
  return fetch(`http://127.0.0.1:${port}${route}`, {
    method,
    headers: {
      cookie: adminCookie,
      'content-type': 'application/json',
      'x-csrf-token': await csrf(port),
    },
    body: JSON.stringify(body),
  });
}

test('control-plane and SCIM mutations roll back when their audit append fails', async () => {
  const local = db.saveAdminUser({
    userName: 'atomic-operator@example.test',
    displayName: 'Atomic Operator',
    role: 'operator',
    active: true,
  });
  const invitationCount = db.listAdminInvitations().length;
  const renewalCount = db.listLicenseRenewalRequests().length;
  const policyBefore = policy.loadPolicy();
  const policyBytesBefore = fs.readFileSync(process.env.REDACTWALL_POLICY_PATH);
  const catalogCount = db.listAiApps().length;
  const queryCount = db.listQueries({ all: true }).length;
  const server = await listen(app);
  db._db.exec(`
    CREATE TRIGGER fail_control_plane_audit
    BEFORE INSERT ON audit
    BEGIN
      SELECT RAISE(ABORT, 'synthetic audit append failure');
    END;
  `);
  try {
    const invite = await adminPost(portOf(server), '/api/admin/users/invitations', {
      userName: 'atomic-invite@example.test',
      displayName: 'Atomic Invite',
      role: 'auditor',
      reason: 'atomic invitation proof',
    });
    assert.strictEqual(invite.status, 500);
    assert.strictEqual(db.listAdminInvitations().length, invitationCount);

    const patchUser = await adminPost(portOf(server), `/api/admin/users/local:${local.id}`, {
      role: 'auditor',
      reason: 'atomic role proof',
    }, 'PATCH');
    assert.strictEqual(patchUser.status, 500);
    assert.strictEqual(db.getAdminUser(local.id).role, 'operator');

    const seat = await adminPost(portOf(server), '/api/admin/license/seats/assign', {
      userKey: `local:${local.id}`,
      reason: 'atomic seat proof',
    });
    assert.strictEqual(seat.status, 500);
    assert.strictEqual(db.getLicenseSeatAssignment(`local:${local.id}`), null);

    const renewal = await adminPost(portOf(server), '/api/admin/license/renewal-request', {
      requestedSeats: 12,
      contactEmail: 'renewal@example.test',
      note: 'atomic renewal proof',
    });
    assert.strictEqual(renewal.status, 500);
    assert.strictEqual(db.listLicenseRenewalRequests().length, renewalCount);

    const policyChange = await adminPost(portOf(server), '/api/policy', {
      enforcementMode: policyBefore.enforcementMode === 'warn' ? 'block' : 'warn',
    }, 'PUT');
    assert.strictEqual(policyChange.status, 500);
    assert.deepStrictEqual(policy.loadPolicy(), policyBefore);
    assert.deepStrictEqual(fs.readFileSync(process.env.REDACTWALL_POLICY_PATH), policyBytesBefore);

    const catalog = await adminPost(portOf(server), '/api/catalog', {
      destination: 'atomic-catalog.example',
      appName: 'Atomic Catalog',
      sanctionedStatus: 'under_review',
    });
    assert.strictEqual(catalog.status, 500);
    assert.strictEqual(db.listAiApps().length, catalogCount);

    const scimUser = await fetch(`http://127.0.0.1:${portOf(server)}/scim/v2/Users`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${process.env.SCIM_BEARER_TOKEN}`,
        'content-type': 'application/scim+json',
      },
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        externalId: 'atomic-scim-subject',
        userName: 'atomic-scim@example.test',
        active: true,
      }),
    });
    assert.strictEqual(scimUser.status, 500);
    assert.strictEqual(db.getScimUserByUserName('atomic-scim@example.test'), null);

    const gate = await fetch(`http://127.0.0.1:${portOf(server)}/api/v1/gate`, {
      method: 'POST',
      headers: {
        'x-api-key': process.env.INGEST_API_KEY,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        prompt: '[REDACTED: US_SSN]',
        user: 'atomic-proxy@example.test',
        destination: 'chatgpt.com',
        source: 'proxy',
        channel: 'proxy_monitor',
        clientOutcome: 'proxy_observed',
        clientPreRedacted: true,
        clientFindings: [{ type: 'US_SSN', severity: 4, score: 0.95, masked: '***-**-6789' }],
        clientCategories: [],
        clientEntityCounts: { US_SSN: 1 },
        clientRiskScore: 30,
        clientMaxSeverity: 4,
        clientMaxSeverityLabel: 'critical',
      }),
    });
    assert.strictEqual(gate.status, 500);
    assert.strictEqual(db.listQueries({ all: true }).length, queryCount);
  } finally {
    db._db.exec('DROP TRIGGER fail_control_plane_audit');
    await new Promise((resolve) => server.close(resolve));
  }
  assert.strictEqual(db.verifyAuditChain().ok, true);
});

function portOf(server) {
  return server.address().port;
}

function launchLockHolder(env) {
  const child = spawn(process.execPath, [mutationWorker, 'lock-hold'], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.output = '';
  child.stdout.on('data', (chunk) => { child.output += chunk.toString(); });
  child.stderr.on('data', (chunk) => { child.output += chunk.toString(); });
  return child;
}

async function waitForMarker(child, file, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) return;
    if (child.exitCode !== null) throw new Error(`lock holder exited early: ${child.output}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`lock holder marker timed out: ${file}`);
}

test('policy lock contention leaves the live health endpoint responsive', async () => {
  const server = await listen(app);
  const port = portOf(server);
  const csrfToken = await csrf(port);
  const ready = path.join(tmp, 'lock-holder-ready');
  const release = path.join(tmp, 'lock-holder-release');
  const done = path.join(tmp, 'lock-holder-done');
  const holder = launchLockHolder({
    MUTATION_TARGET: process.env.REDACTWALL_POLICY_PATH,
    MUTATION_READY: ready,
    MUTATION_RELEASE: release,
    MUTATION_DONE: done,
  });
  let updateRequest;
  try {
    await waitForMarker(holder, ready);
    let probeStarted = false;
    const healthProbe = new Promise((resolve, reject) => {
      fileMutationLock._setContentionObserverForTest(() => {
        if (probeStarted) return;
        probeStarted = true;
        const started = Date.now();
        fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(2000) })
          .then(async (response) => resolve({ response, body: await response.json(), elapsed: Date.now() - started }))
          .catch(reject);
      });
    });
    const before = policy.loadPolicy();
    updateRequest = fetch(`http://127.0.0.1:${port}/api/policy`, {
      method: 'PUT',
      headers: {
        cookie: adminCookie,
        'content-type': 'application/json',
        'x-csrf-token': csrfToken,
      },
      body: JSON.stringify({ enforcementMode: before.enforcementMode === 'warn' ? 'block' : 'warn' }),
    });
    const health = await healthProbe;
    assert.strictEqual(health.response.status, 200);
    assert.deepStrictEqual(health.body, { status: 'ok', service: 'redactwall', version: require('../package.json').version });
    assert.ok(health.elapsed < 750, `health response took ${health.elapsed}ms during lock contention`);
    fs.writeFileSync(release, 'release\n');
    assert.strictEqual((await updateRequest).status, 200);
    if (holder.exitCode === null) await new Promise((resolve) => holder.once('exit', resolve));
    assert.strictEqual(holder.exitCode, 0, holder.output);
    assert.strictEqual(fs.existsSync(done), true);
  } finally {
    fileMutationLock._setContentionObserverForTest(null);
    if (!fs.existsSync(release)) fs.writeFileSync(release, 'release\n');
    if (holder.exitCode === null) await new Promise((resolve) => holder.once('exit', resolve));
    if (updateRequest) await updateRequest.catch(() => null);
    await new Promise((resolve) => server.close(resolve));
  }
});

test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(tmp, { recursive: true, force: true });
});
