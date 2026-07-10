'use strict';
/** Release polling must be scoped to the sensor request that created the hold. */
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
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-release-token-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-release-token-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
  rawRetentionDays: 30,
}, null, 2));

const app = require('../server/app');
const { listen } = require('./support/listen');
const db = require('../server/db');
const releaseTokens = require('../server/release-token');
const dataCrypto = require('../server/crypto');
const license = require('../server/license');


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
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function login(port) {
  const res = await jsonFetch(port, '/api/login', {
    body: { user: 'admin', password: 'unit-pass' },
  });
  assert.strictEqual(res.status, 200);
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  const csrfRes = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } });
  assert.strictEqual(csrfRes.status, 200);
  const csrf = await csrfRes.json();
  return { cookie, csrfToken: csrf.csrfToken };
}

test('held prompt status polling requires the matching release token', async () => withServer(async (port) => {
  const gate = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Please review this synthetic member SSN 524-71-9043 before submission.',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'proxy',
      channel: 'submit',
    },
  });
  assert.strictEqual(gate.status, 200);
  const held = await gate.json();
  assert.strictEqual(held.status, 'pending');
  assert.match(held.releaseToken, /^[A-Za-z0-9_-]{32,}$/);

  const stored = db.getQuery(held.id);
  assert.ok(stored._releaseTokenHash);
  assert.ok(!JSON.stringify(stored).includes(held.releaseToken));

  const statusUrl = `http://127.0.0.1:${port}/api/v1/status/${held.id}`;
  const noToken = await fetch(statusUrl, { headers: { 'x-api-key': 'unit-ingest-key' } });
  assert.strictEqual(noToken.status, 401);
  assert.deepStrictEqual(await noToken.json(), { error: 'invalid release token' });

  const wrongToken = await fetch(statusUrl, {
    headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': 'not-the-release-token' },
  });
  assert.strictEqual(wrongToken.status, 401);

  const queryToken = await fetch(`${statusUrl}?releaseToken=${encodeURIComponent(held.releaseToken)}`, {
    headers: { 'x-api-key': 'unit-ingest-key' },
  });
  assert.strictEqual(queryToken.status, 401);

  const pending = await fetch(statusUrl, {
    headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
  });
  assert.strictEqual(pending.status, 200);
  assert.deepStrictEqual(await pending.json(), { id: held.id, status: 'pending', released: false });

  const { cookie, csrfToken } = await login(port);
  const approve = await jsonFetch(port, `/api/queries/${held.id}/approve`, {
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { note: 'Synthetic approval for release-token test', password: 'unit-pass' },
  });
  assert.strictEqual(approve.status, 200);

  const released = await fetch(statusUrl, {
    headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
  });
  assert.strictEqual(released.status, 200);
  assert.deepStrictEqual(await released.json(), { id: held.id, status: 'approved', released: true });

  license.applyVendorVerdict(true);
  try {
    const revoked = await fetch(statusUrl, {
      headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
    });
    assert.strictEqual(revoked.status, 403);
    assert.deepStrictEqual(await revoked.json(), {
      error: 'license_revoked', status: 'license_revoked', released: false,
    });
  } finally {
    license.applyVendorVerdict(false);
  }

  const publicQuery = await fetch(`http://127.0.0.1:${port}/api/queries/${held.id}`, {
    headers: { cookie },
  });
  assert.strictEqual(publicQuery.status, 200);
  assert.ok(!JSON.stringify(await publicQuery.json()).includes('_releaseTokenHash'));

  const evidence = await fetch(`http://127.0.0.1:${port}/api/export/evidence`, {
    headers: { cookie },
  });
  assert.strictEqual(evidence.status, 200);
  const evidenceWire = JSON.stringify(await evidence.json());
  assert.ok(!evidenceWire.includes('_releaseTokenHash'));
  assert.ok(!evidenceWire.includes(held.releaseToken));
}));

test('held file scan returns a release token for approval polling', async () => withServer(async (port) => {
  const res = await jsonFetch(port, '/api/v1/scan-file', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      filename: 'member-note.txt',
      contentBase64: Buffer.from('Synthetic member SSN 524-71-9043 in a file.').toString('base64'),
      user: 'endpoint@example.test',
      destination: 'desktop-ai-app',
      source: 'endpoint_agent',
      channel: 'file_upload',
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'pending');
  assert.match(body.releaseToken, /^[A-Za-z0-9_-]{32,}$/);
  assert.ok(!JSON.stringify(db.getQuery(body.id)).includes(body.releaseToken));
}));

test('pending justification polling requires its item-specific release token', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(process.env.REDACTWALL_POLICY_PATH, 'utf8');
  try {
    const existingIds = new Set(db.listQueries({ all: true }).map((row) => row.id));
    fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({
      ...JSON.parse(originalPolicy),
      enforcementMode: 'justify',
      blockMinSeverity: 1,
      blockRiskScore: 1,
    }, null, 2));

    const missingReason = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: 'Contact the synthetic borrower at borrower@example.test before proceeding.',
        user: 'analyst@example.test',
        destination: 'chatgpt.com',
        source: 'browser_extension',
        channel: 'submit',
        clientOutcome: 'justified',
        note: '   ',
      },
    });
    assert.strictEqual(missingReason.status, 400, 'the server enforces the business reason, not only browser UI');

    const gate = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: 'Contact the synthetic borrower at borrower@example.test before proceeding.',
        user: 'analyst@example.test',
        destination: 'chatgpt.com',
        source: 'browser_extension',
        channel: 'submit',
      },
    });
    assert.strictEqual(gate.status, 200);
    const held = await gate.json();
    assert.strictEqual(held.status, 'pending_justification');
    assert.match(held.releaseToken, /^[A-Za-z0-9_-]{32,}$/);
    assert.ok(db.getQuery(held.id)._releaseTokenHash);

    const statusUrl = `http://127.0.0.1:${port}/api/v1/status/${held.id}`;
    const noToken = await fetch(statusUrl, { headers: { 'x-api-key': 'unit-ingest-key' } });
    assert.strictEqual(noToken.status, 401);
    const wrongToken = await fetch(statusUrl, {
      headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': 'wrong-token' },
    });
    assert.strictEqual(wrongToken.status, 401);
    const matching = await fetch(statusUrl, {
      headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
    });
    assert.strictEqual(matching.status, 200);
    assert.deepStrictEqual(await matching.json(), { id: held.id, status: 'pending_justification', released: false });

    const wrongResolution = await jsonFetch(port, `/api/v1/justify/${encodeURIComponent(held.id)}`, {
      headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': 'wrong-token' },
      body: { outcome: 'justified', note: 'Approved member-service workflow' },
    });
    assert.strictEqual(wrongResolution.status, 401);

    license.applyVendorVerdict(true);
    try {
      const revoked = await jsonFetch(port, `/api/v1/justify/${encodeURIComponent(held.id)}`, {
        headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
        body: { outcome: 'justified', note: 'Approved member-service workflow' },
      });
      assert.strictEqual(revoked.status, 403);
      assert.deepStrictEqual(await revoked.json(), {
        error: 'license_revoked', status: 'license_revoked', released: false,
      });
      assert.strictEqual(db.getQuery(held.id).status, 'pending_justification');
      assert.ok(db.getQuery(held.id)._rawPrompt, 'revocation leaves held evidence intact');
      assert.ok(db.getQuery(held.id)._releaseTokenHash, 'revocation does not consume authorization');
    } finally {
      license.applyVendorVerdict(false);
    }

    const resolutionNote = 'Approved member 524-71-9043 at borrower@example.test';
    const auditCountBefore = db.listAudit(1000).filter((entry) => entry.queryId === held.id && entry.action === 'JUSTIFIED').length;
    const resolutions = await Promise.all([
      jsonFetch(port, `/api/v1/justify/${encodeURIComponent(held.id)}`, {
        headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
        body: { outcome: 'justified', note: resolutionNote },
      }),
      jsonFetch(port, `/api/v1/justify/${encodeURIComponent(held.id)}`, {
        headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
        body: { outcome: 'justified', note: resolutionNote },
      }),
    ]);
    assert.deepStrictEqual(resolutions.map((response) => response.status).sort(), [200, 409]);
    const resolved = resolutions.find((response) => response.status === 200);
    assert.deepStrictEqual(await resolved.json(), { id: held.id, decision: 'allow', status: 'justified' });

    const created = db.listQueries({ all: true }).filter((row) => !existingIds.has(row.id));
    assert.strictEqual(created.length, 1, 'one browser action creates one durable row');
    assert.strictEqual(created[0].id, held.id);
    assert.strictEqual(created[0].status, 'justified');
    assert.strictEqual(created[0].decisionNote, 'Approved member [US_SSN] at [EMAIL_ADDRESS]');
    assert.strictEqual(created[0]._rawPrompt, undefined, 'terminal justification clears retained raw prompt');
    assert.strictEqual(created[0]._releaseTokenHash, undefined, 'terminal justification clears its bearer token hash');
    assert.strictEqual(db.listQueries({ status: 'pending_justification', all: true }).some((row) => row.id === held.id), false);
    const resolutionAudits = db.listAudit(1000).filter((entry) => entry.queryId === held.id && entry.action === 'JUSTIFIED');
    assert.strictEqual(resolutionAudits.length - auditCountBefore, 1, 'a racing retry cannot append a duplicate resolution audit');
    assert.strictEqual(resolutionAudits[0].detail, 'Approved member [US_SSN] at [EMAIL_ADDRESS]');
    assert.strictEqual(db.verifyAuditChain().ok, true);

    const released = await fetch(statusUrl, {
      headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
    });
    assert.strictEqual(released.status, 200);
    assert.deepStrictEqual(await released.json(), { id: held.id, status: 'justified', released: true });

    const repeat = await jsonFetch(port, `/api/v1/justify/${encodeURIComponent(held.id)}`, {
      headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
      body: { outcome: 'justified', note: 'Duplicate browser retry' },
    });
    assert.strictEqual(repeat.status, 409, 'a resolved hold cannot be terminalized twice');
  } finally {
    fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, originalPolicy);
  }
}));

test('cancelling a pending justification terminalizes its original row and clears retained secrets', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(process.env.REDACTWALL_POLICY_PATH, 'utf8');
  try {
    fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({
      ...JSON.parse(originalPolicy), enforcementMode: 'justify', blockMinSeverity: 1, blockRiskScore: 1,
    }, null, 2));
    const existingIds = new Set(db.listQueries({ all: true }).map((row) => row.id));
    const gate = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: 'Contact cancellation@example.test about the synthetic account update.',
        user: 'cancel-user@example.test',
        destination: 'chatgpt.com',
        source: 'browser_extension',
        channel: 'submit',
      },
    });
    assert.strictEqual(gate.status, 200);
    const held = await gate.json();
    assert.strictEqual(held.status, 'pending_justification');

    const cancel = await jsonFetch(port, `/api/v1/justify/${encodeURIComponent(held.id)}`, {
      headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
      body: { outcome: 'blocked_by_user', note: '' },
    });
    assert.strictEqual(cancel.status, 200);
    assert.deepStrictEqual(await cancel.json(), { id: held.id, decision: 'block', status: 'blocked_by_user' });

    const created = db.listQueries({ all: true }).filter((row) => !existingIds.has(row.id));
    assert.strictEqual(created.length, 1);
    assert.strictEqual(created[0].id, held.id);
    assert.strictEqual(created[0].status, 'blocked_by_user');
    assert.strictEqual(created[0]._rawPrompt, undefined);
    assert.strictEqual(created[0]._releaseTokenHash, undefined);
    const audits = db.listAudit(1000).filter((entry) => entry.queryId === held.id && entry.action === 'SELF_BLOCKED');
    assert.strictEqual(audits.length, 1);
    assert.strictEqual(audits[0].detail, 'User cancelled the justification request');
    assert.strictEqual(db.verifyAuditChain().ok, true);

    const status = await fetch(`http://127.0.0.1:${port}/api/v1/status/${held.id}`, {
      headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': held.releaseToken },
    });
    assert.strictEqual(status.status, 200);
    assert.deepStrictEqual(await status.json(), { id: held.id, status: 'blocked_by_user', released: false });
  } finally {
    fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, originalPolicy);
  }
}));

test('rehydrate fails closed for token vault rows without a release-token hash', async () => withServer(async (port) => {
  const row = db.createQuery({
    status: 'redacted',
    user: 'legacy@example.test',
    destination: 'desktop-ai-app',
    source: 'endpoint_agent',
    channel: 'file_upload',
    prompt: 'Reviewed [[US_SSN_1]].',
    _tokenVault: dataCrypto.seal(JSON.stringify({ '[[US_SSN_1]]': '524-71-9043' })),
  });

  const res = await jsonFetch(port, '/api/v1/rehydrate', {
    headers: { 'x-api-key': 'unit-ingest-key', 'x-release-token': 'anything' },
    body: { id: row.id, text: 'Reviewed [[US_SSN_1]].' },
  });
  assert.strictEqual(res.status, 401);
  assert.deepStrictEqual(await res.json(), { error: 'invalid release token' });
}));

test('release token helper verifies hashes and fails closed on malformed stored hashes', () => {
  const issued = releaseTokens.issueReleaseToken();
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: issued.hash }, issued.token), true);
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: issued.hash }, 'wrong'), false);
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: 'not-hex' }, issued.token), false);
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: 'a'.repeat(63) }, issued.token), false);
  assert.strictEqual(releaseTokens.verifyReleaseToken({ status: 'allowed' }, ''), true);
});

test('a release token for one hold is rejected against every other hold', () => {
  // Confused-deputy isolation: each hold verifies only its own token.
  const holdA = releaseTokens.issueReleaseToken();
  const holdB = releaseTokens.issueReleaseToken();

  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: holdA.hash }, holdA.token), true);
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: holdB.hash }, holdA.token), false, "hold A's token must not open hold B");
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: holdA.hash }, holdB.token), false, "hold B's token must not open hold A");
});

test('release token verification tolerates uppercase stored hashes', () => {
  const issued = releaseTokens.issueReleaseToken();
  assert.strictEqual(releaseTokens.verifyReleaseToken({ _releaseTokenHash: issued.hash.toUpperCase() }, issued.token), true);
});

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.REDACTWALL_POLICY_PATH); } catch {}
});
