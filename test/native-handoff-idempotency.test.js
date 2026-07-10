'use strict';
/**
 * A native handoff may lose the HTTP response after /api/v1/gate commits.
 * Its retry must recover the original durable record instead of creating a
 * second query, audit, or approval notification.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-native-idempotency-'));
const policyPath = path.join(root, 'policy.json');
fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), policyPath);
process.env.NODE_ENV = 'test';
process.env.ADMIN_PASSWORD = 'native-idempotency-admin';
process.env.REDACTWALL_SECRET = 'native-idempotency-secret-at-least-thirty-two-characters';
process.env.REDACTWALL_DATA_KEY = 'native-idempotency-data-key-at-least-thirty-two-characters';
process.env.INGEST_API_KEY = 'native-idempotency-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(root, 'redactwall.db');
process.env.REDACTWALL_AUDIT_DIR = path.join(root, 'audit-integrity');
process.env.REDACTWALL_POLICY_PATH = policyPath;
process.env.REDACTWALL_ENV_PATH = path.join(root, 'missing.env');
process.env.REDACTWALL_ALLOW_INSECURE_SERVER = '1';

const app = require('../server/app');
const db = require('../server/db');
const parsePool = require('../server/parse-pool');
const { listen, loopbackHttpFetch } = require('./support/listen');
const { processNativeHandoffFile, nativeHandoff } = require('../sensors/endpoint-agent/agent');

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

test('commit then lost native response retries to one query, audit, and approval record', async (t) => {
  const handoffDir = path.join(root, 'handoff');
  const sourceDir = path.join(root, 'source');
  nativeHandoff.ensurePrivateDirectory(handoffDir);
  fs.mkdirSync(sourceDir, { recursive: true });
  const source = path.join(sourceDir, 'evidence.txt');
  fs.writeFileSync(source, 'Synthetic member SSN 524-71-9043.');
  const handoffPath = path.join(handoffDir, 'event.json');
  const secret = 'native-handoff-idempotency-secret-0000000000001';
  const now = new Date();
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: crypto.randomUUID(),
    createdAt: now.toISOString(),
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-idempotency@example.test',
    nonce: crypto.randomBytes(16).toString('hex'),
  }, secret);
  fs.writeFileSync(handoffPath, JSON.stringify(event));

  const server = await listen(app);
  t.after(async () => {
    await close(server);
    parsePool.shutdown();
    try { db._db.close(); } catch {}
    fs.rmSync(root, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const gateBodies = [];
  let gateCalls = 0;
  const loseFirstCommittedResponse = async (url, options = {}) => {
    const response = await loopbackHttpFetch(url, options);
    if (!String(url).endsWith('/api/v1/gate')) return response;
    gateCalls += 1;
    gateBodies.push(JSON.parse(options.body));
    if (gateCalls === 1) {
      await response.arrayBuffer();
      throw new Error('synthetic response lost after commit');
    }
    return response;
  };

  const errors = [];
  const originalError = console.error;
  console.error = (...args) => errors.push(args.join(' '));
  let result;
  try {
    result = await processNativeHandoffFile(handoffPath, {
      secret,
      now,
      server: base,
      key: process.env.INGEST_API_KEY,
      fetchImpl: loseFirstCommittedResponse,
      policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    });
  } finally {
    console.error = originalError;
  }

  assert.strictEqual(gateCalls, 2, 'the lost response must exercise one real retry');
  assert.match(errors.join('\n'), /synthetic response lost after commit/);
  assert.strictEqual(result.status, 'processed');
  assert.strictEqual(result.result.status, 'pending');
  assert.strictEqual(result.terminal.status, 'pending');
  assert.strictEqual(result.result.id, result.terminal.recordId);
  assert.strictEqual(gateBodies[0].idempotency.scope, 'native_handoff_v1');
  assert.match(gateBodies[0].idempotency.key, /^[0-9a-f]{64}$/);
  assert.deepStrictEqual(gateBodies[1].idempotency, gateBodies[0].idempotency,
    'fallback reporting must remain bound to the same signed event');
  assert.strictEqual(gateBodies[0].clientOutcome, undefined);
  assert.strictEqual(gateBodies[1].clientOutcome, 'scan_unavailable');

  await new Promise((resolve) => setTimeout(resolve, 250));
  const queries = db.listQueries({ all: true }).filter((row) => row.source === 'endpoint_agent');
  assert.strictEqual(queries.length, 1, 'one native event creates one durable query');
  assert.strictEqual(queries[0].id, result.result.id);
  assert.ok(!JSON.stringify(queries[0]).includes('524-71-9043'));
  const audit = db.listAudit(1000).filter((entry) => entry.queryId === queries[0].id);
  assert.strictEqual(audit.filter((entry) => entry.action === 'BLOCKED').length, 1,
    'the gate decision audit is committed once');
  assert.ok(audit.filter((entry) => entry.action === 'APPROVAL_ROUTED').length <= 1,
    'approval routing is not duplicated');
  assert.ok(audit.every((entry) => !JSON.stringify(entry).includes('524-71-9043')));
  assert.deepStrictEqual(db.verifyAuditChain().ok, true);

  const gate = async (body) => {
    const response = await loopbackHttpFetch(`${base}/api/v1/gate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': process.env.INGEST_API_KEY },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  };

  const transition = db.transitionQueryWithAudit(
    result.result.id,
    { status: 'pending' },
    { status: 'approved', decisionNote: 'approved after native hold' },
    { action: 'APPROVED', actor: 'native-idempotency-test', detail: 'approved synthetic native hold' },
  );
  assert.strictEqual(transition.outcome, 'updated');
  assert.strictEqual(db.getQuery(result.result.id).status, 'approved');
  const afterApprovalRetry = await gate(gateBodies[0]);
  assert.strictEqual(afterApprovalRetry.status, 200);
  assert.strictEqual(afterApprovalRetry.body.id, result.result.id);
  assert.strictEqual(afterApprovalRetry.body.decision, 'block');
  assert.strictEqual(afterApprovalRetry.body.status, 'pending',
    'replay semantics stay immutable after the live query is approved');
  assert.strictEqual(afterApprovalRetry.body.idempotentReplay, true);
  assert.strictEqual(Object.hasOwn(afterApprovalRetry.body, 'releaseToken'), false);
  const postApprovalAudit = db.listAudit(1000).filter((entry) => entry.queryId === result.result.id);
  assert.strictEqual(postApprovalAudit.filter((entry) => entry.action === 'BLOCKED').length, 1);
  assert.strictEqual(postApprovalAudit.filter((entry) => entry.action === 'APPROVED').length, 1);

  const mappingStatement = db._db.prepare(
    'SELECT replaySnapshot FROM ingest_idempotency WHERE queryId = ?',
  );
  const updateSnapshot = db._db.prepare(
    'UPDATE ingest_idempotency SET replaySnapshot = ? WHERE queryId = ?',
  );
  const originalSnapshot = mappingStatement.get(result.result.id).replaySnapshot;
  const assertSnapshotTamperFailsClosed = async (tampered) => {
    updateSnapshot.run(tampered, result.result.id);
    const failed = await gate(gateBodies[0]);
    assert.strictEqual(failed.status, 500);
    assert.deepStrictEqual(failed.body, { error: 'internal_error' });
    assert.strictEqual(db.listQueries({ all: true }).filter((row) => row.id === result.result.id).length, 1);
    updateSnapshot.run(originalSnapshot, result.result.id);
  };
  await assertSnapshotTamperFailsClosed('{malformed');
  await assertSnapshotTamperFailsClosed(JSON.stringify({
    ...JSON.parse(originalSnapshot),
    decision: 'allow',
  }));
  assert.strictEqual(db._internal.validIngestReplaySnapshot({
    ...JSON.parse(originalSnapshot),
    decision: 'allow',
  }), false, 'contradictory decision and status are structurally invalid');

  const indexedAudit = db._db.prepare(
    'SELECT id, ingestIdentityHash FROM audit WHERE queryId = ? AND ingestIdentityHash IS NOT NULL',
  ).get(result.result.id);
  assert.ok(indexedAudit);
  assert.match(indexedAudit.ingestIdentityHash, /^[0-9a-f]{64}$/);
  assert.throws(
    () => db._db.prepare('UPDATE audit SET ingestIdentityHash = ? WHERE id = ?')
      .run('0'.repeat(64), indexedAudit.id),
    (error) => error && error.code === 'SQLITE_ERROR'
      && /generated|append-only/i.test(String(error.message || '')),
    'the indexed identity is protected by the append-only audit guard',
  );
  const deletedMappings = db._db.prepare(
    'DELETE FROM ingest_idempotency WHERE queryId = ?',
  ).run(result.result.id);
  assert.strictEqual(deletedMappings.changes, 1);
  const afterMappingDeletion = await gate(gateBodies[0]);
  assert.strictEqual(afterMappingDeletion.status, 200);
  assert.strictEqual(afterMappingDeletion.body.id, result.result.id);
  assert.strictEqual(afterMappingDeletion.body.decision, 'block');
  assert.strictEqual(afterMappingDeletion.body.status, 'pending');
  assert.strictEqual(afterMappingDeletion.body.idempotentReplay, true);
  assert.strictEqual(db._db.prepare(
    'SELECT COUNT(*) AS n FROM ingest_idempotency WHERE queryId = ?',
  ).get(result.result.id).n, 0, 'replay recovers from immutable audit evidence without trusting a replacement map');
  assert.strictEqual(db.listQueries({ all: true }).filter((row) => row.id === result.result.id).length, 1);
  const postDeletionAudit = db.listAudit(1000).filter((entry) => entry.queryId === result.result.id);
  assert.strictEqual(postDeletionAudit.filter((entry) => entry.action === 'BLOCKED').length, 1);
  assert.strictEqual(postDeletionAudit.filter((entry) => entry.action === 'APPROVED').length, 1);
  assert.strictEqual(db.verifyAuditChain().ok, true);

  const scopedKey = 'd'.repeat(64);
  const nativeContext = {
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: { name: 'endpoint_agent', version: '1.0.0', platform: 'test' },
    destination: 'Desktop AI',
    user: 'tenant-scope@example.test',
    clientOutcome: 'allowed',
    idempotency: { scope: 'native_handoff_v1', key: scopedKey },
  };
  const firstTenant = await gate({ ...nativeContext, orgId: 'org-a', prompt: 'Ordinary public schedule.' });
  assert.strictEqual(firstTenant.status, 200);
  const reused = await gate({
    ...nativeContext,
    orgId: 'org-a',
    prompt: 'Different retry body with synthetic SSN 123-45-6789.',
    clientOutcome: 'scan_unavailable',
  });
  assert.strictEqual(reused.status, 200);
  assert.strictEqual(reused.body.id, firstTenant.body.id);
  assert.strictEqual(reused.body.decision, 'allow');
  assert.strictEqual(reused.body.status, 'allowed');
  assert.strictEqual(reused.body.idempotentReplay, true);
  assert.strictEqual(Object.hasOwn(reused.body, 'releaseToken'), false);
  assert.strictEqual(Object.hasOwn(reused.body, 'redactedPrompt'), false);
  assert.ok(!JSON.stringify(reused.body).includes('123-45-6789'));

  const secondTenant = await gate({ ...nativeContext, orgId: 'org-b', prompt: 'Ordinary public schedule.' });
  assert.strictEqual(secondTenant.status, 200);
  assert.notStrictEqual(secondTenant.body.id, firstTenant.body.id,
    'the same opaque key in another normalized tenant scope is independent');

  const malformed = await gate({
    ...nativeContext,
    orgId: 'org-c',
    prompt: 'Ordinary public schedule.',
    idempotency: { scope: 'native_handoff_v1', key: 'not-a-digest' },
  });
  assert.strictEqual(malformed.status, 400);
  const wrongSensor = await gate({
    ...nativeContext,
    orgId: 'org-c',
    prompt: 'Ordinary public schedule.',
    source: 'browser_extension',
  });
  assert.strictEqual(wrongSensor.status, 400);
});
