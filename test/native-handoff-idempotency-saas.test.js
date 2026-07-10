'use strict';
/** Native handoff idempotency must carry the customer-silo tenant itself. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-native-saas-'));
const policyPath = path.join(root, 'policy.json');
fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), policyPath);
process.env.NODE_ENV = 'test';
process.env.ADMIN_PASSWORD = 'native-saas-admin';
process.env.REDACTWALL_SECRET = 'native-saas-secret-at-least-thirty-two-characters';
process.env.REDACTWALL_DATA_KEY = 'native-saas-data-key-at-least-thirty-two-characters';
process.env.INGEST_API_KEY = 'native-saas-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(root, 'redactwall.db');
process.env.REDACTWALL_AUDIT_DIR = path.join(root, 'audit-integrity');
process.env.REDACTWALL_POLICY_PATH = policyPath;
process.env.REDACTWALL_ENV_PATH = path.join(root, 'missing.env');
process.env.REDACTWALL_ALLOW_INSECURE_SERVER = '1';
process.env.REDACTWALL_SAAS_MODE = 'true';
process.env.REDACTWALL_TENANT_ID = 'cu-native-saas';
process.env.REDACTWALL_SEAT_LIMIT = '10';
process.env.REDACTWALL_REQUIRE_TENANT_CONTEXT = 'true';
process.env.REDACTWALL_REQUIRE_USER_IDENTITY = 'true';

const app = require('../server/app');
const db = require('../server/db');
const parsePool = require('../server/parse-pool');
const { listen, loopbackHttpFetch } = require('./support/listen');
const { processNativeHandoffFile, nativeHandoff } = require('../sensors/endpoint-agent/agent');

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

test('signed native SaaS handoff survives a lost response with one tenant-scoped commit', async (t) => {
  const handoffDir = path.join(root, 'handoff');
  const sourceDir = path.join(root, 'source');
  nativeHandoff.ensurePrivateDirectory(handoffDir);
  fs.mkdirSync(sourceDir, { recursive: true });
  const source = path.join(sourceDir, 'evidence.txt');
  fs.writeFileSync(source, 'Synthetic member SSN 524-71-9043.');
  const handoffPath = path.join(handoffDir, 'event.json');
  const secret = 'native-saas-handoff-secret-00000000000000001';
  const now = new Date();
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: crypto.randomUUID(),
    createdAt: now.toISOString(),
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-saas@example.test',
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
  const bodies = [];
  let calls = 0;
  const loseFirstCommittedResponse = async (url, options = {}) => {
    const response = await loopbackHttpFetch(url, options);
    if (!String(url).endsWith('/api/v1/gate')) return response;
    calls += 1;
    bodies.push(JSON.parse(options.body));
    if (calls === 1) {
      await response.arrayBuffer();
      throw new Error('synthetic SaaS response lost after commit');
    }
    return response;
  };

  const originalError = console.error;
  console.error = () => {};
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

  assert.strictEqual(calls, 2);
  assert.ok(bodies.every((body) => body.orgId === 'cu-native-saas'));
  assert.deepStrictEqual(bodies[1].idempotency, bodies[0].idempotency);
  assert.strictEqual(result.status, 'processed');
  assert.strictEqual(result.result.status, 'pending');
  assert.strictEqual(result.result.id, result.terminal.recordId);
  const queries = db.listQueries({ all: true, orgId: 'cu-native-saas' })
    .filter((row) => row.source === 'endpoint_agent');
  assert.strictEqual(queries.length, 1);
  assert.strictEqual(queries[0].id, result.result.id);
  assert.strictEqual(queries[0].orgId, 'cu-native-saas');
  const mapping = db._db.prepare(
    'SELECT orgId, queryId, replaySnapshot FROM ingest_idempotency WHERE scope = ? AND keyHash = ?',
  ).all(bodies[0].idempotency.scope, bodies[0].idempotency.key);
  assert.strictEqual(mapping.length, 1);
  assert.strictEqual(mapping[0].orgId, 'cu-native-saas');
  assert.strictEqual(mapping[0].queryId, result.result.id);
  assert.strictEqual(JSON.parse(mapping[0].replaySnapshot).status, 'pending');
  const audit = db.listAudit(1000).filter((entry) => entry.queryId === result.result.id);
  assert.strictEqual(audit.filter((entry) => entry.action === 'BLOCKED').length, 1);
  assert.ok(audit.some((entry) => entry.ingestIdempotency));
  assert.ok(!JSON.stringify({ queries, audit, mapping }).includes('524-71-9043'));
  assert.strictEqual(db.verifyAuditChain().ok, true);
});
