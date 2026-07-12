'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-audit-health-'));
process.env.NODE_ENV = 'test';
process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-audit-health';
process.env.REDACTWALL_DATA_KEY = 'unit-data-audit-health';
process.env.INGEST_API_KEY = 'unit-ingest-audit-health';
process.env.REDACTWALL_DB_PATH = path.join(root, `audit-${crypto.randomBytes(6).toString('hex')}.db`);
process.env.REDACTWALL_POLICY_PATH = path.join(root, 'policy.json');
fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({ enforcementMode: 'block' }));

const app = require('../server/app');
const db = require('../server/db');
const { listen } = require('./support/listen');

function waitImmediate() {
  return new Promise((resolve) => setImmediate(resolve));
}

test('checkpoint EACCES makes readiness fail and freezes audit-coupled mutation until synchronous repair', async (t) => {
  const checkpointPath = path.resolve(db._auditAnchorPaths.checkpointPath);
  const beforeCheckpoint = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
  // Checkpoint publication commits a staged .tmp file through an exclusive
  // hard link; rollback restores from quarantine through linkSync too, so the
  // denial must match only the staged-candidate source.
  const originalLink = fs.linkSync;
  let denyCheckpointPublication = true;
  fs.linkSync = function injectedCheckpointLink(source, destination) {
    if (denyCheckpointPublication
        && path.resolve(destination) === checkpointPath
        && String(source).endsWith('.tmp')) {
      const error = new Error('synthetic checkpoint publication denial');
      error.code = 'EACCES';
      throw error;
    }
    return originalLink.call(this, source, destination);
  };
  t.after(() => { fs.linkSync = originalLink; });

  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;

  const committed = db.appendAudit({
    action: 'CHECKPOINT_PUBLICATION_FAILED',
    actor: 'audit-health-test',
    detail: 'sanitized failure proof',
  });
  await waitImmediate();
  assert.strictEqual(db.auditHealth().ok, false);
  assert.ok(db.listAudit(50).some((entry) => entry.id === committed.id), 'the row committed before sidecar publication failed');
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(checkpointPath, 'utf8')), beforeCheckpoint);

  const readiness = await fetch(`http://127.0.0.1:${port}/readyz`);
  assert.strictEqual(readiness.status, 503);
  const readinessBody = await readiness.json();
  assert.deepStrictEqual({
    ready: readinessBody.ready,
    database: readinessBody.database,
    audit: readinessBody.audit,
    error: readinessBody.error,
  }, {
    ready: false,
    database: true,
    audit: false,
    error: 'audit_checkpoint_unavailable',
  });
  assert.strictEqual(readinessBody.configuration, app.currentPreflight().level);

  let mutationCalled = false;
  assert.throws(
    () => db.mutateWithAudit(
      () => { mutationCalled = true; return { changed: true }; },
      { action: 'MUST_NOT_COMMIT', actor: 'audit-health-test', detail: 'sanitized' },
    ),
    (error) => error && error.code === 'REDACTWALL_AUDIT_CHECKPOINT_UNHEALTHY',
  );
  assert.strictEqual(mutationCalled, false);
  assert.ok(!db.listAudit(50).some((entry) => entry.action === 'MUST_NOT_COMMIT'));

  denyCheckpointPublication = false;
  const recovered = db.appendAudit({
    action: 'CHECKPOINT_PUBLICATION_RECOVERED',
    actor: 'audit-health-test',
    detail: 'sanitized recovery proof',
  });
  await waitImmediate();
  assert.strictEqual(db.auditHealth().ok, true);
  assert.ok(db.listAudit(50).some((entry) => entry.id === recovered.id));
  assert.strictEqual(db.verifyAuditChain().ok, true);
  const recoveredReadiness = await fetch(`http://127.0.0.1:${port}/readyz`);
  const recoveredBody = await recoveredReadiness.text();
  assert.strictEqual(recoveredReadiness.status, 200, recoveredBody);
});

test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(root, { recursive: true, force: true });
});
