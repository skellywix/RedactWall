'use strict';
/** Approval notification status and escalation workflow. */
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
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-workflow-notify-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-workflow-notify-policy-' + crypto.randomBytes(6).toString('hex') + '.json');
process.env.APPROVAL_NOTIFY_WEBHOOK_URL = 'https://approval.example.test/hook';

fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
  rawRetentionDays: 30,
}, null, 2));

const app = require('../server/app');
const { listen, loopbackHttpFetch } = require('./support/listen');
const db = require('../server/db');


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
  return loopbackHttpFetch(`http://127.0.0.1:${port}${apiPath}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function waitFor(fn, label, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = fn();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail(`timed out waiting for ${label}`);
}

test('blocked prompt sends sanitized approval notification and persists delivery status', async () => withServer(async (port) => {
  const originalFetch = global.fetch;
  const sent = [];
  global.fetch = async (url, opts) => {
    if (String(url) === process.env.APPROVAL_NOTIFY_WEBHOOK_URL) {
      sent.push(JSON.parse(opts.body));
      return { ok: true, status: 202, json: async () => ({ ok: true }) };
    }
    return originalFetch(url, opts);
  };

  try {
    const secret = '524-71-9043';
    const res = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: 'Please review member SSN ' + secret,
        user: 'analyst@example.test',
        destination: 'chatgpt.com',
        source: 'browser_extension',
        channel: 'submit',
      },
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.status, 'pending');

    const stored = await waitFor(() => {
      const q = db.getQuery(body.id);
      return q && q.notificationStatus === 'sent' ? q : null;
    }, 'initial approval notification persistence');
    assert.deepStrictEqual(stored.notificationChannels, ['webhook']);
    assert.strictEqual(stored.notificationAttemptCount, 1);
    assert.match(stored.notificationLastAttemptAt, /^\d{4}-\d{2}-\d{2}T/);
    assert.strictEqual(sent.length, 1);
    assert.strictEqual(sent[0].action, 'APPROVAL_ROUTED');
    assert.strictEqual(sent[0].workflow.assignedGroup, 'security');
    const wire = JSON.stringify(sent[0]);
    assert.ok(!wire.includes(secret));
    assert.ok(!wire.includes('Please review member'));
    assert.ok(db.listAudit(20).some((entry) => entry.action === 'APPROVAL_NOTIFICATION_SENT' && entry.queryId === body.id));
  } finally {
    global.fetch = originalFetch;
  }
}));

test('SLA escalation persists state, audits the event, and sends a second notification', async () => withServer(async (port) => {
  const originalFetch = global.fetch;
  const sent = [];
  global.fetch = async (url, opts) => {
    if (String(url) === process.env.APPROVAL_NOTIFY_WEBHOOK_URL) {
      sent.push(JSON.parse(opts.body));
      return { ok: true, status: 202, json: async () => ({ ok: true }) };
    }
    return originalFetch(url, opts);
  };

  try {
    const res = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: 'Member SSN 524-71-9043 needs exception review.',
        user: 'analyst@example.test',
        destination: 'chatgpt.com',
        source: 'browser_extension',
        channel: 'submit',
      },
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    const initial = await waitFor(() => {
      const q = db.getQuery(body.id);
      return q && q.notificationAttemptCount === 1 ? q : null;
    }, 'initial escalation notification attempt');

    const due = new Date(Date.parse(initial.slaDueAt) + 1000);
    const result = app.runWorkflowEscalation({ now: due, notify: true });
    assert.ok(result.escalated.some((row) => row.id === body.id));

    const escalated = await waitFor(() => {
      const q = db.getQuery(body.id);
      return q && q.escalatedAt && q.notificationAttemptCount === 2 ? q : null;
    }, 'escalation notification persistence');
    assert.strictEqual(escalated.assignedRole, 'security_admin');
    assert.strictEqual(escalated.escalationReason, 'sla_due');
    assert.ok(sent.some((payload) => payload.action === 'APPROVAL_ESCALATED'));
    assert.ok(db.listAudit(50).some((entry) => entry.action === 'APPROVAL_ESCALATED' && entry.queryId === body.id));
    assert.ok(db.listAudit(50).filter((entry) => entry.action === 'APPROVAL_NOTIFICATION_SENT' && entry.queryId === body.id).length >= 2);
  } finally {
    global.fetch = originalFetch;
  }
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.REDACTWALL_POLICY_PATH); } catch {}
  delete process.env.APPROVAL_NOTIFY_WEBHOOK_URL;
});
