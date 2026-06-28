'use strict';
/** Approval workflow persistence should not mutate evidence without audit. */
const test = require('node:test');
const assert = require('node:assert');
const workflow = require('../server/workflow');

function fakeDb(query) {
  const calls = { updates: [], audits: [] };
  return {
    calls,
    getQuery: () => query,
    updateQuery: (id, patch) => {
      calls.updates.push({ id, patch });
      query = { ...query, ...patch };
      return query;
    },
    appendAudit: (event) => {
      calls.audits.push(event);
      return event;
    },
  };
}

test('disabled or non-routeable approval notifications do not mutate queries', async () => {
  const allowedDb = fakeDb({ id: 'q_allowed', status: 'allowed' });
  const allowed = await workflow.emitAndPersistApprovalNotification(allowedDb.getQuery(), {
    db: allowedDb,
    env: {},
  });
  assert.strictEqual(allowed.reason, 'not_routeable');
  assert.deepStrictEqual(allowedDb.calls.updates, []);
  assert.deepStrictEqual(allowedDb.calls.audits, []);

  const pendingDb = fakeDb({
    id: 'q_pending',
    status: 'pending',
    assignedGroup: 'security',
    assignedRole: 'security_admin',
    slaDueAt: '2026-06-28T10:00:00.000Z',
    notificationStatus: 'not_configured',
  });
  const pending = await workflow.emitAndPersistApprovalNotification(pendingDb.getQuery(), {
    db: pendingDb,
    env: {},
  });
  assert.strictEqual(pending.reason, 'disabled');
  assert.deepStrictEqual(pendingDb.calls.updates, []);
  assert.deepStrictEqual(pendingDb.calls.audits, []);
});

test('ticket notification channel persists delivery status without prompt content', async () => {
  const db = fakeDb({
    id: 'q_ticket',
    status: 'pending',
    destination: 'chatgpt.com',
    findings: [{ type: 'US_SSN', value: '524-71-9043' }],
    reasons: ['Hard-stop entity present: US_SSN'],
    assignedGroup: 'compliance',
    assignedRole: 'approver',
    workflowReason: 'detector:US_SSN',
    slaDueAt: '2026-06-28T10:00:00.000Z',
    notificationStatus: 'not_configured',
    redactedPrompt: 'Member Jane has SSN [US_SSN]',
    _rawPrompt: 'sealed raw 524-71-9043',
  });

  const bodies = [];
  const result = await workflow.emitAndPersistApprovalNotification(db.getQuery(), {
    db,
    channels: [{ type: 'ticket', name: 'ticket', url: 'https://tickets.example.test' }],
    fetch: async (_url, opts) => {
      bodies.push(opts.body);
      return { ok: true, status: 201 };
    },
    now: new Date('2026-06-28T08:00:00.000Z'),
  });

  assert.strictEqual(result.status, 'sent');
  assert.deepStrictEqual(db.calls.updates[0].patch.notificationChannels, ['ticket']);
  assert.strictEqual(db.calls.updates[0].patch.notificationAttemptCount, 1);
  assert.strictEqual(db.calls.audits[0].action, 'APPROVAL_NOTIFICATION_SENT');
  assert.match(db.calls.audits[0].detail, /channels=ticket/);
  assert.ok(!bodies.join('\n').includes('524-71-9043'));
  assert.ok(!bodies.join('\n').includes('Member Jane'));
  assert.ok(!bodies.join('\n').includes('sealed raw'));
});
