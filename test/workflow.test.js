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
