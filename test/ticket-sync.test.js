'use strict';
/** Two-way ticket state stays metadata-only and prompt-free. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-ticket-sync-' + crypto.randomBytes(6).toString('hex') + '.db');

const db = require('../server/db');
const notifiers = require('../server/notifiers');
const workflow = require('../server/workflow');
const ticketSync = require('../server/ticket-sync');

function createTicketQuery(query) {
  return db.createQueryWithAudit(query, {
    action: 'TEST_TICKET_QUERY_CREATED',
    actor: 'ticket-test',
    detail: 'transactional test fixture',
  }).row;
}

const JIRA_CHANNEL = {
  type: 'jira',
  name: 'jira',
  url: 'https://cu.atlassian.net/rest/api/3/issue',
  email: 'sec@example.test',
  token: 'unit-jira-token',
  projectKey: 'SEC',
  issueType: 'Task',
};

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

test('jira ticket creation captures the issue key as delivery metadata', async () => {
  const query = createTicketQuery({
    status: 'pending',
    user: 'analyst@example.test',
    destination: 'chatgpt.com',
    redactedPrompt: '[US_SSN] paste blocked',
    assignedGroup: 'security',
  });
  const result = await workflow.emitAndPersistApprovalNotification(query, {
    db,
    channels: [JIRA_CHANNEL],
    fetch: async (url, opts) => {
      assert.strictEqual(url, JIRA_CHANNEL.url);
      assert.ok(!String(opts.body).includes('524-71-9043'));
      return jsonResponse({ id: '10001', key: 'SEC-42' }, 201);
    },
  });
  assert.strictEqual(result.sent, true);
  assert.strictEqual(result.results[0].externalId, 'SEC-42');

  const stored = db.getQuery(query.id);
  assert.strictEqual(stored.ticketRefs.length, 1);
  assert.deepStrictEqual(
    { channel: stored.ticketRefs[0].channel, externalId: stored.ticketRefs[0].externalId, status: stored.ticketRefs[0].status },
    { channel: 'jira', externalId: 'SEC-42', status: 'open' },
  );
});

test('ticket sync stamps jira status back onto the query without ticket bodies', async () => {
  const syncQuery = createTicketQuery({
    status: 'pending',
    user: 'sync@example.test',
    destination: 'chatgpt.com',
    ticketRefs: [{ channel: 'jira', externalId: 'SEC-142', status: 'open', statusCategory: 'new', syncedAt: null }],
  });

  const result = await ticketSync.syncTicketStatuses({
    db,
    channels: new Map([['jira', JIRA_CHANNEL]]),
    fetchImpl: async (url, opts) => {
      if (!url.includes('/SEC-142?')) return { ok: false, status: 404 };
      assert.strictEqual(url, 'https://cu.atlassian.net/rest/api/3/issue/SEC-142?fields=status');
      assert.match(opts.headers.Authorization, /^Basic /);
      return jsonResponse({
        fields: {
          status: { name: 'In Review', statusCategory: { key: 'indeterminate' } },
          summary: 'SENSITIVE ticket summary must never be stored',
        },
      });
    },
  });
  assert.strictEqual(result.updated, 1);

  const stored = db.getQuery(syncQuery.id);
  assert.strictEqual(stored.ticketRefs[0].status, 'In Review');
  assert.strictEqual(stored.ticketRefs[0].statusCategory, 'indeterminate');
  assert.ok(stored.ticketRefs[0].syncedAt);
  assert.ok(!JSON.stringify(stored).includes('SENSITIVE ticket summary'), 'ticket bodies are never stored');
  assert.ok(db.listAudit(10).some((entry) => entry.action === 'TICKET_STATUS_SYNCED'
    && /jira:SEC-142=In Review/.test(entry.detail)));
});

test('ticket sync skips done tickets and tolerates fetch failures', async () => {
  const doneQuery = createTicketQuery({
    status: 'approved',
    user: 'analyst@example.test',
    destination: 'chatgpt.com',
    ticketRefs: [{ channel: 'jira', externalId: 'SEC-77', status: 'Done', statusCategory: 'done', syncedAt: null }],
  });
  createTicketQuery({
    status: 'pending',
    user: 'open@example.test',
    destination: 'chatgpt.com',
    ticketRefs: [{ channel: 'jira', externalId: 'SEC-42', status: 'open', statusCategory: 'new', syncedAt: null }],
  });
  let fetched = 0;
  const result = await ticketSync.syncTicketStatuses({
    db,
    channels: new Map([['jira', JIRA_CHANNEL]]),
    fetchImpl: async (url) => {
      fetched += 1;
      if (url.includes('SEC-42')) throw new Error('jira offline');
      return { ok: false, status: 500 };
    },
  });
  assert.ok(fetched >= 1, 'open tickets are polled');
  assert.strictEqual(result.updated, 0, 'failures never fabricate a status change');
  assert.strictEqual(db.getQuery(doneQuery.id).ticketRefs[0].status, 'Done', 'done tickets are left alone');
});

test('linear status fetch uses the graphql state shape', async () => {
  const channel = { type: 'linear', name: 'linear', url: 'https://api.linear.app/graphql', token: 'unit-linear-token' };
  const latest = await ticketSync.fetchLinearStatus(channel, 'PW-9', async (url, opts) => {
    assert.strictEqual(url, channel.url);
    assert.strictEqual(JSON.parse(opts.body).variables.id, 'PW-9');
    assert.strictEqual(opts.redirect, 'error');
    return jsonResponse({ data: { issue: { state: { name: 'Done', type: 'completed' } } } });
  });
  assert.deepStrictEqual(latest, { status: 'Done', statusCategory: 'completed' });
});

test('ticket status polling fails closed on oversized or unstreamable provider bodies', async () => {
  const oversized = await ticketSync.fetchJiraStatus(JIRA_CHANNEL, 'SEC-42', async (_url, opts) => {
    assert.strictEqual(opts.redirect, 'error');
    return jsonResponse({ fields: { status: { name: 'Open' } } }, 200, {
      'content-length': String(256 * 1024 + 1),
    });
  });
  assert.strictEqual(oversized, null);

  const unstreamable = await ticketSync.fetchLinearStatus(
    { type: 'linear', name: 'linear', url: 'https://api.linear.app/graphql', token: 'unit-linear-token' },
    'PW-9',
    async () => ({ ok: true, status: 200, json: async () => ({ data: { issue: { state: { name: 'Done' } } } }) }),
  );
  assert.strictEqual(unstreamable, null);
});

test('ticket status metadata is sanitized before query or audit persistence', async () => {
  const query = createTicketQuery({
    status: 'pending',
    user: 'privacy@example.test',
    destination: 'chatgpt.com',
    ticketRefs: [{ channel: 'jira', externalId: 'SEC-188', status: 'open', statusCategory: 'new', syncedAt: null }],
  });
  const raw = '123-45-6789';
  const result = await ticketSync.syncTicketStatuses({
    db,
    channels: new Map([['jira', JIRA_CHANNEL]]),
    fetchImpl: async (url) => url.includes('/SEC-188?')
      ? jsonResponse({ fields: { status: { name: `Member SSN ${raw}`, statusCategory: { key: `secret-${raw}` } } } })
      : { ok: false, status: 404 },
  });
  assert.strictEqual(result.updated, 1);
  const wire = JSON.stringify({ query: db.getQuery(query.id), audit: db.listAudit(50) });
  assert.ok(!wire.includes(raw));
  assert.match(wire, /US_SSN/);
});

test('ticket, notification, and escalation audit failures roll back exact query bytes', async () => {
  const trigger = (name, action) => db._db.exec(`
    CREATE TRIGGER ${name} BEFORE INSERT ON audit
    WHEN NEW.action ${action}
    BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END;
  `);
  const drop = (name) => db._db.exec(`DROP TRIGGER IF EXISTS ${name}`);

  const ticket = createTicketQuery({
    status: 'pending',
    user: 'rollback-ticket@example.test',
    destination: 'chatgpt.com',
    ticketRefs: [{ channel: 'jira', externalId: 'SEC-99', status: 'open', statusCategory: 'new', syncedAt: null }],
  });
  const ticketBefore = JSON.stringify(db.getQuery(ticket.id));
  trigger('fail_ticket_sync_audit', "= 'TICKET_STATUS_SYNCED'");
  await assert.rejects(ticketSync.syncTicketStatuses({
    db,
    channels: new Map([['jira', JIRA_CHANNEL]]),
    fetchImpl: async () => jsonResponse({ fields: { status: { name: 'Done', statusCategory: { key: 'done' } } } }),
  }), /forced audit failure/);
  drop('fail_ticket_sync_audit');
  assert.strictEqual(JSON.stringify(db.getQuery(ticket.id)), ticketBefore);

  const notified = createTicketQuery({
    status: 'pending',
    user: 'rollback-notify@example.test',
    destination: 'chatgpt.com',
    assignedGroup: 'security',
    notificationStatus: 'not_configured',
  });
  const notifiedBefore = JSON.stringify(db.getQuery(notified.id));
  trigger('fail_notification_audit', "LIKE 'APPROVAL_NOTIFICATION_%'");
  await assert.rejects(workflow.emitAndPersistApprovalNotification(notified, {
    db,
    channels: [{ type: 'webhook', name: 'webhook', url: 'https://notify.example.test/hook' }],
    fetch: async () => ({ ok: true, status: 202, body: { cancel: async () => {} } }),
  }), /forced audit failure/);
  drop('fail_notification_audit');
  assert.strictEqual(JSON.stringify(db.getQuery(notified.id)), notifiedBefore);

  const escalation = createTicketQuery({
    status: 'pending',
    user: 'rollback-escalation@example.test',
    destination: 'chatgpt.com',
    assignedGroup: 'security',
    assignedRole: 'approver',
    slaDueAt: '2026-01-01T00:00:00.000Z',
  });
  const escalationBefore = JSON.stringify(db.getQuery(escalation.id));
  trigger('fail_escalation_audit', "= 'APPROVAL_ESCALATED'");
  assert.throws(() => workflow.escalateDueApprovals({
    db, now: new Date('2026-01-02T00:00:00.000Z'), notify: false,
  }), /forced audit failure/);
  drop('fail_escalation_audit');
  assert.strictEqual(JSON.stringify(db.getQuery(escalation.id)), escalationBefore);
  assert.strictEqual(db.verifyAuditChain().ok, true);
});
