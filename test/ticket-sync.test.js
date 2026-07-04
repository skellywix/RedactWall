'use strict';
/** Two-way ticket state stays metadata-only and prompt-free. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-ticket-sync-' + crypto.randomBytes(6).toString('hex') + '.db');

const db = require('../server/db');
const notifiers = require('../server/notifiers');
const workflow = require('../server/workflow');
const ticketSync = require('../server/ticket-sync');

const JIRA_CHANNEL = {
  type: 'jira',
  name: 'jira',
  url: 'https://cu.atlassian.net/rest/api/3/issue',
  email: 'sec@example.test',
  token: 'unit-jira-token',
  projectKey: 'SEC',
  issueType: 'Task',
};

test('jira ticket creation captures the issue key as delivery metadata', async () => {
  const query = db.createQuery({
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
      return { ok: true, status: 201, json: async () => ({ id: '10001', key: 'SEC-42' }) };
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
  const rows = db.listQueries({ limit: 10 }).filter((q) => Array.isArray(q.ticketRefs));
  assert.ok(rows.length >= 1, 'previous test seeded a ticket ref');

  const result = await ticketSync.syncTicketStatuses({
    db,
    channels: new Map([['jira', JIRA_CHANNEL]]),
    fetchImpl: async (url, opts) => {
      assert.strictEqual(url, 'https://cu.atlassian.net/rest/api/3/issue/SEC-42?fields=status');
      assert.match(opts.headers.Authorization, /^Basic /);
      return {
        ok: true,
        json: async () => ({
          fields: {
            status: { name: 'In Review', statusCategory: { key: 'indeterminate' } },
            summary: 'SENSITIVE ticket summary must never be stored',
          },
        }),
      };
    },
  });
  assert.strictEqual(result.updated, 1);

  const stored = db.listQueries({ limit: 10 }).find((q) => Array.isArray(q.ticketRefs));
  assert.strictEqual(stored.ticketRefs[0].status, 'In Review');
  assert.strictEqual(stored.ticketRefs[0].statusCategory, 'indeterminate');
  assert.ok(stored.ticketRefs[0].syncedAt);
  assert.ok(!JSON.stringify(stored).includes('SENSITIVE ticket summary'), 'ticket bodies are never stored');
  assert.ok(db.listAudit(10).some((entry) => entry.action === 'TICKET_STATUS_SYNCED'
    && /jira:SEC-42=In Review/.test(entry.detail)));
});

test('ticket sync skips done tickets and tolerates fetch failures', async () => {
  const doneQuery = db.createQuery({
    status: 'approved',
    user: 'analyst@example.test',
    destination: 'chatgpt.com',
    ticketRefs: [{ channel: 'jira', externalId: 'SEC-77', status: 'Done', statusCategory: 'done', syncedAt: null }],
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
    return { ok: true, json: async () => ({ data: { issue: { state: { name: 'Done', type: 'completed' } } } }) };
  });
  assert.deepStrictEqual(latest, { status: 'Done', statusCategory: 'completed' });
});
