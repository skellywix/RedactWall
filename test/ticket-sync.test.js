'use strict';
/** Two-way ticket state stays metadata-only and prompt-free. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

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

function syncRow(id, refs = 1) {
  return {
    id,
    ticketRefs: Array.from({ length: refs }, (_, index) => ({
      channel: 'jira',
      externalId: `${id}-${index + 1}`,
      status: 'open',
      statusCategory: 'new',
      syncedAt: null,
    })),
  };
}

function mutableSyncDb(rows, list = () => rows) {
  return {
    listQueries: list,
    mutateQueryWithAudit(id, mutate, audit) {
      const index = rows.findIndex((row) => row.id === id);
      if (index < 0) return { outcome: 'missing', row: null };
      const patch = mutate(rows[index]);
      if (!patch) return { outcome: 'unchanged', row: rows[index] };
      const updated = { ...rows[index], ...patch };
      audit(updated);
      rows[index] = updated;
      return { outcome: 'updated', row: updated };
    },
  };
}

function fakeResponse() {
  const response = new EventEmitter();
  response.statusCode = 200;
  response.body = null;
  response.destroyed = false;
  response.writableEnded = false;
  response.status = (statusCode) => {
    response.statusCode = statusCode;
    return response;
  };
  response.json = (body) => {
    response.body = body;
    response.writableEnded = true;
    return response;
  };
  return response;
}

function fakeRequest(complete = true) {
  const request = new EventEmitter();
  request.aborted = false;
  request.complete = complete;
  return request;
}

function completedSyncResult() {
  return {
    status: 'complete',
    checked: 0,
    matched: 0,
    checksAttempted: 0,
    updated: 0,
    succeeded: 0,
    failed: 0,
    generatedAt: '2026-07-10T12:00:00.000Z',
  };
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
  assert.ok(result.succeeded >= 1, 'successful provider polls are counted');
  assert.ok(result.failed >= 0);
  assert.match(result.generatedAt, /^\d{4}-\d{2}-\d{2}T/);

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
  const openQuery = createTicketQuery({
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
  assert.ok(result.failed >= 1, 'provider failures remain visible to the caller');
  assert.strictEqual(db.getQuery(doneQuery.id).ticketRefs[0].status, 'Done', 'done tickets are left alone');
  const candidates = db.listTicketSyncQueries({ limit: 500 });
  assert.ok(candidates.some((row) => row.id === openQuery.id), 'database candidate query retains open tickets');
  assert.ok(!candidates.some((row) => row.id === doneQuery.id), 'database candidate query excludes terminal tickets');
});

test('ticket sync summary distinguishes complete provider checks from partial failure', async () => {
  const now = new Date('2026-07-10T12:00:00.000Z');
  const rows = [
    {
      id: 'q_ticket_ok',
      ticketRefs: [{ channel: 'jira', externalId: 'SEC-201', status: 'open', statusCategory: 'new', syncedAt: null }],
    },
    {
      id: 'q_ticket_failed',
      ticketRefs: [{ channel: 'jira', externalId: 'SEC-202', status: 'open', statusCategory: 'new', syncedAt: null }],
    },
  ];
  const fakeDb = {
    listQueries: () => rows,
    mutateQueryWithAudit: (id, mutate, audit) => {
      const current = rows.find((row) => row.id === id);
      const patch = mutate(current);
      const row = { ...current, ...patch };
      audit(row);
      return { outcome: 'updated', row };
    },
  };
  const result = await ticketSync.syncTicketStatuses({
    db: fakeDb,
    now,
    channels: new Map([['jira', JIRA_CHANNEL]]),
    fetchImpl: async (url) => {
      if (url.includes('SEC-202')) throw new Error('provider unavailable');
      return jsonResponse({ fields: { status: { name: 'In Review', statusCategory: { key: 'indeterminate' } } } });
    },
  });

  assert.deepStrictEqual(result, {
    status: 'partial',
    checked: 2,
    matched: 2,
    checksAttempted: 2,
    updated: 1,
    succeeded: 1,
    failed: 1,
    generatedAt: now.toISOString(),
    reason: 'provider_failures',
  });
});

test('ticket sync enforces one total reference cap across every matching query', async () => {
  const rows = [syncRow('q_cap_1', 3), syncRow('q_cap_2', 2), syncRow('q_cap_3', 2)];
  let fetched = 0;
  const result = await ticketSync.syncTicketStatuses({
    db: mutableSyncDb(rows),
    channels: new Map([['jira', JIRA_CHANNEL]]),
    maxChecks: 3,
    fetchImpl: async (_url, opts) => {
      fetched += 1;
      assert.ok(opts.signal instanceof AbortSignal, 'every provider call receives the shared bounded signal');
      return jsonResponse({ fields: { status: { name: 'open', statusCategory: { key: 'new' } } } });
    },
  });

  assert.strictEqual(fetched, 3);
  assert.deepStrictEqual(
    {
      status: result.status,
      reason: result.reason,
      checked: result.checked,
      matched: result.matched,
      checksAttempted: result.checksAttempted,
      succeeded: result.succeeded,
      failed: result.failed,
    },
    {
      status: 'partial',
      reason: 'check_limit_reached',
      checked: 1,
      matched: 3,
      checksAttempted: 3,
      succeeded: 3,
      failed: 0,
    },
  );
});

test('ticket sync filters ticket candidates before applying the query limit', async () => {
  const rows = [
    ...Array.from({ length: 500 }, (_, index) => ({ id: `newer-no-ticket-${index}` })),
    syncRow('older-open-ticket'),
  ];
  let listOptions;
  let fetched = 0;
  const result = await ticketSync.syncTicketStatuses({
    db: mutableSyncDb(rows, (options) => {
        listOptions = options;
        return options.all ? rows : rows.slice(0, options.limit);
      }),
    channels: new Map([['jira', JIRA_CHANNEL]]),
    maxChecks: 1,
    fetchImpl: async () => {
      fetched += 1;
      return jsonResponse({ fields: { status: { name: 'open', statusCategory: { key: 'new' } } } });
    },
  });

  assert.deepStrictEqual(listOptions, { all: true });
  assert.strictEqual(fetched, 1);
  assert.strictEqual(result.matched, 1);
  assert.strictEqual(result.checked, 1);
});

test('ticket sync rotates attempted rows so the check cap cannot starve later open tickets', async () => {
  const rows = Array.from({ length: 70 }, (_, index) => syncRow(`q_fair_${String(index).padStart(2, '0')}`));
  const seen = new Set();
  const fakeDb = mutableSyncDb(rows);
  const run = (now) => ticketSync.syncTicketStatuses({
    db: fakeDb,
    now,
    channels: new Map([['jira', JIRA_CHANNEL]]),
    maxChecks: 64,
    fetchImpl: async (url) => {
      seen.add(url);
      return jsonResponse({ fields: { status: { name: 'open', statusCategory: { key: 'new' } } } });
    },
  });

  const first = await run(new Date('2026-07-10T12:00:00.000Z'));
  assert.strictEqual(first.reason, 'check_limit_reached');
  assert.strictEqual(seen.size, 64);
  await run(new Date('2026-07-10T12:01:00.000Z'));
  assert.strictEqual(seen.size, 70, 'a second bounded run reaches every previously unattempted ticket');
  assert.ok(rows.every((row) => row.ticketRefs[0].lastAttemptAt), 'attempt ordering is durably recorded');
});

test('ticket sync aborts a hung provider at the total wall-clock deadline', async () => {
  const rows = [syncRow('q_deadline_1'), syncRow('q_deadline_2')];
  let providerSignal;
  const startedAt = Date.now();
  const result = await ticketSync.syncTicketStatuses({
    db: mutableSyncDb(rows),
    channels: new Map([['jira', JIRA_CHANNEL]]),
    totalTimeoutMs: 25,
    fetchImpl: async (_url, opts) => new Promise((resolve, reject) => {
      providerSignal = opts.signal;
      opts.signal.addEventListener('abort', () => reject(opts.signal.reason), { once: true });
    }),
  });

  assert.ok(Date.now() - startedAt < 1000, 'total deadline stops serial provider work promptly');
  assert.strictEqual(providerSignal.aborted, true);
  assert.strictEqual(result.status, 'partial');
  assert.strictEqual(result.reason, 'deadline_exceeded');
  assert.strictEqual(result.checked, 1);
  assert.strictEqual(result.matched, 2);
  assert.strictEqual(result.checksAttempted, 1);
  assert.strictEqual(result.succeeded, 0);
  assert.strictEqual(result.failed, 0, 'deadline cancellation is not mislabeled as a provider failure');
});

test('ticket sync request cancellation propagates when the client disconnects', async () => {
  let sharedSignal;
  let providerSignal;
  const handler = ticketSync.createTicketSyncRequestHandler(({ signal }) => {
    sharedSignal = signal;
    return ticketSync.syncTicketStatuses({
      db: { listQueries: () => [syncRow('q_disconnect')] },
      channels: new Map([['jira', JIRA_CHANNEL]]),
      signal,
      fetchImpl: async (_url, opts) => new Promise((resolve, reject) => {
        providerSignal = opts.signal;
        opts.signal.addEventListener('abort', () => reject(opts.signal.reason), { once: true });
      }),
    });
  });
  const request = fakeRequest(false);
  const response = fakeResponse();
  const pending = handler(request, response, (err) => { throw err; });

  request.emit('close');
  await pending;

  assert.strictEqual(sharedSignal.aborted, true);
  assert.strictEqual(sharedSignal.reason.code, 'client_disconnected');
  assert.strictEqual(providerSignal.aborted, true, 'disconnect reaches the in-flight provider fetch');
  assert.strictEqual(response.body, null, 'a disconnected socket receives no late response');
  assert.strictEqual(request.listenerCount('close'), 0);
  assert.strictEqual(response.listenerCount('close'), 0);
});

test('ticket sync request rejects overlap and releases single-flight after completion', async () => {
  let releaseFirst;
  let runs = 0;
  const firstGate = new Promise((resolve) => { releaseFirst = resolve; });
  const handler = ticketSync.createTicketSyncRequestHandler(async () => {
    runs += 1;
    if (runs === 1) return firstGate;
    return completedSyncResult();
  });
  const firstResponse = fakeResponse();
  const first = handler(fakeRequest(), firstResponse, (err) => { throw err; });

  const overlapResponse = fakeResponse();
  await handler(fakeRequest(), overlapResponse, (err) => { throw err; });
  assert.strictEqual(overlapResponse.statusCode, 409);
  assert.deepStrictEqual(overlapResponse.body, { status: 'busy', reason: 'ticket_sync_in_progress' });
  assert.strictEqual(runs, 1, 'overlap never starts another provider sweep');

  releaseFirst(completedSyncResult());
  await first;
  assert.strictEqual(firstResponse.statusCode, 200);
  assert.strictEqual(firstResponse.body.status, 'complete');

  const nextResponse = fakeResponse();
  await handler(fakeRequest(), nextResponse, (err) => { throw err; });
  assert.strictEqual(runs, 2, 'single-flight is released only after the prior run settles');
  assert.strictEqual(nextResponse.body.status, 'complete');
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
