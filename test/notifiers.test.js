'use strict';
/** Approval notification adapters must stay sanitized. */
const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const notifiers = require('../server/notifiers');
const linearSmoke = require('../scripts/smoke-linear-approval');
const { listenNet } = require('./support/listen');

function sampleQuery(overrides = {}) {
  return {
    id: 'q_notify',
    createdAt: '2026-06-28T06:00:00.000Z',
    status: 'pending',
    user: 'member-services@example.test',
    orgId: 'cu-demo',
    source: 'browser_extension',
    channel: 'submit',
    sensor: {
      name: 'browser_extension',
      version: '0.3.0',
      platform: 'chrome_mv3',
      ingestKey: 'ps_ingest_should_not_leave',
    },
    destination: 'chatgpt.com',
    redactedPrompt: 'Member Jane has SSN [US_SSN]',
    _rawPrompt: 'sealed raw 524-71-9043',
    _tokenVault: 'sealed-vault',
    _releaseTokenHash: 'release-secret-hash',
    decisionNote: 'contains SSN 524-71-9043',
    findings: [{ type: 'US_SSN', severity: 4, score: 0.92, masked: '**** 9043', value: '524-71-9043' }],
    categories: [],
    reasons: ['Hard-stop entity present: US_SSN'],
    riskScore: 74,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    assignedRole: 'approver',
    assignedGroup: 'compliance',
    workflowReason: 'detector:US_SSN',
    slaDueAt: '2026-06-28T10:00:00.000Z',
    escalatedAt: null,
    notificationStatus: 'not_configured',
    ...overrides,
  };
}

test('sanitized approval notification omits prompt text, secrets, and raw finding values', () => {
  const payload = notifiers.sanitizedApprovalNotification(sampleQuery());
  const wire = JSON.stringify(payload);

  assert.strictEqual(payload.eventType, 'promptwall.approval_workflow');
  assert.strictEqual(payload.action, 'APPROVAL_ROUTED');
  assert.deepStrictEqual(payload.labels, ['US_SSN']);
  assert.strictEqual(payload.workflow.assignedGroup, 'compliance');
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member Jane'));
  assert.ok(!wire.includes('sealed raw'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.ok(!wire.includes('release-secret-hash'));
  assert.ok(!wire.includes('contains SSN'));
  assert.ok(!wire.includes('ps_ingest_should_not_leave'));
});

test('approval notification is disabled without configured channels', async () => {
  const result = await notifiers.emitApprovalNotification(sampleQuery(), { env: {} });
  assert.deepStrictEqual(result, { sent: false, reason: 'disabled', channels: [], results: [] });
});

test('generic, Slack, Teams, and ticket adapters send sanitized payloads', async () => {
  const requests = [];
  const env = {
    APPROVAL_NOTIFY_WEBHOOK_URL: 'https://notify.example.test/hook',
    APPROVAL_NOTIFY_WEBHOOK_TOKEN: 'unit-token',
    APPROVAL_SLACK_WEBHOOK_URL: 'https://hooks.slack.example.test/unit',
    APPROVAL_TEAMS_WEBHOOK_URL: 'https://teams.example.test/unit',
    APPROVAL_TICKET_WEBHOOK_URL: 'https://tickets.example.test/unit',
    APPROVAL_TICKET_WEBHOOK_TOKEN: 'ticket-token',
    APPROVAL_TICKET_SYSTEM: 'jira',
    APPROVAL_TICKET_PROJECT: 'SEC',
    APPROVAL_TICKET_ISSUE_TYPE: 'Incident',
  };

  const result = await notifiers.emitApprovalNotification(sampleQuery(), {
    env,
    fetch: async (url, opts) => {
      requests.push({ url, opts });
      return { ok: true, status: 202 };
    },
  });

  assert.strictEqual(result.sent, true);
  assert.strictEqual(result.status, 'sent');
  assert.deepStrictEqual(result.channels, ['webhook', 'slack', 'teams', 'ticket']);
  assert.strictEqual(requests.length, 4);
  assert.strictEqual(requests[0].opts.headers.Authorization, 'Bearer unit-token');
  assert.strictEqual(requests[3].opts.headers.Authorization, 'Bearer ticket-token');
  assert.ok(requests[1].opts.body.includes('PromptWall approval routed'));
  assert.ok(requests[2].opts.body.includes('MessageCard'));
  const ticket = JSON.parse(requests[3].opts.body);
  assert.strictEqual(ticket.eventType, 'promptwall.approval_ticket');
  assert.strictEqual(ticket.dedupeKey, 'promptwall:q_notify:APPROVAL_ROUTED');
  assert.strictEqual(ticket.priority, 'critical');
  assert.deepStrictEqual(ticket.ticket, {
    system: 'jira',
    project: 'SEC',
    issueType: 'Incident',
  });
  assert.strictEqual(ticket.query.labels[0], 'US_SSN');
  assert.strictEqual(ticket.workflow.assignedGroup, 'compliance');
  const wire = requests.map((request) => request.opts.body).join('\n');
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member Jane'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.match(wire, /US_SSN/);
});

test('ticket payload builder produces a bridge-safe issue shape', () => {
  const payload = notifiers.sanitizedApprovalNotification(sampleQuery({
    riskScore: 54,
    maxSeverity: 3,
    maxSeverityLabel: 'high',
  }));
  const ticket = notifiers.ticketPayload({
    system: 'linear',
    project: 'security-alerts',
    issueType: 'Security Review',
  }, payload);

  assert.strictEqual(ticket.priority, 'high');
  assert.strictEqual(ticket.ticket.system, 'linear');
  assert.strictEqual(ticket.query.id, 'q_notify');
  assert.strictEqual(ticket.query.destination, 'chatgpt.com');
  assert.deepStrictEqual(ticket.query.labels, ['US_SSN']);
  assert.ok(!JSON.stringify(ticket).includes('524-71-9043'));
  assert.ok(!JSON.stringify(ticket).includes('Member Jane'));
  assert.ok(!JSON.stringify(ticket).includes('sealed-vault'));

  const normal = notifiers.ticketPayload({ system: 'jira' }, notifiers.sanitizedApprovalNotification(sampleQuery({
    riskScore: 12,
    maxSeverity: 1,
    maxSeverityLabel: 'low',
  })));
  assert.strictEqual(normal.priority, 'normal');
});

test('native Jira and Linear adapters create sanitized issue requests', async () => {
  const requests = [];
  const env = {
    PROMPTWALL_APPROVAL_JIRA_BASE_URL: 'https://acme.atlassian.net',
    PROMPTWALL_APPROVAL_JIRA_EMAIL: 'secops@example.test',
    PROMPTWALL_APPROVAL_JIRA_API_TOKEN: 'jira-secret-token',
    PROMPTWALL_APPROVAL_JIRA_PROJECT_KEY: 'SEC',
    PROMPTWALL_APPROVAL_JIRA_ISSUE_TYPE: 'Task',
    PROMPTWALL_APPROVAL_LINEAR_API_KEY: 'linear-secret-key',
    PROMPTWALL_APPROVAL_LINEAR_TEAM_ID: 'team-security',
    PROMPTWALL_APPROVAL_LINEAR_STATE_ID: 'triage-state',
    PROMPTWALL_APPROVAL_LINEAR_PROJECT_ID: 'promptwall-project',
    PROMPTWALL_APPROVAL_LINEAR_LABEL_IDS: 'label-dlp,label-approval',
  };

  const result = await notifiers.emitApprovalNotification(sampleQuery(), {
    env,
    fetch: async (url, opts) => {
      requests.push({ url, opts });
      if (url.includes('linear.app')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ data: { issueCreate: { success: true, issue: { identifier: 'SEC-1' } } } }),
        };
      }
      return { ok: true, status: 201 };
    },
  });

  assert.strictEqual(result.sent, true);
  assert.strictEqual(result.status, 'sent');
  assert.deepStrictEqual(result.channels, ['jira', 'linear']);
  assert.strictEqual(requests.length, 2);

  assert.strictEqual(requests[0].url, 'https://acme.atlassian.net/rest/api/3/issue');
  assert.strictEqual(
    requests[0].opts.headers.Authorization,
    'Basic ' + Buffer.from('secops@example.test:jira-secret-token').toString('base64'),
  );
  const jira = JSON.parse(requests[0].opts.body);
  assert.strictEqual(jira.fields.project.key, 'SEC');
  assert.strictEqual(jira.fields.issuetype.name, 'Task');
  assert.ok(jira.fields.summary.includes('PromptWall approval'));
  assert.deepStrictEqual(jira.fields.labels.slice(0, 3), ['promptwall', 'approval', 'critical']);

  assert.strictEqual(requests[1].url, 'https://api.linear.app/graphql');
  assert.strictEqual(requests[1].opts.headers.Authorization, 'linear-secret-key');
  const linear = JSON.parse(requests[1].opts.body);
  assert.match(linear.query, /issueCreate/);
  assert.deepStrictEqual(linear.variables.input, {
    teamId: 'team-security',
    title: jira.fields.summary,
    description: linear.variables.input.description,
    stateId: 'triage-state',
    projectId: 'promptwall-project',
    labelIds: ['label-dlp', 'label-approval'],
  });
  assert.match(linear.variables.input.description, /sanitized PromptWall workflow metadata only/);

  const wire = requests.map((request) => request.opts.body).join('\n');
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member Jane'));
  assert.ok(!wire.includes('sealed raw'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.ok(!wire.includes('release-secret-hash'));
  assert.ok(!wire.includes('ps_ingest_should_not_leave'));
  assert.match(wire, /US_SSN/);
});

test('approval outbound URLs require HTTPS without URL credentials', () => {
  const channels = notifiers.configuredChannels({
    APPROVAL_NOTIFY_WEBHOOK_URL: 'http://notify.example.test/hook',
    APPROVAL_NOTIFY_WEBHOOK_TOKEN: 'unit-token',
    APPROVAL_SLACK_WEBHOOK_URL: 'https://user:secret@hooks.slack.example.test/unit',
    APPROVAL_TEAMS_WEBHOOK_URL: 'not a url',
    APPROVAL_TICKET_WEBHOOK_URL: 'https://tickets.example.test/unit#fragment-secret',
    PROMPTWALL_APPROVAL_JIRA_BASE_URL: 'http://acme.atlassian.net',
    PROMPTWALL_APPROVAL_JIRA_EMAIL: 'secops@example.test',
    PROMPTWALL_APPROVAL_JIRA_API_TOKEN: 'jira-secret-token',
    PROMPTWALL_APPROVAL_JIRA_PROJECT_KEY: 'SEC',
  });

  assert.deepStrictEqual(channels.map((channel) => channel.type), ['ticket']);
  assert.strictEqual(channels[0].url, 'https://tickets.example.test/unit');
  assert.deepStrictEqual(notifiers.configuredChannels({}, {
    channels: [
      { type: 'webhook', name: 'cleartext', url: 'http://notify.example.test/hook' },
      { type: 'ticket', name: 'credentialed', url: 'https://token:secret@tickets.example.test/unit' },
      { type: 'webhook', name: 'safe', url: 'https://notify.example.test/hook#frag' },
      { type: 'smtp', name: 'smtp', host: '127.0.0.1' },
    ],
  }).map((channel) => [channel.type, channel.name, channel.url || null]), [
    ['webhook', 'safe', 'https://notify.example.test/hook'],
    ['smtp', 'smtp', null],
  ]);
});

test('Linear adapter treats GraphQL errors as failed notification delivery', async () => {
  const result = await notifiers.emitApprovalNotification(sampleQuery(), {
    env: {
      PROMPTWALL_APPROVAL_LINEAR_API_KEY: 'linear-secret-key',
      PROMPTWALL_APPROVAL_LINEAR_TEAM_ID: 'team-security',
    },
    fetch: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ errors: [{ message: 'invalid input' }] }),
    }),
  });

  assert.strictEqual(result.sent, false);
  assert.strictEqual(result.status, 'failed');
  assert.deepStrictEqual(result.channels, ['linear']);
  assert.strictEqual(result.results[0].reason, 'graphql_error');
});

test('Linear adapter treats malformed JSON as failed notification delivery', async () => {
  const result = await notifiers.linearResponseResult({
    ok: true,
    json: async () => {
      throw new Error('not json');
    },
  });

  assert.deepStrictEqual(result, { reason: 'invalid_graphql_response', issue: null });
});

test('notification delivery records sanitized adapter exceptions', async () => {
  const result = await notifiers.emitApprovalNotification(sampleQuery(), {
    channels: [{ type: 'webhook', name: 'webhook', url: 'https://notify.example.test/hook' }],
    fetch: async () => {
      throw new Error('network down with SSN 524-71-9043');
    },
  });

  assert.strictEqual(result.sent, false);
  assert.strictEqual(result.status, 'failed');
  assert.deepStrictEqual(result.results, [{ channel: 'webhook', sent: false, reason: 'error' }]);
  assert.ok(!JSON.stringify(result).includes('524-71-9043'));
});

test('native Linear adapter returns created issue metadata', async () => {
  const result = await notifiers.emitApprovalNotification(sampleQuery(), {
    env: {
      PROMPTWALL_APPROVAL_LINEAR_API_KEY: 'linear-secret-key',
      PROMPTWALL_APPROVAL_LINEAR_TEAM_ID: 'team-security',
    },
    fetch: async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        data: {
          issueCreate: {
            success: true,
            issue: {
              id: 'lin-id',
              identifier: 'OPS-7',
              url: 'https://linear.app/example/issue/OPS-7/promptwall-smoke',
              title: 'PromptWall approval',
            },
          },
        },
      }),
    }),
  });

  assert.strictEqual(result.sent, true);
  assert.strictEqual(result.results[0].externalId, 'OPS-7');
  assert.strictEqual(result.results[0].url, 'https://linear.app/example/issue/OPS-7/promptwall-smoke');
});

test('Linear smoke command builds a sanitized native request', () => {
  const parsed = linearSmoke.parseArgs([
    '--send',
    '--team-id=team-security',
    '--state-id',
    'state-review',
    '--project-id',
    'project-ai',
    '--label-ids',
    'risk,ai',
    '--api-url',
    'https://api.linear.app/graphql',
    '--query-id',
    'linear_smoke_test',
  ]);
  assert.strictEqual(parsed.send, true);
  assert.strictEqual(parsed.teamId, 'team-security');
  assert.strictEqual(parsed.stateId, 'state-review');
  assert.strictEqual(parsed.projectId, 'project-ai');
  assert.strictEqual(parsed.labelIds, 'risk,ai');
  assert.strictEqual(parsed.apiUrl, 'https://api.linear.app/graphql');
  assert.strictEqual(parsed.queryId, 'linear_smoke_test');
  assert.deepStrictEqual(linearSmoke.linearEnv({}, parsed), {
    PROMPTWALL_APPROVAL_LINEAR_API_URL: 'https://api.linear.app/graphql',
    PROMPTWALL_APPROVAL_LINEAR_TEAM_ID: 'team-security',
    PROMPTWALL_APPROVAL_LINEAR_STATE_ID: 'state-review',
    PROMPTWALL_APPROVAL_LINEAR_PROJECT_ID: 'project-ai',
    PROMPTWALL_APPROVAL_LINEAR_LABEL_IDS: 'risk,ai',
  });

  const smoke = linearSmoke.buildSmokeRequest({
    env: {},
    argv: ['--team-id', 'team-security', '--query-id', 'linear_smoke_test'],
    now: new Date('2026-06-29T12:00:00.000Z'),
  });

  assert.strictEqual(smoke.body.variables.input.teamId, 'team-security');
  assert.match(smoke.body.query, /issueCreate/);
  assert.match(smoke.body.variables.input.description, /sanitized PromptWall workflow metadata only/);
  assert.ok(!smoke.wire.includes('000-00-0000'));
  assert.ok(!smoke.wire.includes('Synthetic Member'));
  assert.ok(!smoke.wire.includes('sealed-linear-smoke-vault'));
  assert.ok(!smoke.wire.includes('linear-smoke-release-token'));
  assert.ok(!smoke.wire.includes('ps_ingest_linear_smoke_secret'));
});

test('native Linear adapter rejects unsafe API URL overrides', () => {
  assert.strictEqual(notifiers.linearApiUrl('http://api.linear.test/graphql'), '');
  assert.strictEqual(notifiers.linearApiUrl('not a url'), '');
  assert.strictEqual(notifiers.linearApiUrl('https://api-key:secret@api.linear.app/graphql'), '');
  assert.strictEqual(
    notifiers.configuredChannels({
      PROMPTWALL_APPROVAL_LINEAR_API_KEY: 'linear-secret-key',
      PROMPTWALL_APPROVAL_LINEAR_TEAM_ID: 'team-security',
      PROMPTWALL_APPROVAL_LINEAR_API_URL: 'http://api.linear.test/graphql',
    }).length,
    0,
  );
  assert.throws(
    () => linearSmoke.buildSmokeRequest({
      env: {},
      argv: ['--team-id', 'team-security', '--api-url', 'http://api.linear.test/graphql'],
    }),
    /invalid Linear API URL/,
  );
  assert.throws(
    () => linearSmoke.linearChannelForPayload({}),
    /missing Linear team id/,
  );
  assert.throws(
    () => linearSmoke.assertSanitizedWire('payload sealed-linear-smoke-vault'),
    /leaked marker/,
  );
});

test('Linear smoke command supports dry-run and CLI output without sending', async () => {
  const result = await linearSmoke.runSmoke({
    env: {},
    argv: ['--team-id', 'team-security', '--query-id', 'linear_smoke_dry'],
    now: new Date('2026-06-29T12:00:00.000Z'),
  });
  assert.strictEqual(result.dryRun, true);
  assert.strictEqual(result.sent, false);
  assert.strictEqual(result.queryId, 'linear_smoke_dry');
  assert.strictEqual(result.teamId, 'team-security');

  const logs = [];
  await linearSmoke.main(['--team-id', 'team-security'], {
    console: { log: (line) => logs.push(String(line)) },
    runSmoke: async () => ({
      dryRun: true,
      queryId: 'linear_smoke_main',
      teamId: 'team-security',
      url: 'https://api.linear.app/graphql',
      title: 'PromptWall approval',
    }),
  });
  assert.match(logs.join('\n'), /LINEAR_APPROVAL_SMOKE_DRY_RUN query=linear_smoke_main/);
  assert.match(logs.join('\n'), /wire=sanitized send=false/);
});

test('Linear smoke command requires an API key before sending', async () => {
  await assert.rejects(
    () => linearSmoke.runSmoke({
      env: {},
      argv: ['--send', '--team-id', 'team-security'],
      now: new Date('2026-06-29T12:00:00.000Z'),
      fetchImpl: async () => ({ ok: true, status: 200 }),
    }),
    /missing Linear API key/,
  );
});

test('Linear smoke command reports adapter send failures', async () => {
  await assert.rejects(
    () => linearSmoke.runSmoke({
      env: { PROMPTWALL_APPROVAL_LINEAR_API_KEY: 'linear-secret-key' },
      argv: ['--send', '--team-id', 'team-security'],
      now: new Date('2026-06-29T12:00:00.000Z'),
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            issueCreate: {
              success: false,
            },
          },
        }),
      }),
    }),
    /Linear approval smoke failed/,
  );
});

test('Linear smoke command sends through the native adapter', async () => {
  const requests = [];
  const result = await linearSmoke.runSmoke({
    env: { PROMPTWALL_APPROVAL_LINEAR_API_KEY: 'linear-secret-key' },
    argv: ['--send', '--team-id', 'team-security', '--query-id', 'linear_smoke_test'],
    now: new Date('2026-06-29T12:00:00.000Z'),
    fetchImpl: async (url, opts) => {
      requests.push({ url, opts });
      return {
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            issueCreate: {
              success: true,
              issue: {
                id: 'lin-id',
                identifier: 'OPS-8',
                url: 'https://linear.app/example/issue/OPS-8/promptwall-smoke',
                title: 'PromptWall approval',
              },
            },
          },
        }),
      };
    },
  });

  assert.strictEqual(result.sent, true);
  assert.strictEqual(result.externalId, 'OPS-8');
  assert.strictEqual(requests.length, 1);
  assert.strictEqual(requests[0].url, 'https://api.linear.app/graphql');
  assert.strictEqual(requests[0].opts.headers.Authorization, 'linear-secret-key');
  assert.ok(!requests[0].opts.body.includes('000-00-0000'));
  assert.ok(!requests[0].opts.body.includes('sealed-linear-smoke-vault'));

  const logs = [];
  await linearSmoke.main(['--send'], {
    console: { log: (line) => logs.push(String(line)) },
    runSmoke: async () => ({
      dryRun: false,
      queryId: 'linear_smoke_main',
      externalId: '',
      status: 'approval_ticket_sent',
      url: 'https://linear.app/example/issue/OPS-8/promptwall-smoke',
    }),
  });
  assert.match(logs.join('\n'), /LINEAR_APPROVAL_SMOKE_OK query=linear_smoke_main issue=created/);
  assert.match(logs.join('\n'), /url=https:\/\/linear\.app\/example\/issue\/OPS-8/);
});

test('SMTP adapter sends sanitized approval email through a relay', async (t) => {
  const received = [];
  const server = net.createServer((socket) => {
    let buffer = '';
    let dataMode = false;
    let message = '';
    socket.on('error', () => {});
    socket.write('220 smtp.test ESMTP\r\n');
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      while (buffer.includes('\n')) {
        const idx = buffer.indexOf('\n');
        const line = buffer.slice(0, idx).replace(/\r$/, '');
        buffer = buffer.slice(idx + 1);
        if (dataMode) {
          if (line === '.') {
            received.push(message);
            message = '';
            dataMode = false;
            socket.write('250 queued\r\n');
          } else {
            message += line + '\n';
          }
          continue;
        }
        if (/^EHLO\b/i.test(line)) socket.write('250 smtp.test\r\n');
        else if (/^MAIL FROM:/i.test(line)) socket.write('250 sender ok\r\n');
        else if (/^RCPT TO:/i.test(line)) socket.write('250 recipient ok\r\n');
        else if (/^DATA$/i.test(line)) {
          dataMode = true;
          socket.write('354 end with dot\r\n');
        } else if (/^QUIT$/i.test(line)) {
          socket.write('221 bye\r\n');
          socket.end();
        } else {
          socket.write('250 ok\r\n');
        }
      }
    });
  });
  await listenNet(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const port = server.address().port;
  const result = await notifiers.emitApprovalNotification(sampleQuery(), {
    env: {
      APPROVAL_SMTP_HOST: '127.0.0.1',
      APPROVAL_SMTP_PORT: String(port),
      APPROVAL_SMTP_FROM: 'PromptWall <alerts@example.test>',
      APPROVAL_SMTP_TO: 'compliance@example.test; security@example.test',
      APPROVAL_SMTP_ALLOW_INSECURE: 'true',
    },
  });

  assert.strictEqual(result.sent, true);
  assert.strictEqual(result.status, 'sent');
  assert.deepStrictEqual(result.channels, ['smtp']);
  assert.strictEqual(received.length, 1);
  const wire = received[0];
  assert.match(wire, /Subject: \[PromptWall\] Approval routed: q_notify/);
  assert.match(wire, /To: compliance@example.test, security@example.test/);
  assert.match(wire, /Owner: compliance \/ approver/);
  assert.match(wire, /Labels: US_SSN/);
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member Jane'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.ok(!wire.includes('release-secret-hash'));
  assert.ok(!wire.includes('ps_ingest_should_not_leave'));
});

test('SMTP message builder strips header injection and sensitive prompt fields', () => {
  const payload = notifiers.sanitizedApprovalNotification(sampleQuery());
  const message = notifiers.smtpMessageForPayload({
    from: 'PromptWall\r\nBcc: leak@example.test <alerts@example.test>',
    to: ['compliance@example.test'],
  }, payload, new Date('2026-06-28T12:00:00.000Z'));

  assert.doesNotMatch(message, /^Bcc:/m);
  assert.match(message, /Subject: \[PromptWall\] Approval routed: q_notify/);
  assert.ok(!message.includes('524-71-9043'));
  assert.ok(!message.includes('Member Jane'));
  assert.ok(!message.includes('sealed raw'));
  assert.ok(!message.includes('sealed-vault'));
  assert.ok(!message.includes('release-secret-hash'));
});

test('delivery status distinguishes sent, partial, failed, and disabled', () => {
  assert.strictEqual(notifiers.deliveryStatus({ reason: 'disabled' }), 'not_configured');
  assert.strictEqual(notifiers.deliveryStatus({ results: [{ sent: true }] }), 'sent');
  assert.strictEqual(notifiers.deliveryStatus({ results: [{ sent: true }, { sent: false }] }), 'partial');
  assert.strictEqual(notifiers.deliveryStatus({ results: [{ sent: false }] }), 'failed');
});
