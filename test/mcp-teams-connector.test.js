'use strict';
/** Microsoft Teams MCP connector must sanitize Graph messages before model use. */
const test = require('node:test');
const assert = require('node:assert');
const {
  buildTeamsChannelMessagesUrl,
  buildTeamsChatMessagesUrl,
  createTeamsChannelMessagesTool,
  createTeamsChatMessagesTool,
  fetchTeamsChannelMessages,
  fetchTeamsChatMessages,
  graphScopes,
  htmlToText,
  messagesToText,
  sanitizeTeamsChannelMessages,
  sanitizeTeamsChatMessages,
  teamsConnectorHealth,
} = require('../sensors/mcp-guard/connectors/teams');

function headers(values = {}) {
  const lower = Object.fromEntries(Object.entries(values).map(([key, value]) => [key.toLowerCase(), value]));
  return { get: (name) => lower[String(name).toLowerCase()] || '' };
}

function response(body, opts = {}) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  const status = opts.status || 200;
  return new Response(text, {
    status,
    headers: {
      'content-type': opts.contentType || 'application/json',
      'content-length': opts.contentLength || String(Buffer.byteLength(text, 'utf8')),
    },
  });
}

test('Teams URL builders target Graph channel and chat messages safely', () => {
  assert.strictEqual(
    buildTeamsChannelMessagesUrl({
      teamId: 'team 1',
      channelId: '19:channel@thread.tacv2',
      top: 99,
    }, { graphRoot: 'https://graph.test/v1.0/' }),
    'https://graph.test/v1.0/teams/team%201/channels/19%3Achannel%40thread.tacv2/messages?%24top=50'
  );
  assert.strictEqual(
    buildTeamsChatMessagesUrl({
      chatId: '19:chat@thread.v2',
      top: 2,
      orderby: 'createdDateTime desc',
    }),
    'https://graph.microsoft.com/v1.0/chats/19%3Achat%40thread.v2/messages?%24top=2&%24orderby=createdDateTime+desc'
  );

  assert.throws(() => buildTeamsChannelMessagesUrl({ teamId: 'team/1', channelId: 'C1' }), /opaque id/);
  assert.throws(() => buildTeamsChatMessagesUrl({ chatId: '' }), /chatId is required/);
  assert.throws(() => buildTeamsChatMessagesUrl({ chatId: 'chat1', orderby: 'displayName asc' }), /orderby/);
  assert.throws(() => buildTeamsChatMessagesUrl({ chatId: 'chat1', filter: 'from/user eq admin' }), /filter/);
  assert.throws(() => buildTeamsChatMessagesUrl({ chatId: 'chat1' }, { graphRoot: 'http://graph.test/v1.0' }), /must use https/);
});

test('fetchTeamsChannelMessages reads bounded HTML message bodies through Graph', async () => {
  let request;
  const result = await fetchTeamsChannelMessages({ teamId: 'team1', channelId: 'channel1', top: 2 }, {
    accessToken: 'unit-teams-token',
    fetchImpl: async (url, opts = {}) => {
      request = { url, headers: opts.headers };
      return response({
        '@odata.nextLink': 'https://graph.microsoft.com/next',
        value: [
          { id: 'm1', from: { user: { id: 'u1' } }, body: { contentType: 'html', content: '<div>Loan queue &amp; branch hours</div>' } },
          { id: 'm2', body: { contentType: 'html', content: '<p>Public update<br>Ready</p>' } },
        ],
      });
    },
  });

  assert.strictEqual(request.url, 'https://graph.microsoft.com/v1.0/teams/team1/channels/channel1/messages?%24top=2');
  assert.strictEqual(request.headers.Authorization, 'Bearer unit-teams-token');
  assert.strictEqual(result.content[0].text, 'Loan queue & branch hours\n\nPublic update\nReady');
  assert.ok(!JSON.stringify(result).includes('team1'));
  assert.ok(!JSON.stringify(result).includes('u1'));
  assert.deepStrictEqual(result.structuredContent, {
    connector: 'teams',
    operation: 'channels.messages',
    contentType: 'text/plain',
    sizeBytes: 46,
    messageCount: 2,
    hasMore: true,
  });
});

test('fetchTeamsChatMessages supports chat reads and bounded output', async () => {
  const result = await fetchTeamsChatMessages({ chatId: '19:chat@thread.v2', top: 1 }, {
    accessToken: 'unit-teams-token',
    fetchImpl: async () => response({
      value: [
        { body: { contentType: 'text', content: 'Branch hours are public.' } },
      ],
    }),
  });
  assert.strictEqual(result.content[0].text, 'Branch hours are public.');
  assert.strictEqual(result.structuredContent.operation, 'chats.messages');
  assert.strictEqual(result.structuredContent.hasMore, false);

  await assert.rejects(
    () => fetchTeamsChatMessages({ chatId: '19:chat@thread.v2' }, {
      accessToken: 'unit-teams-token',
      maxBytes: 4,
      fetchImpl: async () => response({ value: [{ body: { contentType: 'text', content: 'public body' } }] }),
    }),
    /message content exceeds 4 byte limit/
  );
});

test('sanitizeTeamsChannelMessages redacts Teams channel text before returning MCP output', async () => {
  let outbound;
  const sanitized = await sanitizeTeamsChannelMessages({ teamId: 'team1', channelId: 'channel1' }, {
    accessToken: 'unit-teams-token',
    fetchImpl: async () => response({
      value: [
        { body: { contentType: 'html', content: '<div>Teams paste: SSN 524-71-9043 and card 4111 1111 1111 1111.</div>' } },
      ],
    }),
    guardOptions: {
      server: 'https://redactwall.test',
      key: 'unit-ingest-key',
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async (url, opts = {}) => {
        outbound = { url, body: JSON.parse(opts.body), headers: opts.headers };
        return { ok: true };
      },
    },
  });

  assert.strictEqual(sanitized.redacted, true);
  assert.ok(sanitized.findings.includes('US_SSN'));
  assert.ok(sanitized.findings.includes('CREDIT_CARD'));
  assert.ok(!JSON.stringify(sanitized.result).includes('524-71-9043'));
  assert.ok(!JSON.stringify(sanitized.result).includes('4111 1111 1111 1111'));
  assert.strictEqual(outbound.url, 'https://redactwall.test/api/v1/gate');
  assert.strictEqual(outbound.body.destination, 'teams.channels.messages');
  assert.strictEqual(outbound.body.source, 'mcp_guard');
  assert.ok(!JSON.stringify(outbound.body).includes('unit-teams-token'));
});

test('Teams connector tools return sanitized MCP results only', async () => {
  const opts = {
    accessToken: 'unit-teams-token',
    fetchImpl: async () => response({
      value: [{ body: { contentType: 'html', content: '<p>Member SSN 524-71-9043.</p>' } }],
    }),
    guardOptions: {
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async () => ({ ok: true }),
    },
  };
  const channelTool = createTeamsChannelMessagesTool(opts);
  const channelResult = await channelTool({ teamId: 'team1', channelId: 'channel1' });
  assert.ok(channelResult.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(channelResult).includes('524-71-9043'));

  const chatTool = createTeamsChatMessagesTool(opts);
  const chatResult = await chatTool({ chatId: 'chat1' });
  assert.ok(chatResult.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(chatResult).includes('524-71-9043'));
});

test('Teams connector errors and health evidence are secret-free', async () => {
  assert.strictEqual(htmlToText('<div>A&nbsp;&amp;&nbsp;B<br><span>C</span></div>'), 'A & B\nC');
  assert.strictEqual(messagesToText([{ body: { contentType: 'html', content: '<div>Hi</div>' } }]), 'Hi');

  await assert.rejects(
    () => fetchTeamsChannelMessages({ teamId: 'team1', channelId: 'channel1' }, {
      env: {},
      fetchImpl: async () => response({ value: [] }),
    }),
    /access token is required/
  );
  await assert.rejects(
    () => fetchTeamsChannelMessages({ teamId: 'team1', channelId: 'channel1' }, {
      accessToken: 'unit-teams-token',
      fetchImpl: async () => response({ error: { code: 'Forbidden', message: 'SSN 524-71-9043' } }, { status: 403 }),
    }),
    (err) => {
      assert.match(err.message, /HTTP 403/);
      assert.ok(!err.message.includes('unit-teams-token'));
      assert.ok(!err.message.includes('524-71-9043'));
      return true;
    }
  );

  const sanitized = await sanitizeTeamsChatMessages({ chatId: 'chat1' }, {
    accessToken: 'unit-teams-token',
    fetchImpl: async () => response({ value: [{ body: { contentType: 'text', content: 'Member SSN 524-71-9043.' } }] }),
    guardOptions: {
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async () => ({ ok: true }),
    },
  });
  assert.strictEqual(sanitized.redacted, true);

  const check = teamsConnectorHealth({
    tenantId: 'tenant-acme',
    scopes: ['ChannelMessage.Read.Group', 'ChatMessage.Read.Chat'],
    accessToken: 'should-not-appear',
  }, true, 'OAuth probe ok');
  assert.strictEqual(check.id, 'mcp_connector_microsoft_teams');
  assert.strictEqual(check.ok, true);
  assert.ok(check.detail.includes('tenant:tenant-acme'));
  assert.ok(check.detail.includes('scopes:2'));
  assert.ok(!JSON.stringify(check).includes('should-not-appear'));
  assert.deepStrictEqual(graphScopes({ env: {} }), ['ChannelMessage.Read.Group', 'ChatMessage.Read.Chat']);
  assert.deepStrictEqual(graphScopes({ env: { TEAMS_GRAPH_SCOPES: 'Chat.Read ChannelMessage.Read.All' } }), ['Chat.Read', 'ChannelMessage.Read.All']);
});

test('Teams Graph JSON enforces declared response bounds before parsing', async () => {
  let jsonCalled = false;
  await assert.rejects(() => fetchTeamsChannelMessages({ teamId: 'team1', channelId: 'channel1' }, {
    accessToken: 'unit-teams-token',
    maxJsonBytes: 16,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      headers: headers({ 'content-length': '50000000' }),
      json: async () => { jsonCalled = true; return { value: [] }; },
    }),
  }), /exceeds 16 byte limit/);
  assert.strictEqual(jsonCalled, false);
});
