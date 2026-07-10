'use strict';
/** First-party MCP tools must enforce tool policy before any upstream read. */
const test = require('node:test');
const assert = require('node:assert');
const {
  createConfluencePageTool,
  createJiraIssueTool,
} = require('../sensors/mcp-guard/connectors/atlassian');
const {
  createDatabaseReadonlyQueryTool,
  createDatabaseSchemaTool,
} = require('../sensors/mcp-guard/connectors/database-readonly');
const { createDriveFileContentTool } = require('../sensors/mcp-guard/connectors/google-drive');
const {
  createDriveItemContentTool,
  createListItemFieldsTool,
  createSitePageContentTool,
} = require('../sensors/mcp-guard/connectors/microsoft365');
const {
  createSlackConversationHistoryTool,
  createSlackFileContentTool,
} = require('../sensors/mcp-guard/connectors/slack');
const {
  createTeamsChannelMessagesTool,
  createTeamsChatMessagesTool,
} = require('../sensors/mcp-guard/connectors/teams');

function headers(values = {}) {
  const normalized = Object.fromEntries(
    Object.entries(values).map(([key, value]) => [key.toLowerCase(), value])
  );
  return { get: (name) => normalized[String(name).toLowerCase()] || '' };
}

function response(body, contentType = 'application/json') {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    ok: true,
    status: 200,
    headers: headers({
      'content-type': contentType,
      'content-length': String(Buffer.byteLength(text, 'utf8')),
    }),
    json: async () => (typeof body === 'string' ? JSON.parse(body) : body),
    text: async () => text,
  };
}

function blockedGuardOptions(telemetry) {
  return {
    server: 'https://redactwall.test',
    key: 'unit-ingest-key',
    policy: { mcpBlockedTools: ['*'] },
    fetchImpl: async (url, request = {}) => {
      telemetry.push({ url, body: JSON.parse(request.body) });
      return { ok: true };
    },
  };
}

function assertBlockedBeforeRead(name, result, executions, telemetry) {
  assert.strictEqual(executions, 0, `${name} performed an upstream read`);
  assert.match(result.content[0].text, /^\[BLOCKED: MCP tool blocked by policy\]$/);
  assert.strictEqual(telemetry.length, 1, `${name} should log one policy decision`);
  assert.strictEqual(telemetry[0].body.channel, 'mcp_tool');
  assert.ok(!JSON.stringify(telemetry).includes('524-71-9043'));
}

test('network-backed first-party connector tools preflight every operation', async () => {
  const cases = [
    {
      name: 'atlassian Jira',
      factory: createJiraIssueTool,
      args: { issueIdOrKey: 'CU-42', memberSsn: '524-71-9043' },
      options: {
        siteUrl: 'https://acme.atlassian.net', email: 'admin@example.test', apiToken: 'unit-token',
      },
      reply: () => response({ fields: { summary: 'Public issue' } }),
    },
    {
      name: 'atlassian Confluence',
      factory: createConfluencePageTool,
      args: { pageId: '12345' },
      options: {
        siteUrl: 'https://acme.atlassian.net', email: 'admin@example.test', apiToken: 'unit-token',
      },
      reply: () => response({ title: 'Public page', body: { storage: { value: '<p>Public</p>' } } }),
    },
    {
      name: 'Google Drive',
      factory: createDriveFileContentTool,
      args: { fileId: 'file123', mimeType: 'text/plain' },
      options: { accessToken: 'unit-token' },
      reply: () => response('Public file', 'text/plain'),
    },
    {
      name: 'Microsoft 365 drive item',
      factory: createDriveItemContentTool,
      args: { driveId: 'drive123', itemId: 'item123' },
      options: { accessToken: 'unit-token' },
      reply: () => response('Public file', 'text/plain'),
    },
    {
      name: 'Microsoft 365 site page',
      factory: createSitePageContentTool,
      args: { siteId: 'site123', pageId: 'page123' },
      options: { accessToken: 'unit-token' },
      reply: () => response({ title: 'Public page', canvasLayout: {} }),
    },
    {
      name: 'Microsoft 365 list item',
      factory: createListItemFieldsTool,
      args: { siteId: 'site123', listId: 'list123', itemId: 'item123' },
      options: { accessToken: 'unit-token' },
      reply: () => response({ fields: { Title: 'Public item' } }),
    },
    {
      name: 'Slack conversation',
      factory: createSlackConversationHistoryTool,
      args: { channel: 'C123' },
      options: { accessToken: 'unit-token' },
      reply: () => response({ ok: true, messages: [] }),
    },
    {
      name: 'Slack file',
      factory: createSlackFileContentTool,
      args: { fileId: 'F123' },
      options: { accessToken: 'unit-token' },
      reply: (url) => url.includes('files.info')
        ? response({ ok: true, file: { url_private: 'https://files.slack.com/public.txt' } })
        : response('Public file', 'text/plain'),
    },
    {
      name: 'Teams channel',
      factory: createTeamsChannelMessagesTool,
      args: { teamId: 'team123', channelId: 'channel123' },
      options: { accessToken: 'unit-token' },
      reply: () => response({ value: [] }),
    },
    {
      name: 'Teams chat',
      factory: createTeamsChatMessagesTool,
      args: { chatId: 'chat123' },
      options: { accessToken: 'unit-token' },
      reply: () => response({ value: [] }),
    },
  ];

  for (const entry of cases) {
    let executions = 0;
    const telemetry = [];
    const tool = entry.factory({
      ...entry.options,
      fetchImpl: async (url) => {
        executions += 1;
        return entry.reply(url);
      },
      guardOptions: blockedGuardOptions(telemetry),
    });

    const result = await tool(entry.args);
    assertBlockedBeforeRead(entry.name, result, executions, telemetry);
  }
});

test('database first-party tools preflight query and schema reads', async () => {
  for (const entry of [
    { name: 'database query', factory: createDatabaseReadonlyQueryTool, args: { sql: 'select 1 as ok' } },
    { name: 'database schema', factory: createDatabaseSchemaTool, args: {} },
  ]) {
    let executions = 0;
    const telemetry = [];
    const db = {
      prepare() {
        executions += 1;
        return { all: () => [] };
      },
    };
    const tool = entry.factory({ db, guardOptions: blockedGuardOptions(telemetry) });

    const result = await tool(entry.args);
    assertBlockedBeforeRead(entry.name, result, executions, telemetry);
  }
});

test('Google Drive preflights both possible operations before metadata lookup', async () => {
  let executions = 0;
  const telemetry = [];
  const tool = createDriveFileContentTool({
    accessToken: 'unit-token',
    fetchImpl: async () => {
      executions += 1;
      return response({ mimeType: 'application/vnd.google-apps.document' });
    },
    guardOptions: {
      ...blockedGuardOptions(telemetry),
      policy: { mcpBlockedTools: ['google_drive.files.export'] },
    },
  });

  const result = await tool({ fileId: 'workspace-doc' });

  assertBlockedBeforeRead('Google Drive inferred export', result, executions, telemetry);
  assert.strictEqual(telemetry[0].body.destination, 'google_drive.files.export');
});
