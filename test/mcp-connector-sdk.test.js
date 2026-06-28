'use strict';
/** MCP connector SDK must sanitize tool results before model delivery. */
const test = require('node:test');
const assert = require('node:assert');
const {
  connectorContext,
  connectorHealthCheck,
  sanitizeToolResult,
  toolResultText,
  wrapConnectorTool,
} = require('../sensors/mcp-guard/sdk');

const cleanPolicy = { ignore: [], disabledDetectors: [] };
const noOpFetch = async () => ({ ok: true });

test('sanitizeToolResult redacts MCP content before returning it to the model', async () => {
  const raw = {
    content: [
      { type: 'text', text: 'SharePoint member record: SSN 524-71-9043.' },
    ],
    structuredContent: {
      label: 'member-card',
      card: '4111 1111 1111 1111',
    },
    debugSummary: 'Loan reviewer note includes SSN 524-71-9043.',
  };
  let outbound;

  const sanitized = await sanitizeToolResult(raw, {
    agent: 'claude-desktop',
    connector: 'microsoft365',
    tool: 'driveItem.getContent',
  }, {
    fetchImpl: async (url, opts = {}) => {
      outbound = { url, headers: opts.headers, body: JSON.parse(opts.body) };
      return { ok: true };
    },
    server: 'http://sentinel.test',
    key: 'unit-ingest-key',
    policy: cleanPolicy,
  });

  assert.strictEqual(sanitized.redacted, true);
  assert.ok(sanitized.findings.includes('US_SSN'));
  assert.ok(sanitized.findings.includes('CREDIT_CARD'));
  assert.deepStrictEqual(sanitized.result, {
    content: [{ type: 'text', text: sanitized.text }],
  });
  assert.ok(!JSON.stringify(sanitized.result).includes('524-71-9043'));
  assert.ok(!JSON.stringify(sanitized.result).includes('4111 1111 1111 1111'));
  assert.strictEqual(outbound.url, 'http://sentinel.test/api/v1/gate');
  assert.strictEqual(outbound.headers['x-api-key'], 'unit-ingest-key');
  assert.strictEqual(outbound.body.user, 'claude-desktop');
  assert.strictEqual(outbound.body.destination, 'microsoft365.driveItem.getContent');
  assert.strictEqual(outbound.body.source, 'mcp_guard');
  assert.strictEqual(outbound.body.channel, 'mcp_doc');
  assert.ok(!JSON.stringify(outbound.body).includes('524-71-9043'));
  assert.ok(!JSON.stringify(outbound.body).includes('4111 1111 1111 1111'));
});

test('sanitizeToolResult preserves clean MCP result objects and skips logging', async () => {
  const raw = {
    content: [{ type: 'text', text: 'Public branch hours and ATM maintenance schedule.' }],
    structuredContent: { documentId: 'public-faq', classification: 'public' },
  };
  let calls = 0;

  const sanitized = await sanitizeToolResult(raw, {
    agent: 'claude-desktop',
    connector: 'microsoft365',
    tool: 'driveItem.getContent',
  }, {
    fetchImpl: async () => {
      calls += 1;
      return { ok: true };
    },
    key: 'unit-ingest-key',
    policy: cleanPolicy,
  });

  assert.strictEqual(sanitized.redacted, false);
  assert.strictEqual(sanitized.result, raw);
  assert.strictEqual(calls, 0);
});

test('wrapConnectorTool forces sanitization around connector handlers', async () => {
  const wrapped = wrapConnectorTool(async () => ({
    content: [{ type: 'text', text: 'Member file includes SSN 524-71-9043.' }],
    isError: true,
  }), {
    agent: 'test-agent',
    connector: 'google-drive',
    tool: 'files.export',
  }, {
    fetchImpl: noOpFetch,
    policy: cleanPolicy,
  });

  const result = await wrapped({ fileId: 'abc' });
  assert.strictEqual(result.isError, true);
  assert.strictEqual(result.content.length, 1);
  assert.ok(result.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(result).includes('524-71-9043'));
});

test('connector context ignores raw args and normalizes destination labels', () => {
  const ctx = connectorContext({
    agent: 'mcp runner',
    connector: 'microsoft365',
    tool: 'driveItem.getContent',
    args: { query: 'SSN 524-71-9043' },
  });

  assert.deepStrictEqual(ctx, {
    agent: 'mcp runner',
    tool: 'microsoft365.driveItem.getContent',
  });
  assert.ok(!JSON.stringify(ctx).includes('524-71-9043'));
});

test('connector health checks are bounded and secret-free', () => {
  const check = connectorHealthCheck({
    id: 'Microsoft 365 Graph',
    tenantId: 'cu-acme',
    scopes: ['Files.Read.All', 'Sites.Read.All'],
  }, false, 'bearer token abcdefghijklmnopqrstuvwxyz123456 failed OAuth probe');

  assert.strictEqual(check.id, 'mcp_connector_microsoft_365_graph');
  assert.strictEqual(check.ok, false);
  assert.ok(check.detail.includes('tenant:cu-acme'));
  assert.ok(check.detail.includes('scopes:2'));
  assert.ok(!check.detail.includes('abcdefghijklmnopqrstuvwxyz123456'));
  assert.ok(check.detail.length <= 160);
});

test('toolResultText handles circular connector output without throwing', () => {
  const raw = { content: [{ type: 'text', text: 'public data' }] };
  raw.self = raw;
  const text = toolResultText(raw);
  assert.ok(text.includes('public data'));
  assert.ok(text.includes('[Circular]'));

  const circularOnly = { name: 'public' };
  circularOnly.self = circularOnly;
  assert.match(toolResultText(circularOnly), /\[Circular\]/);
});
