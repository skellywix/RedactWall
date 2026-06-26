'use strict';
/** MCP guard must never pass sensitive tool output to the model unchanged. */
const test = require('node:test');
const assert = require('node:assert');
const { guardToolResult, reportBody } = require('../mcp-guard/guard');

test('redacts structured PII in MCP tool output', async () => {
  const raw = 'Member SSN 524-71-9043 should not reach the model.';
  const guarded = await guardToolResult(raw, { agent: 'test', tool: 'sharepoint.fetchDoc' });
  assert.strictEqual(guarded.redacted, true);
  assert.ok(guarded.findings.includes('US_SSN'));
  assert.ok(!guarded.text.includes('524-71-9043'));
  assert.ok(guarded.text.includes('[US_SSN]'));
});

test('whole-chunk redacts category-only confidential MCP output', async () => {
  const raw = 'Between us, we are switching away from our core processor next quarter. Keep this internal and do not forward.';
  const guarded = await guardToolResult(raw, { agent: 'test', tool: 'sharepoint.fetchDoc' });
  assert.strictEqual(guarded.redacted, true);
  assert.ok(guarded.findings.includes('CONFIDENTIAL_BUSINESS'));
  assert.ok(!guarded.text.includes('switching away from our core processor'));
  assert.match(guarded.text, /^\[REDACTED: .*CONFIDENTIAL_BUSINESS.*\]$/);
});

test('reports sanitized client analysis for locally redacted MCP output', async () => {
  const raw = 'SharePoint record: SSN 524-71-9043 and card 4111 1111 1111 1111.';
  let outbound;
  const guarded = await guardToolResult(raw, { agent: 'mcp-unit', tool: 'drive.fetch' }, {
    fetchImpl: async (url, opts) => {
      outbound = { url, body: JSON.parse(opts.body), headers: opts.headers };
      return { ok: true };
    },
    server: 'http://sentinel.test',
    key: 'unit-key',
  });

  assert.strictEqual(guarded.redacted, true);
  assert.strictEqual(outbound.url, 'http://sentinel.test/api/v1/gate');
  assert.strictEqual(outbound.headers['x-api-key'], 'unit-key');
  assert.strictEqual(outbound.body.source, 'mcp_guard');
  assert.strictEqual(outbound.body.channel, 'mcp_doc');
  assert.strictEqual(outbound.body.clientOutcome, 'redacted_sent');
  assert.strictEqual(outbound.body.clientPreRedacted, true);
  assert.ok(outbound.body.clientFindings.some((f) => f.type === 'US_SSN'));
  assert.ok(outbound.body.clientFindings.some((f) => f.type === 'CREDIT_CARD'));
  assert.ok(!JSON.stringify(outbound.body).includes('524-71-9043'));
  assert.ok(!JSON.stringify(outbound.body).includes('4111 1111 1111 1111'));
});

test('report body preserves category evidence without raw confidential text', () => {
  const analysis = {
    findings: [],
    categories: [{ category: 'CONFIDENTIAL_BUSINESS', score: 0.88 }],
    entityCounts: { CONFIDENTIAL_BUSINESS: 1 },
    riskScore: 42,
    maxSeverity: 3,
    maxSeverityLabel: 'high',
  };
  const body = reportBody({
    safeText: '[REDACTED: CONFIDENTIAL_BUSINESS]',
    analysis,
    ctx: { agent: 'claude-desktop', tool: 'sharepoint.fetchDoc' },
  });

  assert.deepStrictEqual(body.clientCategories, [{ category: 'CONFIDENTIAL_BUSINESS', score: 0.88 }]);
  assert.deepStrictEqual(body.clientEntityCounts, { CONFIDENTIAL_BUSINESS: 1 });
  assert.strictEqual(body.prompt, '[REDACTED: CONFIDENTIAL_BUSINESS]');
  assert.ok(!JSON.stringify(body).includes('switching away from our core processor'));
});
