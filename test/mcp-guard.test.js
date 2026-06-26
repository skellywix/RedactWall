'use strict';
/** MCP guard must never pass sensitive tool output to the model unchanged. */
const test = require('node:test');
const assert = require('node:assert');
const { guardToolResult, reportBody, refreshPolicy, requestTimeoutMs } = require('../mcp-guard/guard');

const noOpFetch = async () => ({ ok: true });

test('redacts structured PII in MCP tool output', async () => {
  const raw = 'Member SSN 524-71-9043 should not reach the model.';
  const guarded = await guardToolResult(raw, { agent: 'test', tool: 'sharepoint.fetchDoc' }, {
    fetchImpl: noOpFetch,
    policy: { ignore: [], disabledDetectors: [] },
  });
  assert.strictEqual(guarded.redacted, true);
  assert.ok(guarded.findings.includes('US_SSN'));
  assert.ok(!guarded.text.includes('524-71-9043'));
  assert.ok(guarded.text.includes('[US_SSN]'));
});

test('whole-chunk redacts category-only confidential MCP output', async () => {
  const raw = 'Between us, we are switching away from our core processor next quarter. Keep this internal and do not forward.';
  const guarded = await guardToolResult(raw, { agent: 'test', tool: 'sharepoint.fetchDoc' }, {
    fetchImpl: noOpFetch,
    policy: { ignore: [], disabledDetectors: [] },
  });
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
    policy: { ignore: [], disabledDetectors: [] },
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

test('MCP control-plane request timeout is bounded', () => {
  assert.strictEqual(requestTimeoutMs({ timeoutMs: 1 }), 50);
  assert.strictEqual(requestTimeoutMs({ timeoutMs: 999999 }), 120000);
  assert.strictEqual(requestTimeoutMs({ timeoutMs: 'bad' }), 10000);
});

test('returns redacted tool output when audit logging stalls', async () => {
  const started = Date.now();
  const guarded = await guardToolResult('Member SSN 524-71-9043 must be redacted.', { agent: 'test', tool: 'drive.fetch' }, {
    policy: { ignore: [], disabledDetectors: [] },
    server: 'http://sentinel.test',
    key: 'unit-key',
    timeoutMs: 10,
    fetchImpl: async (url, opts) => new Promise((resolve, reject) => {
      assert.strictEqual(url, 'http://sentinel.test/api/v1/gate');
      assert.strictEqual(opts.headers['x-api-key'], 'unit-key');
      opts.signal.addEventListener('abort', () => {
        const e = new Error('aborted');
        e.name = 'AbortError';
        reject(e);
      });
    }),
  });

  assert.strictEqual(guarded.redacted, true);
  assert.ok(guarded.text.includes('[US_SSN]'));
  assert.ok(!guarded.text.includes('524-71-9043'));
  assert.ok(Date.now() - started < 1000);
});

test('honors detector ignore policy for MCP tool output', async () => {
  const raw = 'Member SSN 524-71-9043 should be ignored by this policy.';
  const guarded = await guardToolResult(raw, { agent: 'test', tool: 'sharepoint.fetchDoc' }, {
    fetchImpl: noOpFetch,
    policy: { ignore: ['US_SSN'], disabledDetectors: [] },
  });

  assert.strictEqual(guarded.redacted, false);
  assert.deepStrictEqual(guarded.findings, []);
  assert.strictEqual(guarded.text, raw);
});

test('refreshes MCP detection policy from the control plane', async () => {
  let request;
  const policy = await refreshPolicy({
    server: 'http://sentinel.test',
    key: 'policy-key',
    fetchImpl: async (url, opts) => {
      request = { url, headers: opts.headers };
      return {
        ok: true,
        json: async () => ({ ignore: ['US_SSN', 'CREDENTIALS'], disabledDetectors: ['CREDIT_CARD'] }),
      };
    },
  });

  assert.strictEqual(request.url, 'http://sentinel.test/api/v1/policy');
  assert.strictEqual(request.headers['x-api-key'], 'policy-key');
  assert.deepStrictEqual(policy.ignore, ['US_SSN', 'CREDENTIALS']);
  assert.deepStrictEqual(policy.disabledDetectors, ['CREDIT_CARD']);

  const guarded = await guardToolResult('SSN 524-71-9043', { agent: 'test', tool: 'drive.fetch' }, {
    fetchImpl: noOpFetch,
    skipPolicyRefresh: true,
  });
  assert.strictEqual(guarded.redacted, false);
});
