'use strict';
/** MCP guard must never pass sensitive tool output to the model unchanged. */
const test = require('node:test');
const assert = require('node:assert');
const {
  demo,
  fetchPolicy,
  guardToolRequest,
  guardToolResult,
  mcpToolDecision,
  reportToolPolicyBody,
  reportBody,
  refreshPolicy,
  requestTimeoutMs,
  wrapTool,
} = require('../sensors/mcp-guard/guard');
const pkg = require('../package.json');

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
  assert.deepStrictEqual(outbound.body.sensor, { name: 'mcp_guard', version: pkg.version, platform: 'node' });
  assert.strictEqual(outbound.body.clientOutcome, 'redacted_sent');
  assert.strictEqual(outbound.body.clientPreRedacted, true);
  assert.ok(outbound.body.clientFindings.some((f) => f.type === 'US_SSN'));
  assert.ok(outbound.body.clientFindings.some((f) => f.type === 'CREDIT_CARD'));
  assert.ok(!JSON.stringify(outbound.body).includes('524-71-9043'));
  assert.ok(!JSON.stringify(outbound.body).includes('4111 1111 1111 1111'));
});

test('does not contact the control plane without an ingest key', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return { ok: true, json: async () => ({ ignore: ['US_SSN'], disabledDetectors: [] }) };
  };

  const policy = await fetchPolicy({ server: 'http://sentinel.test', key: '', fetchImpl });
  assert.strictEqual(policy, null);

  const guarded = await guardToolResult('Member SSN 524-71-9043 must stay local.', {
    agent: 'mcp-unit',
    tool: 'drive.fetch',
  }, {
    server: 'http://sentinel.test',
    key: '',
    fetchImpl,
    policy: { ignore: [], disabledDetectors: [] },
  });

  assert.strictEqual(guarded.redacted, true);
  assert.ok(guarded.text.includes('[US_SSN]'));
  assert.strictEqual(calls, 0);
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

test('blocks disallowed MCP tools before the handler runs and logs sanitized evidence', async () => {
  let handlerCalled = false;
  let outbound;
  const wrapped = wrapTool(async () => {
    handlerCalled = true;
    return 'SharePoint record SSN 524-71-9043.';
  }, {
    agent: 'mcp-unit',
    tool: 'sharepoint.deleteRecord',
  }, {
    server: 'http://sentinel.test',
    key: 'unit-key',
    policy: { ignore: [], disabledDetectors: [], mcpAllowedTools: ['sharepoint.fetch*'] },
    fetchImpl: async (url, opts) => {
      outbound = { url, body: JSON.parse(opts.body), headers: opts.headers };
      return { ok: true };
    },
  });

  const result = await wrapped({ memberSsn: '524-71-9043' });
  assert.strictEqual(handlerCalled, false);
  assert.match(result, /\[BLOCKED: MCP tool is outside the allowed registry\]/);
  assert.strictEqual(outbound.url, 'http://sentinel.test/api/v1/gate');
  assert.strictEqual(outbound.body.source, 'mcp_guard');
  assert.strictEqual(outbound.body.channel, 'mcp_tool');
  assert.strictEqual(outbound.body.clientOutcome, 'action_blocked');
  assert.strictEqual(outbound.body.destination, 'sharepoint.deleteRecord');
  assert.ok(!JSON.stringify(outbound.body).includes('524-71-9043'));

  const decision = await guardToolRequest({ agent: 'mcp-unit', tool: 'drive.fetchDoc' }, {
    policy: { mcpBlockedTools: ['drive.*'] },
    fetchImpl: async () => ({ ok: true }),
  });
  assert.strictEqual(decision.allowed, false);
  assert.strictEqual(mcpToolDecision({ tool: 'drive.fetchDoc' }, { mcpBlockedTools: ['drive.*'] }).status, 'blocked');
  assert.strictEqual(mcpToolDecision({ tool: 'sharepoint.deleteRecord' }, { mcpBlockedTools: ['*.delete*'] }).status, 'blocked');
  assert.strictEqual(reportToolPolicyBody({ decision, ctx: { agent: 'mcp-unit', tool: 'drive.fetchDoc' } }).prompt, '[MCP tool blocked] drive.fetchDoc');
  assert.strictEqual(reportToolPolicyBody({ decision: { reason: 'blocked' }, ctx: null }).user, 'mcp-agent');
});

test('policy refresh failures log sanitized errors only when requested', async () => {
  const errors = [];
  const originalError = console.error;
  console.error = (...args) => errors.push(args.join(' '));
  try {
    const policy = await fetchPolicy({
      server: 'http://sentinel.test',
      key: 'policy-key',
      silent: false,
      fetchImpl: async () => {
        throw new Error('network down for policy-key');
      },
    });

    assert.strictEqual(policy, null);
    assert.strictEqual(errors.length, 1);
    assert.match(errors[0], /policy refresh failed/);
    assert.ok(!errors[0].includes('SSN 524-71-9043'));
  } finally {
    console.error = originalError;
  }
});

test('redaction still works without implicit development ingest key logging', async () => {
  let called = false;
  const guarded = await guardToolResult('Member SSN 524-71-9043 must be redacted.', { agent: 'test', tool: 'drive.fetch' }, {
    policy: { ignore: [], disabledDetectors: [] },
    key: '',
    fetchImpl: async () => {
      called = true;
      return { ok: true };
    },
  });

  assert.strictEqual(guarded.redacted, true);
  assert.ok(guarded.text.includes('[US_SSN]'));
  assert.strictEqual(called, false);
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

test('guardToolResult refreshes live policy before scanning when no explicit policy is supplied', async () => {
  const requests = [];
  const guarded = await guardToolResult('Member SSN 524-71-9043 should follow live policy.', {
    agent: 'mcp-unit',
    tool: 'sharepoint.fetchDoc',
  }, {
    server: 'http://sentinel.test',
    key: 'policy-key',
    policyRefreshMs: 0,
    fetchImpl: async (url, opts = {}) => {
      requests.push({ url, headers: opts.headers });
      assert.ok(!JSON.stringify(opts).includes('524-71-9043'));
      return {
        ok: true,
        json: async () => ({ ignore: ['US_SSN'], disabledDetectors: [], customDetectors: [] }),
      };
    },
  });

  assert.strictEqual(requests[0].url, 'http://sentinel.test/api/v1/policy');
  // The policy refresh also fires a fire-and-forget presence heartbeat.
  assert.ok(requests.slice(1).every((r) => r.url === 'http://sentinel.test/api/v1/heartbeat'));
  assert.strictEqual(requests[0].headers['x-api-key'], 'policy-key');
  assert.strictEqual(guarded.redacted, false);
  assert.deepStrictEqual(guarded.findings, []);
});

test('wrapTool returns only guarded text for string and structured tool results', async () => {
  await refreshPolicy({
    server: 'http://sentinel.test',
    key: 'policy-key',
    fetchImpl: async () => ({
      ok: true,
      json: async () => ({ ignore: [], disabledDetectors: [], customDetectors: [] }),
    }),
  });

  const stringTool = wrapTool(async () => 'SharePoint record SSN 524-71-9043.', {
    agent: 'mcp-unit',
    tool: 'sharepoint.fetchDoc',
  });
  const structuredTool = wrapTool(async () => ({
    content: [{ type: 'text', text: 'Card 4111 1111 1111 1111' }],
  }), {
    agent: 'mcp-unit',
    tool: 'drive.fetch',
  });

  const stringResult = await stringTool({});
  const structuredResult = await structuredTool({});

  assert.ok(stringResult.includes('[US_SSN]'));
  assert.ok(!stringResult.includes('524-71-9043'));
  assert.ok(structuredResult.includes('[CREDIT_CARD]'));
  assert.ok(!structuredResult.includes('4111 1111 1111 1111'));
});

test('demo path prints raw and guarded MCP examples for operator verification', async () => {
  const lines = [];
  const result = await demo({
    console: {
      log(...args) {
        lines.push(args.join(' '));
      },
    },
    guardToolResult: async (text, ctx) => {
      assert.ok(text.includes('PS-CANARY-MCPDEMO123456'));
      assert.deepStrictEqual(ctx, { agent: 'claude-desktop', tool: 'sharepoint.fetchDoc' });
      return { text: '[CANARY_TOKEN]', redacted: true, findings: ['CANARY_TOKEN'] };
    },
  });

  assert.strictEqual(result.redacted, true);
  assert.ok(lines.some((line) => /raw MCP tool result/.test(line)));
  assert.ok(lines.some((line) => /guarded result/.test(line)));
  assert.ok(lines.some((line) => /detected: CANARY_TOKEN/.test(line)));
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
