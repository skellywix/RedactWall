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
    server: 'https://redactwall.test',
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
  assert.strictEqual(outbound.url, 'https://redactwall.test/api/v1/gate');
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
  assert.notStrictEqual(sanitized.result, raw);
  assert.deepStrictEqual(sanitized.result, raw);
  raw.content[0].text = 'Member SSN 524-71-9043.';
  raw.structuredContent.classification = 'restricted';
  assert.deepStrictEqual(sanitized.result, {
    content: [{ type: 'text', text: 'Public branch hours and ATM maintenance schedule.' }],
    structuredContent: { documentId: 'public-faq', classification: 'public' },
  });
  assert.strictEqual(calls, 0);
});

test('sanitizeToolResult delivers the exact clean snapshot inspected from stateful toJSON output', async () => {
  let serializations = 0;
  const raw = {
    toJSON() {
      serializations += 1;
      return serializations === 1
        ? { content: [{ type: 'text', text: 'Public branch schedule.' }] }
        : { content: [{ type: 'text', text: 'Member SSN 524-71-9043.' }] };
    },
  };

  const sanitized = await sanitizeToolResult(raw, {
    connector: 'records', tool: 'fetchStatefulResult',
  }, { key: '', policy: cleanPolicy });
  const delivered = JSON.stringify(sanitized.result);

  assert.strictEqual(serializations, 1);
  assert.deepStrictEqual(sanitized.result, {
    content: [{ type: 'text', text: 'Public branch schedule.' }],
  });
  assert.doesNotMatch(delivered, /524-71-9043/);
});

test('sanitizeToolResult preserves repeated aliases as detached JSON values', async () => {
  const shared = { type: 'text', text: 'Public branch schedule.' };
  const raw = {
    content: [shared],
    structuredContent: { mirror: shared },
  };

  const sanitized = await sanitizeToolResult(raw, {
    connector: 'records', tool: 'fetchAliasedResult',
  }, { key: '', policy: cleanPolicy });

  assert.deepStrictEqual(sanitized.result, {
    content: [{ type: 'text', text: 'Public branch schedule.' }],
    structuredContent: { mirror: { type: 'text', text: 'Public branch schedule.' } },
  });
  assert.notStrictEqual(sanitized.result.content[0], sanitized.result.structuredContent.mirror);
  shared.text = 'Member SSN 524-71-9043.';
  assert.doesNotMatch(JSON.stringify(sanitized.result), /524-71-9043/);
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

test('wrapConnectorTool enforces request policy before handler execution', async () => {
  const cases = [
    {
      name: 'blocked',
      policy: { mcpBlockedTools: ['records.deleteMember'] },
      expected: 'MCP tool blocked by policy',
    },
    {
      name: 'approval-required',
      policy: { mcpApprovalRequiredTools: ['records.deleteMember'] },
      expected: 'MCP tool requires approval before execution',
    },
    {
      name: 'allowed',
      policy: { mcpAllowedTools: ['records.deleteMember'] },
      expected: 'Public confirmation',
    },
  ];

  for (const entry of cases) {
    let executions = 0;
    const telemetry = [];
    const wrapped = wrapConnectorTool(async () => {
      executions += 1;
      return { content: [{ type: 'text', text: 'Public confirmation' }] };
    }, {
      agent: 'connector-agent',
      connector: 'records',
      tool: 'deleteMember',
    }, {
      key: 'unit-ingest-key',
      policy: entry.policy,
      fetchImpl: async (url, request = {}) => {
        telemetry.push({ url, body: JSON.parse(request.body) });
        return { ok: true };
      },
    });

    const result = await wrapped({ memberId: 'public-record' });

    assert.strictEqual(executions, entry.name === 'allowed' ? 1 : 0, entry.name);
    assert.deepStrictEqual(result, {
      content: [{ type: 'text', text: entry.name === 'allowed'
        ? entry.expected
        : `[BLOCKED: ${entry.expected}]` }],
    });
    assert.strictEqual(telemetry.length, entry.name === 'allowed' ? 0 : 1, entry.name);
    assert.ok(!JSON.stringify(telemetry).includes('public-record'), entry.name);
  }
});

test('wrapConnectorTool does not bypass request policy with an empty context list', async () => {
  let executions = 0;
  const wrapped = wrapConnectorTool(async () => {
    executions += 1;
    return { content: [{ type: 'text', text: 'should not run' }] };
  }, () => [], {
    key: '',
    policy: { mcpBlockedTools: ['mcp-tool'] },
  });

  const result = await wrapped({});

  assert.strictEqual(executions, 0);
  assert.match(result.content[0].text, /^\[BLOCKED:/);
});

test('connector arguments are scanned before network or database side effects', async () => {
  for (const entry of [
    { tool: 'files.search', args: { query: 'member SSN 524-71-9043' } },
    { tool: 'database.query', args: { sql: 'select * from members where ssn = 524-71-9043' } },
    { tool: 'files.upload', args: { future_payload: Buffer.from('SSN 524-71-9043').toString('base64') } },
  ]) {
    let sideEffects = 0;
    const telemetry = [];
    const wrapped = wrapConnectorTool(async () => {
      sideEffects += 1;
      return { content: [{ type: 'text', text: 'should not execute' }] };
    }, { agent: 'connector-agent', connector: 'records', tool: entry.tool }, {
      key: 'unit-ingest-key',
      policy: cleanPolicy,
      fetchImpl: async (url, request = {}) => {
        telemetry.push({ url, body: JSON.parse(request.body) });
        return { ok: true, body: { cancel: async () => {} } };
      },
    });

    const result = await wrapped(entry.args);
    assert.strictEqual(sideEffects, 0, entry.tool);
    assert.match(result.content[0].text, /^\[BLOCKED:/);
    assert.strictEqual(telemetry.length, 1, entry.tool);
    assert.doesNotMatch(JSON.stringify(telemetry), /524-71-9043/);
  }
});

test('connector handler receives the exact clean argument snapshot that was inspected', async () => {
  let serializations = 0;
  let received;
  const args = {
    toJSON() {
      serializations += 1;
      return { query: serializations === 1 ? 'public branch hours' : 'SSN 524-71-9043' };
    },
  };
  const wrapped = wrapConnectorTool(async (snapshot) => {
    received = snapshot;
    return { content: [{ type: 'text', text: 'Public confirmation' }] };
  }, { connector: 'records', tool: 'search' }, {
    key: '',
    policy: cleanPolicy,
  });

  const result = await wrapped(args);
  assert.strictEqual(serializations, 1);
  assert.deepStrictEqual(received, { query: 'public branch hours' });
  assert.match(result.content[0].text, /Public confirmation/);
});

test('connector SDK blocks unscannable binary results with label-only output', async () => {
  const encoded = Buffer.from('Member SSN 123-45-6789').toString('base64');
  const raw = {
    content: [{ type: 'image', mimeType: 'image/png', data: encoded }],
    structuredContent: { contentBase64: encoded },
  };
  let outbound;
  const opts = {
    fetchImpl: async (url, request = {}) => {
      outbound = { url, body: JSON.parse(request.body) };
      return { ok: true };
    },
    server: 'https://redactwall.test',
    key: 'unit-ingest-key',
    policy: cleanPolicy,
  };

  const sanitized = await sanitizeToolResult(raw, {
    agent: 'connector-agent', connector: 'records', tool: 'fetchImage',
  }, opts);
  const wrapped = wrapConnectorTool(async () => raw, {
    agent: 'connector-agent', connector: 'records', tool: 'fetchImage',
  }, opts);
  const delivered = await wrapped({});

  assert.strictEqual(sanitized.redacted, true);
  assert.strictEqual(sanitized.blocked, true);
  assert.deepStrictEqual(sanitized.findings, ['UNSCANNABLE_BINARY']);
  assert.deepStrictEqual(sanitized.result, {
    content: [{ type: 'text', text: '[BLOCKED: MCP tool result contains binary content RedactWall cannot inspect]' }],
  });
  assert.ok(!JSON.stringify(sanitized).includes(encoded));
  assert.ok(!JSON.stringify(delivered).includes(encoded));
  assert.deepStrictEqual(delivered, sanitized.result);
  assert.strictEqual(outbound.url, 'https://redactwall.test/api/v1/gate');
  assert.strictEqual(outbound.body.prompt, '[MCP tool result blocked] unscannable binary content');
  assert.ok(!JSON.stringify(outbound.body).includes(encoded));
});

test('connector SDK blocks binary content revealed only during serialization', async () => {
  const encoded = Buffer.from('Member SSN 123-45-6789').toString('base64');
  const disguised = {
    toJSON() {
      return { content: [{ type: 'image', mimeType: 'image/png', data: encoded }] };
    },
  };

  const sanitized = await sanitizeToolResult(disguised, {
    connector: 'records', tool: 'fetchSerializedImage',
  }, { key: '', policy: cleanPolicy });

  assert.strictEqual(sanitized.blocked, true);
  assert.ok(!JSON.stringify(sanitized).includes(encoded));
  assert.match(sanitized.result.content[0].text, /^\[BLOCKED:/);
});

test('connector SDK blocks typed bytes returned by a custom serializer', async () => {
  const raw = {
    toJSON() {
      return Uint8Array.from(Buffer.from('Member SSN 123-45-6789'));
    },
  };

  const sanitized = await sanitizeToolResult(raw, {
    connector: 'records', tool: 'fetchSerializedBytes',
  }, { key: '', policy: cleanPolicy });

  assert.strictEqual(sanitized.blocked, true);
  assert.deepStrictEqual(sanitized.findings, ['UNSCANNABLE_BINARY']);
  assert.match(sanitized.result.content[0].text, /^\[BLOCKED:/);
});

test('connector SDK withholds reversible encoded and numeric content snapshots', async () => {
  const secret = 'SSN 123-45-6789';
  const opaqueResults = [
    { content: [{ type: 'text', text: Buffer.from(secret).toString('base64') }] },
    { content: [{ type: 'text', text: Buffer.from(secret).toString('hex') }] },
    { content: [{ type: 'text', text: 'ordinary result', metadata: { raw: [...Buffer.from(secret)] } }] },
  ];

  for (const raw of opaqueResults) {
    const serialized = JSON.stringify(raw);
    const sanitized = await sanitizeToolResult(raw, {
      connector: 'records', tool: 'fetchEncodedRecord',
    }, { key: '', policy: cleanPolicy });
    assert.strictEqual(sanitized.blocked, true);
    assert.deepStrictEqual(sanitized.findings, ['UNSCANNABLE_BINARY']);
    assert.match(sanitized.result.content[0].text, /^\[BLOCKED:/);
    assert.ok(!JSON.stringify(sanitized.result).includes(serialized));
  }
});

test('connector SDK preserves harmless encodings and structured numeric records', async () => {
  const raw = {
    content: [{ type: 'text', text: Buffer.from('quarterly branch hours').toString('base64') }],
    structuredContent: {
      label: 'CustomerAccountStatus',
      rows: [{ year: 2025, amount: 42 }],
      metrics: [1, 2, 3],
      embedding: [0.125, -0.5, 0.75],
    },
  };
  const sanitized = await sanitizeToolResult(raw, {
    connector: 'records', tool: 'fetchPublicMetrics',
  }, { key: '', policy: cleanPolicy });

  assert.strictEqual(sanitized.blocked, undefined);
  assert.strictEqual(sanitized.redacted, false);
  assert.deepStrictEqual(sanitized.result, raw);
});

test('connector SDK scans resource-link fields mixed with ordinary text', async () => {
  const raw = {
    content: [
      { type: 'text', text: 'Public branch schedule.' },
      {
        type: 'resource_link',
        uri: 'https://records.example.test/member/524-71-9043',
        name: 'Member record',
      },
    ],
  };

  const sanitized = await sanitizeToolResult(raw, {
    connector: 'records', tool: 'fetchResourceLink',
  }, { key: '', policy: cleanPolicy });

  assert.strictEqual(sanitized.redacted, true);
  assert.ok(sanitized.findings.includes('US_SSN'));
  assert.ok(!JSON.stringify(sanitized.result).includes('524-71-9043'));
});

test('connector SDK scans unknown content fields and structured property names', async () => {
  const raw = {
    content: [
      { type: 'text', text: 'Public member summary.' },
      { type: 'vendor_card', name: 'Member 524-71-9043', status: 'active' },
    ],
    structuredContent: {
      'member_524-71-9043': { classification: 'restricted' },
    },
  };

  const sanitized = await sanitizeToolResult(raw, {
    connector: 'records', tool: 'fetchVendorCard',
  }, { key: '', policy: cleanPolicy });

  assert.strictEqual(sanitized.redacted, true);
  assert.ok(sanitized.findings.includes('US_SSN'));
  assert.ok(!JSON.stringify(sanitized.result).includes('524-71-9043'));
});

test('connector SDK fails closed when result inspection throws', async () => {
  const secrets = ['111-22-3333', '222-33-4444', '333-44-5555'];
  const getterResult = {};
  Object.defineProperty(getterResult, 'content', {
    enumerable: true,
    get() { throw new Error(`hostile getter ${secrets[0]}`); },
  });
  const proxyResult = new Proxy({}, {
    ownKeys() { throw new Error(`hostile proxy ${secrets[1]}`); },
  });
  const toJsonResult = {
    toJSON() { throw new Error(`hostile toJSON ${secrets[2]}`); },
  };
  const telemetry = [];
  const opts = {
    server: 'https://redactwall.test',
    key: 'unit-ingest-key',
    policy: cleanPolicy,
    fetchImpl: async (url, request = {}) => {
      telemetry.push({ url, body: JSON.parse(request.body) });
      return { ok: true };
    },
  };

  for (const result of [getterResult, proxyResult, toJsonResult]) {
    const sanitized = await sanitizeToolResult(result, {
      connector: 'records', tool: 'fetchHostileResult',
    }, opts);

    assert.strictEqual(sanitized.redacted, true);
    assert.strictEqual(sanitized.blocked, true);
    assert.deepStrictEqual(sanitized.findings, ['UNINSPECTABLE_RESULT']);
    assert.deepStrictEqual(sanitized.result, {
      content: [{ type: 'text', text: '[BLOCKED: MCP tool result could not be safely inspected]' }],
    });
  }
  assert.strictEqual(telemetry.length, 3);
  assert.ok(telemetry.every((entry) => entry.body.prompt === '[MCP tool result blocked] inspection failed'));
  for (const secret of secrets) assert.ok(!JSON.stringify(telemetry).includes(secret));
});

test('wrapConnectorTool contains hostile result-context getters inside the fail-closed boundary', async () => {
  const secret = '524-71-9043';
  const raw = {};
  Object.defineProperty(raw, 'structuredContent', {
    enumerable: true,
    get() { throw new Error(`hostile result context ${secret}`); },
  });
  const telemetry = [];
  const wrapped = wrapConnectorTool(async () => raw, {
    connector: 'records', tool: 'fetchHostileContext',
  }, {
    server: 'https://redactwall.test',
    key: 'unit-ingest-key',
    policy: cleanPolicy,
    fetchImpl: async (url, request = {}) => {
      telemetry.push({ url, body: JSON.parse(request.body) });
      return { ok: true };
    },
  });

  const delivered = await wrapped({});

  assert.deepStrictEqual(delivered, {
    content: [{ type: 'text', text: '[BLOCKED: MCP tool result could not be safely inspected]' }],
  });
  assert.strictEqual(telemetry.length, 1);
  assert.strictEqual(telemetry[0].body.prompt, '[MCP tool result blocked] inspection failed');
  assert.ok(!JSON.stringify({ delivered, telemetry }).includes(secret));
});

test('connector SDK fails closed on a true result cycle without leaking cycle contents', async () => {
  const secret = '524-71-9043';
  const raw = { content: [{ type: 'text', text: `Member ${secret}` }] };
  raw.self = raw;
  const telemetry = [];

  const sanitized = await sanitizeToolResult(raw, {
    connector: 'records', tool: 'fetchCyclicResult',
  }, {
    server: 'https://redactwall.test',
    key: 'unit-ingest-key',
    policy: cleanPolicy,
    fetchImpl: async (url, request = {}) => {
      telemetry.push({ url, body: JSON.parse(request.body) });
      return { ok: true };
    },
  });

  assert.strictEqual(sanitized.blocked, true);
  assert.deepStrictEqual(sanitized.findings, ['UNINSPECTABLE_RESULT']);
  assert.deepStrictEqual(sanitized.result, {
    content: [{ type: 'text', text: '[BLOCKED: MCP tool result could not be safely inspected]' }],
  });
  assert.strictEqual(telemetry.length, 1);
  assert.ok(!JSON.stringify({ sanitized, telemetry }).includes(secret));
});

test('connector SDK fails closed when a structured result has no serializable snapshot', async () => {
  const sanitized = await sanitizeToolResult({
    toJSON() { return undefined; },
  }, {
    connector: 'records', tool: 'fetchUnserializableResult',
  }, { key: '', policy: cleanPolicy });

  assert.strictEqual(sanitized.blocked, true);
  assert.deepStrictEqual(sanitized.findings, ['UNINSPECTABLE_RESULT']);
  assert.deepStrictEqual(sanitized.result, {
    content: [{ type: 'text', text: '[BLOCKED: MCP tool result could not be safely inspected]' }],
  });
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

test('SDK handles resource text and preserves redacted non-content result shapes', async () => {
  const resourceEnvelope = toolResultText({
    content: [
      null,
      { resource: { text: 'resource text' } },
      { type: 'image', data: 'not-text' },
    ],
  });
  assert.ok(resourceEnvelope.includes('resource text'));
  assert.ok(resourceEnvelope.includes('not-text'));

  const textEnvelope = await sanitizeToolResult({ text: 'Member SSN 524-71-9043' }, {
    connector: 'microsoft365',
    tool: 'search',
  }, {
    fetchImpl: noOpFetch,
    policy: cleanPolicy,
  });
  assert.deepStrictEqual(textEnvelope.result, { text: textEnvelope.text });
  assert.ok(textEnvelope.text.includes('[US_SSN]'));

  const plainObject = await sanitizeToolResult({ value: 'Member SSN 524-71-9043' }, {
    connector: 'microsoft365',
    tool: 'search',
  }, {
    fetchImpl: noOpFetch,
    policy: cleanPolicy,
  });
  assert.deepStrictEqual(plainObject.result, { content: [{ type: 'text', text: plainObject.text }] });
  assert.ok(!JSON.stringify(plainObject.result).includes('524-71-9043'));
});
