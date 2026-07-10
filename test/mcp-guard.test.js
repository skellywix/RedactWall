'use strict';
/** MCP guard must never pass sensitive tool output to the model unchanged. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  demo,
  detectionOptions,
  fetchPolicy,
  guardToolRequest,
  guardToolResult,
  mcpToolDecision,
  reportToolPolicyBody,
  reportBody,
  refreshPolicy,
  requestTimeoutMs,
  wrapTool,
  carriesUnscannableToolResult,
} = require('../sensors/mcp-guard/guard');
const pkg = require('../package.json');
const D = require('../detection-engine/detect');

const POLICY_KEYS = crypto.generateKeyPairSync('ed25519');
const POLICY_PUBLIC_KEY = POLICY_KEYS.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const POLICY_CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-mcp-policy-'));
let policyCacheId = 0;
test.after(() => fs.rmSync(POLICY_CACHE_DIR, { recursive: true, force: true }));

function signedPolicyBundle(policy) {
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  const policyHash = crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex');
  const input = JSON.stringify({ version: 1, issuedAt, expiresAt, policyHash });
  return { version: 1, issuedAt, expiresAt, policy, signature: crypto.sign(null, Buffer.from(input), POLICY_KEYS.privateKey).toString('base64') };
}

function signedPolicyOptions() {
  policyCacheId += 1;
  return { policyPublicKey: POLICY_PUBLIC_KEY, policyCachePath: path.join(POLICY_CACHE_DIR, `${policyCacheId}.json`) };
}

const noOpFetch = async () => ({ ok: true });

function jsonResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

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

test('MCP detection options carry EDM and cannot disable active hard stops', async () => {
  const value = '550e8400-e29b-41d4-a716-446655440000';
  const salt = 'mcp-unit-salt-0123456789abcdef012345';
  const exactMatch = {
    formatVersion: 2,
    algorithm: 'sha256',
    valuePolicy: 'offline-random-id-v1',
    salt,
    minLen: 20,
    maxWords: 1,
    fingerprints: [D.edmFingerprint(value, salt)],
  };
  const policy = {
    alwaysBlock: ['US_SSN', 'EXACT_MATCH'],
    disabledDetectors: ['US_SSN', 'EXACT_MATCH', 'EMAIL_ADDRESS'],
    exactMatch,
  };
  const opts = detectionOptions(policy);
  assert.deepStrictEqual(opts.disabledDetectors, ['EMAIL_ADDRESS']);
  assert.strictEqual(opts.exactMatch, exactMatch);
  assert.ok(opts.alwaysBlock.includes('CREDIT_CARD'), 'remote policy cannot remove mandatory MCP hard stops');

  const guarded = await guardToolResult(`opaque record ${value}`, {
    agent: 'mcp-unit', tool: 'database.read',
  }, { policy, key: '', fetchImpl: noOpFetch });
  assert.strictEqual(guarded.redacted, true);
  assert.ok(guarded.findings.includes('EXACT_MATCH'));
  assert.ok(!guarded.text.includes(value));
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
    server: 'https://redactwall.test',
    key: 'unit-key',
  });

  assert.strictEqual(guarded.redacted, true);
  assert.strictEqual(outbound.url, 'https://redactwall.test/api/v1/gate');
  assert.strictEqual(outbound.headers['x-api-key'], 'unit-key');
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

  const policy = await fetchPolicy({ server: 'https://redactwall.test', key: '', fetchImpl });
  assert.strictEqual(policy, null);

  const guarded = await guardToolResult('Member SSN 524-71-9043 must stay local.', {
    agent: 'mcp-unit',
    tool: 'drive.fetch',
  }, {
    server: 'https://redactwall.test',
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
    server: 'https://redactwall.test',
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
  assert.strictEqual(outbound.url, 'https://redactwall.test/api/v1/gate');
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
      server: 'https://redactwall.test',
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

test('MCP policy refresh bounds stalled and oversized response bodies', async () => {
  let cancelled = 0;
  const stalled = new Response(new ReadableStream({
    cancel() { cancelled += 1; },
  }), { status: 200, headers: { 'content-type': 'application/json' } });

  const stalledPolicy = await fetchPolicy({
    server: 'https://redactwall.test',
    key: 'policy-key',
    timeoutMs: 10,
    silent: true,
    fetchImpl: async () => stalled,
  });
  assert.strictEqual(stalledPolicy, null);
  assert.strictEqual(cancelled, 1);

  const oversizedPolicy = await fetchPolicy({
    server: 'https://redactwall.test',
    key: 'policy-key',
    maxResponseBytes: 1024,
    silent: true,
    fetchImpl: async () => jsonResponse(200, { padding: 'x'.repeat(2048) }),
  });
  assert.strictEqual(oversizedPolicy, null);
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
    server: 'https://redactwall.test',
    key: 'unit-key',
    timeoutMs: 10,
    fetchImpl: async (url, opts) => new Promise((resolve, reject) => {
      assert.strictEqual(url, 'https://redactwall.test/api/v1/gate');
      assert.strictEqual(opts.headers['x-api-key'], 'unit-key');
      assert.strictEqual(opts.redirect, 'error');
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
  const raw = 'Contact jane.doe@example.com for branch hours.';
  const guarded = await guardToolResult(raw, { agent: 'test', tool: 'sharepoint.fetchDoc' }, {
    fetchImpl: noOpFetch,
    policy: { ignore: ['EMAIL_ADDRESS'], disabledDetectors: [] },
  });

  assert.strictEqual(guarded.redacted, false);
  assert.deepStrictEqual(guarded.findings, []);
  assert.strictEqual(guarded.text, raw);
});

test('guardToolResult refreshes live policy before scanning when no explicit policy is supplied', async () => {
  const requests = [];
  const guarded = await guardToolResult('Contact jane.doe@example.com for branch hours.', {
    agent: 'mcp-unit',
    tool: 'sharepoint.fetchDoc',
  }, {
    server: 'https://redactwall.test',
    key: 'policy-key',
    ...signedPolicyOptions(),
    policyRefreshMs: 0,
    fetchImpl: async (url, opts = {}) => {
      requests.push({ url, headers: opts.headers });
      assert.ok(!JSON.stringify(opts).includes('jane.doe@example.com'));
      assert.strictEqual(opts.redirect, 'error');
      return jsonResponse(200, signedPolicyBundle({ ignore: ['EMAIL_ADDRESS'], disabledDetectors: [], customDetectors: [] }));
    },
  });

  assert.strictEqual(requests[0].url, 'https://redactwall.test/api/v1/policy/bundle');
  // The policy refresh also fires a fire-and-forget presence heartbeat.
  assert.ok(requests.slice(1).every((r) => r.url === 'https://redactwall.test/api/v1/heartbeat'));
  assert.strictEqual(requests[0].headers['x-api-key'], 'policy-key');
  assert.strictEqual(guarded.redacted, false);
  assert.deepStrictEqual(guarded.findings, []);
});

test('wrapTool returns only guarded text for string and structured tool results', async () => {
  await refreshPolicy({
    server: 'https://redactwall.test',
    key: 'policy-key',
    ...signedPolicyOptions(),
    fetchImpl: async () => jsonResponse(200, signedPolicyBundle({ ignore: [], disabledDetectors: [], customDetectors: [] })),
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

test('wrapTool scans sensitive arguments before the handler can cause effects', async () => {
  let calls = 0;
  const wrapped = wrapTool(async () => {
    calls += 1;
    return 'connector side effect completed';
  }, {
    agent: 'mcp-unit',
    tool: 'records.update',
  }, { key: '', policy: {} });

  const result = await wrapped({ note: 'Member SSN 524-71-9043' });

  assert.match(result, /^\[BLOCKED:/);
  assert.strictEqual(calls, 0, 'sensitive arguments must be rejected before handler execution');
  assert.ok(!result.includes('524-71-9043'));
});

test('wrapTool blocks structured image/base64 results before model delivery', async () => {
  const encodedSensitiveImage = Buffer.from('Member SSN 123-45-6789').toString('base64');
  const imageTool = wrapTool(async () => ({
    content: [{ type: 'image', mimeType: 'image/png', data: encodedSensitiveImage }],
  }), {
    agent: 'mcp-unit',
    tool: 'records.fetchImage',
  }, { key: '', policy: {} });

  const result = await imageTool({});

  assert.match(result, /^\[BLOCKED:/);
  assert.ok(!result.includes(encodedSensitiveImage), 'reversible binary payload must not reach the model');
});

test('wrapTool blocks binary payloads hidden by JSON strings or toJSON', async () => {
  const encoded = Buffer.from('Member SSN 123-45-6789').toString('base64');
  const jsonStringTool = wrapTool(async () => JSON.stringify({ data: [{ b64_json: encoded }] }), {
    agent: 'mcp-unit', tool: 'images.generate',
  }, { key: '', policy: {} });
  const toJsonTool = wrapTool(async () => ({
    toJSON: () => ({ content: [{ type: 'image', data: encoded }] }),
  }), {
    agent: 'mcp-unit', tool: 'images.fetch',
  }, { key: '', policy: {} });

  for (const result of [await jsonStringTool({}), await toJsonTool({})]) {
    assert.match(result, /^\[BLOCKED:/);
    assert.ok(!result.includes(encoded));
  }
});

test('MCP wrapper withholds encoded SSNs and numeric content before model delivery', async () => {
  const secret = 'SSN 123-45-6789';
  const wrappedBase64 = Buffer.from(secret).toString('base64').match(/.{1,4}/g).join(' ');
  const opaqueValues = [
    Buffer.from(secret).toString('base64'),
    wrappedBase64,
    Buffer.from(secret).toString('hex'),
    Buffer.from([0, 255, 1, 254, 2, 253, 3, 252, 4, 251, 5, 250]).toString('base64'),
    [...Buffer.from(secret)],
    JSON.stringify([...Buffer.from(secret)]),
    { type: 'text', text: 'ordinary result', metadata: { raw: [...Buffer.from(secret)] } },
  ];

  for (const opaque of opaqueValues) {
    const wrapped = wrapTool(async () => ({ content: opaque }), {
      agent: 'mcp-unit',
      tool: 'records.fetch',
    }, { key: '', policy: {} });
    const result = await wrapped({});
    assert.match(result, /^\[BLOCKED:/);
    assert.ok(!result.includes(secret));
    assert.ok(!result.includes(typeof opaque === 'string' ? opaque : JSON.stringify(opaque)));
  }
});

test('MCP wrapper joins adjacent text parts before encoded-content inspection', async () => {
  const secret = 'SSN 123-45-6789';
  const encoded = Buffer.from(secret).toString('base64');
  const wrapped = wrapTool(async () => ({
    content: [
      { type: 'text', text: encoded.slice(0, 8) },
      { type: 'text', text: encoded.slice(8) },
    ],
  }), {
    agent: 'mcp-unit',
    tool: 'records.fetch',
  }, { key: '', policy: {} });

  const result = await wrapped({});
  assert.match(result, /^\[BLOCKED:/);
  assert.ok(!result.includes(encoded.slice(0, 8)));
  assert.ok(!result.includes(encoded.slice(8)));
});

test('MCP guard permits harmless alphanumeric encodings and structured numeric records', async () => {
  const harmlessEncodedText = Buffer.from('quarterly branch hours').toString('base64');
  const record = {
    content: harmlessEncodedText,
    label: 'CustomerAccountStatus',
    rows: [{ year: 2025, amount: 42 }],
    metrics: [1, 2, 3],
    embedding: [0.125, -0.5, 0.75],
  };
  assert.strictEqual(carriesUnscannableToolResult(record), false);

  const wrapped = wrapTool(async () => record, {
    agent: 'mcp-unit',
    tool: 'records.fetch',
  }, { key: '', policy: {} });
  const result = await wrapped({});
  assert.deepStrictEqual(JSON.parse(result), record);

  for (const benignId of [
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1bml0LXVzZXIifQ.signature',
  ]) {
    const idTool = wrapTool(async () => ({ content: benignId }), {
      agent: 'mcp-unit', tool: 'records.fetch',
    }, { key: '', policy: {} });
    assert.deepStrictEqual(JSON.parse(await idTool({})), { content: benignId });
  }
});

test('MCP binary detection covers MIME-only and data-URL shapes but permits structured text data', () => {
  const encoded = Buffer.from('Member SSN 123-45-6789').toString('base64');

  assert.strictEqual(carriesUnscannableToolResult({ mime_type: 'image/png', data: encoded }), true);
  assert.strictEqual(carriesUnscannableToolResult({ source: { url: 'data:image/png;base64,' + encoded } }), true);
  assert.strictEqual(carriesUnscannableToolResult({ source: { url: 'data:;base64,' + encoded } }), true);
  assert.strictEqual(carriesUnscannableToolResult({ source: { url: 'data:image/png;charset=utf-8;base64,' + encoded } }), true);
  assert.strictEqual(carriesUnscannableToolResult({ data: [{ b64_json: encoded }] }), true);
  assert.strictEqual(carriesUnscannableToolResult({ data: [{ b64Json: encoded }] }), true);
  assert.strictEqual(carriesUnscannableToolResult(JSON.stringify({ data: [{ b64_json: encoded }] })), true);
  assert.strictEqual(carriesUnscannableToolResult({ data: 'ordinary structured text', metadata: { source: 'crm' } }), false);
  assert.strictEqual(carriesUnscannableToolResult({ type: 'file_search_call', data: 'ordinary structured text' }), false);
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
    server: 'https://redactwall.test',
    key: 'policy-key',
    ...signedPolicyOptions(),
    fetchImpl: async (url, opts) => {
      request = { url, headers: opts.headers };
      assert.strictEqual(opts.redirect, 'error');
      return jsonResponse(200, signedPolicyBundle({ ignore: ['US_SSN', 'CREDENTIALS'], disabledDetectors: ['CREDIT_CARD'] }));
    },
  });

  assert.strictEqual(request.url, 'https://redactwall.test/api/v1/policy/bundle');
  assert.strictEqual(request.headers['x-api-key'], 'policy-key');
  assert.deepStrictEqual(policy.ignore, ['CREDENTIALS']);
  assert.deepStrictEqual(policy.disabledDetectors, []);

  const guarded = await guardToolResult('SSN 524-71-9043', { agent: 'test', tool: 'drive.fetch' }, {
    fetchImpl: noOpFetch,
    skipPolicyRefresh: true,
  });
  assert.strictEqual(guarded.redacted, true);
  assert.ok(guarded.text.includes('[US_SSN]'));
});
