'use strict';
/**
 * Gateway provider adapters + canonical helpers — the translation seam between
 * the OpenAI-compatible front and real upstreams. Upstream HTTP is stubbed by
 * replacing global fetch, so request shaping (URL, headers, body) is asserted
 * without network. Streaming, embeddings, and error routes are covered against
 * the mock adapter through the real gateway app.
 */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const canonical = require('../gateway/canonical');
const { getAdapter, ADAPTERS } = require('../gateway/adapters');
const anthropic = require('../gateway/adapters/anthropic');
const openai = require('../gateway/adapters/openai');
const { createGateway } = require('../gateway/server');
const tokens = require('../gateway/tokens');

function tmpTokens(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-adp-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return path.join(dir, 'tokens.json');
}

function listenAndRequest(app, { method = 'POST', pathName = '/v1/chat/completions', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const { port } = server.address();
      const payload = body ? JSON.stringify(body) : '';
      const req = http.request({ host: '127.0.0.1', port, path: pathName, method, headers: { 'content-type': 'application/json', ...headers } }, (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => { server.close(); let json = null; try { json = data ? JSON.parse(data) : null; } catch (e) { json = null; } resolve({ status: res.statusCode, json, raw: data, headers: res.headers }); });
      });
      req.on('error', (e) => { server.close(); reject(e); });
      if (payload) req.write(payload);
      req.end();
    });
  });
}

function stubClient({ verdict, scan } = {}) {
  const requestVerdict = verdict || { decision: 'allow' };
  const responseVerdict = scan || { leaked: false, decision: 'allow', blocked: false };
  return {
    gate: async () => requestVerdict.status !== undefined || requestVerdict.decision === 'allow'
      ? requestVerdict
      : { ...requestVerdict, status: ({ block: 'pending', redact: 'redacted', warn: 'warned', log: 'proxy_observed' })[requestVerdict.decision] },
    scanResponse: async () => responseVerdict.status !== undefined
      ? responseVerdict
      : { ...responseVerdict, status: ({ allow: 'allowed', block: 'response_blocked', redact: 'response_redacted', flag: 'response_flagged' })[responseVerdict.decision] },
    rehydrate: async (id, text) => ({ text, rehydrated: false }),
  };
}

// Replace global fetch for the duration of one test, capturing the call.
function stubFetch(t, { status = 200, bodyText = '{}' } = {}) {
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    calls.push({ url, opts });
    return new Response(bodyText, { status, headers: { 'content-type': 'application/json' } });
  };
  t.after(() => { globalThis.fetch = original; });
  return calls;
}

// ---------------------------------------------------------------------------
test('canonical.requestText extracts text from every OpenAI request shape', () => {
  assert.strictEqual(canonical.requestText({ messages: [{ role: 'user', content: 'a' }, { role: 'user', content: 'b' }] }), 'a\nb');
  assert.strictEqual(canonical.requestText({ prompt: 'plain prompt' }), 'plain prompt');
  assert.strictEqual(canonical.requestText({ prompt: ['one', 2, 'two'] }), 'one\ntwo');
  assert.strictEqual(canonical.requestText({ input: 'embed me' }), 'embed me');
  assert.strictEqual(canonical.requestText({ input: ['x', null, 'y'] }), 'x\ny');
  assert.strictEqual(canonical.requestText({}), '');
  assert.strictEqual(canonical.requestText(null), '');
});

test('canonical.messageText joins multi-part content and tolerates junk', () => {
  assert.strictEqual(canonical.messageText({ content: [{ type: 'text', text: 'p1' }, { type: 'image' }, { type: 'text', text: 'p2' }] }), 'p1\np2');
  assert.strictEqual(canonical.messageText({ content: 42 }), '');
  assert.strictEqual(canonical.messageText(null), '');
});

test('canonical.applyRedactedRequest rewrites each request shape with tokenized text', () => {
  const viaMessages = canonical.applyRedactedRequest({ messages: [{ role: 'system', content: 'keep' }, { role: 'user', content: 'pii' }] }, 'TOK');
  assert.deepStrictEqual(viaMessages.messages, [{ role: 'system', content: 'keep' }, { role: 'user', content: 'TOK' }]);
  assert.strictEqual(canonical.applyRedactedRequest({ prompt: 'pii' }, 'TOK').prompt, 'TOK');
  assert.strictEqual(canonical.applyRedactedRequest({ input: 'pii' }, 'TOK').input, 'TOK');
  const fallback = canonical.applyRedactedRequest({ model: 'x' }, 'TOK');
  assert.deepStrictEqual(fallback.messages, [{ role: 'user', content: 'TOK' }]);
});

test('canonical.responseText reads chat choices, text choices, and embeddings', () => {
  assert.strictEqual(canonical.responseText({ choices: [{ message: { content: 'chat' } }] }), 'chat');
  assert.strictEqual(canonical.responseText({ choices: [{ text: 'completion' }] }), 'completion');
  assert.strictEqual(canonical.responseText({ data: [{ embedding: [0] }] }), '', 'embeddings have no scannable text');
  assert.strictEqual(canonical.responseText(null), '');
});

test('canonical.applyResponseText replaces the first textual choice only', () => {
  const chat = canonical.applyResponseText({ choices: [{ message: { content: 'old' } }, { message: { content: 'second' } }] }, 'new');
  assert.strictEqual(chat.choices[0].message.content, 'new');
  assert.strictEqual(chat.choices[1].message.content, 'second');
  const completion = canonical.applyResponseText({ choices: [{ text: 'old' }] }, 'new');
  assert.strictEqual(completion.choices[0].text, 'new');
  const noChoices = { data: [] };
  assert.strictEqual(canonical.applyResponseText(noChoices, 'new'), noChoices, 'non-choice payloads pass through');
});

// ---------------------------------------------------------------------------
test('getAdapter resolves supported aliases and rejects unknown providers', () => {
  assert.strictEqual(getAdapter('internal-http'), ADAPTERS.openai);
  assert.strictEqual(getAdapter('Anthropic'), ADAPTERS.anthropic);
  assert.throws(() => getAdapter('azure-openai'), /gateway provider must be one of/i);
  assert.throws(() => getAdapter('no-such-provider'), /gateway provider must be one of/i);
  assert.strictEqual(getAdapter(undefined), ADAPTERS.openai);
});

test('gateway construction rejects invalid or incomplete provider configuration', () => {
  assert.throws(() => createGateway({ provider: 'opneai' }), /gateway provider must be one of/i);
  assert.throws(() => createGateway({ provider: 'azure-openai' }), /gateway provider must be one of/i);
  assert.throws(
    () => createGateway({ provider: 'internal-http', upstreamBaseUrl: undefined }),
    /internal-http.*requires GATEWAY_UPSTREAM_URL/i
  );
});

test('gateway construction cannot override production onto the mock adapter', () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    assert.throws(
      () => createGateway({ provider: 'mock' }),
      /mock gateway provider is not allowed in production/i
    );
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
});

test('gateway construction requires credentials for public providers only', () => {
  const cases = [
    ['openai', undefined],
    ['anthropic', undefined],
  ];
  for (const [provider, upstreamBaseUrl] of cases) {
    assert.throws(
      () => createGateway({ provider, upstreamBaseUrl, upstreamApiKey: '   ' }),
      new RegExp(`${provider}.*requires GATEWAY_UPSTREAM_API_KEY`, 'i')
    );
  }
  assert.doesNotThrow(() => createGateway({
    provider: 'internal-http',
    upstreamBaseUrl: 'https://internal.example.test',
    upstreamApiKey: undefined,
  }));
});

// ---------------------------------------------------------------------------
test('anthropic.toAnthropic splits system turns and applies defaults', () => {
  const out = anthropic.toAnthropic({ model: 'claude-sonnet-4', messages: [
    { role: 'system', content: 'be brief' },
    { role: 'user', content: 'hi' },
    { role: 'assistant', content: 'hello' },
  ] });
  assert.strictEqual(out.system, 'be brief');
  assert.deepStrictEqual(out.messages, [{ role: 'user', content: 'hi' }, { role: 'assistant', content: 'hello' }]);
  assert.strictEqual(out.model, 'claude-sonnet-4');
  assert.strictEqual(out.max_tokens, 1024, 'default max_tokens');
});

test('anthropic.toAnthropic rejects non-chat and empty message shapes instead of inventing content', () => {
  assert.throws(
    () => anthropic.toAnthropic({ prompt: 'bare prompt', model: 'claude-x', max_tokens: 9 }),
    /does not support prompt/
  );
  assert.throws(
    () => anthropic.toAnthropic({ model: 'claude-x', messages: [] }),
    /require at least one message/
  );
});

test('anthropic.fromAnthropic maps content parts and stop_reason to OpenAI shape', () => {
  const out = anthropic.fromAnthropic({ id: 'msg_1', model: 'claude-x', stop_reason: 'end_turn', content: [{ type: 'text', text: 'a' }, { type: 'text', text: 'b' }] });
  assert.strictEqual(out.object, 'chat.completion');
  assert.strictEqual(out.choices[0].message.content, 'ab');
  assert.strictEqual(out.choices[0].finish_reason, 'stop');
  assert.strictEqual(typeof out.created, 'number');
  assert.throws(() => anthropic.fromAnthropic(null), /response is malformed/);
});

test('anthropic translates OpenAI function tools, results, choices, usage, and stop reasons', () => {
  const request = anthropic.toAnthropic({
    model: 'claude-x', max_completion_tokens: 77, parallel_tool_calls: false,
    tool_choice: { type: 'function', function: { name: 'lookup' } },
    tools: [{ type: 'function', function: {
      name: 'lookup', description: 'Lookup public data', strict: true,
      parameters: { type: 'object', properties: { id: { type: 'string' } } },
    } }],
    messages: [
      { role: 'user', content: 'Find it' },
      { role: 'assistant', content: null, tool_calls: [{
        id: 'call_1', type: 'function', function: { name: 'lookup', arguments: '{"id":"public"}' },
      }] },
      { role: 'tool', tool_call_id: 'call_1', content: 'found' },
    ],
  });
  assert.strictEqual(request.max_tokens, 77);
  assert.deepStrictEqual(request.tool_choice, {
    type: 'tool', name: 'lookup', disable_parallel_tool_use: true,
  });
  assert.strictEqual(request.tools[0].strict, true);
  assert.deepStrictEqual(request.messages[1].content, [{
    type: 'tool_use', id: 'call_1', name: 'lookup', input: { id: 'public' },
  }]);
  assert.deepStrictEqual(request.messages[2].content, [{
    type: 'tool_result', tool_use_id: 'call_1', content: 'found',
  }]);

  const response = anthropic.fromAnthropic({
    id: 'msg_tool', model: 'claude-x', stop_reason: 'tool_use',
    content: [{ type: 'tool_use', id: 'toolu_1', name: 'lookup', input: { id: 'public' } }],
    usage: { input_tokens: 3, output_tokens: 4 },
  });
  assert.strictEqual(response.choices[0].finish_reason, 'tool_calls');
  assert.strictEqual(response.choices[0].message.content, null);
  assert.deepStrictEqual(response.choices[0].message.tool_calls, [{
    id: 'toolu_1', type: 'function',
    function: { name: 'lookup', arguments: '{"id":"public"}' },
  }]);
  assert.deepStrictEqual(response.usage, {
    prompt_tokens: 3, completion_tokens: 4, total_tokens: 7,
  });
});

test('anthropic rejects unsupported semantics before translation', () => {
  const base = { model: 'claude-x', messages: [{ role: 'user', content: 'hello' }] };
  assert.throws(() => anthropic.validateRequest('embeddings', base), /chat\/completions/);
  assert.throws(() => anthropic.validateRequest('chat', { ...base, response_format: { type: 'json_object' } }), /response_format/);
  assert.throws(() => anthropic.validateRequest('chat', { ...base, temperature: 1.5 }), /between 0 and 1/);
  assert.throws(() => anthropic.toAnthropic({ ...base, messages: [{ role: 'assistant', content: 'leading' }, ...base.messages] }), /begin with a user/);
});

test('anthropic.callUpstream posts a translated body to /v1/messages with anthropic headers', async (t) => {
  const calls = stubFetch(t, { bodyText: JSON.stringify({ id: 'msg_2', model: 'claude-x', content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn' }) });
  const up = await anthropic.callUpstream('chat', { model: 'claude-x', messages: [{ role: 'user', content: 'hi' }] }, { upstreamBaseUrl: 'https://up.example//', upstreamApiKey: 'k1', requestTimeoutMs: 1000 });
  assert.strictEqual(calls[0].url, 'https://up.example/v1/messages', 'trailing slashes stripped');
  assert.strictEqual(calls[0].opts.headers['x-api-key'], 'k1');
  assert.strictEqual(calls[0].opts.headers['anthropic-version'], '2023-06-01');
  const sent = JSON.parse(calls[0].opts.body);
  assert.deepStrictEqual(sent.messages, [{ role: 'user', content: 'hi' }]);
  assert.ok(up.ok);
  assert.strictEqual(up.json.choices[0].message.content, 'ok', 'response translated back to OpenAI shape');
});

test('anthropic.callUpstream returns json null on an unparseable upstream body', async (t) => {
  stubFetch(t, { status: 500, bodyText: 'not json' });
  const up = await anthropic.callUpstream('chat', { model: 'claude-x', messages: [{ role: 'user', content: 'hi' }] }, { upstreamApiKey: 'unit-key', requestTimeoutMs: 1000 });
  assert.strictEqual(up.ok, false);
  assert.strictEqual(up.status, 500);
  assert.strictEqual(up.json, null);
  assert.strictEqual(up.rawText, 'not json');
});

test('openai.callUpstream routes each kind to its endpoint with a bearer key', async (t) => {
  const calls = stubFetch(t);
  const ctx = { upstreamBaseUrl: 'https://up.example/', upstreamApiKey: 'sk-test', requestTimeoutMs: 1000 };
  await openai.callUpstream('chat', { messages: [] }, ctx);
  await openai.callUpstream('completions', { prompt: 'p' }, ctx);
  await openai.callUpstream('embeddings', { input: 'i' }, ctx);
  assert.deepStrictEqual(calls.map((c) => c.url), [
    'https://up.example/v1/chat/completions',
    'https://up.example/v1/completions',
    'https://up.example/v1/embeddings',
  ]);
  assert.strictEqual(calls[0].opts.headers.authorization, 'Bearer sk-test');
});

test('openai.callUpstream survives an unparseable upstream body', async (t) => {
  stubFetch(t, { status: 200, bodyText: '<html>gateway timeout</html>' });
  const up = await openai.callUpstream('chat', { messages: [] }, { upstreamApiKey: 'unit-key', requestTimeoutMs: 1000 });
  assert.strictEqual(up.ok, true);
  assert.strictEqual(up.json, null, 'callers must treat unparseable success bodies as errors');
});

test('internal OpenAI-compatible adapter requires a URL and omits empty authorization', async (t) => {
  await assert.rejects(
    () => openai.callUpstream('chat', { messages: [] }, {
      provider: 'internal-http', requestTimeoutMs: 1000, maxUpstreamResponseBytes: 1024,
    }),
    /internal-http.*requires GATEWAY_UPSTREAM_URL/i
  );
  const calls = stubFetch(t);
  await openai.callUpstream('chat', { messages: [] }, {
    provider: 'internal-http', upstreamBaseUrl: 'https://internal.example.test',
    requestTimeoutMs: 1000, maxUpstreamResponseBytes: 1024,
  });
  assert.strictEqual(calls[0].opts.headers.authorization, undefined);
});

test('gateway rejects an unsupported Anthropic request before gate or upstream side effects', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let gateCalls = 0;
  let fetchCalls = 0;
  const original = globalThis.fetch;
  globalThis.fetch = async () => { fetchCalls += 1; throw new Error('must not fetch'); };
  t.after(() => { globalThis.fetch = original; });
  const client = { ...stubClient(), gate: async () => { gateCalls += 1; return { decision: 'allow' }; } };
  const { app } = createGateway({
    provider: 'anthropic', upstreamApiKey: 'unit-key', client, agentTokensPath: tp,
  });
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: {
      model: 'claude-x', response_format: { type: 'json_object' },
      messages: [{ role: 'user', content: 'safe request' }],
    },
  });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(gateCalls, 0);
  assert.strictEqual(fetchCalls, 0);
});

// ---------------------------------------------------------------------------
test('gateway serves stream:true as buffered SSE chunks ending in [DONE]', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { app } = createGateway({ provider: 'mock', client: stubClient(), agentTokensPath: tp });
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', stream: true, messages: [{ role: 'user', content: 'branch hours?' }] },
  });
  assert.strictEqual(res.status, 200);
  assert.match(res.headers['content-type'], /text\/event-stream/);
  const events = res.raw.split('\n\n').filter(Boolean);
  const first = JSON.parse(events[0].replace(/^data: /, ''));
  assert.strictEqual(first.object, 'chat.completion.chunk');
  assert.match(first.choices[0].delta.content, /branch hours/);
  const second = JSON.parse(events[1].replace(/^data: /, ''));
  assert.strictEqual(second.choices[0].finish_reason, 'stop');
  assert.strictEqual(events[2], 'data: [DONE]');
});

test('gateway streams the completions shape for /v1/completions', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { app } = createGateway({ provider: 'mock', client: stubClient(), agentTokensPath: tp });
  const res = await listenAndRequest(app, {
    pathName: '/v1/completions',
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', stream: true, prompt: 'say hi' },
  });
  assert.strictEqual(res.status, 200);
  const first = JSON.parse(res.raw.split('\n\n')[0].replace(/^data: /, ''));
  assert.strictEqual(first.object, 'text_completion');
  assert.match(first.choices[0].text, /say hi/);
});

test('gateway serves embeddings and ignores stream:true for them', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { app } = createGateway({ provider: 'mock', client: stubClient(), agentTokensPath: tp });
  const res = await listenAndRequest(app, {
    pathName: '/v1/embeddings',
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', stream: true, input: 'embed this' },
  });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.object, 'list', 'plain JSON, not SSE');
  assert.ok(Array.isArray(res.json.data));
});

test('gateway returns 502 when the upstream errors or replies unparseably', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const adapter = { ...ADAPTERS.mock, callUpstream: async () => ({ ok: false, status: 503, json: null }) };
  const { app } = createGateway({ client: stubClient(), adapter, agentTokensPath: tp });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: { model: 'x', messages: [{ role: 'user', content: 'hi' }] } });
  assert.strictEqual(res.status, 502);
  assert.strictEqual(res.json.error.type, 'upstream_error');
  assert.deepStrictEqual(res.json.error.reasons, ['upstream status 503']);
});

test('gateway gates structural outbound strings even when message content is empty', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let gateCalls = 0;
  let gatedPrompt = '';
  const client = { ...stubClient(), gate: async (payload) => { gateCalls++; gatedPrompt = payload.prompt; return { decision: 'allow' }; } };
  const { app, metrics } = createGateway({ provider: 'mock', client, agentTokensPath: tp });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: { model: 'x', messages: [] } });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(gateCalls, 1, 'every forwarded string crosses the DLP gate');
  assert.match(gatedPrompt, /model\nx/);
  assert.strictEqual(metrics.allowed, 1);
});

test('gateway serves anonymous identity when agent tokens are not required', async (t) => {
  const tp = tmpTokens(t);
  let gated = null;
  const client = { ...stubClient(), gate: async (p) => { gated = p; return { decision: 'allow' }; } };
  const { app } = createGateway({ provider: 'mock', client, agentTokensPath: tp, requireAgentToken: false });
  const res = await listenAndRequest(app, { body: { model: 'x', messages: [{ role: 'user', content: 'hi' }] } });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(gated.user, 'unattributed@gateway');
});

test('gateway health endpoints report ready only when the control plane answers', async (t) => {
  const tp = tmpTokens(t);
  const up = createGateway({ provider: 'mock', client: stubClient(), agentTokensPath: tp });
  const healthz = await listenAndRequest(up.app, { method: 'GET', pathName: '/healthz' });
  assert.strictEqual(healthz.status, 200);
  assert.strictEqual(healthz.json.status, 'ok');
  const ready = await listenAndRequest(up.app, { method: 'GET', pathName: '/readyz' });
  assert.strictEqual(ready.status, 200);
  assert.strictEqual(ready.json.ready, true);

  const down = createGateway({
    provider: 'mock', agentTokensPath: tp,
    client: { ...stubClient(), gate: async () => ({ decision: 'block', status: 'control_plane_unavailable', _failClosed: true }) },
  });
  const notReady = await listenAndRequest(down.app, { method: 'GET', pathName: '/readyz' });
  assert.strictEqual(notReady.status, 503);
  assert.strictEqual(notReady.json.ready, false);
});

test('gateway readiness exposes committed token-store cleanup degradation', async (t) => {
  const tp = tmpTokens(t);
  const original = tokens.storageHealth;
  tokens.storageHealth = () => ({ ok: false, reason: 'gateway-token-storage-cleanup-degraded' });
  t.after(() => { tokens.storageHealth = original; });
  const gateway = createGateway({ provider: 'mock', client: stubClient(), agentTokensPath: tp });
  const response = await listenAndRequest(gateway.app, { method: 'GET', pathName: '/readyz' });
  assert.strictEqual(response.status, 503);
  assert.deepStrictEqual(response.json, {
    ready: false,
    controlPlane: false,
    durableStorage: false,
    error: 'gateway_token_storage_cleanup_degraded',
  });
});

test('gateway blocks the response when the scan itself errors (fail closed)', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  // Real control-plane client against a server that 500s: scanResponse must
  // block the model output rather than release it unscanned.
  const errServer = http.createServer((req, res) => { res.writeHead(500, { 'content-type': 'application/json' }); res.end('{}'); });
  await new Promise((r) => errServer.listen(0, r));
  t.after(() => errServer.close());
  const { makeClient } = require('../gateway/client');
  const real = makeClient({ controlPlaneUrl: 'http://127.0.0.1:' + errServer.address().port, ingestKey: 'x', requestTimeoutMs: 2000 });
  const client = { ...stubClient(), scanResponse: real.scanResponse };
  const { app } = createGateway({ provider: 'mock', client, agentTokensPath: tp });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: { model: 'x', messages: [{ role: 'user', content: 'hello there' }] } });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'response_blocked_by_redactwall');
});
