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
  return {
    gate: async () => verdict || { decision: 'allow' },
    scanResponse: async () => scan || { leaked: false, decision: 'allow', blocked: false },
    rehydrate: async (id, text) => ({ text, rehydrated: false }),
  };
}

// Replace global fetch for the duration of one test, capturing the call.
function stubFetch(t, { status = 200, bodyText = '{}' } = {}) {
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    calls.push({ url, opts });
    return { ok: status >= 200 && status < 300, status, text: async () => bodyText };
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
test('getAdapter resolves aliases, is case-insensitive, and falls back to openai', () => {
  assert.strictEqual(getAdapter('azure-openai'), ADAPTERS.openai);
  assert.strictEqual(getAdapter('internal-http'), ADAPTERS.openai);
  assert.strictEqual(getAdapter('Anthropic'), ADAPTERS.anthropic);
  assert.strictEqual(getAdapter('no-such-provider'), ADAPTERS.openai);
  assert.strictEqual(getAdapter(undefined), ADAPTERS.openai);
});

// ---------------------------------------------------------------------------
test('anthropic.toAnthropic splits system turns and applies defaults', () => {
  const out = anthropic.toAnthropic({ messages: [
    { role: 'system', content: 'be brief' },
    { role: 'user', content: 'hi' },
    { role: 'assistant', content: 'hello' },
  ] });
  assert.strictEqual(out.system, 'be brief');
  assert.deepStrictEqual(out.messages, [{ role: 'user', content: 'hi' }, { role: 'assistant', content: 'hello' }]);
  assert.strictEqual(out.model, 'claude-sonnet-4', 'default model');
  assert.strictEqual(out.max_tokens, 1024, 'default max_tokens');
});

test('anthropic.toAnthropic falls back to requestText when no user/assistant turns exist', () => {
  const out = anthropic.toAnthropic({ prompt: 'bare prompt', model: 'claude-x', max_tokens: 9 });
  assert.deepStrictEqual(out.messages, [{ role: 'user', content: 'bare prompt' }]);
  assert.strictEqual(out.model, 'claude-x');
  assert.strictEqual(out.max_tokens, 9);
});

test('anthropic.fromAnthropic maps content parts and stop_reason to OpenAI shape', () => {
  const out = anthropic.fromAnthropic({ id: 'msg_1', model: 'claude-x', stop_reason: 'end_turn', content: [{ type: 'text', text: 'a' }, { type: 'tool_use' }, { type: 'text', text: 'b' }] });
  assert.strictEqual(out.object, 'chat.completion');
  assert.strictEqual(out.choices[0].message.content, 'ab');
  assert.strictEqual(out.choices[0].finish_reason, 'end_turn');
  const empty = anthropic.fromAnthropic(null);
  assert.strictEqual(empty.choices[0].message.content, '');
  assert.strictEqual(empty.choices[0].finish_reason, 'stop');
});

test('anthropic.callUpstream posts a translated body to /v1/messages with anthropic headers', async (t) => {
  const calls = stubFetch(t, { bodyText: JSON.stringify({ id: 'msg_2', content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn' }) });
  const up = await anthropic.callUpstream('chat', { messages: [{ role: 'user', content: 'hi' }] }, { upstreamBaseUrl: 'https://up.example//', upstreamApiKey: 'k1', requestTimeoutMs: 1000 });
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
  const up = await anthropic.callUpstream('chat', { messages: [] }, { requestTimeoutMs: 1000 });
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
  const up = await openai.callUpstream('chat', { messages: [] }, { requestTimeoutMs: 1000 });
  assert.strictEqual(up.ok, true);
  assert.strictEqual(up.json, null, 'callers must treat unparseable success bodies as errors');
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

test('gateway skips the gate for empty prompts but still calls upstream', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let gateCalls = 0;
  const client = { ...stubClient(), gate: async () => { gateCalls++; return { decision: 'allow' }; } };
  const { app, metrics } = createGateway({ provider: 'mock', client, agentTokensPath: tp });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: { model: 'x', messages: [] } });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(gateCalls, 0, 'no text to gate');
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
  assert.strictEqual(res.json.error.type, 'response_blocked_by_promptwall');
});
