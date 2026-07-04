'use strict';
/**
 * AI Gateway — fail-closed request/response gating over an OpenAI-compatible
 * surface. Uses an injected control-plane client (no network) plus the mock
 * upstream adapter, so the security properties are asserted deterministically.
 */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { createGateway } = require('../gateway/server');
const tokens = require('../gateway/tokens');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

function tmpTokens(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-tok-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return path.join(dir, 'tokens.json');
}

// Minimal in-process HTTP client against an ephemeral listen().
function listenAndRequest(app, { method = 'POST', pathName = '/v1/chat/completions', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const { port } = server.address();
      const payload = body ? JSON.stringify(body) : '';
      const req = http.request({ host: '127.0.0.1', port, path: pathName, method, headers: { 'content-type': 'application/json', ...headers } }, (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => { server.close(); let json = null; try { json = data ? JSON.parse(data) : null; } catch (e) { json = null; } resolve({ status: res.statusCode, json, raw: data }); });
      });
      req.on('error', (e) => { server.close(); reject(e); });
      if (payload) req.write(payload);
      req.end();
    });
  });
}

// A scripted control-plane client. verdictFor/scanFor decide behavior per text.
function stubClient({ verdict, scan, rehydrated } = {}) {
  return {
    gate: async (payload) => (typeof verdict === 'function' ? verdict(payload) : (verdict || { decision: 'allow' })),
    scanResponse: async (payload) => (typeof scan === 'function' ? scan(payload) : (scan || { leaked: false, decision: 'allow', blocked: false })),
    rehydrate: async (id, text) => ({ text: rehydrated || text, rehydrated: !!rehydrated }),
  };
}

function chatBody(content) {
  return { model: 'x', messages: [{ role: 'user', content }] };
}

test('gateway rejects requests without an agent token', async (t) => {
  const { app } = createGateway({ provider: 'mock', client: stubClient(), agentTokensPath: tmpTokens(t) });
  const res = await listenAndRequest(app, { body: chatBody('hi') });
  assert.strictEqual(res.status, 401);
  assert.strictEqual(res.json.error.type, 'invalid_agent_token');
});

test('gateway allows a clean prompt and returns the model output', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x', orgId: 'o' }, tp);
  const { app } = createGateway({ provider: 'mock', client: stubClient({ verdict: { decision: 'allow' } }), agentTokensPath: tp });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: chatBody('branch hours?') });
  assert.strictEqual(res.status, 200);
  assert.match(res.json.choices[0].message.content, /branch hours/);
});

test('gateway blocks a prompt the control plane blocks — upstream is never called', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  const adapter = { requestText: (b) => b.messages[0].content, applyRedactedRequest: (b) => b, responseText: () => '', applyResponseText: (j) => j, callUpstream: async () => { upstreamCalls++; return { ok: true, json: {} }; } };
  const { app } = createGateway({ client: stubClient({ verdict: { decision: 'block', status: 'pending', reasons: ['Hard-stop entity present: US_SSN'] } }), adapter, agentTokensPath: tp });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: chatBody('SSN 412-22-7843') });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'blocked_by_promptwall');
  assert.strictEqual(upstreamCalls, 0, 'upstream must not be called on a blocked prompt');
});

test('gateway fails closed when the control plane is unreachable', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  const adapter = { requestText: (b) => b.messages[0].content, applyRedactedRequest: (b) => b, responseText: () => '', applyResponseText: (j) => j, callUpstream: async () => { upstreamCalls++; return { ok: true, json: {} }; } };
  const { app } = createGateway({ client: stubClient({ verdict: { decision: 'block', status: 'control_plane_unavailable', _failClosed: true, reasons: ['control plane unreachable'] } }), adapter, agentTokensPath: tp });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: chatBody('anything') });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(upstreamCalls, 0);
});

test('gateway blocks a model response the control plane flags as a leak', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { app } = createGateway({ provider: 'mock', client: stubClient({ verdict: { decision: 'allow' }, scan: { leaked: true, decision: 'block', blocked: true, reasons: ['Sensitive data present in AI response'] } }), agentTokensPath: tp });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: chatBody('tell me a secret') });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'response_blocked_by_promptwall');
});

test('gateway tokenizes on redact and rehydrates the response locally', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const sent = {};
  const adapter = {
    requestText: (b) => b.messages.map((m) => m.content).join('\n'),
    applyRedactedRequest: (b, tok) => { sent.tokenized = tok; return { ...b, messages: [{ role: 'user', content: tok }] }; },
    responseText: (j) => j.choices[0].message.content,
    applyResponseText: (j, txt) => ({ ...j, choices: [{ message: { role: 'assistant', content: txt } }] }),
    callUpstream: async (kind, body) => ({ ok: true, json: { choices: [{ message: { role: 'assistant', content: 'reply about ' + body.messages[0].content } }] } }),
  };
  const client = stubClient({ verdict: { decision: 'redact', id: 'q1', tokenizedPrompt: 'member [[US_SSN_1]]' }, scan: { leaked: false, decision: 'allow', blocked: false }, rehydrated: 'reply about member 412-22-7843' });
  const { app } = createGateway({ client, adapter, agentTokensPath: tp });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: chatBody('member 412-22-7843') });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(sent.tokenized, 'member [[US_SSN_1]]', 'tokenized prompt is forwarded, not raw PII');
  assert.match(res.json.choices[0].message.content, /412-22-7843/, 'response is rehydrated locally');
});

test('gateway enforces per-token rate limits', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { app } = createGateway({ provider: 'mock', client: stubClient(), agentTokensPath: tp, rateLimitPerMin: 2 });
  const send = () => listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: chatBody('hi') });
  assert.strictEqual((await send()).status, 200);
  assert.strictEqual((await send()).status, 200);
  assert.strictEqual((await send()).status, 429);
});

test('agent tokens are stored hashed and revocation takes effect', async (t) => {
  const tp = tmpTokens(t);
  const { token, id } = tokens.mintToken({ user: 'a@x' }, tp);
  const stored = JSON.parse(fs.readFileSync(tp, 'utf8'));
  assert.ok(!JSON.stringify(stored).includes(token), 'raw token is never persisted');
  assert.ok(tokens.resolveToken(token, tp), 'token resolves before revocation');
  tokens.revokeToken(id, tp);
  assert.strictEqual(tokens.resolveToken(token, tp), null, 'revoked token no longer resolves');
});
