'use strict';
/**
 * Regression tests for two gateway audit fixes:
 *   - anthropic.toAnthropic must not drop tool-role messages, emit empty-content
 *     turns, or start with an assistant turn (all rejected by Anthropic).
 *   - streaming /v1/completions must emit a text_completion-shaped terminal chunk.
 */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const anthropic = require('../gateway/adapters/anthropic');
const { createGateway } = require('../gateway/server');
const tokens = require('../gateway/tokens');

function tmpTokens(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-adpstr-'));
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
        res.on('end', () => { server.close(); resolve({ status: res.statusCode, raw: data }); });
      });
      req.on('error', (e) => { server.close(); reject(e); });
      if (payload) req.write(payload);
      req.end();
    });
  });
}

function stubClient() {
  return { gate: async () => ({ decision: 'allow' }), scanResponse: async () => ({ decision: 'allow', blocked: false }), health: async () => ({ ok: true }) };
}

test('toAnthropic maps tool-role results to user turns instead of dropping them', () => {
  const out = anthropic.toAnthropic({ messages: [
    { role: 'user', content: 'What is the balance?' },
    { role: 'assistant', content: '', tool_calls: [{ id: 't1', type: 'function', function: { name: 'lookup', arguments: '{"acct":"123"}' } }] },
    { role: 'tool', tool_call_id: 't1', content: 'balance is 4200' },
    { role: 'user', content: 'thanks, summarize it' },
  ] });
  const roles = out.messages.map((m) => m.role);
  assert.strictEqual(roles[0], 'user', 'first turn must be a user turn');
  // The tool result must survive somewhere in the transcript.
  assert.ok(out.messages.some((m) => m.content.includes('balance is 4200')), 'tool result is preserved as a user turn');
  // No empty-content turns.
  assert.ok(out.messages.every((m) => m.content && m.content.length), 'no empty-content turns');
  // Roles must alternate (Anthropic requirement).
  for (let i = 1; i < out.messages.length; i++) assert.notStrictEqual(out.messages[i].role, out.messages[i - 1].role, 'roles alternate');
});

test('toAnthropic drops a leading assistant turn so the first turn is a user turn', () => {
  const out = anthropic.toAnthropic({ messages: [
    { role: 'assistant', content: 'Hi, how can I help?' },
    { role: 'user', content: 'reset my password' },
  ] });
  assert.strictEqual(out.messages[0].role, 'user');
  assert.strictEqual(out.messages[0].content, 'reset my password');
});

test('streaming /v1/completions emits a text_completion-shaped terminal chunk', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { app } = createGateway({ provider: 'mock', client: stubClient(), agentTokensPath: tp });
  const res = await listenAndRequest(app, {
    pathName: '/v1/completions',
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', prompt: 'branch hours?', stream: true },
  });
  assert.strictEqual(res.status, 200);
  const chunks = res.raw.split('\n\n').map((l) => l.replace(/^data: /, '').trim()).filter((l) => l && l !== '[DONE]').map((l) => JSON.parse(l));
  const terminal = chunks[chunks.length - 1];
  assert.strictEqual(terminal.object, 'text_completion');
  assert.strictEqual(terminal.choices[0].finish_reason, 'stop');
  assert.strictEqual(terminal.choices[0].text, '', 'completions terminal chunk carries a text field, not a chat delta');
  assert.strictEqual(terminal.choices[0].delta, undefined, 'no chat-style delta on a text_completion chunk');
});
