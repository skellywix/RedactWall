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
  return {
    gate: async () => ({ decision: 'allow' }),
    scanResponse: async () => ({ decision: 'allow', status: 'allowed', blocked: false }),
    health: async () => ({ ok: true }),
  };
}

test('toAnthropic maps tool-role results to user turns instead of dropping them', () => {
  const out = anthropic.toAnthropic({ model: 'claude-x', messages: [
    { role: 'user', content: 'What is the balance?' },
    { role: 'assistant', content: '', tool_calls: [{ id: 't1', type: 'function', function: { name: 'lookup', arguments: '{"acct":"123"}' } }] },
    { role: 'tool', tool_call_id: 't1', content: 'balance is 4200' },
    { role: 'user', content: 'thanks, summarize it' },
  ] });
  const roles = out.messages.map((m) => m.role);
  assert.strictEqual(roles[0], 'user', 'first turn must be a user turn');
  const toolUse = out.messages[1].content.find((part) => part.type === 'tool_use');
  const toolResult = out.messages[2].content.find((part) => part.type === 'tool_result');
  assert.deepStrictEqual(toolUse.input, { acct: '123' });
  assert.strictEqual(toolResult.content, 'balance is 4200');
  assert.strictEqual(
    out.messages[1].content.some((part) => part.type === 'text' && part.text.includes('123')),
    false,
    'tool arguments are not duplicated into assistant text'
  );
  // No empty-content turns.
  assert.ok(out.messages.every((m) => m.content && m.content.length), 'no empty-content turns');
  // Roles must alternate (Anthropic requirement).
  for (let i = 1; i < out.messages.length; i++) assert.notStrictEqual(out.messages[i].role, out.messages[i - 1].role, 'roles alternate');
});

test('toAnthropic rejects a leading assistant turn instead of silently dropping it', () => {
  assert.throws(() => anthropic.toAnthropic({ model: 'claude-x', messages: [
    { role: 'assistant', content: 'Hi, how can I help?' },
    { role: 'user', content: 'reset my password' },
  ] }), /begin with a user/);
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

test('buffered chat streaming preserves all choices, tool calls, finish reasons, and usage', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const adapter = {
    callUpstream: async () => ({
      ok: true,
      status: 200,
      json: {
        id: 'chatcmpl_multi',
        model: 'x',
        created: 123,
        choices: [
          {
            index: 0,
            message: {
              role: 'assistant',
              content: null,
              tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'lookup', arguments: '{"id":"public"}' } }],
            },
            finish_reason: 'tool_calls',
          },
          { index: 1, message: { role: 'assistant', content: 'second safe answer' }, finish_reason: 'length' },
        ],
        usage: { prompt_tokens: 3, completion_tokens: 4, total_tokens: 7 },
      },
    }),
  };
  const { app } = createGateway({ provider: 'mock', client: stubClient(), adapter, agentTokensPath: tp });
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', stream: true, messages: [{ role: 'user', content: 'public prompt' }] },
  });
  assert.strictEqual(res.status, 200);
  const chunks = res.raw.split('\n\n').map((line) => line.replace(/^data: /, '').trim())
    .filter((line) => line && line !== '[DONE]').map((line) => JSON.parse(line));
  assert.strictEqual(chunks[0].choices.length, 2);
  assert.strictEqual(chunks[0].choices[0].delta.tool_calls[0].function.name, 'lookup');
  assert.strictEqual(chunks[0].choices[1].delta.content, 'second safe answer');
  assert.deepStrictEqual(chunks[1].choices.map((choice) => choice.finish_reason), ['tool_calls', 'length']);
  assert.deepStrictEqual(chunks[1].usage, { prompt_tokens: 3, completion_tokens: 4, total_tokens: 7 });
});
