'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { createGateway } = require('../gateway/server');
const tokens = require('../gateway/tokens');
const {
  classifyRequestVerdict,
  classifyResponseVerdict,
  REQUEST_MATRIX,
  RESPONSE_MATRIX,
} = require('../gateway/verdict');

function tmpTokens(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-verdict-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return path.join(dir, 'tokens.json');
}

function request(app, token, content = 'ordinary prompt') {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const payload = JSON.stringify({ model: 'x', messages: [{ role: 'user', content }] });
      const req = http.request({
        host: '127.0.0.1',
        port: server.address().port,
        path: '/v1/chat/completions',
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload),
        },
      }, (res) => {
        let raw = '';
        res.on('data', (chunk) => { raw += chunk; });
        res.on('end', () => {
          server.close();
          let json = null;
          try { json = JSON.parse(raw); } catch {}
          resolve({ status: res.statusCode, raw, json });
        });
      });
      req.on('error', (error) => { server.close(); reject(error); });
      req.end(payload);
    });
  });
}

test('gateway verdict matrices accept only their declared decision/status pairs', () => {
  for (const [decision, statuses] of Object.entries(REQUEST_MATRIX)) {
    for (const status of statuses) {
      assert.strictEqual(classifyRequestVerdict({ decision, status }), decision, `${decision}/${status}`);
    }
  }
  for (const [decision, statuses] of Object.entries(RESPONSE_MATRIX)) {
    for (const status of statuses) {
      assert.strictEqual(
        classifyResponseVerdict({ decision, status, blocked: decision === 'block' }),
        decision,
        `${decision}/${status}`,
      );
    }
  }

  const requestContradictions = [
    { decision: 'allow', status: 'pending' },
    { decision: 'block', status: 'allowed' },
    { decision: 'redact', status: 'allowed' },
    { decision: 'warn', status: 'redacted' },
    { decision: 'log', status: 'warned' },
    { decision: 'redact' },
  ];
  for (const verdict of requestContradictions) {
    assert.strictEqual(classifyRequestVerdict(verdict), 'invalid', JSON.stringify(verdict));
  }

  const responseContradictions = [
    { decision: 'allow', status: 'response_blocked', blocked: false },
    { decision: 'block', status: 'allowed', blocked: true },
    { decision: 'redact', status: 'allowed', blocked: false },
    { decision: 'flag', status: 'response_redacted', blocked: false },
    { decision: 'allow', status: 'allowed', blocked: true },
    { decision: 'block', status: 'response_blocked', blocked: false },
    { decision: 'allow', blocked: false },
  ];
  for (const verdict of responseContradictions) {
    assert.strictEqual(classifyResponseVerdict(verdict), 'invalid', JSON.stringify(verdict));
  }
});

test('contradictory request verdicts fail closed before any upstream call', async (t) => {
  const tokenPath = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'verdict@example.test' }, tokenPath);
  const contradictions = [
    { decision: 'allow', status: 'pending' },
    { decision: 'block', status: 'allowed' },
    { decision: 'redact', status: 'allowed' },
    { decision: 'warn', status: 'redacted' },
    { decision: 'log', status: 'warned' },
  ];

  for (const verdict of contradictions) {
    let upstreamCalls = 0;
    const { app, metrics } = createGateway({
      agentTokensPath: tokenPath,
      client: {
        gate: async () => verdict,
        scanResponse: async () => ({ decision: 'allow', status: 'allowed', blocked: false }),
      },
      adapter: {
        callUpstream: async () => {
          upstreamCalls += 1;
          return { ok: true, status: 200, json: { choices: [{ message: { content: 'must not run' } }] } };
        },
      },
    });
    const response = await request(app, token);
    assert.strictEqual(response.status, 403, JSON.stringify(verdict));
    assert.strictEqual(response.json.error.type, 'blocked_by_redactwall');
    assert.strictEqual(upstreamCalls, 0, JSON.stringify(verdict));
    assert.strictEqual(metrics.failClosed, 1, JSON.stringify(verdict));
  }
});

test('contradictory response verdicts withhold the complete upstream response', async (t) => {
  const tokenPath = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'verdict@example.test' }, tokenPath);
  const contradictions = [
    { decision: 'allow', status: 'response_blocked', blocked: false },
    { decision: 'block', status: 'allowed', blocked: true },
    { decision: 'redact', status: 'allowed', blocked: false },
    { decision: 'flag', status: 'response_redacted', blocked: false },
  ];

  for (const scan of contradictions) {
    let upstreamCalls = 0;
    const secretOutput = 'MODEL_OUTPUT_MUST_BE_WITHHELD';
    const { app, metrics } = createGateway({
      agentTokensPath: tokenPath,
      client: {
        gate: async () => ({ decision: 'allow' }),
        scanResponse: async () => scan,
      },
      adapter: {
        callUpstream: async () => {
          upstreamCalls += 1;
          return { ok: true, status: 200, json: { choices: [{ message: { content: secretOutput } }] } };
        },
      },
    });
    const response = await request(app, token);
    assert.strictEqual(response.status, 403, JSON.stringify(scan));
    assert.strictEqual(response.json.error.type, 'response_blocked_by_redactwall');
    assert.strictEqual(upstreamCalls, 1, JSON.stringify(scan));
    assert.strictEqual(response.raw.includes(secretOutput), false, JSON.stringify(scan));
    assert.strictEqual(metrics.responseBlocked, 1, JSON.stringify(scan));
    assert.strictEqual(metrics.failClosed, 1, JSON.stringify(scan));
  }
});

test('contradictory final rescan verdict withholds a rehydrated response', async (t) => {
  const tokenPath = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'verdict@example.test' }, tokenPath);
  let responseScans = 0;
  const { app, metrics } = createGateway({
    agentTokensPath: tokenPath,
    client: {
      gate: async () => ({ decision: 'redact', status: 'redacted', findings: [] }),
      scanResponse: async () => {
        responseScans += 1;
        if (responseScans === 1) return { decision: 'allow', status: 'allowed', blocked: false };
        return { decision: 'allow', status: 'response_blocked', blocked: false };
      },
    },
    adapter: {
      callUpstream: async (kind, body) => ({
        ok: true,
        status: 200,
        json: { choices: [{ message: { content: body.messages[0].content } }] },
      }),
    },
  });

  const response = await request(app, token, 'Member SSN 524-71-9043');
  assert.strictEqual(response.status, 403);
  assert.strictEqual(response.json.error.type, 'response_blocked_by_redactwall');
  assert.strictEqual(responseScans, 2);
  assert.strictEqual(response.raw.includes('524-71-9043'), false);
  assert.strictEqual(metrics.responseBlocked, 1);
  assert.strictEqual(metrics.failClosed, 1);
});
