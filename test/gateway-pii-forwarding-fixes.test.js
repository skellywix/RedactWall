'use strict';
/**
 * Regression tests for gateway audit fixes: raw PII must never reach upstream or
 * return to the caller. Covers the four HIGH findings —
 *   1. redact no-ops on array-form prompt/input,
 *   2. local redaction missing custom-detector/EDM coverage (fail closed),
 *   3. response truncation via the control plane's 600-char scan preview,
 *   4. n>1 responses leaving raw PII in choices[1..].
 * Plus mixed text+image fail-closed and /readyz not writing records.
 *
 * Uses an injected control-plane client (no network) + the mock upstream, which
 * echoes the forwarded (redacted) prompt, so what reaches upstream is observable.
 */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const { createGateway } = require('../gateway/server');
const canonical = require('../gateway/canonical');
const tokens = require('../gateway/tokens');

function tmpTokens(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gw-pii-'));
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
        res.on('end', () => { server.close(); let json = null; try { json = data ? JSON.parse(data) : null; } catch (e) { json = null; } resolve({ status: res.statusCode, json, raw: data }); });
      });
      req.on('error', (e) => { server.close(); reject(e); });
      if (payload) req.write(payload);
      req.end();
    });
  });
}

function stubClient({ verdict, scan, health } = {}) {
  return {
    gate: async (p) => (typeof verdict === 'function' ? verdict(p) : (verdict || { decision: 'allow' })),
    scanResponse: async (p) => (typeof scan === 'function' ? scan(p) : (scan || { leaked: false, decision: 'allow', blocked: false })),
    health: typeof health === 'function' ? health : undefined,
  };
}

// Adapter that captures the exact body forwarded upstream and lets a test seed
// the model output text directly (so response-side paths are observable).
function captureAdapter(makeJson) {
  const state = { forwarded: null };
  const adapter = {
    requestText: canonical.requestText,
    responseText: canonical.responseText,
    applyResponseText: canonical.applyResponseText,
    callUpstream: async (kind, b) => { state.forwarded = b; return { ok: true, status: 200, json: makeJson(kind, b) }; },
  };
  return { adapter, state };
}

// HIGH #1 — array-form prompt must be tokenized (was a silent no-op).
test('redact tokenizes array-form prompt entries — no raw PII upstream', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { adapter, state } = captureAdapter(() => ({ choices: [{ text: 'ok' }] }));
  const { app } = createGateway({ client: stubClient({ verdict: { decision: 'redact' } }), adapter, agentTokensPath: tp });
  const res = await listenAndRequest(app, {
    pathName: '/v1/completions',
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', prompt: ['my SSN is 524-71-3312', 'and card 4012888888881881'] },
  });
  assert.strictEqual(res.status, 200);
  const forwarded = JSON.stringify(state.forwarded);
  assert.ok(!forwarded.includes('524-71-3312'), 'array-form SSN must not reach upstream');
  assert.ok(!forwarded.includes('4012888888881881'), 'array-form card must not reach upstream');
  assert.ok(/\[\[US_SSN_\d+\]\]/.test(forwarded), 'array-form prompt is tokenized');
});

// HIGH #1 — array-form embeddings input must be tokenized too.
test('redact tokenizes array-form embeddings input — no raw PII upstream', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { adapter, state } = captureAdapter(() => ({ object: 'list', data: [] }));
  const { app } = createGateway({ client: stubClient({ verdict: { decision: 'redact' } }), adapter, agentTokensPath: tp });
  const res = await listenAndRequest(app, {
    pathName: '/v1/embeddings',
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', input: ['member SSN 524-71-3312 here'] },
  });
  assert.strictEqual(res.status, 200);
  assert.ok(!JSON.stringify(state.forwarded).includes('524-71-3312'), 'array-form input SSN must not reach upstream');
});

// HIGH #2 — a redact verdict whose findings local detection can't reproduce
// (custom detector / EDM) must fail closed, never forward the raw value.
test('redact fails closed when local detection cannot reproduce the verdict findings', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  const adapter = {
    requestText: canonical.requestText,
    responseText: () => '',
    applyResponseText: (j) => j,
    callUpstream: async () => { upstreamCalls++; return { ok: true, status: 200, json: {} }; },
  };
  // Control plane reports a finding (via custom detector/EDM) that a default
  // local analyze of "EMP-000123" does not detect.
  const { app } = createGateway({
    client: stubClient({ verdict: { decision: 'redact', findings: [{ type: 'EMPLOYEE_ID', masked: 'EMP-***' }] } }),
    adapter, agentTokensPath: tp,
  });
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: 'look up EMP-000123 please' }] },
  });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'incomplete_redaction');
  assert.strictEqual(upstreamCalls, 0, 'raw PII must not be forwarded when local redaction is incomplete');
});

// HIGH #3 — a long leaked response must be redacted at full length, not
// truncated to the control plane's 600-char preview.
test('leaked response is redacted at full length (not truncated to the 600-char preview)', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const filler = 'The quarterly summary continues. '.repeat(60); // > 600 chars
  const longAnswer = filler + ' Member SSN 524-71-3312 appears once.';
  const { adapter } = captureAdapter(() => ({ choices: [{ message: { role: 'assistant', content: longAnswer } }] }));
  const { app } = createGateway({
    client: stubClient({
      verdict: { decision: 'allow' },
      // Preview mimics safePreview: truncated to 600 chars, masked SSN.
      scan: { leaked: true, decision: 'redact', blocked: false, redacted: longAnswer.slice(0, 600).replace('524-71-3312', '[US_SSN]'), findings: [{ type: 'US_SSN', masked: '***-**-3312' }], categories: [] },
    }),
    adapter, agentTokensPath: tp,
  });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: { model: 'x', messages: [{ role: 'user', content: 'summary?' }] } });
  assert.strictEqual(res.status, 200);
  const out = res.json.choices[0].message.content;
  assert.ok(!out.includes('524-71-3312'), 'SSN must be redacted from the response');
  assert.ok(out.length > 600, 'the full response is preserved, not truncated to the preview');
  assert.ok(out.includes('[US_SSN]'), 'the SSN was locally redacted in place');
});

// HIGH #3 — a semantic-category leak the gateway cannot reproduce locally must
// withhold the response rather than forward it.
test('response is withheld when the scan flags a semantic category the gateway cannot redact', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { adapter } = captureAdapter(() => ({ choices: [{ message: { role: 'assistant', content: 'Internal roadmap: launch in Q3.' } }] }));
  const { app } = createGateway({
    client: stubClient({ verdict: { decision: 'allow' }, scan: { leaked: true, decision: 'redact', blocked: false, redacted: '[REDACTED: CONFIDENTIAL]', findings: [], categories: ['CONFIDENTIAL'] } }),
    adapter, agentTokensPath: tp,
  });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: { model: 'x', messages: [{ role: 'user', content: 'roadmap?' }] } });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'response_blocked_by_redactwall');
});

// HIGH #4 — with n>1, EVERY choice must be redacted, not just choices[0].
test('n>1 responses redact raw PII in every choice, not just the first', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { adapter } = captureAdapter(() => ({ choices: [
    { index: 0, message: { role: 'assistant', content: 'First answer, nothing here.' } },
    { index: 1, message: { role: 'assistant', content: 'Second answer with SSN 524-71-3312.' } },
  ] }));
  const { app } = createGateway({
    client: stubClient({ verdict: { decision: 'allow' }, scan: { leaked: true, decision: 'redact', blocked: false, redacted: '[preview]', findings: [{ type: 'US_SSN', masked: '***-**-3312' }], categories: [] } }),
    adapter, agentTokensPath: tp,
  });
  const res = await listenAndRequest(app, { headers: { authorization: 'Bearer ' + token }, body: { model: 'x', n: 2, messages: [{ role: 'user', content: 'give me two answers' }] } });
  assert.strictEqual(res.status, 200);
  const whole = JSON.stringify(res.json.choices);
  assert.ok(!whole.includes('524-71-3312'), 'choices[1..] must not return raw PII');
  assert.ok(res.json.choices[1].message.content.includes('[US_SSN]'), 'the second choice is redacted');
});

// MEDIUM #5 — a message mixing text with an image part must fail closed even
// though the text part is scannable.
test('mixed text+image content fails closed — image never forwarded', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  const adapter = { requestText: canonical.requestText, responseText: () => '', applyResponseText: (j) => j, callUpstream: async () => { upstreamCalls++; return { ok: true, json: {} }; } };
  const { app } = createGateway({ client: stubClient({ verdict: { decision: 'allow' } }), adapter, agentTokensPath: tp });
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: [{ type: 'text', text: 'describe this' }, { type: 'image_url', image_url: { url: 'data:image/png;base64,AAAA' } }] }] },
  });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'unscannable_content');
  assert.strictEqual(upstreamCalls, 0);
});

// Coverage must match by TYPE, not raw count: a plane finding the gateway
// cannot reproduce (EDM/custom) hidden behind an equal count of a different,
// locally-detectable type must still fail closed.
test('redact fails closed when finding COUNT matches but a reported type is unreproduced', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  const adapter = {
    requestText: canonical.requestText,
    responseText: () => '', applyResponseText: (j) => j,
    callUpstream: async (kind, b) => { upstreamCalls++; return { ok: true, status: 200, json: {}, forwarded: b }; },
  };
  // Prompt locally analyzes to exactly ONE finding (the email). The plane
  // reports TWO findings — the email PLUS a custom ORG_CODENAME the gateway
  // cannot see. Old count check: local 1 >= reported 2 is false anyway, so make
  // the collision exact: prompt carries an email AND a phone (local = 2), while
  // the plane reports email + ORG_CODENAME (also 2) — count matches, type does not.
  const { app } = createGateway({
    client: stubClient({ verdict: { decision: 'redact', findings: [{ type: 'EMAIL', masked: 'a***@x' }, { type: 'ORG_CODENAME', masked: 'OR***' }] } }),
    adapter, agentTokensPath: tp,
  });
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: 'mail bob@corp.com or call 415-555-0100 re ORION-7' }] },
  });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'incomplete_redaction');
  assert.strictEqual(upstreamCalls, 0, 'a count-collision must not slip an unreproduced type upstream');
});

// An image/binary part in a SYSTEM or ASSISTANT message is forwarded upstream
// just like one in a user message, so it must fail closed too.
test('image content in a system/assistant message fails closed', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  const adapter = { requestText: canonical.requestText, responseText: () => '', applyResponseText: (j) => j, callUpstream: async () => { upstreamCalls++; return { ok: true, json: {} }; } };
  const { app } = createGateway({ client: stubClient({ verdict: { decision: 'allow' } }), adapter, agentTokensPath: tp });
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [
      { role: 'system', content: [{ type: 'image_url', image_url: { url: 'data:image/png;base64,AAAA' } }] },
      { role: 'user', content: 'hello' },
    ] },
  });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'unscannable_content');
  assert.strictEqual(upstreamCalls, 0);
});

// MEDIUM #6 — token-id array input (non-strings) must fail closed.
test('token-id array input fails closed (unscannable)', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  const adapter = { requestText: canonical.requestText, responseText: () => '', applyResponseText: (j) => j, callUpstream: async () => { upstreamCalls++; return { ok: true, json: {} }; } };
  const { app } = createGateway({ client: stubClient({ verdict: { decision: 'allow' } }), adapter, agentTokensPath: tp });
  const res = await listenAndRequest(app, {
    pathName: '/v1/embeddings',
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', input: [[3923, 374, 264, 1296]] },
  });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'unscannable_content');
  assert.strictEqual(upstreamCalls, 0);
});

// MEDIUM #7 — /readyz must probe via health() and create no gate() record.
test('/readyz probes health() and never issues a record-writing gate()', async (t) => {
  const tp = tmpTokens(t);
  let gateCalls = 0;
  let healthCalls = 0;
  const client = {
    gate: async () => { gateCalls++; return { decision: 'allow' }; },
    scanResponse: async () => ({ decision: 'allow' }),
    health: async () => { healthCalls++; return { ok: true }; },
  };
  const { app } = createGateway({ provider: 'mock', client, agentTokensPath: tp });
  const res = await listenAndRequest(app, { method: 'GET', pathName: '/readyz' });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.ready, true);
  assert.strictEqual(healthCalls, 1, 'readyz uses the non-persisting health probe');
  assert.strictEqual(gateCalls, 0, 'readyz must not issue a gate() that writes a query row');
});
