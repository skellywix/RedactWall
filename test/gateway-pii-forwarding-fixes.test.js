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
const detect = require('../detection-engine/detect');
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
      const payload = body === undefined ? '' : JSON.stringify(body);
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
  const requestFixture = async (payload) => {
    const result = typeof verdict === 'function' ? await verdict(payload) : (verdict || { decision: 'allow' });
    if (result.status !== undefined || result.decision === 'allow') return result;
    return { ...result, status: ({ block: 'pending', redact: 'redacted', warn: 'warned', log: 'proxy_observed' })[result.decision] };
  };
  const responseFixture = async (payload) => {
    const result = typeof scan === 'function' ? await scan(payload) : (scan || { leaked: false, decision: 'allow', blocked: false });
    if (result.status !== undefined) return result;
    return { ...result, status: ({ allow: 'allowed', block: 'response_blocked', redact: 'response_redacted', flag: 'response_flagged' })[result.decision] };
  };
  return {
    gate: requestFixture,
    scanResponse: responseFixture,
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

test('deep string mapping preserves __proto__ as data without mutating prototypes', () => {
  const input = JSON.parse('{"__proto__":"provider-data","nested":{"value":"safe"}}');
  const mapped = canonical.mapStrings(input, (value) => value.toUpperCase());

  assert.strictEqual(Object.getPrototypeOf(mapped), Object.prototype);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(mapped, '__proto__'), true);
  assert.strictEqual(mapped.__proto__, 'PROVIDER-DATA');
  assert.strictEqual(mapped.nested.value, 'SAFE');
  assert.strictEqual({}.value, undefined);
});

test('gateway rejects non-object JSON bodies before gating or upstream forwarding', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let gateCalls = 0;
  let upstreamCalls = 0;
  const { app } = createGateway({
    client: {
      ...stubClient(),
      gate: async () => { gateCalls += 1; return { decision: 'allow', status: 'allowed' }; },
    },
    adapter: { callUpstream: async () => { upstreamCalls += 1; return { ok: true, json: {} }; } },
    agentTokensPath: tp,
  });
  for (const body of [['SSN 123-45-6789'], 'SSN 123-45-6789', 42, null, undefined]) {
    const response = await listenAndRequest(app, {
      headers: { authorization: 'Bearer ' + token },
      body,
    });
    assert.strictEqual(response.status, 400);
    assert.strictEqual(response.json.error.type, 'invalid_request');
  }
  assert.strictEqual(gateCalls, 0);
  assert.strictEqual(upstreamCalls, 0);
});

test('gateway encoded preflight joins adjacent content parts but does not treat metadata IDs as binary content', () => {
  const encoded = Buffer.from('SSN 123-45-6789').toString('base64');
  const analyze = (text, options = {}) => detect.analyze(text, options);
  assert.strictEqual(canonical.carriesEncodedSensitiveText({
    messages: [{ role: 'user', content: [
      { type: 'text', text: encoded.slice(0, 8) },
      { type: 'text', text: encoded.slice(8) },
    ] }],
  }, analyze), true);
  assert.strictEqual(canonical.carriesEncodedSensitiveText({
    metadata: { requestId: 'AAECAwQFBgcICQoL' },
  }, analyze), false);
  assert.strictEqual(canonical.carriesEncodedSensitiveText({
    metadata: { future_payload: 'AAECAwQFBgcICQoL' },
  }, analyze), true);
  assert.strictEqual(canonical.carriesEncodedSensitiveText({
    content: 'AAECAwQFBgcICQoL',
  }, analyze), true);
  assert.strictEqual(canonical.carriesNumericContent({
    metadata: { future_payload_v2: [...Buffer.from('123-45-6789')] },
  }), true);
  assert.strictEqual(canonical.carriesNumericContent({
    metadata: { metrics: [1, 2, 3], embeddings: [0.1, -0.4], requestIds: [1001, 1002] },
  }), false);
});

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

test('request is withheld when a redact verdict contains a semantic category', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  const adapter = {
    requestText: canonical.requestText,
    responseText: () => '',
    applyResponseText: (j) => j,
    callUpstream: async () => { upstreamCalls += 1; return { ok: true, status: 200, json: {} }; },
  };
  const { app } = createGateway({
    client: stubClient({
      verdict: {
        decision: 'redact',
        findings: [],
        categories: ['CONFIDENTIAL_BUSINESS'],
      },
    }),
    adapter,
    agentTokensPath: tp,
  });
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: 'Internal roadmap: launch in Q3.' }] },
  });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'incomplete_redaction');
  assert.strictEqual(upstreamCalls, 0, 'category-only prose cannot be span-tokenized safely');
});

// HIGH #2 (count-smuggling) — a reported type local detection cannot reproduce
// must fail closed even when an UNRELATED default finding pads the local count
// to match the reported total. A bare count check (1 >= 1) would forward the
// custom value raw; per-type coverage must catch the unreproduced type.
test('redact fails closed on count-smuggling (custom type padded by an unrelated default finding)', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  const adapter = {
    requestText: canonical.requestText, responseText: () => '', applyResponseText: (j) => j,
    callUpstream: async () => { upstreamCalls++; return { ok: true, status: 200, json: {} }; },
  };
  // Plane reports ONE custom EMPLOYEE_ID; the prompt also carries an ordinary
  // email a default analyze DOES detect, padding the local count to 1.
  const { app } = createGateway({
    client: stubClient({ verdict: { decision: 'redact', findings: [{ type: 'EMPLOYEE_ID', masked: 'EMP-***' }] } }),
    adapter, agentTokensPath: tp,
  });
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: 'look up EMP-000123 for bob@example.com' }] },
  });
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'incomplete_redaction');
  assert.strictEqual(upstreamCalls, 0, 'custom secret must not forward when a default finding merely pads the count');
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

test('request gating covers every forwarded string field, including user metadata', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  let gatedText = '';
  const { adapter } = captureAdapter(() => {
    upstreamCalls += 1;
    return { choices: [{ message: { content: 'ok' } }] };
  });
  const { app } = createGateway({
    client: stubClient({
      verdict: ({ prompt }) => {
        gatedText = prompt;
        return prompt.includes('123-45-6789') && prompt.includes('524-71-9043')
          ? { decision: 'block', reasons: ['sensitive request metadata'] }
          : { decision: 'allow' };
      },
    }),
    adapter,
    agentTokensPath: tp,
  });

  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: {
      model: 'x',
      messages: [{ role: 'user', content: 'hello' }],
      user: 'member-123-45-6789',
      metadata: { case: '524-71-9043' },
    },
  });

  assert.strictEqual(res.status, 403);
  assert.match(gatedText, /123-45-6789/);
  assert.match(gatedText, /524-71-9043/);
  assert.strictEqual(upstreamCalls, 0, 'unscanned request metadata must never reach upstream');
});

test('request gating covers the forwarded model identifier', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  let gatedText = '';
  const { adapter } = captureAdapter(() => {
    upstreamCalls += 1;
    return { choices: [{ message: { content: 'ok' } }] };
  });
  const { app } = createGateway({
    client: stubClient({
      verdict: ({ prompt }) => {
        gatedText = prompt;
        return prompt.includes('219-09-9999') ? { decision: 'block' } : { decision: 'allow' };
      },
    }),
    adapter,
    agentTokensPath: tp,
  });

  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'private-model-219-09-9999', messages: [{ role: 'user', content: 'hello' }] },
  });

  assert.strictEqual(res.status, 403);
  assert.match(gatedText, /219-09-9999/);
  assert.strictEqual(upstreamCalls, 0);
});

test('request gating covers forwarded JSON property names', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  let gatedText = '';
  const { adapter } = captureAdapter(() => {
    upstreamCalls += 1;
    return { choices: [{ message: { content: 'ok' } }] };
  });
  const { app } = createGateway({
    client: stubClient({
      verdict: ({ prompt }) => {
        gatedText = prompt;
        return prompt.includes('219-09-9999') ? { decision: 'block' } : { decision: 'allow' };
      },
    }),
    adapter,
    agentTokensPath: tp,
  });

  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: {
      model: 'x',
      messages: [{ role: 'user', content: 'hello' }],
      metadata: { 'case-219-09-9999': 'safe value' },
    },
  });

  assert.strictEqual(res.status, 403);
  assert.match(gatedText, /219-09-9999/);
  assert.strictEqual(upstreamCalls, 0);
});

test('redact tokenizes sensitive strings in request metadata before forwarding', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { adapter, state } = captureAdapter(() => ({ choices: [{ message: { content: 'ok' } }] }));
  const { app } = createGateway({
    client: stubClient({ verdict: { decision: 'redact', findings: [{ type: 'US_SSN', masked: '***-**-3312' }] } }),
    adapter,
    agentTokensPath: tp,
  });

  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: {
      model: 'x',
      messages: [{ role: 'user', content: 'hello' }],
      metadata: { case: 'Member SSN 524-71-3312' },
    },
  });

  assert.strictEqual(res.status, 200);
  assert.ok(!JSON.stringify(state.forwarded).includes('524-71-3312'));
  assert.match(state.forwarded.metadata.case, /\[\[US_SSN_\d+\]\]/);
});

test('response scanning covers extra string fields before any JSON is returned', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let scannedText = '';
  const { adapter } = captureAdapter(() => ({
    choices: [{ message: { role: 'assistant', content: 'safe response' } }],
    extra: { caseSummary: 'response SSN 219-09-9999' },
  }));
  const { app } = createGateway({
    client: stubClient({
      verdict: { decision: 'allow' },
      scan: ({ text }) => {
        scannedText = text;
        return text.includes('219-09-9999')
          ? { decision: 'block', blocked: true, reasons: ['sensitive response metadata'] }
          : { decision: 'allow', blocked: false };
      },
    }),
    adapter,
    agentTokensPath: tp,
  });

  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: 'hello' }] },
  });

  assert.strictEqual(res.status, 403);
  assert.match(scannedText, /219-09-9999/);
  assert.ok(!res.raw.includes('219-09-9999'));
});

test('response scanning covers JSON property names before any JSON is returned', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let scannedText = '';
  const { adapter } = captureAdapter(() => ({
    choices: [{ message: { role: 'assistant', content: 'safe response' } }],
    extra: { 'case-219-09-9999': 'safe value' },
  }));
  const { app } = createGateway({
    client: stubClient({
      verdict: { decision: 'allow' },
      scan: ({ text }) => {
        scannedText = text;
        return text.includes('219-09-9999')
          ? { decision: 'block', blocked: true }
          : { decision: 'allow', blocked: false };
      },
    }),
    adapter,
    agentTokensPath: tp,
  });

  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: 'hello' }] },
  });

  assert.strictEqual(res.status, 403);
  assert.match(scannedText, /219-09-9999/);
  assert.ok(!res.raw.includes('219-09-9999'));
});

test('response redaction rewrites sensitive strings in extra response fields', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const { adapter } = captureAdapter(() => ({
    choices: [{ message: { role: 'assistant', content: 'safe response' } }],
    extra: { caseSummary: 'response SSN 219-09-9999' },
  }));
  const { app } = createGateway({
    client: stubClient({
      verdict: { decision: 'allow' },
      scan: {
        decision: 'redact',
        blocked: false,
        findings: [{ type: 'US_SSN', masked: '***-**-9999' }],
        categories: [],
      },
    }),
    adapter,
    agentTokensPath: tp,
  });

  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: 'hello' }] },
  });

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.extra.caseSummary, 'response SSN [US_SSN]');
  assert.ok(!res.raw.includes('219-09-9999'));
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

test('an image part cannot masquerade as scannable by adding a text field', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let forwarded = null;
  const adapter = {
    callUpstream: async (kind, body) => {
      forwarded = body;
      return { ok: true, json: { choices: [{ message: { content: 'ok' } }] } };
    },
  };
  const { app } = createGateway({ client: stubClient({ verdict: { decision: 'allow' } }), adapter, agentTokensPath: tp });
  const encodedSensitiveImage = Buffer.from('SSN 123-45-6789').toString('base64');
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: {
      model: 'x',
      messages: [{
        role: 'user',
        content: [{
          type: 'image_url',
          text: 'decoy text',
          image_url: { url: 'data:image/png;base64,' + encodedSensitiveImage },
        }],
      }],
    },
  });

  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'unscannable_content');
  assert.strictEqual(forwarded, null, 'binary content must not cross the upstream boundary');
});

test('unscannable detection recurses through text-part metadata without blocking ordinary metadata', () => {
  const encodedSensitiveImage = Buffer.from('SSN 123-45-6789').toString('base64');
  const smuggled = {
    messages: [{
      role: 'user',
      content: [{
        type: 'text',
        text: 'decoy text',
        source: { type: 'base64', data: encodedSensitiveImage },
      }],
    }],
  };
  const ordinary = {
    messages: [{
      role: 'user',
      content: [{ type: 'text', text: 'ordinary text', metadata: { source: 'crm', caseId: 'case-7' } }],
    }],
    tools: [{ type: 'file_search', function: { name: 'file_search', description: 'Search approved files' } }],
  };

  assert.strictEqual(canonical.carriesUnscannableContent(smuggled), true);
  assert.strictEqual(canonical.carriesUnscannableContent(ordinary), false);
});

test('explicit binary detection covers unknown metadata shapes but permits file-search definitions', () => {
  const encoded = Buffer.from('SSN 123-45-6789').toString('base64');
  assert.strictEqual(canonical.carriesExplicitBinary({ metadata: { base64: encoded } }), true);
  assert.strictEqual(canonical.carriesExplicitBinary({ metadata: { base64: { type: 'string', payload: encoded } } }), true);
  assert.strictEqual(canonical.carriesExplicitBinary({ data: [{ b64_json: encoded }] }), true);
  assert.strictEqual(canonical.carriesExplicitBinary({ data: [{ b64Json: encoded }] }), true);
  assert.strictEqual(canonical.carriesExplicitBinary({ metadata: { url: 'data:image/png;base64,' + encoded } }), true);
  assert.strictEqual(canonical.carriesExplicitBinary({ metadata: { url: 'data:;base64,' + encoded } }), true);
  assert.strictEqual(canonical.carriesExplicitBinary({ metadata: { url: 'data:image/png;charset=utf-8;base64,' + encoded } }), true);
  assert.strictEqual(canonical.carriesExplicitBinary({ metadata: { mimeType: 'image/png', data: encoded } }), true);
  assert.strictEqual(canonical.carriesExplicitBinary({
    tools: [{ type: 'file_search', file_search: { vector_store_ids: ['vs_123'] } }],
  }), false);
});

test('opaque binary in unknown request metadata is rejected before any upstream call', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let upstreamCalls = 0;
  const adapter = {
    callUpstream: async () => {
      upstreamCalls += 1;
      return { ok: true, json: { choices: [{ message: { content: 'ok' } }] } };
    },
  };
  const { app, metrics } = createGateway({
    client: stubClient({ verdict: { decision: 'allow' } }), adapter, agentTokensPath: tp,
  });
  const encoded = Buffer.from('SSN 123-45-6789').toString('base64');
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: {
      model: 'x',
      messages: [{ role: 'user', content: 'decoy text' }],
      provider_metadata: { nested: { content_base64: encoded } },
    },
  });

  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'unscannable_content');
  assert.strictEqual(upstreamCalls, 0, 'opaque request bytes must not cross the upstream boundary');
  assert.strictEqual(metrics.blocked, 1);
  assert.strictEqual(metrics.failClosed, 1);
  assert.ok(!res.raw.includes(encoded), 'the generic error must not echo encoded content');
});

test('opaque binary in an upstream response is withheld before control-plane scanning', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  let responseScans = 0;
  const encoded = Buffer.from('SSN 123-45-6789').toString('base64');
  const adapter = {
    callUpstream: async () => ({
      ok: true,
      json: {
        choices: [{ message: { content: 'decoy text' } }],
        data: [{ b64_json: encoded }],
      },
    }),
  };
  const { app, metrics } = createGateway({
    client: stubClient({
      verdict: { decision: 'allow' },
      scan: () => { responseScans += 1; return { decision: 'allow', blocked: false }; },
    }),
    adapter,
    agentTokensPath: tp,
  });
  const res = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: 'hello' }] },
  });

  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error.type, 'response_blocked_by_redactwall');
  assert.strictEqual(responseScans, 0, 'opaque bytes are never sent to the text-only response scanner');
  assert.strictEqual(metrics.responseBlocked, 1);
  assert.strictEqual(metrics.failClosed, 1);
  assert.ok(!res.raw.includes(encoded), 'the caller receives only a generic response-block error');
});

test('clearly binary unknown provider fields are blocked on both gateway edges', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const opaque = 'AAECAwQFBgcICQoL';
  let upstreamCalls = 0;
  let responseScans = 0;
  const adapter = {
    callUpstream: async () => {
      upstreamCalls += 1;
      return { ok: true, json: { choices: [{ message: { content: 'ok' }, future_payload: opaque }] } };
    },
  };
  const { app } = createGateway({
    client: stubClient({
      verdict: { decision: 'allow' },
      scan: () => { responseScans += 1; return { decision: 'allow', status: 'allowed' }; },
    }),
    adapter,
    agentTokensPath: tp,
  });

  const rejectedRequest = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: 'hello' }], future_payload: opaque },
  });
  assert.strictEqual(rejectedRequest.status, 403);
  assert.strictEqual(upstreamCalls, 0);

  const rejectedResponse = await listenAndRequest(app, {
    headers: { authorization: 'Bearer ' + token },
    body: { model: 'x', messages: [{ role: 'user', content: 'hello' }] },
  });
  assert.strictEqual(rejectedResponse.status, 403);
  assert.strictEqual(upstreamCalls, 1);
  assert.strictEqual(responseScans, 0);
  assert.ok(!rejectedResponse.raw.includes(opaque));
});

test('reversible encoded prompts and numeric content arrays reach zero upstream bytes', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const secret = 'SSN 123-45-6789';
  const wrappedBase64 = Buffer.from(secret).toString('base64').match(/.{1,4}/g).join(' ');
  const encodedBodies = [
    { model: 'x', messages: [{ role: 'user', content: Buffer.from(secret).toString('base64') }] },
    { model: 'x', messages: [{ role: 'user', content: wrappedBase64 }] },
    { model: 'x', messages: [{ role: 'user', content: Buffer.from(secret).toString('hex') }] },
    { model: 'x', messages: [{ role: 'user', content: Buffer.from([0, 255, 1, 254, 2, 253, 3, 252, 4, 251, 5, 250]).toString('base64') }] },
    {
      model: 'x',
      messages: [{ role: 'user', content: 'ordinary caption' }],
      provider_metadata: { output: [...Buffer.from(secret)] },
    },
    {
      model: 'x',
      messages: [{
        role: 'user',
        content: [{ type: 'text', text: 'ordinary caption', metadata: { raw: [...Buffer.from(secret)] } }],
      }],
    },
  ];
  let upstreamCalls = 0;
  const { app } = createGateway({
    agentTokensPath: tp,
    client: stubClient({ verdict: { decision: 'allow' } }),
    adapter: {
      callUpstream: async () => {
        upstreamCalls += 1;
        return { ok: true, status: 200, json: { choices: [{ message: { content: 'must not run' } }] } };
      },
    },
  });

  for (const body of encodedBodies) {
    const opaque = body.provider_metadata
      ? JSON.stringify(body.provider_metadata.output)
      : JSON.stringify(body.messages[0].content);
    const response = await listenAndRequest(app, {
      headers: { authorization: `Bearer ${token}` },
      body,
    });
    assert.strictEqual(response.status, 403);
    assert.strictEqual(response.json.error.type, 'unscannable_content');
    assert.ok(!response.raw.includes(secret));
    assert.ok(!response.raw.includes(opaque.replace(/^"|"$/g, '')));
  }
  assert.strictEqual(upstreamCalls, 0);
});

test('reversible encoded and numeric model content is never released to the caller', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const secret = 'SSN 123-45-6789';
  const wrappedBase64 = Buffer.from(secret).toString('base64').match(/.{1,4}/g).join('\n');
  const outputs = [
    Buffer.from(secret).toString('base64'),
    wrappedBase64,
    Buffer.from(secret).toString('hex'),
    Buffer.from([0, 255, 1, 254, 2, 253, 3, 252, 4, 251, 5, 250]).toString('base64'),
    [...Buffer.from(secret)],
    [{ type: 'text', text: 'ordinary response', metadata: { raw: [...Buffer.from(secret)] } }],
  ];
  const outputCount = outputs.length;
  let responseScans = 0;
  const { app } = createGateway({
    agentTokensPath: tp,
    client: stubClient({
      verdict: { decision: 'allow' },
      scan: () => { responseScans += 1; return { decision: 'allow', status: 'allowed', blocked: false }; },
    }),
    adapter: {
      callUpstream: async () => ({
        ok: true,
        status: 200,
        json: { choices: [{ message: { content: outputs.shift() } }] },
      }),
    },
  });

  for (let i = 0; i < outputCount; i += 1) {
    const opaque = outputs[0];
    const response = await listenAndRequest(app, {
      headers: { authorization: `Bearer ${token}` },
      body: { model: 'x', messages: [{ role: 'user', content: 'ordinary prompt' }] },
    });
    assert.strictEqual(response.status, 403);
    assert.strictEqual(response.json.error.type, 'response_blocked_by_redactwall');
    assert.ok(!response.raw.includes(secret));
    assert.ok(!response.raw.includes(typeof opaque === 'string' ? opaque : JSON.stringify(opaque)));
  }
  assert.strictEqual(responseScans, 0, 'opaque response content is withheld before a text-only scan');
});

test('ordinary alphanumeric text and structured numeric records remain allowed', async (t) => {
  const tp = tmpTokens(t);
  const { token } = tokens.mintToken({ user: 'a@x' }, tp);
  const harmlessEncodedText = Buffer.from('quarterly branch hours').toString('base64');
  let forwarded = null;
  const { app } = createGateway({
    agentTokensPath: tp,
    client: stubClient({ verdict: { decision: 'allow' }, scan: { decision: 'allow', status: 'allowed', blocked: false } }),
    adapter: {
      callUpstream: async (kind, body) => {
        forwarded = body;
        return {
          ok: true,
          status: 200,
          json: {
            choices: [{ message: { content: 'CustomerAccountStatus' } }],
            data: [{ embedding: [0.125, -0.5, 0.75], records: [2023, 2024, 2025] }],
          },
        };
      },
    },
  });
  const response = await listenAndRequest(app, {
    headers: { authorization: `Bearer ${token}` },
    body: {
      model: 'x',
      messages: [{ role: 'user', content: harmlessEncodedText }],
      provider_metadata: {
        metrics: [1, 2, 3],
        rows: [{ year: 2025, amount: 42 }],
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        jwtId: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1bml0LXVzZXIifQ.signature',
      },
    },
  });

  assert.strictEqual(response.status, 200);
  assert.ok(forwarded);
  assert.deepStrictEqual(response.json.data[0].records, [2023, 2024, 2025]);
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
