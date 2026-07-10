'use strict';
/** AI LLM gateway enforces RedactWall decisions before and after upstream calls. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const {
  createGatewayServer,
  createHttpRateLimiter,
  createRateLimiter,
  extractResponseText,
  gatewayHealth,
  inspectRequestContent,
  isBufferedStreamingRequest,
  modelAllowed,
  modelFromJson,
  modelFromRequest,
  parseArgs,
  pathAllowed,
  promptForwardPlan,
  promptTextFromJson,
  replacePromptPayload,
  rewriteResponseJson,
  signAwsSigV4,
  targetUrl,
} = require('../scripts/ai-llm-gateway');

function jsonFetchResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function textFetchResponse(status, body, headers = {}) {
  return new Response(String(body), {
    status,
    headers: { 'content-type': 'text/plain; charset=utf-8', ...headers },
  });
}

function detectorInventory() {
  return ['US_SSN', 'CREDIT_CARD', 'SECRET_KEY'].map((id) => ({ id }));
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function gatewayRequest(port, {
  method = 'POST',
  path = '/v1/chat/completions',
  token = 'client-token',
  headers = {},
  body = { messages: [{ role: 'user', content: 'Summarize public FAQ copy.' }] },
} = {}) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method,
      path,
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
        json: () => JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'),
      }));
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function openEndedGatewayRequest(port, chunks, timeoutMs = 1500) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const req = http.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: '/v1/chat/completions',
      headers: {
        authorization: 'Bearer client-token',
        'content-type': 'application/json',
        'transfer-encoding': 'chunked',
      },
    }, (res) => {
      const body = [];
      res.on('data', (chunk) => body.push(chunk));
      res.on('end', () => {
        clearTimeout(timer);
        req.destroy();
        resolve({
          status: res.statusCode,
          body: Buffer.concat(body).toString('utf8'),
          elapsedMs: Date.now() - started,
        });
      });
    });
    const timer = setTimeout(() => {
      req.destroy();
      reject(new Error('gateway did not reject the open request in time'));
    }, timeoutMs);
    req.on('error', (error) => {
      if (error && error.code === 'ECONNRESET') return;
      clearTimeout(timer);
      reject(error);
    });
    for (const chunk of chunks) req.write(chunk);
  });
}

test('utility functions constrain target paths and rewrite known prompt and response shapes', () => {
  assert.strictEqual(pathAllowed('/v1/chat/completions'), true);
  assert.strictEqual(pathAllowed('/openai/deployments/unit/chat/completions'), true);
  assert.strictEqual(pathAllowed('/v1beta/models/gemini-1.5-pro:generateContent'), true);
  assert.strictEqual(pathAllowed('/v1/models/gemini-2.5-flash:streamGenerateContent'), true);
  assert.strictEqual(pathAllowed('/model/anthropic.claude-3-5-sonnet-20240620-v1%3A0/converse'), true);
  assert.strictEqual(pathAllowed('/model/amazon.titan-text-premier-v1%3A0/invoke'), true);
  assert.strictEqual(pathAllowed('/model/anthropic.claude-3-haiku-20240307-v1%3A0/converse-stream'), true);
  assert.strictEqual(pathAllowed('/v1/files'), false);
  assert.throws(() => targetUrl({ url: 'https://evil.test/v1/chat/completions' }, 'https://api.openai.test'), /absolute proxy targets/);

  const parsed = parseArgs(['--port', '4999', '--host', '0.0.0.0', '--token', 'client-token', '--upstream', 'https://upstream.test', '--upstream-auth-header', 'x-goog-api-key', '--upstream-auth-scheme', 'none', '--aws-region', 'us-east-1', '--aws-service', 'bedrock', '--upstream-header', 'anthropic-version=2023-06-01', '--approval-wait-ms', '250', '--rate-store', 'sqlite', '--rate-db-path', 'C:\\RedactWall\\rate.db', '--allowed-models', 'gpt-4o-mini,company-*']);
  assert.strictEqual(parsed.port, 4999);
  assert.strictEqual(parsed.host, '0.0.0.0');
  assert.strictEqual(parsed.clientToken, 'client-token');
  assert.strictEqual(parsed.upstream, 'https://upstream.test');
  assert.strictEqual(parsed.upstreamAuthHeader, 'x-goog-api-key');
  assert.strictEqual(parsed.upstreamAuthScheme, 'none');
  assert.strictEqual(parsed.awsRegion, 'us-east-1');
  assert.strictEqual(parsed.awsService, 'bedrock');
  assert.deepStrictEqual(parsed.upstreamHeader, ['anthropic-version=2023-06-01']);
  assert.strictEqual(parsed.approvalWaitMs, 250);
  assert.strictEqual(parsed.rateLimitStore, 'sqlite');
  assert.strictEqual(parsed.rateLimitDbPath, 'C:\\RedactWall\\rate.db');
  assert.strictEqual(parsed.allowedModels, 'gpt-4o-mini,company-*');
  const parsedHttpLimiter = parseArgs(['--rate-store', 'http', '--rate-url', 'https://limiter.example.test/check', '--rate-token', 'limiter-token', '--rate-timeout-ms', '1500']);
  assert.strictEqual(parsedHttpLimiter.rateLimitStore, 'http');
  assert.strictEqual(parsedHttpLimiter.rateLimitUrl, 'https://limiter.example.test/check');
  assert.strictEqual(parsedHttpLimiter.rateLimitToken, 'limiter-token');
  assert.strictEqual(parsedHttpLimiter.rateLimitTimeoutMs, 1500);
  assert.strictEqual(parseArgs(['--allow-multimodal']).allowMultimodal, true);
  assert.strictEqual(promptTextFromJson({
    input: [{ role: 'user', content: [{ type: 'input_text', text: 'Responses API prompt' }] }],
  }), 'Responses API prompt');
  assert.strictEqual(promptTextFromJson({
    contents: [{ role: 'user', parts: [{ text: 'Gemini native prompt' }] }],
  }), 'Gemini native prompt');
  assert.strictEqual(promptTextFromJson({
    messages: [{ role: 'user', content: [{ text: 'Bedrock Converse prompt' }] }],
  }), 'Bedrock Converse prompt');
  assert.strictEqual(promptTextFromJson({ inputText: 'Bedrock InvokeModel prompt' }), 'Bedrock InvokeModel prompt');
  assert.strictEqual(modelFromJson({ model: 'gpt-4o-mini' }), 'gpt-4o-mini');
  assert.strictEqual(modelFromRequest({ pathname: '/v1beta/models/gemini-1.5-pro:generateContent' }, {}), 'gemini-1.5-pro');
  assert.strictEqual(modelFromRequest({ pathname: '/model/anthropic.claude-3-5-sonnet-20240620-v1%3A0/converse' }, {}), 'anthropic.claude-3-5-sonnet-20240620-v1:0');
  assert.strictEqual(modelAllowed('company-private-v1', { allowedModels: ['gpt-4o-mini', 'company-*'] }).allowed, true);
  assert.strictEqual(modelAllowed('unknown-model', { allowedModels: ['gpt-4o-mini'] }).allowed, false);
  assert.strictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'https://upstream.test', allowedModels: ['gpt-4o-mini'] }).status, 'ready');
  assert.strictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'https://upstream.test' }).streaming, 'buffered_scan_sse');
  assert.strictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'https://upstream.test' }).bedrockEventStream, 'unsupported');
  assert.strictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'https://bedrock-runtime.us-east-1.amazonaws.com', upstreamAuthScheme: 'aws-sigv4' }).status, 'attention');
  assert.strictEqual(gatewayHealth({
    clientToken: 'client-token',
    upstream: 'https://bedrock-runtime.us-east-1.amazonaws.com',
    upstreamAuthScheme: 'aws-sigv4',
    awsAccessKeyId: 'AKIATEST',
    awsSecretAccessKey: 'secret',
    awsRegion: 'us-east-1',
  }).upstreamAuth.configured, true);
  assert.deepStrictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'https://upstream.test', rateLimitStore: 'sqlite' }).rateLimit, {
    limit: 60,
    windowMs: 60000,
    store: 'sqlite',
    shared: true,
    scope: 'single_host',
  });
  assert.deepStrictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'https://upstream.test', rateLimitStore: 'http', rateLimitUrl: 'https://limiter.example.test/check' }).rateLimit, {
    limit: 60,
    windowMs: 60000,
    store: 'http',
    shared: true,
    endpoint: 'https://limiter.example.test',
    externalConfigured: true,
  });
  assert.strictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'https://upstream.test', rateLimitStore: 'http' }).status, 'attention');
  assert.throws(() => createRateLimiter({ rateLimitStore: 'redis' }), /unsupported gateway rate limit store/);
  assert.throws(() => createHttpRateLimiter({ limit: 1, windowMs: 1000, url: 'https://user:pass@limiter.test/check' }), /must not contain credentials/);
  assert.strictEqual(isBufferedStreamingRequest({ pathname: '/v1/messages' }, { stream: true }), true);
  assert.strictEqual(isBufferedStreamingRequest({ pathname: '/model/anthropic.claude-3-haiku-20240307-v1%3A0/converse-stream' }, {}), false);
  const signed = signAwsSigV4({
    method: 'POST',
    target: new URL('https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-haiku-20240307-v1%3A0/converse'),
    headers: { 'content-type': 'application/json' },
    body: '{"messages":[]}',
    opts: {
      awsAccessKeyId: 'AKIATEST',
      awsSecretAccessKey: 'test-secret',
      awsRegion: 'us-east-1',
      awsNow: new Date('2026-07-04T00:00:00.000Z'),
    },
  });
  assert.match(signed.authorization, /^AWS4-HMAC-SHA256 Credential=AKIATEST\/20260704\/us-east-1\/bedrock\/aws4_request/);
  assert.strictEqual(signed['x-amz-date'], '20260704T000000Z');
  assert.match(signed['x-amz-content-sha256'], /^[a-f0-9]{64}$/);
  assert.ok(!signed.authorization.includes('test-secret'));

  const replaced = replacePromptPayload({
    messages: [
      { role: 'system', content: 'ignore' },
      { role: 'user', content: 'first secret' },
      { role: 'user', content: [{ type: 'text', text: 'second secret' }] },
    ],
  }, '[[US_SSN_1]]');
  assert.strictEqual(replaced.replaced, 2);
  assert.strictEqual(replaced.body.messages[1].content, '[[US_SSN_1]]');
  assert.strictEqual(replaced.body.messages[2].content[0].text, '[[US_SSN_1]]');
  const replacedGeminiPrompt = replacePromptPayload({
    contents: [{ role: 'user', parts: [{ text: 'Gemini secret' }] }],
  }, 'Gemini [[REDACTED]]');
  assert.strictEqual(replacedGeminiPrompt.replaced, 1);
  assert.strictEqual(replacedGeminiPrompt.body.contents[0].parts[0].text, 'Gemini [[REDACTED]]');
  const replacedBedrockPrompt = replacePromptPayload({
    inputText: 'Titan secret',
    messages: [{ role: 'user', content: [{ text: 'Bedrock secret' }] }],
  }, 'Bedrock [[REDACTED]]');
  assert.strictEqual(replacedBedrockPrompt.replaced, 2);
  assert.strictEqual(replacedBedrockPrompt.body.inputText, 'Bedrock [[REDACTED]]');
  assert.strictEqual(replacedBedrockPrompt.body.messages[0].content[0].text, 'Bedrock [[REDACTED]]');

  const response = {
    choices: [{ message: { role: 'assistant', content: 'Member SSN 524-71-9043' } }],
    output_text: 'Member SSN 524-71-9043',
  };
  assert.match(extractResponseText(response), /524-71-9043/);
  const redacted = rewriteResponseJson(response, 'Member SSN ***-**-9043');
  assert.ok(!JSON.stringify(redacted).includes('524-71-9043'));
  assert.strictEqual(redacted.redactwall.responseRedacted, true);
  const contentArrayResponse = {
    choices: [{ message: { role: 'assistant', content: [{ type: 'text', text: 'Array SSN 524-71-9043' }] } }],
  };
  assert.match(extractResponseText(contentArrayResponse), /524-71-9043/);
  const redactedArray = rewriteResponseJson(contentArrayResponse, 'Array SSN ***-**-9043');
  assert.ok(!JSON.stringify(redactedArray).includes('524-71-9043'));
  const geminiResponse = { candidates: [{ content: { parts: [{ text: 'Gemini SSN 524-71-9043' }] } }] };
  assert.match(extractResponseText(geminiResponse), /524-71-9043/);
  const redactedGemini = rewriteResponseJson(geminiResponse, 'Gemini SSN ***-**-9043');
  assert.ok(!JSON.stringify(redactedGemini).includes('524-71-9043'));
  const bedrockResponse = { output: { message: { role: 'assistant', content: [{ text: 'Bedrock SSN 524-71-9043' }] } } };
  assert.match(extractResponseText(bedrockResponse), /524-71-9043/);
  const redactedBedrock = rewriteResponseJson(bedrockResponse, 'Bedrock SSN ***-**-9043');
  assert.ok(!JSON.stringify(redactedBedrock).includes('524-71-9043'));
  assert.strictEqual(redactedBedrock.output.message.content[0].text, 'Bedrock SSN ***-**-9043');
  assert.strictEqual(inspectRequestContent({ contents: [{ role: 'user', parts: [{ inlineData: { mimeType: 'image/png', data: 'abc' } }] }] }).inspectable, false);
  assert.deepStrictEqual(inspectRequestContent({ messages: [{ role: 'user', content: [{ document: { name: 'loan', source: { bytes: 'abc' } } }] }] }), {
    inspectable: false,
    reasons: ['opaque_binary_content', 'unscannable_content', 'bedrock_non_text_document'],
  });
  assert.strictEqual(inspectRequestContent({ input: [123, 456] }).inspectable, false);
  assert.strictEqual(inspectRequestContent({
    messages: [{ role: 'user', content: 'safe text' }],
    provider_metadata: { content_base64: Buffer.from('SSN 123-45-6789').toString('base64') },
  }).inspectable, false);

  const splitEncoded = Buffer.from('SSN 123-45-6789').toString('base64');
  assert.strictEqual(inspectRequestContent({
    messages: [{ role: 'user', content: [
      { type: 'text', text: splitEncoded.slice(0, 8) },
      { type: 'text', text: splitEncoded.slice(8) },
    ] }],
  }).inspectable, false);

  assert.deepStrictEqual(promptForwardPlan({ decision: 'redact', status: 'redacted', tokenizedPrompt: 'safe' }), {
    forward: true,
    bodyMode: 'redacted',
    prompt: 'safe',
  });
  for (const verdict of [
    { decision: 'allow', status: 'pending' },
    { decision: 'block', status: 'allowed' },
    { decision: 'redact', status: 'allowed', tokenizedPrompt: 'safe' },
    { decision: 'warn', status: 'pending' },
  ]) {
    assert.strictEqual(promptForwardPlan(verdict).forward, false, JSON.stringify(verdict));
  }
});

test('gateway rejects contradictory control-plane verdicts before the upstream boundary', async () => {
  const contradictions = [
    { decision: 'allow', status: 'pending' },
    { decision: 'block', status: 'allowed' },
    { decision: 'redact', status: 'allowed', tokenizedPrompt: '[safe]' },
  ];
  for (const contradiction of contradictions) {
    let upstreamCalls = 0;
    const server = createGatewayServer({
      clientToken: 'client-token',
      upstream: 'https://upstream.test',
      fetchImpl: async (url) => {
        if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, contradiction);
        upstreamCalls += 1;
        return jsonFetchResponse(200, { choices: [{ message: { content: 'must not be returned' } }] });
      },
    });
    const port = await listen(server);
    try {
      const response = await gatewayRequest(port);
      assert.strictEqual(response.status, 403, JSON.stringify(contradiction));
      assert.strictEqual(upstreamCalls, 0, JSON.stringify(contradiction));
    } finally {
      await close(server);
    }
  }
});

test('gateway rejects declared and chunked oversized bodies without waiting for request end', async () => {
  let fetchCalls = 0;
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    maxBodyBytes: 1024,
    requestBodyTimeoutMs: 1000,
    fetchImpl: async () => { fetchCalls += 1; return jsonFetchResponse(200, {}); },
  });
  const port = await listen(server);
  try {
    const declared = await gatewayRequest(port, {
      headers: { 'content-length': '4096' },
      body: '{}',
    });
    assert.strictEqual(declared.status, 413);

    const chunked = await openEndedGatewayRequest(port, [Buffer.alloc(800, 0x61), Buffer.alloc(400, 0x62)]);
    assert.strictEqual(chunked.status, 413);
    assert.ok(chunked.elapsedMs < 750, `oversize rejection took ${chunked.elapsedMs} ms`);
    assert.strictEqual(fetchCalls, 0);
  } finally {
    await close(server);
  }
});

test('gateway times out a stalled request body and configures bounded server timeouts', async () => {
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    requestBodyTimeoutMs: 100,
    headersTimeoutMs: 500,
    keepAliveTimeoutMs: 750,
    fetchImpl: async () => jsonFetchResponse(200, {}),
  });
  assert.strictEqual(server.requestTimeout, 1100);
  assert.strictEqual(server.headersTimeout, 500);
  assert.strictEqual(server.keepAliveTimeout, 750);
  const port = await listen(server);
  try {
    const response = await openEndedGatewayRequest(port, [Buffer.from('{"messages":[')]);
    assert.strictEqual(response.status, 408);
    assert.match(response.body, /request body timed out/);
  } finally {
    await close(server);
  }
});

test('gateway requires client auth, rate-limits callers, and leaves upstream untouched on failure', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    rateLimit: 1,
    rateWindowMs: 60000,
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url, opts });
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_allowed', decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) return jsonFetchResponse(200, { leaked: false, decision: 'allow', status: 'allowed', blocked: false });
      return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: 'safe answer' } }] });
    },
  });
  const port = await listen(server);
  try {
    const missing = await gatewayRequest(port, { token: '' });
    assert.strictEqual(missing.status, 401);
    assert.match(missing.body, /missing gateway client token/);
    assert.match(missing.headers['x-redactwall-request-id'], /^[A-Za-z0-9_-]/);
    assert.strictEqual(calls.length, 0);

    const first = await gatewayRequest(port);
    assert.strictEqual(first.status, 200);
    assert.strictEqual(first.headers['x-ratelimit-limit'], '1');
    assert.strictEqual(first.headers['x-ratelimit-remaining'], '0');
    const second = await gatewayRequest(port);
    assert.strictEqual(second.status, 429);
    assert.match(second.body, /gateway rate limit exceeded/);
    assert.strictEqual(second.headers['x-ratelimit-limit'], '1');
  } finally {
    await close(server);
  }
});

test('sqlite gateway rate limit store is shared across gateway instances', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-gateway-rate-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const dbPath = path.join(dir, 'rate-limit.db');
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url: String(url), opts });
    if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_allowed', decision: 'allow', status: 'allowed' });
    if (String(url).includes('/api/v1/scan-response')) return jsonFetchResponse(200, { leaked: false, decision: 'allow', status: 'allowed', blocked: false });
    return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: 'safe answer' } }] });
  };
  const opts = {
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    rateLimit: 1,
    rateWindowMs: 60000,
    rateLimitStore: 'sqlite',
    rateLimitDbPath: dbPath,
    fetchImpl,
  };
  const firstServer = createGatewayServer(opts);
  const secondServer = createGatewayServer(opts);
  const firstPort = await listen(firstServer);
  const secondPort = await listen(secondServer);
  try {
    const first = await gatewayRequest(firstPort);
    assert.strictEqual(first.status, 200);
    assert.strictEqual(first.headers['x-ratelimit-limit'], '1');
    assert.strictEqual(first.headers['x-ratelimit-remaining'], '0');

    const second = await gatewayRequest(secondPort);
    assert.strictEqual(second.status, 429);
    assert.match(second.body, /gateway rate limit exceeded/);
    assert.strictEqual(second.headers['x-ratelimit-limit'], '1');
    assert.strictEqual(calls.filter((call) => call.url === 'https://upstream.test/v1/chat/completions').length, 1);
  } finally {
    await close(firstServer);
    await close(secondServer);
  }
});

test('http gateway rate limit store delegates hashed keys and fails closed', async () => {
  const limiterRequests = [];
  const upstreamCalls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    rateLimit: 1,
    rateWindowMs: 60000,
    rateLimitStore: 'http',
    rateLimitUrl: 'https://limiter.example.test/check',
    rateLimitToken: 'limiter-token',
    fetchImpl: async (url, opts = {}) => {
      if (String(url) === 'https://limiter.example.test/check') {
        limiterRequests.push({ headers: opts.headers, body: JSON.parse(opts.body) });
        return jsonFetchResponse(200, {
          ok: limiterRequests.length === 1,
          limit: 1,
          remaining: 0,
          resetMs: 5000,
        });
      }
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_allowed', decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) return jsonFetchResponse(200, { leaked: false, decision: 'allow', status: 'allowed', blocked: false });
      upstreamCalls.push(String(url));
      return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: 'safe answer' } }] });
    },
  });
  const port = await listen(server);
  try {
    const first = await gatewayRequest(port);
    assert.strictEqual(first.status, 200);
    assert.strictEqual(first.headers['x-ratelimit-limit'], '1');

    const second = await gatewayRequest(port);
    assert.strictEqual(second.status, 429);
    assert.match(second.body, /gateway rate limit exceeded/);
    assert.strictEqual(limiterRequests.length, 2);
    assert.strictEqual(limiterRequests[0].headers.authorization, 'Bearer limiter-token');
    assert.match(limiterRequests[0].body.key, /^[a-f0-9]{64}$/);
    assert.notStrictEqual(limiterRequests[0].body.key, 'client-token');
    assert.strictEqual(limiterRequests[0].body.limit, 1);
    assert.strictEqual(limiterRequests[0].body.windowMs, 60000);
    assert.deepStrictEqual(upstreamCalls, ['https://upstream.test/v1/chat/completions']);
  } finally {
    await close(server);
  }

  const downServer = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    rateLimitStore: 'http',
    rateLimitUrl: 'https://limiter.example.test/check',
    fetchImpl: async (url) => {
      if (String(url) === 'https://limiter.example.test/check') throw new Error('limiter down');
      throw new Error('upstream should not be called without limiter');
    },
  });
  const downPort = await listen(downServer);
  try {
    const res = await gatewayRequest(downPort);
    assert.strictEqual(res.status, 503);
    assert.match(res.body, /shared rate limiter unavailable/);
  } finally {
    await close(downServer);
  }
});

test('gateway publishes readiness and blocks disallowed models without leaking prompt text', async () => {
  const secret = '524-71-9043';
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    allowedModels: ['gpt-4o-mini', 'company-*'],
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url: String(url), opts });
      if (String(url) === 'http://localhost:4000/api/v1/detectors') {
        return jsonFetchResponse(200, detectorInventory());
      }
      if (String(url) === 'http://localhost:4000/readyz') {
        return jsonFetchResponse(200, { ready: true, database: true });
      }
      if (String(url) === 'https://upstream.test/' && opts.method === 'HEAD') {
        return new Response(null, { status: 204 });
      }
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_model_blocked', decision: 'block', status: 'action_blocked' });
      throw new Error('upstream should not be called for a blocked model');
    },
  });
  const port = await listen(server);
  try {
    const health = await gatewayRequest(port, { method: 'GET', path: '/readyz', body: '', token: '' });
    assert.strictEqual(health.status, 200);
    const healthBody = health.json();
    assert.strictEqual(healthBody.status, 'ready');
    assert.strictEqual(healthBody.controlPlaneReachable, true);
    assert.strictEqual(healthBody.upstreamReachable, true);
    assert.deepStrictEqual(healthBody.allowedModels, ['gpt-4o-mini', 'company-*']);
    assert.ok(!health.body.includes('client-token'));

    const blocked = await gatewayRequest(port, {
      headers: { 'x-redactwall-user': 'analyst@example.test' },
      body: { model: 'unknown-model', messages: [{ role: 'user', content: `Member SSN ${secret}` }] },
    });
    assert.strictEqual(blocked.status, 403);
    assert.match(blocked.body, /model blocked/);
    assert.ok(!blocked.body.includes(secret));
    assert.match(blocked.headers['x-redactwall-request-id'], /^[A-Za-z0-9_-]/);

    const gate = calls.find((call) => call.url.includes('/api/v1/gate'));
    assert.ok(gate);
    const gateBody = JSON.parse(gate.opts.body);
    assert.strictEqual(gateBody.clientOutcome, 'action_blocked');
    assert.strictEqual(gateBody.prompt, '[LLM model blocked] unknown-model');
    assert.ok(!gate.opts.body.includes(secret));
  } finally {
    await close(server);
  }
});

test('gateway readiness fails closed when configured dependencies are unreachable', async () => {
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    readinessFetchImpl: async (url) => {
      if (String(url) === 'http://localhost:4000/api/v1/detectors') {
        return jsonFetchResponse(200, detectorInventory());
      }
      if (String(url) === 'http://localhost:4000/readyz') {
        return jsonFetchResponse(200, { ready: true, database: true });
      }
      throw new Error('upstream unavailable');
    },
  });
  const port = await listen(server);
  try {
    const response = await gatewayRequest(port, { method: 'GET', path: '/readyz', body: '', token: '' });
    assert.strictEqual(response.status, 503);
    const body = response.json();
    assert.strictEqual(body.status, 'attention');
    assert.strictEqual(body.controlPlaneReady, true);
    assert.strictEqual(body.upstreamReady, false);
    assert.strictEqual(body.upstreamReachable, false);
  } finally {
    await close(server);
  }
});

test('gateway readiness rejects a reachable lookalike control plane', async () => {
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    readinessFetchImpl: async (url, options = {}) => {
      if (String(url) === 'http://localhost:4000/api/v1/detectors') {
        return jsonFetchResponse(200, [{ id: 'UNRELATED_DETECTOR' }]);
      }
      if (String(url) === 'http://localhost:4000/readyz') {
        return jsonFetchResponse(200, { ready: true, database: true });
      }
      if (String(url) === 'https://upstream.test/' && options.method === 'HEAD') {
        return new Response(null, { status: 204 });
      }
      throw new Error('unexpected readiness target');
    },
  });
  const port = await listen(server);
  try {
    const response = await gatewayRequest(port, { method: 'GET', path: '/readyz', body: '', token: '' });
    assert.strictEqual(response.status, 503);
    const body = response.json();
    assert.strictEqual(body.controlPlaneReachable, true);
    assert.strictEqual(body.controlPlaneReady, false);
  } finally {
    await close(server);
  }
});

test('gateway readiness authenticates only to the configured control-plane origin', async () => {
  const controlPlanes = [
    'https://control-plane.test/redactwall',
    'http://127.0.0.1:43123/redactwall',
  ];
  for (const controlPlane of controlPlanes) {
    const calls = [];
    const base = controlPlane.replace(/\/+$/, '');
    const server = createGatewayServer({
      clientToken: 'client-token',
      redactwall: controlPlane,
      key: 'invalid-ingest-key',
      upstream: 'https://upstream.test',
      readinessFetchImpl: async (url, options = {}) => {
        calls.push({ url: String(url), options });
        if (String(url) === `${base}/api/v1/detectors`) {
          return jsonFetchResponse(401, { error: 'invalid ingest key' });
        }
        if (String(url) === `${base}/healthz`) {
          return jsonFetchResponse(200, { status: 'ok', service: 'redactwall' });
        }
        if (String(url) === `${base}/readyz`) {
          return jsonFetchResponse(200, { ready: true, database: true });
        }
        if (String(url) === 'https://upstream.test/' && options.method === 'HEAD') {
          return new Response(null, { status: 204 });
        }
        throw new Error('unexpected readiness target');
      },
    });
    const port = await listen(server);
    try {
      const response = await gatewayRequest(port, { method: 'GET', path: '/readyz', body: '', token: '' });
      assert.strictEqual(response.status, 503, `${controlPlane} accepted an invalid ingest key`);
      const body = response.json();
      assert.strictEqual(body.controlPlaneReachable, true);
      assert.strictEqual(body.controlPlaneReady, false);
      assert.ok(!response.body.includes('invalid-ingest-key'));

      const authenticated = calls.filter((call) => new Headers(call.options.headers || {}).has('x-api-key'));
      assert.strictEqual(authenticated.length, 1);
      assert.strictEqual(authenticated[0].url, `${base}/api/v1/detectors`);
      assert.strictEqual(new Headers(authenticated[0].options.headers).get('x-api-key'), 'invalid-ingest-key');
      assert.strictEqual(authenticated[0].options.redirect, 'error');
    } finally {
      await close(server);
    }
  }

  const remoteCleartextCalls = [];
  const remoteCleartextServer = createGatewayServer({
    clientToken: 'client-token',
    redactwall: 'http://control-plane.example/redactwall',
    key: 'must-not-leave-over-cleartext',
    upstream: 'https://upstream.test',
    allowInsecureDev: true,
    readinessFetchImpl: async (url, options = {}) => {
      remoteCleartextCalls.push({ url: String(url), options });
      if (String(url).endsWith('/api/v1/detectors')) return jsonFetchResponse(200, detectorInventory());
      if (String(url).endsWith('/readyz')) return jsonFetchResponse(200, { ready: true, database: true });
      return new Response(null, { status: 204 });
    },
  });
  const remoteCleartextPort = await listen(remoteCleartextServer);
  try {
    const response = await gatewayRequest(remoteCleartextPort, { method: 'GET', path: '/readyz', body: '', token: '' });
    assert.strictEqual(response.status, 503);
    assert.strictEqual(response.json().controlPlaneReady, false);
    assert.ok(!remoteCleartextCalls.some((call) => new Headers(call.options.headers || {}).has('x-api-key')));
    assert.ok(!response.body.includes('must-not-leave-over-cleartext'));
  } finally {
    await close(remoteCleartextServer);
  }
});

test('gateway readiness probes the external shared limiter without consuming a rate-limit slot', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    rateLimitStore: 'http',
    rateLimitUrl: 'https://limiter.test/check',
    rateLimitToken: 'limiter-token',
    readinessFetchImpl: async (url, options = {}) => {
      calls.push({ url: String(url), method: options.method });
      if (String(url) === 'http://localhost:4000/api/v1/detectors') {
        return jsonFetchResponse(200, detectorInventory());
      }
      if (String(url) === 'http://localhost:4000/readyz') {
        return jsonFetchResponse(200, { ready: true, database: true });
      }
      if (String(url) === 'https://upstream.test/' && options.method === 'HEAD') {
        return new Response(null, { status: 401 });
      }
      if (String(url) === 'https://limiter.test/readyz') {
        return jsonFetchResponse(503, { status: 'attention', service: 'redactwall-ai-gateway-rate-limiter' });
      }
      throw new Error('unexpected readiness target');
    },
  });
  const port = await listen(server);
  try {
    const response = await gatewayRequest(port, { method: 'GET', path: '/readyz', body: '', token: '' });
    assert.strictEqual(response.status, 503);
    const body = response.json();
    assert.strictEqual(body.upstreamReachable, true, 'an upstream HTTP response proves network reachability');
    assert.strictEqual(body.rateLimit.ready, false);
    assert.strictEqual(body.rateLimit.reachable, true);
    assert.ok(calls.some((call) => call.url === 'https://limiter.test/readyz' && call.method === 'GET'));
    assert.ok(!calls.some((call) => call.url.endsWith('/check')), 'readiness must not consume a limiter check');
  } finally {
    await close(server);
  }
});

test('allowed prompts are gated, forwarded with gateway upstream auth, and response-scanned', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    upstreamApiKey: 'upstream-key',
    redactwall: 'https://control-plane.test',
    key: 'ingest-key',
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url: String(url), opts });
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_allowed', decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) return jsonFetchResponse(200, { leaked: false, decision: 'allow', status: 'allowed', blocked: false });
      return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: 'safe answer' } }] });
    },
  });
  const port = await listen(server);
  try {
    const res = await gatewayRequest(port, {
      headers: { 'x-redactwall-user': 'analyst@example.test' },
      body: { messages: [{ role: 'user', content: 'Summarize public FAQ copy.' }] },
    });
    assert.strictEqual(res.status, 200, res.body);
    assert.match(res.body, /safe answer/);
    assert.match(res.headers['x-redactwall-request-id'], /^[A-Za-z0-9_-]/);

    const gate = calls.find((call) => call.url === 'https://control-plane.test/api/v1/gate');
    assert.strictEqual(gate.opts.headers['x-api-key'], 'ingest-key');
    assert.strictEqual(JSON.parse(gate.opts.body).source, 'proxy');
    assert.strictEqual(JSON.parse(gate.opts.body).channel, 'llm_gateway');

    const upstream = calls.find((call) => call.url === 'https://upstream.test/v1/chat/completions');
    assert.ok(upstream);
    assert.strictEqual(upstream.opts.headers.authorization, 'Bearer upstream-key');
    assert.ok(!JSON.stringify(upstream.opts.headers).includes('client-token'));

    const scan = calls.find((call) => call.url === 'https://control-plane.test/api/v1/scan-response');
    assert.match(JSON.parse(scan.opts.body).text, /safe answer/);
    assert.match(JSON.parse(scan.opts.body).text, /choices/);
  } finally {
    await close(server);
  }
});

test('gateway supports provider-native Gemini routes and buffered streaming responses', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://provider.test',
    upstreamApiKey: 'provider-key',
    upstreamAuthHeader: 'x-goog-api-key',
    upstreamAuthScheme: 'none',
    upstreamHeader: ['anthropic-version=2023-06-01'],
    allowedModels: ['gemini-*', 'claude-*'],
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url: String(url), opts });
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_allowed', decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) return jsonFetchResponse(200, { leaked: false, decision: 'allow', status: 'allowed', blocked: false });
      if (String(url).includes(':generateContent')) {
        assert.ok(opts.body.includes('Gemini native prompt'));
        assert.strictEqual(opts.headers['x-goog-api-key'], 'provider-key');
        assert.strictEqual(opts.headers['anthropic-version'], '2023-06-01');
        assert.ok(!JSON.stringify(opts.headers).includes('client-token'));
        return jsonFetchResponse(200, { candidates: [{ content: { parts: [{ text: 'Gemini safe answer' }] } }] });
      }
      assert.strictEqual(opts.headers['x-goog-api-key'], 'provider-key');
      assert.ok(!JSON.stringify(opts.headers).includes('client-token'));
      return textFetchResponse(
        200,
        'event: content_block_delta\ndata: {"delta":{"type":"text_delta","text":"Claude streamed safe answer"}}\n\n',
        { 'content-type': 'text/event-stream; charset=utf-8' },
      );
    },
  });
  const port = await listen(server);
  try {
    const gemini = await gatewayRequest(port, {
      path: '/v1beta/models/gemini-1.5-pro:generateContent',
      body: { contents: [{ role: 'user', parts: [{ text: 'Gemini native prompt' }] }] },
    });
    assert.strictEqual(gemini.status, 200);
    assert.match(gemini.body, /Gemini safe answer/);
    const geminiGate = calls.find((call) => call.url.includes('/api/v1/gate'));
    assert.match(JSON.parse(geminiGate.opts.body).prompt, /Gemini native prompt/);
    assert.match(JSON.parse(geminiGate.opts.body).prompt, /contents/);

    calls.length = 0;
    const streamed = await gatewayRequest(port, {
      path: '/v1/messages',
      body: { model: 'claude-sonnet-4-5', stream: true, messages: [{ role: 'user', content: [{ type: 'text', text: 'Claude native prompt' }] }] },
    });
    assert.strictEqual(streamed.status, 200);
    assert.strictEqual(streamed.headers['x-redactwall-stream-buffered'], 'true');
    assert.match(streamed.headers['content-type'], /text\/event-stream/);
    assert.match(streamed.body, /Claude streamed safe answer/);
    const streamScan = calls.find((call) => call.url.includes('/api/v1/scan-response'));
    assert.match(JSON.parse(streamScan.opts.body).text, /Claude streamed safe answer/);
  } finally {
    await close(server);
  }
});

test('buffered OpenAI and Anthropic SSE responses join text deltas before encoded-content release', async () => {
  const encoded = Buffer.from('SSN 123-45-6789').toString('base64');
  const pieces = [encoded.slice(0, 8), encoded.slice(8)];
  const streams = [
    pieces.map((piece) => `data: ${JSON.stringify({ choices: [{ delta: { content: piece } }] })}\n\n`).join('') + 'data: [DONE]\n\n',
    pieces.map((piece) => `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', delta: { type: 'text_delta', text: piece } })}\n\n`).join(''),
    pieces.map((piece) => `data: ${JSON.stringify({ choices: [{ delta: { function_call: { arguments: piece } } }] })}\n\n`).join(''),
    pieces.map((piece) => `data: ${JSON.stringify({ choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: piece } }] } }] })}\n\n`).join(''),
    pieces.map((piece) => `data: ${JSON.stringify({ type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: piece })}\n\n`).join(''),
    pieces.map((piece) => `event: input_json_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: piece } })}\n\n`).join(''),
    pieces.map((piece) => `data: ${JSON.stringify({ candidates: [{ index: 0, content: { parts: [{ text: piece }] } }] })}\n\n`).join(''),
    '\uFEFF' + pieces.map((piece) => `data: ${JSON.stringify({ choices: [{ delta: { content: piece } }] })}\n\n`).join(''),
  ];
  let upstreamCalls = 0;
  let responseScans = 0;
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://provider.test',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) {
        responseScans += 1;
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed', blocked: false });
      }
      const body = streams[upstreamCalls++];
      return textFetchResponse(200, body, { 'content-type': 'text/event-stream' });
    },
  });
  const port = await listen(server);
  try {
    for (let index = 0; index < streams.length; index += 1) {
      const response = await gatewayRequest(port, {
        body: { model: 'provider-model', stream: true, messages: [{ role: 'user', content: 'public prompt' }] },
      });
      assert.strictEqual(response.status, 403);
      assert.match(response.body, /cannot inspect/);
      assert.ok(!response.body.includes(pieces[0]));
      assert.ok(!response.body.includes(pieces[1]));
    }
    assert.strictEqual(responseScans, 0);
  } finally {
    await close(server);
  }
});

test('malformed non-DONE SSE frames fail closed before split encoded content can be released', async () => {
  const encoded = Buffer.from('SSN 123-45-6789').toString('base64');
  const pieces = encoded.match(/.{1,8}/g);
  let responseScans = 0;
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://provider.test',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) {
        responseScans += 1;
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed', blocked: false });
      }
      const safe = `data: ${JSON.stringify({ choices: [{ delta: { content: 'safe prefix' } }] })}\n\n`;
      return textFetchResponse(200, safe + pieces.map((piece) => `data: ${piece}\n\n`).join(''), {
        'content-type': 'text/event-stream',
      });
    },
  });
  const port = await listen(server);
  try {
    const response = await gatewayRequest(port, {
      body: { model: 'provider-model', stream: true, messages: [{ role: 'user', content: 'public prompt' }] },
    });
    assert.strictEqual(response.status, 403);
    assert.match(response.body, /malformed streaming data/);
    assert.strictEqual(responseScans, 0);
    for (const piece of pieces) assert.ok(!response.body.includes(piece));
  } finally {
    await close(server);
  }
});

test('mislabeled SSE is sniffed and reconstructed before release', async () => {
  const encoded = Buffer.from('SSN 123-45-6789').toString('base64');
  const pieces = [encoded.slice(0, 8), encoded.slice(8)];
  let responseScans = 0;
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://provider.test',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) {
        responseScans += 1;
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed', blocked: false });
      }
      const body = pieces.map((piece) => `data: ${JSON.stringify({ choices: [{ delta: { content: piece } }] })}\n\n`).join('');
      return textFetchResponse(200, body, { 'content-type': 'text/plain' });
    },
  });
  const port = await listen(server);
  try {
    const response = await gatewayRequest(port, {
      body: { model: 'provider-model', stream: true, messages: [{ role: 'user', content: 'public prompt' }] },
    });
    assert.strictEqual(response.status, 403);
    assert.strictEqual(responseScans, 0);
    for (const piece of pieces) assert.ok(!response.body.includes(piece));
  } finally {
    await close(server);
  }
});

test('redacted SSE preserves event-stream MIME and valid framing', async () => {
  const rawSsn = '123-45-6789';
  const upstreamBody = `data: ${JSON.stringify({ choices: [{ delta: { content: `Member SSN ${rawSsn}` } }] })}\n\ndata: [DONE]\n\n`;
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://provider.test',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) {
        return jsonFetchResponse(200, {
          decision: 'redact',
          status: 'response_redacted',
          blocked: false,
          findings: [{ type: 'US_SSN' }],
          categories: [],
        });
      }
      return textFetchResponse(200, upstreamBody, { 'content-type': 'text/event-stream; charset=utf-8' });
    },
  });
  const port = await listen(server);
  try {
    const response = await gatewayRequest(port, {
      body: { model: 'provider-model', stream: true, messages: [{ role: 'user', content: 'public prompt' }] },
    });
    assert.strictEqual(response.status, 200, response.body);
    assert.match(response.headers['content-type'], /^text\/event-stream/);
    assert.match(response.body, /^data: /);
    assert.match(response.body, /data: \[DONE\]/);
    assert.match(response.body, /\[US_SSN\]/);
    assert.ok(!response.body.includes(rawSsn));
  } finally {
    await close(server);
  }
});

test('gateway supports Bedrock Converse paths with prompt gating and response redaction', async () => {
  const secret = '524-71-9043';
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://bedrock-runtime.test',
    upstreamAuthScheme: 'aws-sigv4',
    awsAccessKeyId: 'AKIATEST',
    awsSecretAccessKey: 'aws-secret-should-not-leak',
    awsRegion: 'us-east-1',
    awsNow: new Date('2026-07-04T00:00:00.000Z'),
    allowedModels: ['anthropic.claude-*'],
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url: String(url), opts });
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_bedrock_allowed', decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) {
        return jsonFetchResponse(200, {
          leaked: true,
          decision: 'redact',
          status: 'response_redacted',
          blocked: false,
          redacted: 'Bedrock response includes member SSN ***-**-9043.',
          findings: [{ type: 'US_SSN', masked: '***-**-9043' }],
          categories: [],
        });
      }
      assert.strictEqual(String(url), 'https://bedrock-runtime.test/model/anthropic.claude-3-5-sonnet-20240620-v1%3A0/converse');
      assert.match(opts.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIATEST\/20260704\/us-east-1\/bedrock\/aws4_request/);
      assert.strictEqual(opts.headers['x-amz-date'], '20260704T000000Z');
      assert.ok(!JSON.stringify(opts.headers).includes('client-token'));
      assert.ok(!JSON.stringify(opts.headers).includes('aws-secret-should-not-leak'));
      assert.ok(opts.body.includes('Bedrock Converse prompt'));
      return jsonFetchResponse(200, {
        output: { message: { role: 'assistant', content: [{ text: `Bedrock response includes member SSN ${secret}.` }] } },
      });
    },
  });
  const port = await listen(server);
  try {
    const res = await gatewayRequest(port, {
      path: '/model/anthropic.claude-3-5-sonnet-20240620-v1%3A0/converse',
      body: { messages: [{ role: 'user', content: [{ text: 'Bedrock Converse prompt' }] }] },
    });
    assert.strictEqual(res.status, 200);
    assert.ok(!res.body.includes(secret));
    assert.match(res.body, /\[US_SSN\]/);
    const gate = calls.find((call) => call.url.includes('/api/v1/gate'));
    assert.match(JSON.parse(gate.opts.body).prompt, /Bedrock Converse prompt/);
    assert.strictEqual(JSON.parse(gate.opts.body).destination, 'bedrock-runtime.test');
    const scan = calls.find((call) => call.url.includes('/api/v1/scan-response'));
    assert.match(JSON.parse(scan.opts.body).text, /524-71-9043/);
  } finally {
    await close(server);
  }
});

test('gateway rejects Bedrock binary event-stream routes before control-plane or upstream calls', async () => {
  let fetchCalls = 0;
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://bedrock-runtime.test',
    allowedModels: ['anthropic.claude-*'],
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error('Bedrock event-stream route must not make network calls');
    },
  });
  const port = await listen(server);
  try {
    for (const path of [
      '/model/anthropic.claude-3-haiku-20240307-v1%3A0/converse-stream',
      '/model/anthropic.claude-3-haiku-20240307-v1%3A0/invoke-with-response-stream',
    ]) {
      const response = await gatewayRequest(port, {
        path,
        body: { messages: [{ role: 'user', content: [{ text: 'public prompt' }] }] },
      });
      assert.strictEqual(response.status, 501);
      assert.match(response.body, /AWS event-stream decoding is not implemented/);
    }
    assert.strictEqual(fetchCalls, 0);
  } finally {
    await close(server);
  }
});

test('gateway blocks uninspectable provider-native non-text payloads before upstream', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://provider.test',
    allowedModels: ['gemini-*'],
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url: String(url), opts });
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_non_text', decision: 'block', status: 'action_blocked' });
      throw new Error('upstream should not receive non-text payloads');
    },
  });
  const port = await listen(server);
  try {
    const blocked = await gatewayRequest(port, {
      path: '/v1beta/models/gemini-1.5-pro:generateContent',
      body: { contents: [{ role: 'user', parts: [{ text: 'Describe this image.' }, { inlineData: { mimeType: 'image/png', data: 'raw-image-data' } }] }] },
    });
    assert.strictEqual(blocked.status, 415);
    assert.match(blocked.body, /non-text content/);
    assert.ok(!blocked.body.includes('raw-image-data'));
    const gate = calls.find((call) => call.url.includes('/api/v1/gate'));
    assert.ok(gate);
    assert.ok(!gate.opts.body.includes('raw-image-data'));
    assert.ok(!calls.some((call) => call.url.includes(':generateContent')));
  } finally {
    await close(server);
  }
});

test('gateway blocks Bedrock non-text content blocks before upstream', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://bedrock-runtime.test',
    allowedModels: ['anthropic.claude-*'],
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url: String(url), opts });
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_bedrock_non_text', decision: 'block', status: 'action_blocked' });
      throw new Error('upstream should not receive Bedrock document payloads');
    },
  });
  const port = await listen(server);
  try {
    const blocked = await gatewayRequest(port, {
      path: '/model/anthropic.claude-3-5-sonnet-20240620-v1%3A0/converse',
      body: { messages: [{ role: 'user', content: [{ text: 'Review this loan file.' }, { document: { name: 'loan', source: { bytes: 'raw-doc-bytes' } } }] }] },
    });
    assert.strictEqual(blocked.status, 415);
    assert.match(blocked.body, /non-text content/);
    assert.ok(!blocked.body.includes('raw-doc-bytes'));
    const gate = calls.find((call) => call.url.includes('/api/v1/gate'));
    assert.ok(gate);
    assert.ok(!gate.opts.body.includes('raw-doc-bytes'));
    assert.ok(!calls.some((call) => call.url.includes('/model/')));
  } finally {
    await close(server);
  }
});

test('redact prompt verdict sends only tokenized text upstream and redacts leaked model output', async () => {
  const secret = '524-71-9043';
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url: String(url), opts });
      if (String(url).includes('/api/v1/gate')) {
        return jsonFetchResponse(200, {
          id: 'q_redacted',
          decision: 'redact',
          status: 'redacted',
          tokenizedPrompt: 'Review member SSN [[US_SSN_1]].',
          findings: [{ type: 'US_SSN', masked: '***-**-9043' }],
          categories: [],
        });
      }
      if (String(url).includes('/api/v1/scan-response')) {
        return jsonFetchResponse(200, {
          leaked: true,
          decision: 'redact',
          status: 'response_redacted',
          blocked: false,
          redacted: 'The answer includes member SSN ***-**-9043.',
          findings: [{ type: 'US_SSN', masked: '***-**-9043' }],
          categories: [],
        });
      }
      assert.ok(!opts.body.includes(secret));
      assert.ok(opts.body.includes('[US_SSN]'));
      return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: `The answer includes member SSN ${secret}.` } }] });
    },
  });
  const port = await listen(server);
  try {
    const res = await gatewayRequest(port, {
      body: { messages: [{ role: 'user', content: `Review member SSN ${secret}.` }] },
    });
    assert.strictEqual(res.status, 200);
    assert.ok(!res.body.includes(secret));
    assert.match(res.body, /\[US_SSN\]/);
    const upstream = calls.find((call) => call.url === 'https://upstream.test/v1/chat/completions');
    assert.ok(!upstream.opts.body.includes(secret));
  } finally {
    await close(server);
  }
});

test('pending prompts wait for release when configured and block when denied or unavailable', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    approvalWaitMs: 100,
    approvalPollMs: 1,
    sleepImpl: async () => {},
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url: String(url), opts });
      if (String(url).includes('/api/v1/gate')) {
        return jsonFetchResponse(200, { id: 'q_hold', decision: 'block', status: 'pending', releaseToken: 'release-token', reasons: ['Withheld'] });
      }
      if (String(url).includes('/api/v1/status/q_hold')) {
        return jsonFetchResponse(200, { id: 'q_hold', status: 'approved', released: true });
      }
      if (String(url).includes('/api/v1/scan-response')) return jsonFetchResponse(200, { leaked: false, decision: 'allow', status: 'allowed', blocked: false });
      return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: 'released answer' } }] });
    },
  });
  const port = await listen(server);
  try {
    const res = await gatewayRequest(port, {
      body: { messages: [{ role: 'user', content: 'Synthetic member SSN 524-71-9043 for approval.' }] },
    });
    assert.strictEqual(res.status, 200);
    assert.match(res.body, /released answer/);
    const statusCall = calls.find((call) => call.url.includes('/api/v1/status/q_hold'));
    assert.strictEqual(statusCall.opts.headers['x-release-token'], 'release-token');
  } finally {
    await close(server);
  }

  const blockedServer = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    approvalWaitMs: 0,
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_hold', decision: 'block', status: 'pending', releaseToken: 'release-token' });
      throw new Error('upstream should not be called');
    },
  });
  const blockedPort = await listen(blockedServer);
  try {
    const res = await gatewayRequest(blockedPort, {
      body: { messages: [{ role: 'user', content: 'Synthetic member SSN 524-71-9043.' }] },
    });
    assert.strictEqual(res.status, 403);
    assert.match(res.body, /prompt blocked by RedactWall/);
  } finally {
    await close(blockedServer);
  }
});

test('gateway blocks uninspectable requests and fail-closes when control plane or response scan is unavailable', async () => {
  const failClosed = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) throw new Error('control plane down');
      throw new Error('upstream should not be called');
    },
  });
  const failClosedPort = await listen(failClosed);
  try {
    const res = await gatewayRequest(failClosedPort, {
      body: { messages: [{ role: 'user', content: 'safe but ungated' }] },
    });
    assert.strictEqual(res.status, 503);
    assert.match(res.body, /control plane unavailable/);

    const streaming = await gatewayRequest(failClosedPort, {
      body: { stream: true, messages: [{ role: 'user', content: 'stream this' }] },
    });
    assert.strictEqual(streaming.status, 503);
    assert.match(streaming.body, /control plane unavailable/);
    assert.ok(!streaming.body.includes('stream this'));
  } finally {
    await close(failClosed);
  }

  const responseScanDown = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_allowed', decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) throw new Error('response scan down');
      return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: 'unscanned answer' } }] });
    },
  });
  const responseScanDownPort = await listen(responseScanDown);
  try {
    const res = await gatewayRequest(responseScanDownPort);
    assert.strictEqual(res.status, 502);
    assert.match(res.body, /response scan unavailable/);
    assert.ok(!res.body.includes('unscanned answer'));
  } finally {
    await close(responseScanDown);
  }
});

test('gateway withholds opaque encoded request and response envelopes', async () => {
  const encoded = Buffer.from('SSN 123-45-6789').toString('base64');
  let upstreamCalls = 0;
  const requestServer = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    allowMultimodal: true,
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) {
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      }
      upstreamCalls += 1;
      return jsonFetchResponse(200, { choices: [{ message: { content: 'should not run' } }] });
    },
  });
  const requestPort = await listen(requestServer);
  try {
    const res = await gatewayRequest(requestPort, { body: {
      messages: [{ role: 'user', content: 'safe text' }],
      provider_metadata: { content_base64: encoded },
    } });
    assert.strictEqual(res.status, 415);
    assert.strictEqual(upstreamCalls, 0);
    assert.ok(!res.body.includes(encoded));
  } finally {
    await close(requestServer);
  }

  let responseScans = 0;
  const responseServer = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) {
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      }
      if (String(url).includes('/api/v1/scan-response')) {
        responseScans += 1;
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed', blocked: false });
      }
      return jsonFetchResponse(200, {
        choices: [{ message: { role: 'assistant', content: 'safe text' } }],
        provider_metadata: { content_base64: encoded },
      });
    },
  });
  const responsePort = await listen(responseServer);
  try {
    const res = await gatewayRequest(responsePort);
    assert.strictEqual(res.status, 403);
    assert.match(res.body, /cannot inspect/);
    assert.strictEqual(responseScans, 0);
    assert.ok(!res.body.includes(encoded));
  } finally {
    await close(responseServer);
  }
});

test('deployable gateway withholds encoded SSNs and numeric content with zero upstream or released bytes', async () => {
  const secret = 'SSN 123-45-6789';
  const wrappedBase64 = Buffer.from(secret).toString('base64').match(/.{1,4}/g).join(' ');
  const opaqueRequests = [
    { messages: [{ role: 'user', content: Buffer.from(secret).toString('base64') }] },
    { messages: [{ role: 'user', content: wrappedBase64 }] },
    { messages: [{ role: 'user', content: Buffer.from(secret).toString('hex') }] },
    { messages: [{ role: 'user', content: Buffer.from([0, 255, 1, 254, 2, 253, 3, 252, 4, 251, 5, 250]).toString('base64') }] },
    {
      messages: [{ role: 'user', content: 'ordinary caption' }],
      provider_metadata: { output: [...Buffer.from(secret)] },
    },
    {
      messages: [{
        role: 'user',
        content: [{ type: 'text', text: 'ordinary caption', metadata: { raw: [...Buffer.from(secret)] } }],
      }],
    },
  ];
  let upstreamCalls = 0;
  const requestServer = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    allowMultimodal: true,
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      upstreamCalls += 1;
      return jsonFetchResponse(200, { choices: [{ message: { content: 'must not run' } }] });
    },
  });
  const requestPort = await listen(requestServer);
  try {
    for (const body of opaqueRequests) {
      const opaque = body.provider_metadata
        ? JSON.stringify(body.provider_metadata.output)
        : JSON.stringify(body.messages[0].content);
      const response = await gatewayRequest(requestPort, { body });
      assert.strictEqual(response.status, 415);
      assert.ok(!response.body.includes(opaque.replace(/^"|"$/g, '')));
    }
    assert.strictEqual(upstreamCalls, 0);
  } finally {
    await close(requestServer);
  }

  const opaqueResponses = [
    Buffer.from(secret).toString('base64'),
    wrappedBase64,
    Buffer.from(secret).toString('hex'),
    Buffer.from([0, 255, 1, 254, 2, 253, 3, 252, 4, 251, 5, 250]).toString('base64'),
    [...Buffer.from(secret)],
    [{ type: 'text', text: 'ordinary response', metadata: { raw: [...Buffer.from(secret)] } }],
  ];
  const responseCount = opaqueResponses.length;
  let responseScans = 0;
  const responseServer = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) {
        responseScans += 1;
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed', blocked: false });
      }
      return jsonFetchResponse(200, { choices: [{ message: { content: opaqueResponses.shift() } }] });
    },
  });
  const responsePort = await listen(responseServer);
  try {
    for (let i = 0; i < responseCount; i += 1) {
      const opaque = opaqueResponses[0];
      const response = await gatewayRequest(responsePort);
      assert.strictEqual(response.status, 403);
      assert.ok(!response.body.includes(typeof opaque === 'string' ? opaque : JSON.stringify(opaque)));
    }
    assert.strictEqual(responseScans, 0);
  } finally {
    await close(responseServer);
  }

  const textResponses = [
    Buffer.from(secret).toString('base64'),
    Buffer.from(secret).toString('hex'),
    JSON.stringify([...Buffer.from(secret)]),
  ];
  const textResponseCount = textResponses.length;
  let textResponseScans = 0;
  const textResponseServer = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) {
        textResponseScans += 1;
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed', blocked: false });
      }
      return textFetchResponse(200, textResponses.shift());
    },
  });
  const textResponsePort = await listen(textResponseServer);
  try {
    for (let i = 0; i < textResponseCount; i += 1) {
      const opaque = textResponses[0];
      const response = await gatewayRequest(textResponsePort);
      assert.strictEqual(response.status, 403);
      assert.ok(!response.body.includes(opaque));
    }
    assert.strictEqual(textResponseScans, 0);
  } finally {
    await close(textResponseServer);
  }

  let eventResponseScans = 0;
  const eventResponseServer = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) {
        eventResponseScans += 1;
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed', blocked: false });
      }
      const event = { choices: [{ delta: { content: [...Buffer.from(secret)] } }] };
      return textFetchResponse(200, `data: ${JSON.stringify(event)}\n\ndata: [DONE]\n\n`, {
        'content-type': 'text/event-stream',
      });
    },
  });
  const eventResponsePort = await listen(eventResponseServer);
  try {
    const response = await gatewayRequest(eventResponsePort);
    assert.strictEqual(response.status, 403);
    assert.strictEqual(eventResponseScans, 0);
    assert.ok(!response.body.includes(JSON.stringify([...Buffer.from(secret)])));
  } finally {
    await close(eventResponseServer);
  }
});

test('deployable gateway permits harmless alphanumeric encodings and structured numeric records', async () => {
  const harmlessEncodedText = Buffer.from('quarterly branch hours').toString('base64');
  let upstreamBody = null;
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url, opts = {}) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed', blocked: false });
      upstreamBody = JSON.parse(opts.body);
      return jsonFetchResponse(200, {
        choices: [{ message: { content: 'CustomerAccountStatus' } }],
        data: [{ embedding: [0.125, -0.5, 0.75], records: [2023, 2024, 2025] }],
      });
    },
  });
  const port = await listen(server);
  try {
    const response = await gatewayRequest(port, { body: {
      messages: [{ role: 'user', content: harmlessEncodedText }],
      provider_metadata: {
        metrics: [1, 2, 3],
        rows: [{ year: 2025, amount: 42 }],
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        jwtId: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1bml0LXVzZXIifQ.signature',
      },
    } });
    assert.strictEqual(response.status, 200);
    assert.ok(upstreamBody);
    assert.deepStrictEqual(response.json().data[0].records, [2023, 2024, 2025]);
  } finally {
    await close(server);
  }
});

test('deployable gateway withholds contradictory response decision, status, and blocked pairs', async () => {
  const contradictions = [
    { decision: 'allow', status: 'response_blocked', blocked: false },
    { decision: 'block', status: 'allowed', blocked: true },
    { decision: 'redact', status: 'allowed', blocked: false },
    { decision: 'flag', status: 'response_redacted', blocked: false },
    { decision: 'allow', status: 'allowed', blocked: true },
    { decision: 'block', status: 'response_blocked', blocked: false },
    { decision: 'allow', blocked: false },
  ];
  for (const scan of contradictions) {
    let upstreamCalls = 0;
    const marker = 'MODEL_OUTPUT_MUST_NOT_BE_RELEASED';
    const server = createGatewayServer({
      clientToken: 'client-token',
      upstream: 'https://upstream.test',
      fetchImpl: async (url) => {
        if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
        if (String(url).includes('/api/v1/scan-response')) return jsonFetchResponse(200, scan);
        upstreamCalls += 1;
        return jsonFetchResponse(200, { choices: [{ message: { content: marker } }] });
      },
    });
    const port = await listen(server);
    try {
      const response = await gatewayRequest(port);
      assert.strictEqual(response.status, 403, JSON.stringify(scan));
      assert.strictEqual(upstreamCalls, 1, JSON.stringify(scan));
      assert.ok(!response.body.includes(marker), JSON.stringify(scan));
      assert.strictEqual(response.json().status, 'response_scan_invalid');
    } finally {
      await close(server);
    }
  }
});

test('redact verdict sanitizes the complete serialized request envelope before upstream', async () => {
  const secret = '524-71-9043';
  let upstreamBody;
  let gatedText = '';
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url, opts = {}) => {
      if (String(url).includes('/api/v1/gate')) {
        gatedText = JSON.parse(opts.body).prompt;
        return jsonFetchResponse(200, {
          id: 'q_full_envelope',
          decision: 'redact',
          status: 'redacted',
          tokenizedPrompt: '[server-tokenized-envelope]',
          findings: [{ type: 'US_SSN' }],
          categories: [],
        });
      }
      if (String(url).includes('/api/v1/scan-response')) {
        return jsonFetchResponse(200, { leaked: false, decision: 'allow', status: 'allowed', blocked: false });
      }
      upstreamBody = JSON.parse(opts.body);
      return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: 'safe result' } }] });
    },
  });
  const port = await listen(server);
  try {
    const res = await gatewayRequest(port, { body: {
      model: 'unit-model',
      messages: [
        { role: 'system', content: `system ${secret}` },
        { role: 'developer', content: `developer ${secret}` },
        { role: 'assistant', content: `assistant ${secret}`, tool_calls: [{ function: { name: 'lookup', arguments: `{"member":"${secret}"}` } }] },
        { role: 'tool', content: `tool result ${secret}` },
        { role: 'user', content: `user ${secret}` },
      ],
      metadata: { caseNote: `metadata ${secret}` },
    } });
    assert.strictEqual(res.status, 200, res.body);
    assert.match(gatedText, /system 524-71-9043/);
    assert.match(gatedText, /developer 524-71-9043/);
    assert.match(gatedText, /tool result 524-71-9043/);
    assert.match(gatedText, /metadata 524-71-9043/);
    assert.ok(upstreamBody);
    assert.ok(!JSON.stringify(upstreamBody).includes(secret));
    assert.match(JSON.stringify(upstreamBody), /\[US_SSN\]/);
  } finally {
    await close(server);
  }
});

test('response scan covers provider ids and metadata and withholds the raw envelope', async () => {
  const secret = '524-71-9043';
  let scanned = '';
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url, opts = {}) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) {
        scanned = JSON.parse(opts.body).text;
        return jsonFetchResponse(200, { leaked: true, decision: 'block', status: 'blocked', blocked: true, findings: [{ type: 'US_SSN' }] });
      }
      return jsonFetchResponse(200, {
        id: `provider-${secret}`,
        choices: [{ message: { role: 'assistant', content: 'safe answer' } }],
        vendor_metadata: { trace: secret },
      });
    },
  });
  const port = await listen(server);
  try {
    const res = await gatewayRequest(port);
    assert.strictEqual(res.status, 403);
    assert.match(scanned, /provider-524-71-9043/);
    assert.match(scanned, /vendor_metadata/);
    assert.ok(!res.body.includes(secret));
  } finally {
    await close(server);
  }
});

test('deployable gateway cancels chunked upstream overflow before response scanning', async () => {
  let cancelled = false;
  let scanCalls = 0;
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    maxResponseBytes: 1024,
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      if (String(url).includes('/api/v1/scan-response')) {
        scanCalls += 1;
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed', blocked: false });
      }
      let index = 0;
      const chunks = [Buffer.alloc(800, 0x61), Buffer.alloc(400, 0x62), Buffer.from('never-read')];
      return {
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        body: { getReader: () => ({
          read: async () => (index < chunks.length ? { done: false, value: chunks[index++] } : { done: true }),
          cancel: async () => { cancelled = true; },
        }) },
      };
    },
  });
  const port = await listen(server);
  try {
    const res = await gatewayRequest(port);
    assert.strictEqual(res.status, 502);
    assert.strictEqual(cancelled, true);
    assert.strictEqual(scanCalls, 0);
  } finally {
    await close(server);
  }
});

test('deployable gateway rejects remote cleartext upstream before sending credentials or prompts', async () => {
  let fetchCalls = 0;
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'http://provider.example.test',
    upstreamApiKey: 'must-not-leave',
    fetchImpl: async () => { fetchCalls += 1; return jsonFetchResponse(200, {}); },
  });
  const port = await listen(server);
  try {
    const res = await gatewayRequest(port);
    assert.strictEqual(res.status, 400);
    assert.match(res.body, /must use https for a remote host/);
    assert.strictEqual(fetchCalls, 0);
  } finally {
    await close(server);
  }
});

test('authenticated token identity cannot be overridden by caller headers', async () => {
  const gateBodies = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    fetchImpl: async (url, opts = {}) => {
      if (String(url).includes('/api/v1/gate')) {
        gateBodies.push(JSON.parse(opts.body));
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed' });
      }
      if (String(url).includes('/api/v1/scan-response')) {
        return jsonFetchResponse(200, { decision: 'allow', status: 'allowed', blocked: false });
      }
      return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: 'safe' } }] });
    },
  });
  const port = await listen(server);
  try {
    const victim = await gatewayRequest(port, { headers: {
      'x-redactwall-user': 'victim@example.test',
      'x-redactwall-org': 'tenant-victim',
    } });
    const attacker = await gatewayRequest(port, { headers: {
      'x-redactwall-user': 'attacker@example.test',
      'x-redactwall-org': 'tenant-attacker',
    } });
    assert.strictEqual(victim.status, 200);
    assert.strictEqual(attacker.status, 200);
    assert.strictEqual(gateBodies.length, 2);
    assert.strictEqual(gateBodies[0].user, gateBodies[1].user);
    assert.match(gateBodies[0].user, /^gateway-client-[a-f0-9]{12}$/);
    assert.strictEqual(gateBodies[0].orgId, null);
    assert.strictEqual(gateBodies[1].orgId, null);
    assert.ok(!JSON.stringify(gateBodies).includes('victim@example.test'));
    assert.ok(!JSON.stringify(gateBodies).includes('attacker@example.test'));
  } finally {
    await close(server);
  }
});
