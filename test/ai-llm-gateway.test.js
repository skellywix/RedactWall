'use strict';
/** AI LLM gateway enforces PromptWall decisions before and after upstream calls. */
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
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ 'content-type': 'application/json', ...headers }),
    arrayBuffer: async () => Buffer.from(JSON.stringify(body)),
    json: async () => body,
  };
}

function textFetchResponse(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ 'content-type': 'text/plain; charset=utf-8', ...headers }),
    arrayBuffer: async () => Buffer.from(String(body)),
  };
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

  const parsed = parseArgs(['--port', '4999', '--host', '0.0.0.0', '--token', 'client-token', '--upstream', 'http://upstream.test', '--upstream-auth-header', 'x-goog-api-key', '--upstream-auth-scheme', 'none', '--aws-region', 'us-east-1', '--aws-service', 'bedrock', '--upstream-header', 'anthropic-version=2023-06-01', '--approval-wait-ms', '250', '--rate-store', 'sqlite', '--rate-db-path', 'C:\\PromptWall\\rate.db', '--allowed-models', 'gpt-4o-mini,company-*']);
  assert.strictEqual(parsed.port, 4999);
  assert.strictEqual(parsed.host, '0.0.0.0');
  assert.strictEqual(parsed.clientToken, 'client-token');
  assert.strictEqual(parsed.upstream, 'http://upstream.test');
  assert.strictEqual(parsed.upstreamAuthHeader, 'x-goog-api-key');
  assert.strictEqual(parsed.upstreamAuthScheme, 'none');
  assert.strictEqual(parsed.awsRegion, 'us-east-1');
  assert.strictEqual(parsed.awsService, 'bedrock');
  assert.deepStrictEqual(parsed.upstreamHeader, ['anthropic-version=2023-06-01']);
  assert.strictEqual(parsed.approvalWaitMs, 250);
  assert.strictEqual(parsed.rateLimitStore, 'sqlite');
  assert.strictEqual(parsed.rateLimitDbPath, 'C:\\PromptWall\\rate.db');
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
  assert.strictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'http://upstream.test', allowedModels: ['gpt-4o-mini'] }).status, 'ready');
  assert.strictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'http://upstream.test' }).streaming, 'buffered_scan');
  assert.strictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'https://bedrock-runtime.us-east-1.amazonaws.com', upstreamAuthScheme: 'aws-sigv4' }).status, 'attention');
  assert.strictEqual(gatewayHealth({
    clientToken: 'client-token',
    upstream: 'https://bedrock-runtime.us-east-1.amazonaws.com',
    upstreamAuthScheme: 'aws-sigv4',
    awsAccessKeyId: 'AKIATEST',
    awsSecretAccessKey: 'secret',
    awsRegion: 'us-east-1',
  }).upstreamAuth.configured, true);
  assert.deepStrictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'http://upstream.test', rateLimitStore: 'sqlite' }).rateLimit, {
    limit: 60,
    windowMs: 60000,
    store: 'sqlite',
    shared: true,
    scope: 'single_host',
  });
  assert.deepStrictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'http://upstream.test', rateLimitStore: 'http', rateLimitUrl: 'https://limiter.example.test/check' }).rateLimit, {
    limit: 60,
    windowMs: 60000,
    store: 'http',
    shared: true,
    endpoint: 'https://limiter.example.test',
    externalConfigured: true,
  });
  assert.strictEqual(gatewayHealth({ clientToken: 'client-token', upstream: 'http://upstream.test', rateLimitStore: 'http' }).status, 'attention');
  assert.throws(() => createRateLimiter({ rateLimitStore: 'redis' }), /unsupported gateway rate limit store/);
  assert.throws(() => createHttpRateLimiter({ limit: 1, windowMs: 1000, url: 'https://user:pass@limiter.test/check' }), /must not contain credentials/);
  assert.strictEqual(isBufferedStreamingRequest({ pathname: '/v1/messages' }, { stream: true }), true);
  assert.strictEqual(isBufferedStreamingRequest({ pathname: '/model/anthropic.claude-3-haiku-20240307-v1%3A0/converse-stream' }, {}), true);
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
  assert.strictEqual(redacted.promptwall.responseRedacted, true);
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
    reasons: ['bedrock_non_text_document'],
  });

  assert.deepStrictEqual(promptForwardPlan({ decision: 'redact', status: 'redacted', tokenizedPrompt: 'safe' }), {
    forward: true,
    bodyMode: 'redacted',
    prompt: 'safe',
  });
});

test('gateway requires client auth, rate-limits callers, and leaves upstream untouched on failure', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'http://upstream.test',
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
    assert.match(missing.headers['x-promptwall-request-id'], /^[A-Za-z0-9_-]/);
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-gateway-rate-'));
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
    upstream: 'http://upstream.test',
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
    assert.strictEqual(calls.filter((call) => call.url === 'http://upstream.test/v1/chat/completions').length, 1);
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
    upstream: 'http://upstream.test',
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
    assert.deepStrictEqual(upstreamCalls, ['http://upstream.test/v1/chat/completions']);
  } finally {
    await close(server);
  }

  const downServer = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'http://upstream.test',
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
    upstream: 'http://upstream.test',
    allowedModels: ['gpt-4o-mini', 'company-*'],
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url: String(url), opts });
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
    assert.deepStrictEqual(healthBody.allowedModels, ['gpt-4o-mini', 'company-*']);
    assert.ok(!health.body.includes('client-token'));

    const blocked = await gatewayRequest(port, {
      headers: { 'x-promptwall-user': 'analyst@example.test' },
      body: { model: 'unknown-model', messages: [{ role: 'user', content: `Member SSN ${secret}` }] },
    });
    assert.strictEqual(blocked.status, 403);
    assert.match(blocked.body, /model blocked/);
    assert.ok(!blocked.body.includes(secret));
    assert.match(blocked.headers['x-promptwall-request-id'], /^[A-Za-z0-9_-]/);

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

test('allowed prompts are gated, forwarded with gateway upstream auth, and response-scanned', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'http://upstream.test',
    upstreamApiKey: 'upstream-key',
    sentinel: 'http://control-plane.test',
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
      headers: { 'x-promptwall-user': 'analyst@example.test' },
      body: { messages: [{ role: 'user', content: 'Summarize public FAQ copy.' }] },
    });
    assert.strictEqual(res.status, 200);
    assert.match(res.body, /safe answer/);
    assert.match(res.headers['x-promptwall-request-id'], /^[A-Za-z0-9_-]/);

    const gate = calls.find((call) => call.url === 'http://control-plane.test/api/v1/gate');
    assert.strictEqual(gate.opts.headers['x-api-key'], 'ingest-key');
    assert.strictEqual(JSON.parse(gate.opts.body).source, 'proxy');
    assert.strictEqual(JSON.parse(gate.opts.body).channel, 'llm_gateway');

    const upstream = calls.find((call) => call.url === 'http://upstream.test/v1/chat/completions');
    assert.ok(upstream);
    assert.strictEqual(upstream.opts.headers.authorization, 'Bearer upstream-key');
    assert.ok(!JSON.stringify(upstream.opts.headers).includes('client-token'));

    const scan = calls.find((call) => call.url === 'http://control-plane.test/api/v1/scan-response');
    assert.strictEqual(JSON.parse(scan.opts.body).text, 'safe answer');
  } finally {
    await close(server);
  }
});

test('gateway supports provider-native Gemini routes and buffered streaming responses', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'http://provider.test',
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
    assert.strictEqual(JSON.parse(geminiGate.opts.body).prompt, 'Gemini native prompt');

    calls.length = 0;
    const streamed = await gatewayRequest(port, {
      path: '/v1/messages',
      body: { model: 'claude-sonnet-4-5', stream: true, messages: [{ role: 'user', content: [{ type: 'text', text: 'Claude native prompt' }] }] },
    });
    assert.strictEqual(streamed.status, 200);
    assert.strictEqual(streamed.headers['x-promptwall-stream-buffered'], 'true');
    assert.match(streamed.headers['content-type'], /text\/event-stream/);
    assert.match(streamed.body, /Claude streamed safe answer/);
    const streamScan = calls.find((call) => call.url.includes('/api/v1/scan-response'));
    assert.match(JSON.parse(streamScan.opts.body).text, /Claude streamed safe answer/);
  } finally {
    await close(server);
  }
});

test('gateway supports Bedrock Converse paths with prompt gating and response redaction', async () => {
  const secret = '524-71-9043';
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'http://bedrock-runtime.test',
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
      assert.strictEqual(String(url), 'http://bedrock-runtime.test/model/anthropic.claude-3-5-sonnet-20240620-v1%3A0/converse');
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
    assert.match(res.body, /\*\*\*-\*\*-9043/);
    const gate = calls.find((call) => call.url.includes('/api/v1/gate'));
    assert.strictEqual(JSON.parse(gate.opts.body).prompt, 'Bedrock Converse prompt');
    assert.strictEqual(JSON.parse(gate.opts.body).destination, 'bedrock-runtime.test');
    const scan = calls.find((call) => call.url.includes('/api/v1/scan-response'));
    assert.match(JSON.parse(scan.opts.body).text, /524-71-9043/);
  } finally {
    await close(server);
  }
});

test('gateway blocks uninspectable provider-native non-text payloads before upstream', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'http://provider.test',
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
    upstream: 'http://bedrock-runtime.test',
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
    upstream: 'http://upstream.test',
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
      assert.ok(opts.body.includes('[[US_SSN_1]]'));
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
    assert.match(res.body, /\*\*\*-\*\*-9043/);
    const upstream = calls.find((call) => call.url === 'http://upstream.test/v1/chat/completions');
    assert.ok(!upstream.opts.body.includes(secret));
  } finally {
    await close(server);
  }
});

test('pending prompts wait for release when configured and block when denied or unavailable', async () => {
  const calls = [];
  const server = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'http://upstream.test',
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
    upstream: 'http://upstream.test',
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
    assert.match(res.body, /prompt blocked by PromptWall/);
  } finally {
    await close(blockedServer);
  }
});

test('gateway blocks uninspectable requests and fail-closes when control plane or response scan is unavailable', async () => {
  const failClosed = createGatewayServer({
    clientToken: 'client-token',
    upstream: 'http://upstream.test',
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
    upstream: 'http://upstream.test',
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
