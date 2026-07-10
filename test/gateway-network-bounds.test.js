'use strict';

const test = require('node:test');
const assert = require('node:assert');
const openai = require('../gateway/adapters/openai');
const { makeClient } = require('../gateway/client');

function chunkedResponse(chunks, headers = {}) {
  let index = 0;
  let cancelled = false;
  return {
    ok: true,
    status: 200,
    headers: new Headers(headers),
    body: { getReader: () => ({
      read: async () => (index < chunks.length
        ? { done: false, value: Buffer.from(chunks[index++]) }
        : { done: true }),
      cancel: async () => { cancelled = true; },
    }) },
    wasCancelled: () => cancelled,
  };
}

function jsonResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function detectorInventory() {
  return [
    { id: 'US_SSN', severity: 4, severityLabel: 'critical' },
    { id: 'CREDIT_CARD', severity: 4, severityLabel: 'critical' },
    { id: 'SECRET_KEY', severity: 4, severityLabel: 'critical' },
  ];
}

function readyControlPlane() {
  return { ready: true, database: true, configuration: 'ok' };
}

function controlPlaneClient(ingestKey = 'unit-ingest-key') {
  return makeClient({
    controlPlaneUrl: 'https://plane.example.test',
    ingestKey,
    requestTimeoutMs: 1000,
    maxControlPlaneResponseBytes: 1024,
  });
}

test('gateway upstream adapter cancels an unknown-length response at its byte limit', async () => {
  const originalFetch = globalThis.fetch;
  const response = chunkedResponse(['12345678', 'overflow', 'never-read']);
  globalThis.fetch = async () => response;
  try {
    await assert.rejects(() => openai.callUpstream('chat', { messages: [] }, {
      upstreamBaseUrl: 'https://provider.example.test',
      upstreamApiKey: 'unit-key',
      requestTimeoutMs: 1000,
      maxUpstreamResponseBytes: 10,
    }), /exceeds 10 byte limit/);
    assert.strictEqual(response.wasCancelled(), true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('gateway control-plane client rejects declared oversize before JSON parsing', async () => {
  const originalFetch = globalThis.fetch;
  let jsonCalled = false;
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    headers: new Headers({ 'content-length': '50000000' }),
    json: async () => { jsonCalled = true; return { decision: 'allow' }; },
  });
  try {
    const client = makeClient({
      controlPlaneUrl: 'https://plane.example.test',
      ingestKey: 'unit-ingest-key',
      requestTimeoutMs: 1000,
      maxControlPlaneResponseBytes: 1024,
    });
    const result = await client.gate({ prompt: 'safe' });
    assert.strictEqual(result._failClosed, true);
    assert.strictEqual(jsonCalled, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('gateway control-plane client times out a stalled response body', async () => {
  const originalFetch = globalThis.fetch;
  let cancelled = false;
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    headers: new Headers(),
    body: { getReader: () => ({
      read: async () => new Promise(() => {}),
      cancel: async () => { cancelled = true; },
    }) },
  });
  try {
    const client = makeClient({
      controlPlaneUrl: 'https://plane.example.test',
      ingestKey: 'unit-ingest-key',
      requestTimeoutMs: 20,
      maxControlPlaneResponseBytes: 1024,
    });
    const result = await client.gate({ prompt: 'safe' });
    assert.strictEqual(result._failClosed, true);
    assert.strictEqual(cancelled, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('gateway readiness proves the control-plane identity and ingest key without writing', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    const target = String(url);
    calls.push({ url: target, options });
    if (target.endsWith('/readyz')) return jsonResponse(200, readyControlPlane());
    if (options.headers['x-api-key'] !== 'unit-ingest-key') {
      return jsonResponse(401, { error: 'invalid ingest key' });
    }
    return jsonResponse(200, detectorInventory());
  };
  try {
    assert.deepStrictEqual(await controlPlaneClient().health(), { ok: true });
    assert.deepStrictEqual(await controlPlaneClient('wrong-ingest-key').health(), { ok: false });
    assert.deepStrictEqual(calls.map((call) => call.url), [
      'https://plane.example.test/api/v1/detectors',
      'https://plane.example.test/readyz',
      'https://plane.example.test/api/v1/detectors',
    ]);
    assert.ok(calls.every((call) => call.options.method === 'GET'));
    assert.deepStrictEqual(calls[1].options.headers, {}, 'public readiness must not receive the ingest key');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

for (const [label, response] of [
  ['401 response', () => jsonResponse(401, { error: 'invalid ingest key' })],
  ['404 response', () => jsonResponse(404, { error: 'not found' })],
  ['unrelated detector payload', () => jsonResponse(200, { status: 'ok', service: 'not-redactwall' })],
  ['oversize payload', () => jsonResponse(200, detectorInventory(), { 'content-length': '50000000' })],
]) {
  test(`gateway readiness rejects ${label}`, async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => response();
    try {
      assert.deepStrictEqual(await controlPlaneClient().health(), { ok: false });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
}

for (const [label, readyResponse] of [
  ['degraded control plane', () => jsonResponse(503, { ready: false, database: false })],
  ['unrelated readiness payload', () => jsonResponse(200, { status: 'ok', service: 'other' })],
  ['oversize readiness payload', () => jsonResponse(200, readyControlPlane(), { 'content-length': '50000000' })],
]) {
  test(`gateway readiness rejects ${label}`, async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => String(url).endsWith('/api/v1/detectors')
      ? jsonResponse(200, detectorInventory()) : readyResponse();
    try {
      assert.deepStrictEqual(await controlPlaneClient().health(), { ok: false });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
}
