'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { cancelResponseBody, readBoundedJson, readBoundedText } = require('../sensors/shared/bounded-response');

test('bounded response helper cancels an unread non-success body', async () => {
  let cancelled = false;
  await cancelResponseBody({ body: { cancel: async () => { cancelled = true; } } });
  assert.strictEqual(cancelled, true);
});

test('bounded response rejects declared oversize before buffered JSON helpers run', async () => {
  let jsonCalled = false;
  let cancelled = false;
  await assert.rejects(() => readBoundedJson({
    headers: new Headers({ 'content-length': '50000000' }),
    body: { cancel: async () => { cancelled = true; } },
    json: async () => { jsonCalled = true; return {}; },
  }, { maxBytes: 16, label: 'unit response' }), /exceeds 16 byte limit/);
  assert.strictEqual(jsonCalled, false);
  assert.strictEqual(cancelled, true);
});

test('bounded response cancels an unknown-length stream at the first oversize chunk', async () => {
  const chunks = [Buffer.from('abc'), Buffer.from('def'), Buffer.from('never-read')];
  let reads = 0;
  let cancelled = false;
  const response = {
    headers: new Headers(),
    body: { getReader: () => ({
      read: async () => (reads < chunks.length ? { done: false, value: chunks[reads++] } : { done: true }),
      cancel: async () => { cancelled = true; },
    }) },
  };
  await assert.rejects(() => readBoundedText(response, { maxBytes: 4, label: 'chunked response' }), /exceeds 4 byte limit/);
  assert.strictEqual(reads, 2);
  assert.strictEqual(cancelled, true);
});

test('bounded response times out a stalled body read', async () => {
  let cancelled = false;
  const response = {
    headers: new Headers(),
    body: { getReader: () => ({
      read: async () => new Promise(() => {}),
      cancel: async () => { cancelled = true; },
    }) },
  };
  await assert.rejects(
    () => readBoundedText(response, { maxBytes: 16, timeoutMs: 20, label: 'stalled response' }),
    (err) => err && err.code === 'REDACTWALL_RESPONSE_TIMEOUT'
  );
  assert.strictEqual(cancelled, true);
});
