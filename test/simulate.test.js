'use strict';
const test = require('node:test');
const assert = require('node:assert');
const simulate = require('../scripts/simulate');

test('simulation gate calls reject redirects and remote cleartext targets', async () => {
  let request;
  const result = await simulate.post('/api/v1/gate', { prompt: 'public text' }, {
    base: 'https://redactwall.example/control/',
    key: 'unit-ingest-key',
    fetchImpl: async (url, options) => {
      request = { url, options };
      return new Response(JSON.stringify({ decision: 'allow' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  assert.strictEqual(result.json.decision, 'allow');
  assert.strictEqual(request.url, 'https://redactwall.example/control/api/v1/gate');
  assert.strictEqual(request.options.redirect, 'error');
  assert.strictEqual(request.options.headers['x-api-key'], 'unit-ingest-key');

  let cleartextCalled = false;
  await assert.rejects(() => simulate.post('/api/v1/gate', {}, {
    base: 'http://redactwall.example',
    key: 'unit-ingest-key',
    fetchImpl: async () => { cleartextCalled = true; },
  }), /must use HTTPS or loopback HTTP/);
  assert.strictEqual(cleartextCalled, false);
});
