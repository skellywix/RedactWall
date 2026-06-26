'use strict';
/** Real HTTP smoke tests for the importable Express app. */
const test = require('node:test');
const assert = require('node:assert');
const app = require('../server');

function listen(appUnderTest) {
  return new Promise((resolve, reject) => {
    const server = appUnderTest.listen(0, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
}

test('server module exports an app without requiring a fixed listening port', async (t) => {
  assert.strictEqual(typeof app, 'function');
  assert.strictEqual(typeof app.startServer, 'function');

  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();

  const res = await fetch(`http://127.0.0.1:${port}/healthz`);
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers.get('x-powered-by'), null);
  assert.match(res.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
  assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
  assert.strictEqual(res.headers.get('x-frame-options'), 'DENY');
  assert.strictEqual(res.headers.get('referrer-policy'), 'no-referrer');

  const body = await res.json();
  assert.strictEqual(body.status, 'ok');
  assert.strictEqual(body.service, 'promptsentinel');
});

test('readiness endpoint is reachable through the importable app', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();

  const res = await fetch(`http://127.0.0.1:${port}/readyz`);
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.ready, true);
});
