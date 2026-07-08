'use strict';
/** Sensor transport guard: cleartext to a remote plane leaks the ingest key. */
const test = require('node:test');
const assert = require('node:assert');
const { secureServerUrl, isLoopbackHost } = require('../sensors/shared/server-url');

test('https is accepted to any host; http only to loopback', () => {
  assert.ok(secureServerUrl('https://plane.vendor.example'));
  assert.ok(secureServerUrl('http://localhost:4000'));
  assert.ok(secureServerUrl('http://127.0.0.1:4000'));
  assert.ok(secureServerUrl('http://[::1]:4000'));
  assert.strictEqual(secureServerUrl('http://plane.vendor.example:4000'), null);
  assert.strictEqual(secureServerUrl('http://10.0.0.5:4000'), null);
  assert.strictEqual(secureServerUrl('ftp://plane.vendor.example'), null);
  assert.strictEqual(secureServerUrl('https://user:pass@plane.example'), null);
});

test('explicit override allows cleartext to a remote host', () => {
  assert.strictEqual(secureServerUrl('http://plane.vendor.example', false), null);
  assert.ok(secureServerUrl('http://plane.vendor.example', true));
});

test('loopback host detection', () => {
  for (const h of ['localhost', 'dev.localhost', '127.0.0.1', '127.5.5.5', '::1']) assert.ok(isLoopbackHost(h), h);
  for (const h of ['plane.example', '10.0.0.1', '169.254.169.254']) assert.strictEqual(isLoopbackHost(h), false, h);
});
